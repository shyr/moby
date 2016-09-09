package macvlans

import (
	"fmt"
	"net"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/discoverapi"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/idm"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/osl"
	"github.com/docker/libnetwork/types"
	"github.com/hashicorp/serf/serf"
)

const (
	vethLen             = 7
	containerVethPrefix = "eth"
	vethPrefix          = "veth"
	macvlanType         = "macvlans" // driver type name
	modePrivate         = "private"  // macvlan mode private
	modeVepa            = "vepa"     // macvlan mode vepa
	modeBridge          = "bridge"   // macvlan mode bridge
	modePassthru        = "passthru" // macvlan mode passthrough
	parentOpt           = "parent"   // parent interface -o parent
	modeOpt             = "_mode"    // macvlan mode ux opt suffix
	vxlanPort           = 4789
	vxlanEncap          = 50
	networkType         = "macvlans" // Can we merge this with 'macvlanType'?
)

var driverModeOpt = macvlanType + modeOpt // mode --option macvlan_mode

type endpointTable map[string]*endpoint

type networkTable map[string]*network

type driver struct {
	eventCh      chan serf.Event
	notifyCh     chan ovNotify
	exitCh       chan chan struct{}
	networks     networkTable
	serfInstance *serf.Serf
	vxlanIdm     *idm.Idm
	sync.Once
	sync.Mutex
	store            datastore.DataStore
	peerDb           peerNetworkMap
	secMap           *encrMap
	config           map[string]interface{}
	keys             []*key
	bindAddress      string
	advertiseAddress string
	localStore       datastore.DataStore
}

type endpoint struct {
	id       string
	nid      string
	mac      net.HardwareAddr
	addr     *net.IPNet
	addrv6   *net.IPNet
	srcName  string
	dbIndex  uint64
	dbExists bool
}

type network struct {
	id        string
	sbox      osl.Sandbox
	endpoints endpointTable
	driver    *driver
	config    *configuration
	joinCnt   int
	once      *sync.Once
	initErr   error
	initEpoch int
	subnets   []*subnet // TODO: 혹시 config.ipv4Subnets와 통합해야 하는 것은 아닌가? 반드시 그럴 것 같다.
	secure    bool
	mtu       int
	sync.Mutex
}

type subnet struct {
	once      *sync.Once
	vxlanName string
	brName    string
	vni       uint32
	initErr   error
	subnetIP  *net.IPNet
	gwIP      *net.IPNet
}

// Init initializes and registers the libnetwork macvlan driver
func Init(dc driverapi.DriverCallback, config map[string]interface{}) error {
	c := driverapi.Capability{
		DataScope: datastore.GlobalScope,
	}
	d := &driver{
		networks: networkTable{},
		peerDb: peerNetworkMap{
			mp: map[string]*peerMap{},
		},
		secMap: &encrMap{nodes: map[string][]*spi{}},
		config: config,
	}

	if data, ok := config[netlabel.GlobalKVClient]; ok {
		var err error
		dsc, ok := data.(discoverapi.DatastoreConfigData)
		if !ok {
			return types.InternalErrorf("incorrect data in datastore configuration: %v", data)
		}
		d.store, err = datastore.NewDataStoreFromConfig(dsc)
		if err != nil {
			return types.InternalErrorf("failed to initialize data store: %v", err)
		}
	}

	if data, ok := config[netlabel.LocalKVClient]; ok {
		var err error
		dsc, ok := data.(discoverapi.DatastoreConfigData)
		if !ok {
			return types.InternalErrorf("incorrect data in datastore configuration: %v", data)
		}
		d.localStore, err = datastore.NewDataStoreFromConfig(dsc)
		if err != nil {
			return types.InternalErrorf("failed to initialize local data store: %v", err)
		}
	}

	d.restoreEndpoints()

	return dc.RegisterDriver(networkType, d, c)
}

func (d *driver) NetworkAllocate(id string, option map[string]string, ipV4Data, ipV6Data []driverapi.IPAMData) (map[string]string, error) {
	return nil, types.NotImplementedErrorf("not implemented")
}

func (d *driver) NetworkFree(id string) error {
	return types.NotImplementedErrorf("not implemented")
}

func (d *driver) EndpointOperInfo(nid, eid string) (map[string]interface{}, error) {
	return make(map[string]interface{}, 0), nil
}

func (d *driver) Type() string {
	return macvlanType
}

func (d *driver) ProgramExternalConnectivity(nid, eid string, options map[string]interface{}) error {
	return nil
}

func (d *driver) RevokeExternalConnectivity(nid, eid string) error {
	return nil
}

// DiscoverNew is a notification for a new discovery event
func (d *driver) DiscoverNew(dType discoverapi.DiscoveryType, data interface{}) error {
	return nil
}

// DiscoverDelete is a notification for a discovery delete event
func (d *driver) DiscoverDelete(dType discoverapi.DiscoveryType, data interface{}) error {
	return nil
}

func (d *driver) EventNotify(etype driverapi.EventType, nid, tableName, key string, value []byte) {
}

func (d *driver) deleteEndpointFromStore(e *endpoint) error {
	if d.localStore == nil {
		return fmt.Errorf("overlay local store not initialized, ep not deleted")
	}

	if err := d.localStore.DeleteObjectAtomic(e); err != nil {
		return err
	}

	return nil
}

// Endpoints are stored in the local store. Restore them and reconstruct the macvlans sandbox
// Copied from restoreEndpoints() at vendor/src/github.com/docker/libnetwork/drivers/overlay/overlay.go
func (d *driver) restoreEndpoints() error {
	if d.localStore == nil {
		logrus.Warnf("Cannot restore macvlans endpoints because local datastore is missing")
		return nil
	}
	kvol, err := d.localStore.List(datastore.Key(macvlansEndpointPrefix), &endpoint{})
	if err != nil && err != datastore.ErrKeyNotFound {
		return fmt.Errorf("failed to read macvlans endpoint from store: %v", err)
	}

	if err == datastore.ErrKeyNotFound {
		return nil
	}
	for _, kvo := range kvol {
		ep := kvo.(*endpoint)
		n := d.network(ep.nid)
		if n == nil {
			logrus.Debugf("Network (%s) not found for restored endpoint (%s)", ep.nid[0:7], ep.id[0:7])
			logrus.Debugf("Deleting stale macvlans endpoint (%s) from store", ep.id[0:7])
			if err := d.deleteEndpointFromStore(ep); err != nil {
				logrus.Debugf("Failed to delete stale macvlans endpoint (%s) from store", ep.id[0:7])
			}
			continue
		}
		n.addEndpoint(ep)

		s := n.getSubnetforIP(ep.addr)
		if s == nil {
			return fmt.Errorf("could not find subnet for endpoint %s", ep.id)
		}

		if err := n.joinSandbox(true); err != nil {
			return fmt.Errorf("restore network sandbox failed: %v", err)
		}

		if err := n.joinSubnetSandbox(s, true); err != nil {
			return fmt.Errorf("restore subnet sandbox failed for %q: %v", s.subnetIP.String(), err)
		}

		Ifaces := make(map[string][]osl.IfaceOption)
		vethIfaceOption := make([]osl.IfaceOption, 1)
		vethIfaceOption = append(vethIfaceOption, n.sbox.InterfaceOptions().Master(s.brName))
		Ifaces[fmt.Sprintf("%s+%s", "veth", "veth")] = vethIfaceOption

		err := n.sbox.Restore(Ifaces, nil, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to restore macvlans sandbox: %v", err)
		}

		n.incEndpointCount()
		d.peerDbAdd(ep.nid, ep.id, ep.addr.IP, ep.addr.Mask, ep.mac, net.ParseIP(d.advertiseAddress), true)
	}
	return nil
}

func (d *driver) pushLocalEndpointEvent(action, nid, eid string) {
	n := d.network(nid)
	if n == nil {
		logrus.Debugf("Error pushing local endpoint event for network %s", nid)
		return
	}
	ep := n.endpoint(eid)
	if ep == nil {
		logrus.Debugf("Error pushing local endpoint event for ep %s / %s", nid, eid)
		return
	}

	if !d.isSerfAlive() {
		return
	}
	d.notifyCh <- ovNotify{
		action: "join",
		nw:     n,
		ep:     ep,
	}
}
