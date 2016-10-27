package macvlans

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/netutils"
	"github.com/docker/libnetwork/ns"
	"github.com/docker/libnetwork/osl"
	"github.com/docker/libnetwork/types"
)

type endpointTable map[string]*endpoint

const macvlansEndpointPrefix = "macvlans/endpoint"

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

func (n *network) endpoint(eid string) (*endpoint, error) {
	n.Lock()
	defer n.Unlock()
	if eid == "" {
		return nil, fmt.Errorf("endpoint id %s not found", eid)
	}
	if ep, ok := n.endpoints[eid]; ok {
		return ep, nil
	}

	return nil, nil
}

func (n *network) addEndpoint(ep *endpoint) {
	n.Lock()
	n.endpoints[ep.id] = ep
	n.Unlock()
}

func (n *network) deleteEndpoint(eid string) {
	n.Lock()
	delete(n.endpoints, eid)
	n.Unlock()
}

// isIpAcceptable returns whether any ip range contains the given ip address.
func isIpAcceptable(ip net.IP, ipRanges []net.IPNet) bool {
	for _, ipRange := range ipRanges {
		if ipRange.Contains(ip) {
			return true
		}
	}
	return false
}

// CreateEndpoint assigns the mac, ip and endpoint id for the new container
func (d *driver) CreateEndpoint(nid, eid string, ifInfo driverapi.InterfaceInfo,
	epOptions map[string]interface{}) error {
	defer osl.InitOSContext()()

	if err := validateID(nid, eid); err != nil {
		return err
	}
	n, err := d.network(nid)
	if err != nil {
		return fmt.Errorf("network id %q not found", nid)
	}

	if ipRangesString, ok := epOptions[netlabel.MacvlansIpRanges]; ok {
		ipRanges := []net.IPNet{}
		for _, ipRange := range strings.Split(ipRangesString.(string), ",") {
			if _, cidr, err := net.ParseCIDR(ipRange); cidr != nil {
				ipRanges = append(ipRanges, *cidr)
			} else {
				log.Warnf("Invalid ip range: %s: %s", ipRange, err)
			}
		}
		addrs := []*net.IPNet{ifInfo.Address(), ifInfo.AddressIPv6()}
		for _, addr := range addrs {
			if addr == nil {
				continue
			}
			if !isIpAcceptable(addr.IP, ipRanges) {
				return fmt.Errorf(
					"IP %v is not acceptable: %s=%v",
					addr, netlabel.MacvlansIpRanges, ipRangesString)
			}
		}
	}

	ep := &endpoint{
		id:     eid,
		nid:    nid,
		addr:   ifInfo.Address(),
		addrv6: ifInfo.AddressIPv6(),
		mac:    ifInfo.MacAddress(),
	}
	if ep.addr == nil {
		return fmt.Errorf("create endpoint was not passed an IP address")
	}
	if ep.mac == nil {
		ep.mac = netutils.GenerateMACFromIP(ep.addr.IP)
		if err := ifInfo.SetMacAddress(ep.mac); err != nil {
			return err
		}
	}
	// disallow portmapping -p
	if opt, ok := epOptions[netlabel.PortMap]; ok {
		if _, ok := opt.([]types.PortBinding); ok {
			if len(opt.([]types.PortBinding)) > 0 {
				log.Warnf("%s driver does not support port mappings", macvlanType)
			}
		}
	}
	// disallow port exposure --expose
	if opt, ok := epOptions[netlabel.ExposedPorts]; ok {
		if _, ok := opt.([]types.TransportPort); ok {
			if len(opt.([]types.TransportPort)) > 0 {
				log.Warnf("%s driver does not support port exposures", macvlanType)
			}
		}
	}

	if err := d.storeUpdate(ep); err != nil {
		return fmt.Errorf("failed to save macvlan endpoint %s to store: %v", ep.id[0:7], err)
	}

	n.addEndpoint(ep)

	return nil
}

// DeleteEndpoint remove the endpoint and associated netlink interface
func (d *driver) DeleteEndpoint(nid, eid string) error {
	defer osl.InitOSContext()()
	if err := validateID(nid, eid); err != nil {
		return err
	}
	n, _ := d.network(nid)
	if n == nil {
		return fmt.Errorf("network id %q not found", nid)
	}
	ep, _ := n.endpoint(eid)
	if ep == nil {
		return fmt.Errorf("endpoint id %q not found", eid)
	}
	if link, err := ns.NlHandle().LinkByName(ep.srcName); err == nil {
		ns.NlHandle().LinkDel(link)
	}

	if err := d.storeDelete(ep); err != nil {
		log.Warnf("Failed to remove macvlan endpoint %s from store: %v", ep.id[0:7], err)
	}

	n.deleteEndpoint(ep.id)

	return nil
}

func (d *driver) EndpointOperInfo(nid, eid string) (map[string]interface{}, error) {
	return make(map[string]interface{}, 0), nil
}

func (d *driver) deleteEndpointFromStore(e *endpoint) error {
	if d.localStore == nil {
		return fmt.Errorf("macvlans local store not initialized, ep not deleted")
	}

	if err := d.localStore.DeleteObjectAtomic(e); err != nil {
		return err
	}

	return nil
}

func (ep *endpoint) DataScope() string {
	return datastore.LocalScope
}

func (ep *endpoint) New() datastore.KVObject {
	return &endpoint{}
}

func (ep *endpoint) CopyTo(o datastore.KVObject) error {
	dstEp := o.(*endpoint)
	*dstEp = *ep
	return nil
}

func (ep *endpoint) Key() []string {
	return []string{macvlanEndpointPrefix, ep.id}
}

func (ep *endpoint) KeyPrefix() []string {
	return []string{macvlanEndpointPrefix}
}

func (ep *endpoint) Index() uint64 {
	return ep.dbIndex
}

func (ep *endpoint) SetIndex(index uint64) {
	ep.dbIndex = index
	ep.dbExists = true
}

func (ep *endpoint) Exists() bool {
	return ep.dbExists
}

func (ep *endpoint) Skip() bool {
	return false
}

func (ep *endpoint) Value() []byte {
	b, err := json.Marshal(ep)
	if err != nil {
		return nil
	}
	return b
}

func (ep *endpoint) SetValue(value []byte) error {
	return json.Unmarshal(value, ep)
}

func (ep *endpoint) MarshalJSON() ([]byte, error) {
	epMap := make(map[string]interface{})
	epMap["id"] = ep.id
	epMap["nid"] = ep.nid
	epMap["SrcName"] = ep.srcName
	if len(ep.mac) != 0 {
		epMap["MacAddress"] = ep.mac.String()
	}
	if ep.addr != nil {
		epMap["Addr"] = ep.addr.String()
	}
	if ep.addrv6 != nil {
		epMap["Addrv6"] = ep.addrv6.String()
	}
	return json.Marshal(epMap)
}

func (ep *endpoint) UnmarshalJSON(b []byte) error {
	var (
		err   error
		epMap map[string]interface{}
	)

	if err = json.Unmarshal(b, &epMap); err != nil {
		return fmt.Errorf("Failed to unmarshal to macvlan endpoint: %v", err)
	}

	if v, ok := epMap["MacAddress"]; ok {
		if ep.mac, err = net.ParseMAC(v.(string)); err != nil {
			return types.InternalErrorf("failed to decode macvlan endpoint MAC address (%s) after json unmarshal: %v", v.(string), err)
		}
	}
	if v, ok := epMap["Addr"]; ok {
		if ep.addr, err = types.ParseCIDR(v.(string)); err != nil {
			return types.InternalErrorf("failed to decode macvlan endpoint IPv4 address (%s) after json unmarshal: %v", v.(string), err)
		}
	}
	if v, ok := epMap["Addrv6"]; ok {
		if ep.addrv6, err = types.ParseCIDR(v.(string)); err != nil {
			return types.InternalErrorf("failed to decode macvlan endpoint IPv6 address (%s) after json unmarshal: %v", v.(string), err)
		}
	}
	ep.id = epMap["id"].(string)
	ep.nid = epMap["nid"].(string)
	ep.srcName = epMap["SrcName"].(string)

	return nil
}
