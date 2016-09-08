package macvlans

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/parsers/kernel"
	"github.com/docker/docker/pkg/stringid"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/netutils"
	"github.com/docker/libnetwork/ns"
	"github.com/docker/libnetwork/options"
	"github.com/docker/libnetwork/osl"
	"github.com/docker/libnetwork/resolvconf"
	"github.com/docker/libnetwork/types"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
)

var (
	hostMode    bool
	networkOnce sync.Once
	networkMu   sync.Mutex
	vniTbl      = make(map[uint32]string)
)

type subnetJSON struct {
	SubnetIP string
	GwIP     string
	Vni      uint32
}

// CreateNetwork the network for the specified driver type
func (d *driver) CreateNetwork(nid string, option map[string]interface{}, nInfo driverapi.NetworkInfo, ipV4Data, ipV6Data []driverapi.IPAMData) error {
	defer osl.InitOSContext()()
	kv, err := kernel.GetKernelVersion()
	if err != nil {
		return fmt.Errorf("failed to check kernel version for %s driver support: %v", macvlanType, err)
	}
	// ensure Kernel version is >= v3.9 for macvlan support
	if kv.Kernel < macvlanKernelVer || (kv.Kernel == macvlanKernelVer && kv.Major < macvlanMajorVer) {
		return fmt.Errorf("kernel version failed to meet the minimum macvlan kernel requirement of %d.%d, found %d.%d.%d",
			macvlanKernelVer, macvlanMajorVer, kv.Kernel, kv.Major, kv.Minor)
	}
	// reject a null v4 network
	if len(ipV4Data) == 0 || ipV4Data[0].Pool.String() == "0.0.0.0/0" {
		return fmt.Errorf("ipv4 pool is empty")
	}
	// parse and validate the config and bind to networkConfiguration
	config, err := parseNetworkOptions(nid, option)
	if err != nil {
		return err
	}
	config.ID = nid
	err = config.processIPAM(nid, ipV4Data, ipV6Data)
	if err != nil {
		return err
	}
	// verify the macvlan mode from -o macvlan_mode option
	switch config.MacvlanMode {
	case "", modeBridge:
		// default to macvlan bridge mode if -o macvlan_mode is empty
		config.MacvlanMode = modeBridge
	case modeOpt:
		config.MacvlanMode = modeOpt
	case modePassthru:
		config.MacvlanMode = modePassthru
	case modeVepa:
		config.MacvlanMode = modeVepa
	default:
		return fmt.Errorf("requested macvlan mode '%s' is not valid, 'bridge' mode is the macvlan driver default", config.MacvlanMode)
	}
	// loopback is not a valid parent link
	if config.Parent == "lo" {
		return fmt.Errorf("loopback interface is not a valid %s parent link", macvlanType)
	}
	// if parent interface not specified, create a dummy type link to use named dummy+net_id
	if config.Parent == "" {
		config.Parent = getDummyName(stringid.TruncateID(config.ID))
		// empty parent and --internal are handled the same. Set here to update k/v
		config.Internal = true
	}
	err = d.createNetwork(config)
	if err != nil {
		return err
	}
	// update persistent db, rollback on fail
	err = d.storeUpdate(config)
	if err != nil {
		d.deleteNetwork(config.ID)
		logrus.Debugf("encoutered an error rolling back a network create for %s : %v", config.ID, err)
		return err
	}

	return nil
}

// createNetwork is used by new network callbacks and persistent network cache
func (d *driver) createNetwork(config *configuration) error {
	if !parentExists(config.Parent) {
		// if the --internal flag is set, create a dummy link
		if config.Internal {
			err := createDummyLink(config.Parent, getDummyName(stringid.TruncateID(config.ID)))
			if err != nil {
				return err
			}
			config.CreatedSlaveLink = true
			// notify the user in logs they have limited comunicatins
			if config.Parent == getDummyName(stringid.TruncateID(config.ID)) {
				logrus.Debugf("Empty -o parent= and --internal flags limit communications to other containers inside of network: %s",
					config.Parent)
			}
		} else {
			// if the subinterface parent_iface.vlan_id checks do not pass, return err.
			//  a valid example is 'eth0.10' for a parent iface 'eth0' with a vlan id '10'
			err := createVlanLink(config.Parent)
			if err != nil {
				return err
			}
			// if driver created the networks slave link, record it for future deletion
			config.CreatedSlaveLink = true
		}
	}
	n := &network{
		id:        config.ID,
		driver:    d,
		endpoints: endpointTable{},
		config:    config,
	}
	// add the *network
	d.addNetwork(n)

	return nil
}

// DeleteNetwork the network for the specified driver type
func (d *driver) DeleteNetwork(nid string) error {
	defer osl.InitOSContext()()
	n := d.network(nid)
	if n == nil {
		return fmt.Errorf("network id %s not found", nid)
	}
	// if the driver created the slave interface, delete it, otherwise leave it
	if ok := n.config.CreatedSlaveLink; ok {
		// if the interface exists, only delete if it matches iface.vlan or dummy.net_id naming
		if ok := parentExists(n.config.Parent); ok {
			// only delete the link if it is named the net_id
			if n.config.Parent == getDummyName(stringid.TruncateID(nid)) {
				err := delDummyLink(n.config.Parent)
				if err != nil {
					logrus.Debugf("link %s was not deleted, continuing the delete network operation: %v",
						n.config.Parent, err)
				}
			} else {
				// only delete the link if it matches iface.vlan naming
				err := delVlanLink(n.config.Parent)
				if err != nil {
					logrus.Debugf("link %s was not deleted, continuing the delete network operation: %v",
						n.config.Parent, err)
				}
			}
		}
	}
	// delete the *network
	d.deleteNetwork(nid)
	// delete the network record from persistent cache
	err := d.storeDelete(n.config)
	if err != nil {
		return fmt.Errorf("error deleting deleting id %s from datastore: %v", nid, err)
	}
	return nil
}

// parseNetworkOptions parse docker network options
func parseNetworkOptions(id string, option options.Generic) (*configuration, error) {
	var (
		err    error
		config = &configuration{}
	)
	// parse generic labels first
	if genData, ok := option[netlabel.GenericData]; ok && genData != nil {
		if config, err = parseNetworkGenericOptions(genData); err != nil {
			return nil, err
		}
	}
	// setting the parent to "" will trigger an isolated network dummy parent link
	if _, ok := option[netlabel.Internal]; ok {
		config.Internal = true
		// empty --parent= and --internal are handled the same.
		config.Parent = ""
	}

	return config, nil
}

// parseNetworkGenericOptions parse generic driver docker network options
func parseNetworkGenericOptions(data interface{}) (*configuration, error) {
	var (
		err    error
		config *configuration
	)
	switch opt := data.(type) {
	case *configuration:
		config = opt
	case map[string]string:
		config = &configuration{}
		err = config.fromOptions(opt)
	case options.Generic:
		var opaqueConfig interface{}
		if opaqueConfig, err = options.GenerateFromModel(opt, config); err == nil {
			config = opaqueConfig.(*configuration)
		}
	default:
		err = types.BadRequestErrorf("unrecognized network configuration format: %v", opt)
	}

	return config, err
}

// fromOptions binds the generic options to networkConfiguration to cache
func (config *configuration) fromOptions(labels map[string]string) error {
	for label, value := range labels {
		switch label {
		case parentOpt:
			// parse driver option '-o parent'
			config.Parent = value
		case driverModeOpt:
			// parse driver option '-o macvlan_mode'
			config.MacvlanMode = value
		}
	}

	return nil
}

// processIPAM parses v4 and v6 IP information and binds it to the network configuration
func (config *configuration) processIPAM(id string, ipamV4Data, ipamV6Data []driverapi.IPAMData) error {
	if len(ipamV4Data) > 0 {
		for _, ipd := range ipamV4Data {
			s := &ipv4Subnet{
				SubnetIP: ipd.Pool.String(),
				GwIP:     ipd.Gateway.String(),
			}
			config.Ipv4Subnets = append(config.Ipv4Subnets, s)
		}
	}
	if len(ipamV6Data) > 0 {
		for _, ipd := range ipamV6Data {
			s := &ipv6Subnet{
				SubnetIP: ipd.Pool.String(),
				GwIP:     ipd.Gateway.String(),
			}
			config.Ipv6Subnets = append(config.Ipv6Subnets, s)
		}
	}

	return nil
}

func (n *network) incEndpointCount() {
	n.Lock()
	defer n.Unlock()
	n.joinCnt++
}

func (n *network) joinSandbox(restore bool) error {
	// If there is a race between two go routines here only one will win
	// the other will wait.
	n.once.Do(func() {
		// save the error status of initSandbox in n.initErr so that
		// all the racing go routines are able to know the status.
		n.initErr = n.initSandbox(restore)
	})

	return n.initErr
}

func (n *network) joinSubnetSandbox(s *subnet, restore bool) error {
	s.once.Do(func() {
		s.initErr = n.initSubnetSandbox(s, restore)
	})
	return s.initErr
}

func (n *network) vxlanID(s *subnet) uint32 {
	n.Lock()
	defer n.Unlock()

	return s.vni
}

func (n *network) setVxlanID(s *subnet, vni uint32) {
	n.Lock()
	s.vni = vni
	n.Unlock()
}

func populateVNITbl() {
	filepath.Walk(filepath.Dir(osl.GenerateKey("walk")),
		func(path string, info os.FileInfo, err error) error {
			_, fname := filepath.Split(path)

			if len(strings.Split(fname, "-")) <= 1 {
				return nil
			}

			ns, err := netns.GetFromPath(path)
			if err != nil {
				logrus.Errorf("Could not open namespace path %s during vni population: %v", path, err)
				return nil
			}
			defer ns.Close()

			nlh, err := netlink.NewHandleAt(ns, syscall.NETLINK_ROUTE)
			if err != nil {
				logrus.Errorf("Could not open netlink handle during vni population for ns %s: %v", path, err)
				return nil
			}
			defer nlh.Delete()

			links, err := nlh.LinkList()
			if err != nil {
				logrus.Errorf("Failed to list interfaces during vni population for ns %s: %v", path, err)
				return nil
			}

			for _, l := range links {
				if l.Type() == "vxlan" {
					vniTbl[uint32(l.(*netlink.Vxlan).VxlanId)] = path
				}
			}

			return nil
		})
}

func networkOnceInit() {
	populateVNITbl()

	if os.Getenv("_OVERLAY_HOST_MODE") != "" {
		hostMode = true
		return
	}

	err := createVxlan("testvxlan", 1, 0)
	if err != nil {
		logrus.Errorf("Failed to create testvxlan interface: %v", err)
		return
	}

	defer deleteInterface("testvxlan")

	path := "/proc/self/ns/net"
	hNs, err := netns.GetFromPath(path)
	if err != nil {
		logrus.Errorf("Failed to get network namespace from path %s while setting host mode: %v", path, err)
		return
	}
	defer hNs.Close()

	nlh := ns.NlHandle()

	iface, err := nlh.LinkByName("testvxlan")
	if err != nil {
		logrus.Errorf("Failed to get link testvxlan while setting host mode: %v", err)
		return
	}

	// If we are not able to move the vxlan interface to a namespace
	// then fallback to host mode
	if err := nlh.LinkSetNsFd(iface, int(hNs)); err != nil {
		hostMode = true
	}
}

func (n *network) generateVxlanName(s *subnet) string {
	id := n.id
	if len(n.id) > 5 {
		id = n.id[:5]
	}

	return "vx-" + fmt.Sprintf("%06x", n.vxlanID(s)) + "-" + id
}

func (n *network) generateBridgeName(s *subnet) string {
	id := n.id
	if len(n.id) > 5 {
		id = n.id[:5]
	}

	return n.getBridgeNamePrefix(s) + "-" + id
}

func (n *network) getBridgeNamePrefix(s *subnet) string {
	return "mv-" + fmt.Sprintf("%06x", n.vxlanID(s))
}

func isOverlap(nw *net.IPNet) bool {
	var nameservers []string

	if rc, err := resolvconf.Get(); err == nil {
		nameservers = resolvconf.GetNameserversAsCIDR(rc.Content)
	}

	if err := netutils.CheckNameserverOverlaps(nameservers, nw); err != nil {
		return true
	}

	if err := netutils.CheckRouteOverlaps(nw); err != nil {
		return true
	}

	return false
}

func (n *network) restoreSubnetSandbox(s *subnet, brName, vxlanName string) error {
	sbox := n.sandbox()

	// restore macvlans osl sandbox
	Ifaces := make(map[string][]osl.IfaceOption)
	brIfaceOption := make([]osl.IfaceOption, 2)
	brIfaceOption = append(brIfaceOption, sbox.InterfaceOptions().Address(s.gwIP))
	brIfaceOption = append(brIfaceOption, sbox.InterfaceOptions().Bridge(true))
	Ifaces[fmt.Sprintf("%s+%s", brName, "br")] = brIfaceOption

	err := sbox.Restore(Ifaces, nil, nil, nil)
	if err != nil {
		return err
	}

	Ifaces = make(map[string][]osl.IfaceOption)
	vxlanIfaceOption := make([]osl.IfaceOption, 1)
	vxlanIfaceOption = append(vxlanIfaceOption, sbox.InterfaceOptions().Master(brName))
	Ifaces[fmt.Sprintf("%s+%s", vxlanName, "vxlan")] = vxlanIfaceOption
	err = sbox.Restore(Ifaces, nil, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

func (n *network) setupSubnetSandbox(s *subnet, brName, vxlanName string) error {

	if hostMode {
		// Try to delete stale bridge interface if it exists
		if err := deleteInterface(brName); err != nil {
			deleteInterfaceBySubnet(n.getBridgeNamePrefix(s), s)
		}
		// Try to delete the vxlan interface by vni if already present
		deleteVxlanByVNI("", n.vxlanID(s))

		if isOverlap(s.subnetIP) {
			return fmt.Errorf("macvlans subnet %s has conflicts in the host while running in host mode", s.subnetIP.String())
		}
	}

	if !hostMode {
		// Try to find this subnet's vni is being used in some
		// other namespace by looking at vniTbl that we just
		// populated in the once init. If a hit is found then
		// it must a stale namespace from previous
		// life. Destroy it completely and reclaim resourced.
		networkMu.Lock()
		path, ok := vniTbl[n.vxlanID(s)]
		networkMu.Unlock()

		if ok {
			deleteVxlanByVNI(path, n.vxlanID(s))
			if err := syscall.Unmount(path, syscall.MNT_FORCE); err != nil {
				logrus.Errorf("unmount of %s failed: %v", path, err)
			}
			os.Remove(path)

			networkMu.Lock()
			delete(vniTbl, n.vxlanID(s))
			networkMu.Unlock()
		}
	}

	// create a bridge and vxlan device for this subnet and move it to the sandbox
	sbox := n.sandbox()

	if err := sbox.AddInterface(brName, "br",
		sbox.InterfaceOptions().Address(s.gwIP),
		sbox.InterfaceOptions().Bridge(true)); err != nil {
		return fmt.Errorf("bridge creation in sandbox failed for subnet %q: %v", s.subnetIP.String(), err)
	}

	err := createVxlan(vxlanName, n.vxlanID(s), n.maxMTU())
	if err != nil {
		return err
	}

	if err := sbox.AddInterface(vxlanName, "vxlan",
		sbox.InterfaceOptions().Master(brName)); err != nil {
		return fmt.Errorf("vxlan interface creation failed for subnet %q: %v", s.subnetIP.String(), err)
	}

	if hostMode {
		if err := addFilters(n.id[:12], brName); err != nil {
			return err
		}
	}

	return nil
}

func (n *network) initSubnetSandbox(s *subnet, restore bool) error {
	brName := n.generateBridgeName(s)
	vxlanName := n.generateVxlanName(s)

	if restore {
		n.restoreSubnetSandbox(s, brName, vxlanName)
	} else {
		n.setupSubnetSandbox(s, brName, vxlanName)
	}

	n.Lock()
	s.vxlanName = vxlanName
	s.brName = brName
	n.Unlock()

	return nil
}

func (n *network) cleanupStaleSandboxes() {
	filepath.Walk(filepath.Dir(osl.GenerateKey("walk")),
		func(path string, info os.FileInfo, err error) error {
			_, fname := filepath.Split(path)

			pList := strings.Split(fname, "-")
			if len(pList) <= 1 {
				return nil
			}

			pattern := pList[1]
			if strings.Contains(n.id, pattern) {
				// Delete all vnis
				deleteVxlanByVNI(path, 0)
				syscall.Unmount(path, syscall.MNT_DETACH)
				os.Remove(path)

				// Now that we have destroyed this
				// sandbox, remove all references to
				// it in vniTbl so that we don't
				// inadvertently destroy the sandbox
				// created in this life.
				networkMu.Lock()
				for vni, tblPath := range vniTbl {
					if tblPath == path {
						delete(vniTbl, vni)
					}
				}
				networkMu.Unlock()
			}

			return nil
		})
}

func (n *network) initSandbox(restore bool) error {
	n.Lock()
	n.initEpoch++
	n.Unlock()

	networkOnce.Do(networkOnceInit)

	if !restore {
		if hostMode {
			if err := addNetworkChain(n.id[:12]); err != nil {
				return err
			}
		}

		// If there are any stale sandboxes related to this network
		// from previous daemon life clean it up here
		n.cleanupStaleSandboxes()
	}

	// In the restore case network sandbox already exist; but we don't know
	// what epoch number it was created with. It has to be retrieved by
	// searching the net namespaces.
	key := ""
	if restore {
		key = osl.GenerateKey("-" + n.id)
	} else {
		key = osl.GenerateKey(fmt.Sprintf("%d-", n.initEpoch) + n.id)
	}

	sbox, err := osl.NewSandbox(key, !hostMode, restore)
	if err != nil {
		return fmt.Errorf("could not get network sandbox (oper %t): %v", restore, err)
	}

	n.setSandbox(sbox)

	if !restore {
		n.driver.peerDbUpdateSandbox(n.id)
	}

	var nlSock *nl.NetlinkSocket
	sbox.InvokeFunc(func() {
		nlSock, err = nl.Subscribe(syscall.NETLINK_ROUTE, syscall.RTNLGRP_NEIGH)
		if err != nil {
			err = fmt.Errorf("failed to subscribe to neighbor group netlink messages")
		}
	})

	if nlSock != nil {
		go n.watchMiss(nlSock)
	}

	return nil
}

func (n *network) watchMiss(nlSock *nl.NetlinkSocket) {
	for {
		msgs, err := nlSock.Receive()
		if err != nil {
			logrus.Errorf("Failed to receive from netlink: %v ", err)
			continue
		}

		for _, msg := range msgs {
			if msg.Header.Type != syscall.RTM_GETNEIGH && msg.Header.Type != syscall.RTM_NEWNEIGH {
				continue
			}

			neigh, err := netlink.NeighDeserialize(msg.Data)
			if err != nil {
				logrus.Errorf("Failed to deserialize netlink ndmsg: %v", err)
				continue
			}

			if neigh.IP.To4() == nil {
				continue
			}

			// Not any of the network's subnets. Ignore.
			if !n.contains(neigh.IP) {
				continue
			}

			logrus.Debugf("miss notification for dest IP, %v", neigh.IP.String())

			if neigh.State&(netlink.NUD_STALE|netlink.NUD_INCOMPLETE) == 0 {
				continue
			}

			if !n.driver.isSerfAlive() {
				continue
			}

			mac, IPmask, vtep, err := n.driver.resolvePeer(n.id, neigh.IP)
			if err != nil {
				logrus.Errorf("could not resolve peer %q: %v", neigh.IP, err)
				continue
			}

			if err := n.driver.peerAdd(n.id, "dummy", neigh.IP, IPmask, mac, vtep, true); err != nil {
				logrus.Errorf("could not add neighbor entry for missed peer %q: %v", neigh.IP, err)
			}
		}
	}
}

func (n *network) Key() []string {
	return []string{"macvlans", "network", n.id}
}

func (n *network) KeyPrefix() []string {
	return []string{"macvlans", "network"}
}

func (n *network) Value() []byte {
	m := map[string]interface{}{}

	netJSON := []*subnetJSON{}

	for _, s := range n.subnets {
		sj := &subnetJSON{
			SubnetIP: s.subnetIP.String(),
			GwIP:     s.gwIP.String(),
			Vni:      s.vni,
		}
		netJSON = append(netJSON, sj)
	}

	b, err := json.Marshal(netJSON)
	if err != nil {
		return []byte{}
	}

	m["secure"] = n.secure
	m["subnets"] = netJSON
	m["mtu"] = n.mtu
	b, err = json.Marshal(m)
	if err != nil {
		return []byte{}
	}

	return b
}

func (n *network) Index() uint64 {
	return n.config.dbIndex
}

func (n *network) SetIndex(index uint64) {
	n.config.dbIndex = index
	n.config.dbExists = true
}

func (n *network) Exists() bool {
	return n.config.dbExists
}

func (n *network) Skip() bool {
	return false
}

func (n *network) SetValue(value []byte) error {
	var (
		m       map[string]interface{}
		newNet  bool
		isMap   = true
		netJSON = []*subnetJSON{}
	)

	if err := json.Unmarshal(value, &m); err != nil {
		err := json.Unmarshal(value, &netJSON)
		if err != nil {
			return err
		}
		isMap = false
	}

	if len(n.subnets) == 0 {
		newNet = true
	}

	if isMap {
		if val, ok := m["secure"]; ok {
			n.secure = val.(bool)
		}
		if val, ok := m["mtu"]; ok {
			n.mtu = int(val.(float64))
		}
		bytes, err := json.Marshal(m["subnets"])
		if err != nil {
			return err
		}
		if err := json.Unmarshal(bytes, &netJSON); err != nil {
			return err
		}
	}

	for _, sj := range netJSON {
		subnetIPstr := sj.SubnetIP
		gwIPstr := sj.GwIP
		vni := sj.Vni

		subnetIP, _ := types.ParseCIDR(subnetIPstr)
		gwIP, _ := types.ParseCIDR(gwIPstr)

		if newNet {
			s := &subnet{
				subnetIP: subnetIP,
				gwIP:     gwIP,
				vni:      vni,
				once:     &sync.Once{},
			}
			n.subnets = append(n.subnets, s)
		} else {
			sNet := n.getMatchingSubnet(subnetIP)
			if sNet != nil {
				sNet.vni = vni
			}
		}
	}
	return nil
}

func (n *network) DataScope() string {
	return datastore.GlobalScope
}

func (n *network) writeToStore() error {
	if n.driver.store == nil {
		return nil
	}

	return n.driver.store.PutObjectAtomic(n)
}

func (n *network) obtainVxlanID(s *subnet) error {
	//return if the subnet already has a vxlan id assigned
	if s.vni != 0 {
		return nil
	}

	if n.driver.store == nil {
		return fmt.Errorf("no valid vxlan id and no datastore configured, cannot obtain vxlan id")
	}

	for {
		if err := n.driver.store.GetObject(datastore.Key(n.Key()...), n); err != nil {
			return fmt.Errorf("getting network %q from datastore failed %v", n.id, err)
		}

		if s.vni == 0 {
			vxlanID, err := n.driver.vxlanIdm.GetID()
			if err != nil {
				return fmt.Errorf("failed to allocate vxlan id: %v", err)
			}

			n.setVxlanID(s, uint32(vxlanID))
			if err := n.writeToStore(); err != nil {
				n.driver.vxlanIdm.Release(uint64(n.vxlanID(s)))
				n.setVxlanID(s, 0)
				if err == datastore.ErrKeyModified {
					continue
				}
				return fmt.Errorf("network %q failed to update data store: %v", n.id, err)
			}
			return nil
		}
		return nil
	}
}

// contains return true if the passed ip belongs to one the network's
// subnets
func (n *network) contains(ip net.IP) bool {
	for _, s := range n.subnets {
		if s.subnetIP.Contains(ip) {
			return true
		}
	}

	return false
}

// getSubnetforIP returns the subnet to which the given IP belongs
func (n *network) getSubnetforIP(ip *net.IPNet) *subnet {
	for _, s := range n.subnets {
		// first check if the mask lengths are the same
		i, _ := s.subnetIP.Mask.Size()
		j, _ := ip.Mask.Size()
		if i != j {
			continue
		}
		if s.subnetIP.Contains(ip.IP) {
			return s
		}
	}
	return nil
}

// getMatchingSubnet return the network's subnet that matches the input
func (n *network) getMatchingSubnet(ip *net.IPNet) *subnet {
	if ip == nil {
		return nil
	}
	for _, s := range n.subnets {
		// first check if the mask lengths are the same
		i, _ := s.subnetIP.Mask.Size()
		j, _ := ip.Mask.Size()
		if i != j {
			continue
		}
		if s.subnetIP.IP.Equal(ip.IP) {
			return s
		}
	}
	return nil
}
