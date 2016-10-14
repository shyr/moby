package libnetwork

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/reexec"
	"github.com/docker/libnetwork/iptables"
	"github.com/docker/libnetwork/ipvs"
	"github.com/docker/libnetwork/ns"
	"github.com/gogo/protobuf/proto"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
)

func init() {
	reexec.Register("fwmarker", fwMarker)
	reexec.Register("redirecter", redirecter)
}

func newService(name string, id string, ingressPorts []*PortConfig, aliases []string) *service {
	return &service{
		name:          name,
		id:            id,
		ingressPorts:  ingressPorts,
		loadBalancers: make(map[string]*loadBalancer),
		aliases:       aliases,
	}
}

func newConsulClient(consulURLString string) (*consulapi.Client, error) {
	consulURL, err := url.Parse(consulURLString)

	if err != nil {
		return nil, err
	}

	return consulapi.NewClient(&consulapi.Config{
		Address:    consulURL.Host,
		Scheme:     consulURL.Scheme,
		HttpClient: http.DefaultClient,
	})
}

func deregisterService(consulURL string, name string) error {
	logrus.Debugf("Deregistering service '%s' to consul DNS", name)

	errorFmt := "Failed to deregister service '%s' to consul DNS: %v"

	client, err := newConsulClient(consulURL)

	if err != nil {
		return fmt.Errorf(errorFmt, name, err)
	}

	agent := client.Agent()
	err = agent.ServiceDeregister(name)

	if err != nil {
		return fmt.Errorf(errorFmt, name, err)
	}

	logrus.Debugf("Service '%s' deregistered successfully to consul DNS", name)

	return nil
}

func registerService(consulURL string, name string, vip string) error {
	logrus.Debugf("Registering service '%s' to consul DNS", name)

	errorFmt := "Failed to register service '%s' to consul DNS: %v"

	client, err := newConsulClient(consulURL)

	if err != nil {
		return fmt.Errorf(errorFmt, name, err)
	}

	agent := client.Agent()
	service := &consulapi.AgentServiceRegistration{
		ID:      name,
		Name:    name,
		Address: vip,
	}
	err = agent.ServiceRegister(service)

	if err != nil {
		return fmt.Errorf(errorFmt, name, err)
	}

	logrus.Debugf("Service '%s' registered successfully to consul DNS", name)

	return nil
}

func (c *controller) cleanupServiceBindings(cleanupNID string) {
	var cleanupFuncs []func()
	c.Lock()
	for _, s := range c.serviceBindings {
		s.Lock()
		for nid, lb := range s.loadBalancers {
			if cleanupNID != "" && nid != cleanupNID {
				continue
			}

			for eid, ip := range lb.backEnds {
				service := s
				loadBalancer := lb
				networkID := nid
				epID := eid
				epIP := ip

				cleanupFuncs = append(cleanupFuncs, func() {
					if err := c.rmServiceBinding(service.name, service.id, networkID, epID, loadBalancer.vip,
						service.ingressPorts, service.aliases, epIP); err != nil {
						logrus.Errorf("Failed to remove service bindings for service %s network %s endpoint %s while cleanup: %v",
							service.id, networkID, epID, err)
					}
				})
			}
		}
		s.Unlock()
	}
	c.Unlock()

	for _, f := range cleanupFuncs {
		f()
	}

}

func (c *controller) addServiceBinding(name, sid, nid, eid string, vip net.IP, ingressPorts []*PortConfig, aliases []string, ip net.IP) error {
	var (
		s          *service
		addService bool
	)

	n, err := c.NetworkByID(nid)
	if err != nil {
		return err
	}

	skey := serviceKey{
		id:    sid,
		ports: portConfigs(ingressPorts).String(),
	}

	c.Lock()
	s, ok := c.serviceBindings[skey]
	if !ok {
		// Create a new service if we are seeing this service
		// for the first time.
		s = newService(name, sid, ingressPorts, aliases)
		c.serviceBindings[skey] = s
	}
	c.Unlock()

	// Add endpoint IP to special "tasks.svc_name" so that the
	// applications have access to DNS RR.
	n.(*network).addSvcRecords("tasks."+name, ip, nil, false)
	for _, alias := range aliases {
		n.(*network).addSvcRecords("tasks."+alias, ip, nil, false)
	}

	// Add service name to vip in DNS, if vip is valid. Otherwise resort to DNS RR
	svcIP := vip
	if len(svcIP) == 0 {
		svcIP = ip
	}
	n.(*network).addSvcRecords(name, svcIP, nil, false)
	for _, alias := range aliases {
		n.(*network).addSvcRecords(alias, svcIP, nil, false)
	}

	s.Lock()
	defer s.Unlock()

	lb, ok := s.loadBalancers[nid]
	if !ok {
		// Create a new load balancer if we are seeing this
		// network attachment on the service for the first
		// time.
		lb = &loadBalancer{
			vip:      vip,
			fwMark:   fwMarkCtr,
			backEnds: make(map[string]net.IP),
			service:  s,
		}

		fwMarkCtrMu.Lock()
		fwMarkCtr++
		fwMarkCtrMu.Unlock()

		s.loadBalancers[nid] = lb

		// Since we just created this load balancer make sure
		// we add a new service service in IPVS rules.
		addService = true

		if consulURLString := n.Info().Labels()["consul.url"]; consulURLString != "" {
			if err := registerService(consulURLString, name, vip.String()); err != nil {
				logrus.Warnf("%s", err)
			}
		}
	}

	lb.backEnds[eid] = ip

	// Add loadbalancer service and backend in all sandboxes in
	// the network only if vip is valid.
	if len(vip) != 0 {
		n.(*network).addLBBackend(ip, vip, lb.fwMark, ingressPorts, addService)
	}

	return nil
}

func (c *controller) rmServiceBinding(name, sid, nid, eid string, vip net.IP, ingressPorts []*PortConfig, aliases []string, ip net.IP) error {
	var rmService bool

	n, err := c.NetworkByID(nid)
	if err != nil {
		return err
	}

	skey := serviceKey{
		id:    sid,
		ports: portConfigs(ingressPorts).String(),
	}

	c.Lock()
	s, ok := c.serviceBindings[skey]
	if !ok {
		c.Unlock()
		return nil
	}
	c.Unlock()

	s.Lock()
	lb, ok := s.loadBalancers[nid]
	if !ok {
		s.Unlock()
		return nil
	}

	_, ok = lb.backEnds[eid]
	if !ok {
		s.Unlock()
		return nil
	}

	delete(lb.backEnds, eid)
	if len(lb.backEnds) == 0 {
		// All the backends for this service have been
		// removed. Time to remove the load balancer and also
		// remove the service entry in IPVS.
		rmService = true

		delete(s.loadBalancers, nid)
	}

	if len(s.loadBalancers) == 0 {
		// All loadbalancers for the service removed. Time to
		// remove the service itself.
		delete(c.serviceBindings, skey)
	}

	// Remove loadbalancer service(if needed) and backend in all
	// sandboxes in the network only if the vip is valid.
	if len(vip) != 0 {
		n.(*network).rmLBBackend(ip, vip, lb.fwMark, ingressPorts, rmService)
	}
	s.Unlock()

	// Delete the special "tasks.svc_name" backend record.
	n.(*network).deleteSvcRecords("tasks."+name, ip, nil, false)
	for _, alias := range aliases {
		n.(*network).deleteSvcRecords("tasks."+alias, ip, nil, false)
	}

	// If we are doing DNS RR add the endpoint IP to DNS record
	// right away.
	if len(vip) == 0 {
		n.(*network).deleteSvcRecords(name, ip, nil, false)
		for _, alias := range aliases {
			n.(*network).deleteSvcRecords(alias, ip, nil, false)
		}
	}

	// Remove the DNS record for VIP only if we are removing the service
	if rmService && len(vip) != 0 {
		n.(*network).deleteSvcRecords(name, vip, nil, false)
		for _, alias := range aliases {
			n.(*network).deleteSvcRecords(alias, vip, nil, false)
		}

		if consulURLString := n.Info().Labels()["consul.url"]; consulURLString != "" {
			if err := deregisterService(consulURLString, name); err != nil {
				logrus.Warnf("%s", err)
			}

		}
	}

	return nil
}

// Get all loadbalancers on this network that is currently discovered
// on this node.
func (n *network) connectedLoadbalancers() []*loadBalancer {
	c := n.getController()

	serviceBindings := make([]*service, 0, len(c.serviceBindings))
	c.Lock()
	for _, s := range c.serviceBindings {
		serviceBindings = append(serviceBindings, s)
	}
	c.Unlock()

	var lbs []*loadBalancer
	for _, s := range serviceBindings {
		s.Lock()
		if lb, ok := s.loadBalancers[n.ID()]; ok {
			lbs = append(lbs, lb)
		}
		s.Unlock()
	}

	return lbs
}

// Populate all loadbalancers on the network that the passed endpoint
// belongs to, into this sandbox.
func (sb *sandbox) populateLoadbalancers(ep *endpoint) {
	var gwIP net.IP

	// This is an interface less endpoint. Nothing to do.
	if ep.Iface() == nil {
		return
	}

	n := ep.getNetwork()
	eIP := ep.Iface().Address()

	if n.ingress {
		if err := addRedirectRules(sb.Key(), eIP, ep.ingressPorts); err != nil {
			logrus.Errorf("Failed to add redirect rules for ep %s: %v", ep.Name(), err)
		}
	}

	if sb.ingress {
		// For the ingress sandbox if this is not gateway
		// endpoint do nothing.
		if ep != sb.getGatewayEndpoint() {
			return
		}

		// This is the gateway endpoint. Now get the ingress
		// network and plumb the loadbalancers.
		gwIP = ep.Iface().Address().IP
		for _, ep := range sb.getConnectedEndpoints() {
			if !ep.endpointInGWNetwork() {
				n = ep.getNetwork()
				eIP = ep.Iface().Address()
			}
		}
	}

	for _, lb := range n.connectedLoadbalancers() {
		// Skip if vip is not valid.
		if len(lb.vip) == 0 {
			continue
		}

		lb.service.Lock()
		addService := true
		for _, ip := range lb.backEnds {
			sb.addLBBackend(ip, lb.vip, lb.fwMark, lb.service.ingressPorts,
				eIP, gwIP, addService, n.ingress)
			addService = false
		}
		lb.service.Unlock()
	}
}

// Add loadbalancer backend to all sandboxes which has a connection to
// this network. If needed add the service as well, as specified by
// the addService bool.
func (n *network) addLBBackend(ip, vip net.IP, fwMark uint32, ingressPorts []*PortConfig, addService bool) {
	if n.usesGorb() {
		if err := n.addGorbBackend(ip, vip, ingressPorts, addService); err != nil {
			logrus.Warnf("Failed to add backend to gorb: %v", err)
		}
	}

	n.WalkEndpoints(func(e Endpoint) bool {
		ep := e.(*endpoint)
		if sb, ok := ep.getSandbox(); ok {
			if !sb.isEndpointPopulated(ep) {
				return false
			}

			var gwIP net.IP
			if ep := sb.getGatewayEndpoint(); ep != nil {
				gwIP = ep.Iface().Address().IP
			}

			sb.addLBBackend(ip, vip, fwMark, ingressPorts, ep.Iface().Address(), gwIP, addService, n.ingress)
		}

		return false
	})
}

// Remove loadbalancer backend from all sandboxes which has a
// connection to this network. If needed remove the service entry as
// well, as specified by the rmService bool.
func (n *network) rmLBBackend(ip, vip net.IP, fwMark uint32, ingressPorts []*PortConfig, rmService bool) {
	if n.usesGorb() {
		if err := n.rmGorbBackend(ip, vip, ingressPorts, rmService); err != nil {
			logrus.Warnf("Failed to remove backend in gorb: %v", err)
		}
	}

	n.WalkEndpoints(func(e Endpoint) bool {
		ep := e.(*endpoint)
		if sb, ok := ep.getSandbox(); ok {
			if !sb.isEndpointPopulated(ep) {
				return false
			}

			var gwIP net.IP
			if ep := sb.getGatewayEndpoint(); ep != nil {
				gwIP = ep.Iface().Address().IP
			}

			sb.rmLBBackend(ip, vip, fwMark, ingressPorts, ep.Iface().Address(), gwIP, rmService, n.ingress)
		}

		return false
	})
}

// Add loadbalancer backend into one connected sandbox.
func (sb *sandbox) addLBBackend(ip, vip net.IP, fwMark uint32, ingressPorts []*PortConfig, eIP *net.IPNet, gwIP net.IP, addService bool, isIngressNetwork bool) {
	if sb.osSbox == nil {
		return
	}

	if isIngressNetwork && !sb.ingress {
		return
	}

	i, err := ipvs.New(sb.Key())
	if err != nil {
		logrus.Errorf("Failed to create an ipvs handle for sbox %s: %v", sb.Key(), err)
		return
	}
	defer i.Close()

	s := &ipvs.Service{
		AddressFamily: nl.FAMILY_V4,
		FWMark:        fwMark,
		SchedName:     ipvs.RoundRobin,
	}

	if addService {
		var filteredPorts []*PortConfig
		if sb.ingress {
			filteredPorts = filterPortConfigs(ingressPorts, false)
			if err := programIngress(gwIP, filteredPorts, false); err != nil {
				logrus.Errorf("Failed to add ingress: %v", err)
				return
			}
		}

		logrus.Debugf("Creating service for vip %s fwMark %d ingressPorts %#v", vip, fwMark, ingressPorts)
		if err := invokeFWMarker(sb.Key(), vip, fwMark, ingressPorts, eIP, false); err != nil {
			logrus.Errorf("Failed to add firewall mark rule in sbox %s: %v", sb.Key(), err)
			return
		}

		if err := i.NewService(s); err != nil {
			logrus.Errorf("Failed to create a new service for vip %s fwmark %d: %v", vip, fwMark, err)
			return
		}
	}

	d := &ipvs.Destination{
		AddressFamily: nl.FAMILY_V4,
		Address:       ip,
		Weight:        1,
	}

	// Remove the sched name before using the service to add
	// destination.
	s.SchedName = ""
	if err := i.NewDestination(s, d); err != nil && err != syscall.EEXIST {
		logrus.Errorf("Failed to create real server %s for vip %s fwmark %d in sb %s: %v", ip, vip, fwMark, sb.containerID, err)
	}
}

// Remove loadbalancer backend from one connected sandbox.
func (sb *sandbox) rmLBBackend(ip, vip net.IP, fwMark uint32, ingressPorts []*PortConfig, eIP *net.IPNet, gwIP net.IP, rmService bool, isIngressNetwork bool) {
	if sb.osSbox == nil {
		return
	}

	if isIngressNetwork && !sb.ingress {
		return
	}

	i, err := ipvs.New(sb.Key())
	if err != nil {
		logrus.Errorf("Failed to create an ipvs handle for sbox %s: %v", sb.Key(), err)
		return
	}
	defer i.Close()

	s := &ipvs.Service{
		AddressFamily: nl.FAMILY_V4,
		FWMark:        fwMark,
	}

	d := &ipvs.Destination{
		AddressFamily: nl.FAMILY_V4,
		Address:       ip,
		Weight:        1,
	}

	if err := i.DelDestination(s, d); err != nil {
		logrus.Infof("Failed to delete real server %s for vip %s fwmark %d: %v", ip, vip, fwMark, err)
	}

	if rmService {
		s.SchedName = ipvs.RoundRobin
		if err := i.DelService(s); err != nil {
			logrus.Errorf("Failed to delete a new service for vip %s fwmark %d: %v", vip, fwMark, err)
		}

		var filteredPorts []*PortConfig
		if sb.ingress {
			filteredPorts = filterPortConfigs(ingressPorts, true)
			if err := programIngress(gwIP, filteredPorts, true); err != nil {
				logrus.Errorf("Failed to delete ingress: %v", err)
			}
		}

		if err := invokeFWMarker(sb.Key(), vip, fwMark, ingressPorts, eIP, true); err != nil {
			logrus.Errorf("Failed to add firewall mark rule in sbox %s: %v", sb.Key(), err)
		}
	}
}

const ingressChain = "DOCKER-INGRESS"

var (
	ingressOnce     sync.Once
	ingressProxyMu  sync.Mutex
	ingressProxyTbl = make(map[string]io.Closer)
	portConfigMu    sync.Mutex
	portConfigTbl   = make(map[PortConfig]int)
)

func filterPortConfigs(ingressPorts []*PortConfig, isDelete bool) []*PortConfig {
	portConfigMu.Lock()
	iPorts := make([]*PortConfig, 0, len(ingressPorts))
	for _, pc := range ingressPorts {
		if isDelete {
			if cnt, ok := portConfigTbl[*pc]; ok {
				// This is the last reference to this
				// port config. Delete the port config
				// and add it to filtered list to be
				// plumbed.
				if cnt == 1 {
					delete(portConfigTbl, *pc)
					iPorts = append(iPorts, pc)
					continue
				}

				portConfigTbl[*pc] = cnt - 1
			}

			continue
		}

		if cnt, ok := portConfigTbl[*pc]; ok {
			portConfigTbl[*pc] = cnt + 1
			continue
		}

		// We are adding it for the first time. Add it to the
		// filter list to be plumbed.
		portConfigTbl[*pc] = 1
		iPorts = append(iPorts, pc)
	}
	portConfigMu.Unlock()

	return iPorts
}

func programIngress(gwIP net.IP, ingressPorts []*PortConfig, isDelete bool) error {
	addDelOpt := "-I"
	if isDelete {
		addDelOpt = "-D"
	}

	chainExists := iptables.ExistChain(ingressChain, iptables.Nat)
	filterChainExists := iptables.ExistChain(ingressChain, iptables.Filter)

	ingressOnce.Do(func() {
		// Flush nat table and filter table ingress chain rules during init if it
		// exists. It might contain stale rules from previous life.
		if chainExists {
			if err := iptables.RawCombinedOutput("-t", "nat", "-F", ingressChain); err != nil {
				logrus.Errorf("Could not flush nat table ingress chain rules during init: %v", err)
			}
		}
		if filterChainExists {
			if err := iptables.RawCombinedOutput("-F", ingressChain); err != nil {
				logrus.Errorf("Could not flush filter table ingress chain rules during init: %v", err)
			}
		}
	})

	if !isDelete {
		if !chainExists {
			if err := iptables.RawCombinedOutput("-t", "nat", "-N", ingressChain); err != nil {
				return fmt.Errorf("failed to create ingress chain: %v", err)
			}
		}
		if !filterChainExists {
			if err := iptables.RawCombinedOutput("-N", ingressChain); err != nil {
				return fmt.Errorf("failed to create filter table ingress chain: %v", err)
			}
		}

		if !iptables.Exists(iptables.Nat, ingressChain, "-j", "RETURN") {
			if err := iptables.RawCombinedOutput("-t", "nat", "-A", ingressChain, "-j", "RETURN"); err != nil {
				return fmt.Errorf("failed to add return rule in nat table ingress chain: %v", err)
			}
		}

		if !iptables.Exists(iptables.Filter, ingressChain, "-j", "RETURN") {
			if err := iptables.RawCombinedOutput("-A", ingressChain, "-j", "RETURN"); err != nil {
				return fmt.Errorf("failed to add return rule to filter table ingress chain: %v", err)
			}
		}

		for _, chain := range []string{"OUTPUT", "PREROUTING"} {
			if !iptables.Exists(iptables.Nat, chain, "-m", "addrtype", "--dst-type", "LOCAL", "-j", ingressChain) {
				if err := iptables.RawCombinedOutput("-t", "nat", "-I", chain, "-m", "addrtype", "--dst-type", "LOCAL", "-j", ingressChain); err != nil {
					return fmt.Errorf("failed to add jump rule in %s to ingress chain: %v", chain, err)
				}
			}
		}

		if !iptables.Exists(iptables.Filter, "FORWARD", "-j", ingressChain) {
			if err := iptables.RawCombinedOutput("-I", "FORWARD", "-j", ingressChain); err != nil {
				return fmt.Errorf("failed to add jump rule to %s in filter table forward chain: %v", ingressChain, err)
			}
		}

		oifName, err := findOIFName(gwIP)
		if err != nil {
			return fmt.Errorf("failed to find gateway bridge interface name for %s: %v", gwIP, err)
		}

		path := filepath.Join("/proc/sys/net/ipv4/conf", oifName, "route_localnet")
		if err := ioutil.WriteFile(path, []byte{'1', '\n'}, 0644); err != nil {
			return fmt.Errorf("could not write to %s: %v", path, err)
		}

		ruleArgs := strings.Fields(fmt.Sprintf("-m addrtype --src-type LOCAL -o %s -j MASQUERADE", oifName))
		if !iptables.Exists(iptables.Nat, "POSTROUTING", ruleArgs...) {
			if err := iptables.RawCombinedOutput(append([]string{"-t", "nat", "-I", "POSTROUTING"}, ruleArgs...)...); err != nil {
				return fmt.Errorf("failed to add ingress localhost POSTROUTING rule for %s: %v", oifName, err)
			}
		}
	}

	for _, iPort := range ingressPorts {
		if iptables.ExistChain(ingressChain, iptables.Nat) {
			rule := strings.Fields(fmt.Sprintf("-t nat %s %s -p %s --dport %d -j DNAT --to-destination %s:%d",
				addDelOpt, ingressChain, strings.ToLower(PortConfig_Protocol_name[int32(iPort.Protocol)]), iPort.PublishedPort, gwIP, iPort.PublishedPort))
			if err := iptables.RawCombinedOutput(rule...); err != nil {
				errStr := fmt.Sprintf("setting up rule failed, %v: %v", rule, err)
				if !isDelete {
					return fmt.Errorf("%s", errStr)
				}

				logrus.Infof("%s", errStr)
			}
		}

		// Filter table rules to allow a published service to be accessible in the local node from..
		// 1) service tasks attached to other networks
		// 2) unmanaged containers on bridge networks
		rule := strings.Fields(fmt.Sprintf("%s %s -m state -p %s --sport %d --state ESTABLISHED,RELATED -j ACCEPT",
			addDelOpt, ingressChain, strings.ToLower(PortConfig_Protocol_name[int32(iPort.Protocol)]), iPort.PublishedPort))
		if err := iptables.RawCombinedOutput(rule...); err != nil {
			errStr := fmt.Sprintf("setting up rule failed, %v: %v", rule, err)
			if !isDelete {
				return fmt.Errorf("%s", errStr)
			}
			logrus.Warnf("%s", errStr)
		}

		rule = strings.Fields(fmt.Sprintf("%s %s -p %s --dport %d -j ACCEPT",
			addDelOpt, ingressChain, strings.ToLower(PortConfig_Protocol_name[int32(iPort.Protocol)]), iPort.PublishedPort))
		if err := iptables.RawCombinedOutput(rule...); err != nil {
			errStr := fmt.Sprintf("setting up rule failed, %v: %v", rule, err)
			if !isDelete {
				return fmt.Errorf("%s", errStr)
			}

			logrus.Warnf("%s", errStr)
		}

		if err := plumbProxy(iPort, isDelete); err != nil {
			logrus.Warnf("failed to create proxy for port %d: %v", iPort.PublishedPort, err)
		}
	}

	return nil
}

// In the filter table FORWARD chain first rule should be to jump to INGRESS-CHAIN
// This chain has the rules to allow access to the published ports for swarm tasks
// from local bridge networks and docker_gwbridge (ie:taks on other swarm netwroks)
func arrangeIngressFilterRule() {
	if iptables.ExistChain(ingressChain, iptables.Filter) {
		if iptables.Exists(iptables.Filter, "FORWARD", "-j", ingressChain) {
			if err := iptables.RawCombinedOutput("-D", "FORWARD", "-j", ingressChain); err != nil {
				logrus.Warnf("failed to delete jump rule to ingressChain in filter table: %v", err)
			}
		}
		if err := iptables.RawCombinedOutput("-I", "FORWARD", "-j", ingressChain); err != nil {
			logrus.Warnf("failed to add jump rule to ingressChain in filter table: %v", err)
		}
	}
}

func findOIFName(ip net.IP) (string, error) {
	nlh := ns.NlHandle()

	routes, err := nlh.RouteGet(ip)
	if err != nil {
		return "", err
	}

	if len(routes) == 0 {
		return "", fmt.Errorf("no route to %s", ip)
	}

	// Pick the first route(typically there is only one route). We
	// don't support multipath.
	link, err := nlh.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return "", err
	}

	return link.Attrs().Name, nil
}

func plumbProxy(iPort *PortConfig, isDelete bool) error {
	var (
		err error
		l   io.Closer
	)

	portSpec := fmt.Sprintf("%d/%s", iPort.PublishedPort, strings.ToLower(PortConfig_Protocol_name[int32(iPort.Protocol)]))
	if isDelete {
		ingressProxyMu.Lock()
		if listener, ok := ingressProxyTbl[portSpec]; ok {
			if listener != nil {
				listener.Close()
			}
		}
		ingressProxyMu.Unlock()

		return nil
	}

	switch iPort.Protocol {
	case ProtocolTCP:
		l, err = net.ListenTCP("tcp", &net.TCPAddr{Port: int(iPort.PublishedPort)})
	case ProtocolUDP:
		l, err = net.ListenUDP("udp", &net.UDPAddr{Port: int(iPort.PublishedPort)})
	}

	if err != nil {
		return err
	}

	ingressProxyMu.Lock()
	ingressProxyTbl[portSpec] = l
	ingressProxyMu.Unlock()

	return nil
}

func writePortsToFile(ports []*PortConfig) (string, error) {
	f, err := ioutil.TempFile("", "port_configs")
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf, err := proto.Marshal(&EndpointRecord{
		IngressPorts: ports,
	})

	n, err := f.Write(buf)
	if err != nil {
		return "", err
	}

	if n < len(buf) {
		return "", io.ErrShortWrite
	}

	return f.Name(), nil
}

func readPortsFromFile(fileName string) ([]*PortConfig, error) {
	buf, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	var epRec EndpointRecord
	err = proto.Unmarshal(buf, &epRec)
	if err != nil {
		return nil, err
	}

	return epRec.IngressPorts, nil
}

// Invoke fwmarker reexec routine to mark vip destined packets with
// the passed firewall mark.
func invokeFWMarker(path string, vip net.IP, fwMark uint32, ingressPorts []*PortConfig, eIP *net.IPNet, isDelete bool) error {
	var ingressPortsFile string

	if len(ingressPorts) != 0 {
		var err error
		ingressPortsFile, err = writePortsToFile(ingressPorts)
		if err != nil {
			return err
		}

		defer os.Remove(ingressPortsFile)
	}

	addDelOpt := "-A"
	if isDelete {
		addDelOpt = "-D"
	}

	cmd := &exec.Cmd{
		Path:   reexec.Self(),
		Args:   append([]string{"fwmarker"}, path, vip.String(), fmt.Sprintf("%d", fwMark), addDelOpt, ingressPortsFile, eIP.String()),
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reexec failed: %v", err)
	}

	return nil
}

// Firewall marker reexec function.
func fwMarker() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if len(os.Args) < 7 {
		logrus.Error("invalid number of arguments..")
		os.Exit(1)
	}

	var ingressPorts []*PortConfig
	if os.Args[5] != "" {
		var err error
		ingressPorts, err = readPortsFromFile(os.Args[5])
		if err != nil {
			logrus.Errorf("Failed reading ingress ports file: %v", err)
			os.Exit(6)
		}
	}

	vip := os.Args[2]
	fwMark, err := strconv.ParseUint(os.Args[3], 10, 32)
	if err != nil {
		logrus.Errorf("bad fwmark value(%s) passed: %v", os.Args[3], err)
		os.Exit(2)
	}
	addDelOpt := os.Args[4]

	rules := [][]string{}
	for _, iPort := range ingressPorts {
		rule := strings.Fields(fmt.Sprintf("-t mangle %s PREROUTING -p %s --dport %d -j MARK --set-mark %d",
			addDelOpt, strings.ToLower(PortConfig_Protocol_name[int32(iPort.Protocol)]), iPort.PublishedPort, fwMark))
		rules = append(rules, rule)
	}

	ns, err := netns.GetFromPath(os.Args[1])
	if err != nil {
		logrus.Errorf("failed get network namespace %q: %v", os.Args[1], err)
		os.Exit(3)
	}
	defer ns.Close()

	if err := netns.Set(ns); err != nil {
		logrus.Errorf("setting into container net ns %v failed, %v", os.Args[1], err)
		os.Exit(4)
	}

	if addDelOpt == "-A" {
		eIP, subnet, err := net.ParseCIDR(os.Args[6])
		if err != nil {
			logrus.Errorf("Failed to parse endpoint IP %s: %v", os.Args[6], err)
			os.Exit(9)
		}

		ruleParams := strings.Fields(fmt.Sprintf("-m ipvs --ipvs -d %s -j SNAT --to-source %s", subnet, eIP))
		if !iptables.Exists("nat", "POSTROUTING", ruleParams...) {
			rule := append(strings.Fields("-t nat -A POSTROUTING"), ruleParams...)
			rules = append(rules, rule)

			err := ioutil.WriteFile("/proc/sys/net/ipv4/vs/conntrack", []byte{'1', '\n'}, 0644)
			if err != nil {
				logrus.Errorf("Failed to write to /proc/sys/net/ipv4/vs/conntrack: %v", err)
				os.Exit(8)
			}
		}
	}

	rule := strings.Fields(fmt.Sprintf("-t mangle %s OUTPUT -d %s/32 -j MARK --set-mark %d", addDelOpt, vip, fwMark))
	rules = append(rules, rule)

	for _, rule := range rules {
		if err := iptables.RawCombinedOutputNative(rule...); err != nil {
			logrus.Errorf("setting up rule failed, %v: %v", rule, err)
			os.Exit(5)
		}
	}
}

func (n *network) usesGorb() bool {
	return n.gorbURL() != ""
}

func (n *network) gorbURL() string {
	return n.Info().Labels()["gorb.url"]
}

func (n *network) initGorbClient() (*GorbClient, error) {
	logrus.Debugf("Initializing gorb client for network '%s'", n.name)

	errorFmt := "Failed to initialize gorb client for network '%s': %v"

	if !n.usesGorb() {
		return nil, fmt.Errorf(errorFmt, n.name, "gorb is not used")
	}

	gorbURL, err := url.Parse(n.gorbURL())
	if err != nil {
		return nil, fmt.Errorf(errorFmt, n.name, err)
	}

	n.gorbClient = NewGorbClient(gorbURL.String())

	logrus.Debugf("Gorb client initialized for network '%s'", n.name)

	return n.gorbClient, nil
}

func (n *network) GorbClient() (*GorbClient, error) {
	if n.gorbClient != nil {
		return n.gorbClient, nil
	}

	return n.initGorbClient()
}

func makeGorbServiceName(vip string, port uint16, proto string) string {
	return fmt.Sprintf("%s-%d-%s", vip, port, proto)
}

func (n *network) rmGorbBackend(ip net.IP, vip net.IP, ports []*PortConfig, rmService bool) error {
	logrus.Debugf("Removing gorb backend: ip: %s vip: %s ports: %+v", ip, vip, ports)

	gorbClient, err := n.GorbClient()
	if err != nil {
		return fmt.Errorf("Failed to get gorb client: %v", err)
	}

	for _, port := range ports {
		portNumber := uint16(port.TargetPort)
		protocol := port.Protocol.String()
		serviceName := makeGorbServiceName(vip.String(), portNumber, protocol)

		if _, err := gorbClient.DeleteBackend(serviceName, ip.String()); err != nil {
			return err
		}

		if rmService {
			if _, err := gorbClient.DeleteService(serviceName); err != nil {
				return err
			}
		}
	}

	logrus.Debugf("Gorb backend removed: ip: %s vip: %s ports: %+v", ip, vip, ports)

	return nil
}

func (n *network) addGorbBackend(ip net.IP, vip net.IP, ports []*PortConfig, addService bool) error {
	logrus.Debugf("Adding gorb backend: ip: %s vip: %s ports: %+v", ip, vip, ports)

	gorbClient, err := n.GorbClient()
	if err != nil {
		return fmt.Errorf("Failed to get gorb client: %v", err)
	}

	for _, port := range ports {
		if port.PublishedPort != port.TargetPort {
			logrus.Warnf(
				"Gorb load balancer does not support port forwarding. Publishing port '%s' instead of '%s' for vip '%s'.",
				port.TargetPort, port.PublishedPort, vip)
		}

		portNumber := uint16(port.TargetPort)
		protocol := port.Protocol.String()
		serviceName := makeGorbServiceName(vip.String(), portNumber, protocol)

		if addService {
			serviceOptions := MakeGorbServiceOptions(vip.String(), portNumber, protocol)
			if _, err := gorbClient.PutService(serviceName, serviceOptions); err != nil {
				return err
			}
		}

		backendOptions := MakeGorbBackendOptions(ip.String(), portNumber)

		if _, err := gorbClient.PutBackend(serviceName, ip.String(), backendOptions); err != nil {
			return err
		}
	}

	logrus.Debugf("Gorb backend added: ip: %s vip: %s ports: %+v", ip, vip, ports)

	return nil
}

func addRedirectRules(path string, eIP *net.IPNet, ingressPorts []*PortConfig) error {
	var ingressPortsFile string

	if len(ingressPorts) != 0 {
		var err error
		ingressPortsFile, err = writePortsToFile(ingressPorts)
		if err != nil {
			return err
		}
		defer os.Remove(ingressPortsFile)
	}

	cmd := &exec.Cmd{
		Path:   reexec.Self(),
		Args:   append([]string{"redirecter"}, path, eIP.String(), ingressPortsFile),
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reexec failed: %v", err)
	}

	return nil
}

// Redirecter reexec function.
func redirecter() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if len(os.Args) < 4 {
		logrus.Error("invalid number of arguments..")
		os.Exit(1)
	}

	var ingressPorts []*PortConfig
	if os.Args[3] != "" {
		var err error
		ingressPorts, err = readPortsFromFile(os.Args[3])
		if err != nil {
			logrus.Errorf("Failed reading ingress ports file: %v", err)
			os.Exit(2)
		}
	}

	eIP, _, err := net.ParseCIDR(os.Args[2])
	if err != nil {
		logrus.Errorf("Failed to parse endpoint IP %s: %v", os.Args[2], err)
		os.Exit(3)
	}

	rules := [][]string{}
	for _, iPort := range ingressPorts {
		rule := strings.Fields(fmt.Sprintf("-t nat -A PREROUTING -d %s -p %s --dport %d -j REDIRECT --to-port %d",
			eIP.String(), strings.ToLower(PortConfig_Protocol_name[int32(iPort.Protocol)]), iPort.PublishedPort, iPort.TargetPort))
		rules = append(rules, rule)
	}

	ns, err := netns.GetFromPath(os.Args[1])
	if err != nil {
		logrus.Errorf("failed get network namespace %q: %v", os.Args[1], err)
		os.Exit(4)
	}
	defer ns.Close()

	if err := netns.Set(ns); err != nil {
		logrus.Errorf("setting into container net ns %v failed, %v", os.Args[1], err)
		os.Exit(5)
	}

	for _, rule := range rules {
		if err := iptables.RawCombinedOutputNative(rule...); err != nil {
			logrus.Errorf("setting up rule failed, %v: %v", rule, err)
			os.Exit(5)
		}
	}
}
