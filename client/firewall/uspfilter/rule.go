package uspfilter

import (
	"net/netip"

	"github.com/google/gopacket"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

// PeerRule to handle management of rules
type PeerRule struct {
	id         string
	mgmtId     []byte
	ip         netip.Addr
	ipLayer    gopacket.LayerType
	matchByIP  bool
	protoLayer gopacket.LayerType
	sPort      *firewall.Port
	dPort      *firewall.Port
	drop       bool

	// prefix is set instead of ip when the rule matches a whole source network
	// rather than a single peer address. Rules carrying it live in the CIDR
	// slices, which are scanned linearly because a map keyed by address cannot
	// answer "which prefix contains this source".
	prefix netip.Prefix
}

// matchesPrefix reports whether the rule matches on a source network.
func (r *PeerRule) matchesPrefix() bool {
	return r.prefix.IsValid()
}

// ID returns the rule id
func (r *PeerRule) ID() string {
	return r.id
}

type RouteRule struct {
	id           string
	mgmtId       []byte
	sources      []netip.Prefix
	dstSet       firewall.Set
	destinations []netip.Prefix
	protoLayer   gopacket.LayerType
	srcPort      *firewall.Port
	dstPort      *firewall.Port
	action       firewall.Action
}

// ID returns the rule id
func (r *RouteRule) ID() string {
	return r.id
}
