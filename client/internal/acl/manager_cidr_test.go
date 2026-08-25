package acl

import (
	"net"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/client/firewall"
	firewallmgr "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/acl/mocks"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/netiputil"
)

const cidrTestLocalIP = "100.10.0.100"

// newCIDRACLManager wires the real userspace firewall behind a DefaultManager so
// the tests assert on packets that actually traverse the filter, not on calls
// recorded by a stub.
func newCIDRACLManager(t *testing.T) (*DefaultManager, *uspfilter.Manager) {
	t.Helper()

	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	t.Setenv(firewall.EnvForceUserspaceFirewall, "true")

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	network := netip.MustParsePrefix(cidrTestLocalIP + "/16")
	ifaceMock := mocks.NewMockIFaceMapper(ctrl)
	ifaceMock.EXPECT().IsUserspaceBind().Return(true).AnyTimes()
	ifaceMock.EXPECT().SetFilter(gomock.Any()).AnyTimes()
	ifaceMock.EXPECT().Name().Return("lo").AnyTimes()
	ifaceMock.EXPECT().Address().Return(wgaddr.Address{
		IP:      network.Addr(),
		Network: network,
	}).AnyTimes()
	ifaceMock.EXPECT().GetWGDevice().Return(nil).AnyTimes()

	fw, err := firewall.NewFirewall(ifaceMock, nil, flowLogger, false, iface.DefaultMTU)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, fw.Close(nil))
	})

	usp, ok := fw.(*uspfilter.Manager)
	require.True(t, ok, "expected the userspace firewall, got %T", fw)
	require.NoError(t, usp.UpdateLocalIPs())

	return NewDefaultManager(fw), usp
}

// encodedPrefix returns the compact wire encoding management puts in
// FirewallRule.SourcePrefixes.
func encodedPrefix(t *testing.T, prefix string) []byte {
	t.Helper()

	encoded, err := netiputil.EncodePrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	return encoded
}

// cidrTestPacket builds a TCP packet addressed to the local overlay address.
func cidrTestPacket(t *testing.T, srcIP string, dstPort uint16) []byte {
	t.Helper()

	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(cidrTestLocalIP),
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(dstPort),
	}
	require.NoError(t, tcpLayer.SetNetworkLayerForChecksum(ipLayer))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer, gopacket.Payload("x")))
	return buf.Bytes()
}

// TestApplyFiltering_PrefixSourcedRule is the client-side end of the feature: a
// rule whose source is a whole network must admit every host inside it and no
// host outside it.
func TestApplyFiltering_PrefixSourcedRule(t *testing.T) {
	manager, usp := newCIDRACLManager(t)

	networkMap := &mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PolicyID:       []byte("policy-resource-source"),
				PeerIP:         "10.20.0.0", //nolint:staticcheck // the deprecated field is what these tests exercise
				SourcePrefixes: [][]byte{encodedPrefix(t, "10.20.0.0/24")},
				Direction:      mgmProto.RuleDirection_IN,
				Action:         mgmProto.RuleAction_ACCEPT,
				Protocol:       mgmProto.RuleProtocol_TCP,
				Port:           "443",
			},
		},
		FirewallRulesIsEmpty: false,
	}

	manager.ApplyFiltering(networkMap, false)

	require.False(t, usp.FilterInbound(cidrTestPacket(t, "10.20.0.11", 443), 0),
		"a host inside the granted network should be admitted")
	require.False(t, usp.FilterInbound(cidrTestPacket(t, "10.20.0.240", 443), 0),
		"any host inside the granted network should be admitted")
	require.True(t, usp.FilterInbound(cidrTestPacket(t, "10.20.1.11", 443), 0),
		"a host outside the granted network must stay blocked")
	require.True(t, usp.FilterInbound(cidrTestPacket(t, "10.20.0.11", 80), 0),
		"a port the rule does not grant must stay blocked")
}

// TestApplyFiltering_HostPrefixKeepsAddressPath checks that the /32 shape every
// peer-sourced rule has still goes through the address-based path and behaves
// exactly as before.
func TestApplyFiltering_HostPrefixKeepsAddressPath(t *testing.T) {
	manager, usp := newCIDRACLManager(t)

	networkMap := &mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PolicyID:       []byte("policy-peer"),
				PeerIP:         "100.10.0.1", //nolint:staticcheck // the deprecated field is what these tests exercise
				SourcePrefixes: [][]byte{encodedPrefix(t, "100.10.0.1/32")},
				Direction:      mgmProto.RuleDirection_IN,
				Action:         mgmProto.RuleAction_ACCEPT,
				Protocol:       mgmProto.RuleProtocol_ALL,
			},
		},
		FirewallRulesIsEmpty: false,
	}

	manager.ApplyFiltering(networkMap, false)

	require.False(t, usp.FilterInbound(cidrTestPacket(t, "100.10.0.1", 443), 0),
		"the named peer should be admitted")
	require.True(t, usp.FilterInbound(cidrTestPacket(t, "100.10.0.2", 443), 0),
		"a /32 rule must not admit a neighbouring address")
}

// TestApplyFiltering_WildcardPrefixStillMatchesAll is the regression guard for
// the legacy allow-all rule. Management encodes it as 0.0.0.0/0, which is not a
// host prefix, so it must still be recognised as "any source" instead of being
// routed down the prefix path and narrowed.
func TestApplyFiltering_WildcardPrefixStillMatchesAll(t *testing.T) {
	tests := []struct {
		name string
		rule *mgmProto.FirewallRule
	}{
		{
			name: "encoded wildcard prefix",
			rule: &mgmProto.FirewallRule{
				PolicyID:       []byte("policy-wildcard"),
				PeerIP:         "0.0.0.0", //nolint:staticcheck // the deprecated field is what these tests exercise
				SourcePrefixes: [][]byte{encodedPrefix(t, "0.0.0.0/0")},
				Direction:      mgmProto.RuleDirection_IN,
				Action:         mgmProto.RuleAction_ACCEPT,
				Protocol:       mgmProto.RuleProtocol_ALL,
			},
		},
		{
			name: "legacy PeerIP wildcard without prefixes",
			rule: &mgmProto.FirewallRule{
				PolicyID:  []byte("policy-wildcard-legacy"),
				PeerIP:    "0.0.0.0", //nolint:staticcheck // the deprecated field is what these tests exercise
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manager, usp := newCIDRACLManager(t)
			manager.ApplyFiltering(&mgmProto.NetworkMap{
				FirewallRules:        []*mgmProto.FirewallRule{tc.rule},
				FirewallRulesIsEmpty: false,
			}, false)

			require.False(t, usp.FilterInbound(cidrTestPacket(t, "100.10.0.1", 443), 0),
				"a wildcard rule should admit an overlay peer")
			require.False(t, usp.FilterInbound(cidrTestPacket(t, "10.20.0.11", 443), 0),
				"a wildcard rule should admit any source")
		})
	}
}

// TestApplyFiltering_PrefixRuleRemovedOnUpdate checks the rule bookkeeping: a
// prefix rule that disappears from the network map must be torn down, not left
// behind granting access.
func TestApplyFiltering_PrefixRuleRemovedOnUpdate(t *testing.T) {
	manager, usp := newCIDRACLManager(t)

	withRule := &mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PolicyID:       []byte("policy-resource-source"),
				PeerIP:         "10.20.0.0", //nolint:staticcheck // the deprecated field is what these tests exercise
				SourcePrefixes: [][]byte{encodedPrefix(t, "10.20.0.0/24")},
				Direction:      mgmProto.RuleDirection_IN,
				Action:         mgmProto.RuleAction_ACCEPT,
				Protocol:       mgmProto.RuleProtocol_ALL,
			},
		},
		FirewallRulesIsEmpty: false,
	}
	manager.ApplyFiltering(withRule, false)
	require.False(t, usp.FilterInbound(cidrTestPacket(t, "10.20.0.11", 443), 0))

	// The policy is revoked: management sends an empty rule set.
	manager.ApplyFiltering(&mgmProto.NetworkMap{
		FirewallRules:        []*mgmProto.FirewallRule{},
		FirewallRulesIsEmpty: true,
	}, false)

	require.True(t, usp.FilterInbound(cidrTestPacket(t, "10.20.0.11", 443), 0),
		"revoking the policy must remove the prefix rule")
}

// TestApplyFiltering_PrefixDenyRule covers a drop action on a prefix source,
// which has to win over a broader accept rule.
func TestApplyFiltering_PrefixDenyRule(t *testing.T) {
	manager, usp := newCIDRACLManager(t)

	manager.ApplyFiltering(&mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PolicyID:       []byte("policy-allow"),
				PeerIP:         "10.20.0.0", //nolint:staticcheck // the deprecated field is what these tests exercise
				SourcePrefixes: [][]byte{encodedPrefix(t, "10.20.0.0/24")},
				Direction:      mgmProto.RuleDirection_IN,
				Action:         mgmProto.RuleAction_ACCEPT,
				Protocol:       mgmProto.RuleProtocol_ALL,
			},
			{
				PolicyID:       []byte("policy-deny"),
				PeerIP:         "10.20.0.128", //nolint:staticcheck // the deprecated field is what these tests exercise
				SourcePrefixes: [][]byte{encodedPrefix(t, "10.20.0.128/25")},
				Direction:      mgmProto.RuleDirection_IN,
				Action:         mgmProto.RuleAction_DROP,
				Protocol:       mgmProto.RuleProtocol_ALL,
			},
		},
		FirewallRulesIsEmpty: false,
	}, false)

	require.False(t, usp.FilterInbound(cidrTestPacket(t, "10.20.0.11", 443), 0),
		"the lower half of the network stays allowed")
	require.True(t, usp.FilterInbound(cidrTestPacket(t, "10.20.0.200", 443), 0),
		"the denied half must be dropped")
}

// TestExtractRuleSource pins the decoding contract the dispatch depends on.
func TestExtractRuleSource(t *testing.T) {
	tests := []struct {
		name    string
		rule    *mgmProto.FirewallRule
		want    string
		single  bool
		wantErr bool
	}{
		{
			name:   "network prefix",
			rule:   &mgmProto.FirewallRule{SourcePrefixes: [][]byte{encodedPrefix(t, "10.20.0.0/24")}},
			want:   "10.20.0.0/24",
			single: false,
		},
		{
			name:   "host prefix",
			rule:   &mgmProto.FirewallRule{SourcePrefixes: [][]byte{encodedPrefix(t, "100.10.0.1/32")}},
			want:   "100.10.0.1/32",
			single: true,
		},
		{
			name:   "v4 wildcard",
			rule:   &mgmProto.FirewallRule{SourcePrefixes: [][]byte{encodedPrefix(t, "0.0.0.0/0")}},
			want:   "0.0.0.0/0",
			single: true,
		},
		{
			name:   "v6 wildcard",
			rule:   &mgmProto.FirewallRule{SourcePrefixes: [][]byte{encodedPrefix(t, "::/0")}},
			want:   "::/0",
			single: true,
		},
		{
			name:   "legacy PeerIP becomes a host prefix",
			rule:   &mgmProto.FirewallRule{PeerIP: "100.10.0.1"}, //nolint:staticcheck // the deprecated field is what these tests exercise
			want:   "100.10.0.1/32",
			single: true,
		},
		{
			name:   "v6 network prefix",
			rule:   &mgmProto.FirewallRule{SourcePrefixes: [][]byte{encodedPrefix(t, "fd11:2233::/64")}},
			want:   "fd11:2233::/64",
			single: false,
		},
		{
			name:    "no source at all",
			rule:    &mgmProto.FirewallRule{},
			wantErr: true,
		},
		{
			name:    "malformed prefix",
			rule:    &mgmProto.FirewallRule{SourcePrefixes: [][]byte{{1, 2, 3}}},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prefix, err := extractRuleSource(tc.rule)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, prefix.String())
			require.Equal(t, tc.single, singleAddrRule(prefix),
				"dispatch decision for %s", prefix)
		})
	}
}

// TestCIDRRuleUnsupportedBackend asserts a backend that cannot express a prefix
// source reports it instead of installing something narrower.
func TestCIDRRuleUnsupportedBackend(t *testing.T) {
	manager := NewDefaultManager(&addressOnlyFirewall{})

	_, _, err := manager.protoRuleToFirewallRule(&mgmProto.FirewallRule{
		PolicyID:       []byte("policy-resource-source"),
		SourcePrefixes: [][]byte{encodedPrefix(t, "10.20.0.0/24")},
		Direction:      mgmProto.RuleDirection_IN,
		Action:         mgmProto.RuleAction_ACCEPT,
		Protocol:       mgmProto.RuleProtocol_ALL,
	}, "")

	require.ErrorIs(t, err, ErrCIDRFilteringUnsupported)
}

// addressOnlyFirewall is a Manager that deliberately does NOT implement
// CIDRFilteringManager, standing in for a backend without prefix support.
type addressOnlyFirewall struct {
	firewallmgr.Manager
}

func (f *addressOnlyFirewall) IsStateful() bool { return true }
