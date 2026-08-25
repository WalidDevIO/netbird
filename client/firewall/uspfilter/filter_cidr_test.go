package uspfilter

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

// newCIDRTestManager builds a manager whose overlay address is 100.10.0.100/16,
// so traffic addressed to it is treated as local and runs through the peer ACLs.
func newCIDRTestManager(t *testing.T) *Manager {
	t.Helper()

	localIP := netip.MustParseAddr("100.10.0.100")
	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      localIP,
				Network: netip.MustParsePrefix("100.10.0.0/16"),
			}
		},
	}

	manager, err := Create(ifaceMock, false, flowLogger, iface.DefaultMTU)
	require.NoError(t, err)
	require.NotNil(t, manager)
	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil))
	})

	require.NoError(t, manager.UpdateLocalIPs())
	return manager
}

// addCIDRRule installs a prefix-sourced rule and removes it when the test ends.
func addCIDRRule(t *testing.T, m *Manager, prefix string, proto fw.Protocol, dPort *fw.Port, action fw.Action) []fw.Rule {
	t.Helper()

	rules, err := m.AddPeerCIDRFiltering(nil, netip.MustParsePrefix(prefix), proto, nil, dPort, action)
	require.NoError(t, err)
	require.NotEmpty(t, rules)

	t.Cleanup(func() {
		for _, rule := range rules {
			// The rule may already be gone when the test deleted it itself.
			_ = m.DeletePeerRule(rule)
		}
	})
	return rules
}

// TestCIDRPeerFiltering_MatchesSourceNetwork is the core of the feature: an
// agentless host inside the granted network reaches the peer, a host outside it
// does not.
func TestCIDRPeerFiltering_MatchesSourceNetwork(t *testing.T) {
	manager := newCIDRTestManager(t)

	// The agentless host is not a peer, so no peer-keyed rule can cover it.
	packet := createTestPacket(t, "10.20.0.11", "100.10.0.100", fw.ProtocolTCP, 12345, 443)
	require.True(t, manager.FilterInbound(packet, 0), "traffic from an agentless host must be dropped without a rule")

	addCIDRRule(t, manager, "10.20.0.0/24", fw.ProtocolTCP, &fw.Port{Values: []uint16{443}}, fw.ActionAccept)

	tests := []struct {
		name    string
		srcIP   string
		dstPort uint16
		dropped bool
	}{
		{
			name:    "host inside the granted network on the granted port",
			srcIP:   "10.20.0.11",
			dstPort: 443,
			dropped: false,
		},
		{
			name:    "another host inside the same network",
			srcIP:   "10.20.0.250",
			dstPort: 443,
			dropped: false,
		},
		{
			name:    "network address itself",
			srcIP:   "10.20.0.0",
			dstPort: 443,
			dropped: false,
		},
		{
			name:    "broadcast address of the granted network",
			srcIP:   "10.20.0.255",
			dstPort: 443,
			dropped: false,
		},
		{
			name:    "adjacent network is outside the prefix",
			srcIP:   "10.20.1.11",
			dstPort: 443,
			dropped: true,
		},
		{
			name:    "unrelated network",
			srcIP:   "192.168.5.5",
			dstPort: 443,
			dropped: true,
		},
		{
			name:    "granted network but a port the rule does not cover",
			srcIP:   "10.20.0.11",
			dstPort: 80,
			dropped: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			packet := createTestPacket(t, tc.srcIP, "100.10.0.100", fw.ProtocolTCP, 12345, tc.dstPort)
			require.Equal(t, tc.dropped, manager.FilterInbound(packet, 0))
		})
	}
}

// TestCIDRPeerFiltering_ProtocolAll covers the shape management emits for a
// protocol=all policy: no ports, every protocol from the network allowed.
func TestCIDRPeerFiltering_ProtocolAll(t *testing.T) {
	manager := newCIDRTestManager(t)
	addCIDRRule(t, manager, "10.20.0.0/24", fw.ProtocolALL, nil, fw.ActionAccept)

	tcpPacket := createTestPacket(t, "10.20.0.11", "100.10.0.100", fw.ProtocolTCP, 12345, 8080)
	require.False(t, manager.FilterInbound(tcpPacket, 0), "TCP from the granted network should pass")

	udpPacket := createTestPacket(t, "10.20.0.11", "100.10.0.100", fw.ProtocolUDP, 12345, 53)
	require.False(t, manager.FilterInbound(udpPacket, 0), "UDP from the granted network should pass")

	outsidePacket := createTestPacket(t, "10.21.0.11", "100.10.0.100", fw.ProtocolTCP, 12345, 8080)
	require.True(t, manager.FilterInbound(outsidePacket, 0), "a protocol=all rule must not widen the network")
}

// TestCIDRPeerFiltering_UnmaskedPrefixIsNormalized guards the case where a
// resource is stored as a host address inside a subnet (10.20.0.5/24): the rule
// must cover the network, not just that address.
func TestCIDRPeerFiltering_UnmaskedPrefixIsNormalized(t *testing.T) {
	manager := newCIDRTestManager(t)
	addCIDRRule(t, manager, "10.20.0.5/24", fw.ProtocolALL, nil, fw.ActionAccept)

	packet := createTestPacket(t, "10.20.0.200", "100.10.0.100", fw.ProtocolTCP, 12345, 443)
	require.False(t, manager.FilterInbound(packet, 0), "an unmasked prefix must still match its whole network")
}

// TestCIDRPeerFiltering_DenyWinsOverAccept checks both precedence rules:
// a deny prefix beats an accept prefix, and it also beats an exact-address
// accept rule, matching how the address-keyed maps already behave.
func TestCIDRPeerFiltering_DenyWinsOverAccept(t *testing.T) {
	manager := newCIDRTestManager(t)

	addCIDRRule(t, manager, "10.20.0.0/24", fw.ProtocolALL, nil, fw.ActionAccept)
	addCIDRRule(t, manager, "10.20.0.0/25", fw.ProtocolALL, nil, fw.ActionDrop)

	denied := createTestPacket(t, "10.20.0.11", "100.10.0.100", fw.ProtocolTCP, 12345, 443)
	require.True(t, manager.FilterInbound(denied, 0), "the deny prefix must win over the accept prefix")

	// .200 is outside the /25 deny but inside the /24 accept.
	allowed := createTestPacket(t, "10.20.0.200", "100.10.0.100", fw.ProtocolTCP, 12345, 443)
	require.False(t, manager.FilterInbound(allowed, 0), "an address outside the deny prefix stays allowed")

	acceptRules, err := manager.AddPeerFiltering(nil, net.ParseIP("10.20.0.11"), fw.ProtocolALL, nil, nil, fw.ActionAccept, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, rule := range acceptRules {
			require.NoError(t, manager.DeletePeerRule(rule))
		}
	})

	require.True(t, manager.FilterInbound(denied, 0), "a deny prefix must win over an exact-address accept rule")
}

// TestCIDRPeerFiltering_DeleteRemovesRule verifies the rule is really gone, and
// that a second delete reports the miss instead of silently succeeding.
func TestCIDRPeerFiltering_DeleteRemovesRule(t *testing.T) {
	manager := newCIDRTestManager(t)

	rules, err := manager.AddPeerCIDRFiltering(nil, netip.MustParsePrefix("10.20.0.0/24"), fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	packet := createTestPacket(t, "10.20.0.11", "100.10.0.100", fw.ProtocolTCP, 12345, 443)
	require.False(t, manager.FilterInbound(packet, 0), "rule should allow the packet while installed")

	require.NoError(t, manager.DeletePeerRule(rules[0]))
	require.True(t, manager.FilterInbound(packet, 0), "packet must be dropped again once the rule is deleted")

	require.Error(t, manager.DeletePeerRule(rules[0]), "deleting an already-removed rule should report the miss")
}

// TestCIDRPeerFiltering_DeleteDenyRule covers the deny slice, which
// deletePeerCIDRRule selects on the rule's own action.
func TestCIDRPeerFiltering_DeleteDenyRule(t *testing.T) {
	manager := newCIDRTestManager(t)

	addCIDRRule(t, manager, "10.20.0.0/24", fw.ProtocolALL, nil, fw.ActionAccept)
	denyRules, err := manager.AddPeerCIDRFiltering(nil, netip.MustParsePrefix("10.20.0.0/24"), fw.ProtocolALL, nil, nil, fw.ActionDrop)
	require.NoError(t, err)
	require.Len(t, denyRules, 1)

	packet := createTestPacket(t, "10.20.0.11", "100.10.0.100", fw.ProtocolTCP, 12345, 443)
	require.True(t, manager.FilterInbound(packet, 0), "deny rule should block the packet")

	require.NoError(t, manager.DeletePeerRule(denyRules[0]))
	require.False(t, manager.FilterInbound(packet, 0), "removing the deny rule should expose the accept rule again")
}

// TestCIDRPeerFiltering_DoesNotDisturbPeerRules is a regression guard: adding a
// prefix rule must not change how the existing address-keyed rules behave.
func TestCIDRPeerFiltering_DoesNotDisturbPeerRules(t *testing.T) {
	manager := newCIDRTestManager(t)

	peerRules, err := manager.AddPeerFiltering(nil, net.ParseIP("100.10.0.1"), fw.ProtocolTCP, nil, &fw.Port{Values: []uint16{443}}, fw.ActionAccept, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, rule := range peerRules {
			require.NoError(t, manager.DeletePeerRule(rule))
		}
	})

	addCIDRRule(t, manager, "10.20.0.0/24", fw.ProtocolALL, nil, fw.ActionAccept)

	peerPacket := createTestPacket(t, "100.10.0.1", "100.10.0.100", fw.ProtocolTCP, 12345, 443)
	require.False(t, manager.FilterInbound(peerPacket, 0), "the peer rule should still allow its peer")

	otherPeerPacket := createTestPacket(t, "100.10.0.2", "100.10.0.100", fw.ProtocolTCP, 12345, 443)
	require.True(t, manager.FilterInbound(otherPeerPacket, 0), "an unrelated peer must still be dropped")
}

// TestCIDRPeerFiltering_IPv6 checks a v6 resource prefix end to end, including
// that it does not leak into the v4 decision path.
func TestCIDRPeerFiltering_IPv6(t *testing.T) {
	localIP := netip.MustParseAddr("100.10.0.100")
	localIPv6 := netip.MustParseAddr("fd00::100")
	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      localIP,
				Network: netip.MustParsePrefix("100.10.0.0/16"),
				IPv6:    localIPv6,
				IPv6Net: netip.MustParsePrefix("fd00::/64"),
			}
		},
	}

	manager, err := Create(ifaceMock, false, flowLogger, iface.DefaultMTU)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil))
	})
	require.NoError(t, manager.UpdateLocalIPs())

	blocked := createTestPacket(t, "fd11:2233::5", "fd00::100", fw.ProtocolTCP, 12345, 443)
	require.True(t, manager.FilterInbound(blocked, 0), "v6 traffic should be dropped without a rule")

	addCIDRRule(t, manager, "fd11:2233::/64", fw.ProtocolALL, nil, fw.ActionAccept)

	allowed := createTestPacket(t, "fd11:2233::5", "fd00::100", fw.ProtocolTCP, 12345, 443)
	require.False(t, manager.FilterInbound(allowed, 0), "v6 traffic from the granted network should pass")

	outside := createTestPacket(t, "fd11:4444::5", "fd00::100", fw.ProtocolTCP, 12345, 443)
	require.True(t, manager.FilterInbound(outside, 0), "a v6 network outside the prefix stays blocked")

	v4Packet := createTestPacket(t, "10.20.0.11", "100.10.0.100", fw.ProtocolTCP, 12345, 443)
	require.True(t, manager.FilterInbound(v4Packet, 0), "a v6 rule must not allow v4 traffic")
}

// TestCIDRPeerFiltering_InvalidPrefix asserts the manager rejects a zero prefix
// rather than installing a rule that would match nothing.
func TestCIDRPeerFiltering_InvalidPrefix(t *testing.T) {
	manager := newCIDRTestManager(t)

	_, err := manager.AddPeerCIDRFiltering(nil, netip.Prefix{}, fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.Error(t, err)
}

// TestCIDRPeerFiltering_ResetClearsRules covers resetState, which has to clear
// the two prefix slices alongside the address-keyed maps.
func TestCIDRPeerFiltering_ResetClearsRules(t *testing.T) {
	manager := newCIDRTestManager(t)
	addCIDRRule(t, manager, "10.20.0.0/24", fw.ProtocolALL, nil, fw.ActionAccept)

	packet := createTestPacket(t, "10.20.0.11", "100.10.0.100", fw.ProtocolTCP, 12345, 443)
	require.False(t, manager.FilterInbound(packet, 0))

	manager.mutex.Lock()
	manager.resetState()
	manager.mutex.Unlock()

	require.True(t, manager.FilterInbound(packet, 0), "reset must drop the prefix rules")
}
