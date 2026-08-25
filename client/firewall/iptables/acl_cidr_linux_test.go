//go:build privileged

package iptables

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

// cidrTestPrefix stays clear of the mock interface's own 10.20.0.0/24 so a rule
// matching it cannot be confused with the overlay network.
const cidrTestPrefix = "172.31.7.0/24"

func newCIDRManager(t *testing.T) (*Manager, *iptables.IPTables) {
	t.Helper()

	client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)

	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil))
	})

	return manager, client
}

// inputRuleSpecs returns the rules currently in the ACL input chain.
func inputRuleSpecs(t *testing.T, client *iptables.IPTables) []string {
	t.Helper()

	rules, err := client.List("filter", chainNameInputRules)
	require.NoError(t, err)
	return rules
}

func containsSource(rules []string, prefix string) bool {
	for _, r := range rules {
		if strings.Contains(r, "-s "+prefix) {
			return true
		}
	}
	return false
}

// TestIptablesPeerCIDRFiltering checks the rule lands in the ACL input chain
// with a source-network match, and that iptables itself accepted it.
func TestIptablesPeerCIDRFiltering(t *testing.T) {
	manager, client := newCIDRManager(t)
	prefix := netip.MustParsePrefix(cidrTestPrefix)

	rules, err := manager.AddPeerCIDRFiltering(nil, prefix, fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err, "iptables rejected the prefix rule")
	require.Len(t, rules, 1)

	installed := inputRuleSpecs(t, client)
	require.True(t, containsSource(installed, cidrTestPrefix),
		"expected a -s %s rule in %s, got:\n%s", cidrTestPrefix, chainNameInputRules, strings.Join(installed, "\n"))

	var accepted bool
	for _, r := range installed {
		if strings.Contains(r, "-s "+cidrTestPrefix) && strings.Contains(r, "-j ACCEPT") {
			accepted = true
		}
	}
	assert.True(t, accepted, "the prefix rule should carry the ACCEPT target")

	require.NoError(t, manager.DeletePeerRule(rules[0]))
	assert.False(t, containsSource(inputRuleSpecs(t, client), cidrTestPrefix),
		"the prefix rule should be gone after delete")
}

// TestIptablesPeerCIDRFilteringWithPort covers the port-scoped shape.
func TestIptablesPeerCIDRFilteringWithPort(t *testing.T) {
	manager, client := newCIDRManager(t)

	_, err := manager.AddPeerCIDRFiltering(nil, netip.MustParsePrefix(cidrTestPrefix),
		fw.ProtocolTCP, nil, &fw.Port{Values: []uint16{443}}, fw.ActionAccept)
	require.NoError(t, err)

	installed := inputRuleSpecs(t, client)

	var found bool
	for _, r := range installed {
		if strings.Contains(r, "-s "+cidrTestPrefix) && strings.Contains(r, "-p tcp") && strings.Contains(r, "--dport 443") {
			found = true
		}
	}
	assert.True(t, found, "expected a tcp/443 prefix rule, got:\n%s", strings.Join(installed, "\n"))
}

// TestIptablesPeerCIDRFilteringDropIsInsertedFirst mirrors the ordering the
// address-based path guarantees: drops precede accepts in the chain.
func TestIptablesPeerCIDRFilteringDropIsInsertedFirst(t *testing.T) {
	manager, client := newCIDRManager(t)

	const denyPrefix = "172.31.7.128/25"

	_, err := manager.AddPeerCIDRFiltering(nil, netip.MustParsePrefix(cidrTestPrefix), fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err)
	_, err = manager.AddPeerCIDRFiltering(nil, netip.MustParsePrefix(denyPrefix), fw.ProtocolALL, nil, nil, fw.ActionDrop)
	require.NoError(t, err)

	installed := inputRuleSpecs(t, client)

	denyIdx, acceptIdx := -1, -1
	for i, r := range installed {
		switch {
		case strings.Contains(r, "-s "+denyPrefix):
			denyIdx = i
		case strings.Contains(r, "-s "+cidrTestPrefix):
			acceptIdx = i
		}
	}

	require.NotEqual(t, -1, denyIdx, "deny rule not found in:\n%s", strings.Join(installed, "\n"))
	require.NotEqual(t, -1, acceptIdx, "accept rule not found in:\n%s", strings.Join(installed, "\n"))
	assert.Less(t, denyIdx, acceptIdx, "the deny prefix rule must come before the accept one")
}

// TestIptablesPeerCIDRFilteringDoesNotUseIPSet pins the decision that prefix
// rules stay out of the ACL ipsets, which only hold peer addresses.
func TestIptablesPeerCIDRFilteringDoesNotUseIPSet(t *testing.T) {
	manager, client := newCIDRManager(t)

	_, err := manager.AddPeerCIDRFiltering(nil, netip.MustParsePrefix(cidrTestPrefix), fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err)

	for _, r := range inputRuleSpecs(t, client) {
		if strings.Contains(r, "-s "+cidrTestPrefix) {
			assert.NotContains(t, r, "--match-set", "a prefix rule must not go through an ACL ipset")
		}
	}
}

// TestIptablesPeerCIDRFilteringIPv6 exercises the v6 ACL manager, which writes
// to ip6tables rather than iptables.
func TestIptablesPeerCIDRFilteringIPv6(t *testing.T) {
	ifaceMockV6 := &iFaceMock{
		NameFunc: func() string { return "wg-test" },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("10.20.0.1"),
				Network: netip.MustParsePrefix("10.20.0.0/24"),
				IPv6:    netip.MustParseAddr("fd00::1"),
				IPv6Net: netip.MustParsePrefix("fd00::/64"),
			}
		},
	}

	manager, err := Create(ifaceMockV6, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))
	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil))
	})

	const v6Prefix = "fd11:2233::/64"
	rules, err := manager.AddPeerCIDRFiltering(nil, netip.MustParsePrefix(v6Prefix),
		fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err, "ip6tables rejected the v6 prefix rule")
	require.Len(t, rules, 1)

	v6Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	require.NoError(t, err)
	v6Rules, err := v6Client.List("filter", chainNameInputRules)
	require.NoError(t, err)
	require.True(t, containsSource(v6Rules, v6Prefix),
		"expected a -s %s rule in the v6 chain, got: %s", v6Prefix, strings.Join(v6Rules, " | "))

	// The v4 chain must stay untouched: a v6 grant is not a v4 grant.
	v4Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)
	v4Rules, err := v4Client.List("filter", chainNameInputRules)
	require.NoError(t, err)
	assert.False(t, containsSource(v4Rules, v6Prefix), "a v6 prefix must not appear in the v4 chain")

	require.NoError(t, manager.DeletePeerRule(rules[0]))
}

// TestIptablesPeerCIDRFilteringInvalidPrefix asserts a zero prefix is refused.
func TestIptablesPeerCIDRFilteringInvalidPrefix(t *testing.T) {
	manager, _ := newCIDRManager(t)

	_, err := manager.AddPeerCIDRFiltering(nil, netip.Prefix{}, fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.Error(t, err)
}
