package types_test

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
)

const (
	lanPrefix    = "10.20.0.0/24"
	targetPeerIP = "100.64.0.3"
)

// resourceSourceAccount builds an account where a subnet resource sits behind a
// routing peer and a policy lets that subnet initiate toward peer-target.
//
// The routing peer does not masquerade, so packets reach peer-target carrying
// the agentless host's own address — which is exactly why peer-target needs a
// prefix-sourced firewall rule.
func resourceSourceAccount(bidirectional bool) *types.Account {
	peers := map[string]*nbpeer.Peer{
		"peer-target": {
			ID: "peer-target", IP: netip.MustParseAddr(targetPeerIP), Key: "key-target", DNSLabel: "target",
			Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()}, UserID: "user-1",
			Meta: nbpeer.PeerSystemMeta{WtVersion: "0.60.0", GoOS: "linux"},
		},
		"peer-router": {
			ID: "peer-router", IP: netip.MustParseAddr("100.64.0.10"), Key: "key-router", DNSLabel: "router",
			Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()}, UserID: "user-1",
			Meta: nbpeer.PeerSystemMeta{WtVersion: "0.60.0", GoOS: "linux"},
		},
		"peer-bystander": {
			ID: "peer-bystander", IP: netip.MustParseAddr("100.64.0.7"), Key: "key-bystander", DNSLabel: "bystander",
			Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()}, UserID: "user-1",
			Meta: nbpeer.PeerSystemMeta{WtVersion: "0.60.0", GoOS: "linux"},
		},
	}

	groups := map[string]*types.Group{
		"group-target":    {ID: "group-target", Name: "Targets", Peers: []string{"peer-target"}},
		"group-bystander": {ID: "group-bystander", Name: "Bystanders", Peers: []string{"peer-bystander"}},
		"group-all":       {ID: "group-all", Name: "All", Peers: []string{"peer-target", "peer-router", "peer-bystander"}},
	}

	policies := []*types.Policy{
		{
			ID: "policy-lan-initiates", Name: "LAN initiates toward target", Enabled: true,
			Rules: []*types.PolicyRule{{
				ID: "rule-lan-initiates", Name: "lan -> target", Enabled: true,
				Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
				Bidirectional:  bidirectional,
				SourceResource: types.Resource{ID: "resource-lan", Type: types.ResourceTypeSubnet},
				Destinations:   []string{"group-target"},
			}},
		},
	}

	account := &types.Account{
		Id: "account-resource-source", Peers: peers, Groups: groups, Policies: policies,
		Users: map[string]*types.User{
			"user-1": {Id: "user-1", Role: types.UserRoleAdmin, AutoGroups: []string{"group-all"}},
		},
		Network: &types.Network{
			Identifier: "net-test", Net: net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(16, 32)}, Serial: 1,
		},
		PostureChecks: []*posture.Checks{},
		NetworkResources: []*resourceTypes.NetworkResource{
			{
				ID: "resource-lan", NetworkID: "net-1", AccountID: "account-resource-source", Enabled: true,
				Type: resourceTypes.Subnet, Prefix: netip.MustParsePrefix(lanPrefix), Address: lanPrefix,
			},
		},
		Networks: []*networkTypes.Network{
			{ID: "net-1", Name: "Branch LAN", AccountID: "account-resource-source"},
		},
		NetworkRouters: []*routerTypes.NetworkRouter{
			{
				ID: "router-1", NetworkID: "net-1", Peer: "peer-router", Enabled: true,
				AccountID: "account-resource-source", Masquerade: false, Metric: 9999,
			},
		},
		Settings: &types.Settings{PeerLoginExpirationEnabled: false, PeerLoginExpiration: 24 * time.Hour},
	}

	for _, p := range account.Policies {
		p.AccountID = account.Id
	}
	return account
}

// prefixRules returns the firewall rules whose source is the given prefix.
func prefixRules(rules []*types.FirewallRule, prefix string) []*types.FirewallRule {
	var out []*types.FirewallRule
	for _, r := range rules {
		if r.SourcePrefix.IsValid() && r.SourcePrefix.String() == prefix {
			out = append(out, r)
		}
	}
	return out
}

func directions(rules []*types.FirewallRule) []int {
	dirs := make([]int, 0, len(rules))
	for _, r := range rules {
		dirs = append(dirs, r.Direction)
	}
	return dirs
}

// TestResourceSource_TargetPeerGetsInboundPrefixRule is the core assertion: the
// destination peer receives a rule admitting the resource's whole network.
func TestResourceSource_TargetPeerGetsInboundPrefixRule(t *testing.T) {
	account := resourceSourceAccount(false)
	nm := networkMapFromComponents(t, account, "peer-target", allPeersValidated(account))
	require.NotNil(t, nm)

	rules := prefixRules(nm.FirewallRules, lanPrefix)
	require.Len(t, rules, 1, "expected exactly one prefix-sourced rule, got %+v", nm.FirewallRules)

	rule := rules[0]
	assert.Equal(t, types.FirewallRuleDirectionIN, rule.Direction, "a non-bidirectional rule is inbound only")
	assert.Equal(t, string(types.PolicyTrafficActionAccept), rule.Action)
	assert.Equal(t, string(types.PolicyRuleProtocolALL), rule.Protocol)
	assert.Equal(t, "rule-lan-initiates", rule.PolicyID)
}

// TestResourceSource_BidirectionalAddsReturnDirection covers the bidirectional
// form, whose extra rule is what a stateless backend turns into a
// return-traffic rule.
func TestResourceSource_BidirectionalAddsReturnDirection(t *testing.T) {
	account := resourceSourceAccount(true)
	nm := networkMapFromComponents(t, account, "peer-target", allPeersValidated(account))

	rules := prefixRules(nm.FirewallRules, lanPrefix)
	require.Len(t, rules, 2, "bidirectional should yield both directions")
	assert.ElementsMatch(t,
		[]int{types.FirewallRuleDirectionIN, types.FirewallRuleDirectionOUT},
		directions(rules))
}

// TestResourceSource_TargetPeerGetsResourceRoute is the routing half: without a
// route to the resource's network, the peer's replies never make it back
// through the routing peer.
func TestResourceSource_TargetPeerGetsResourceRoute(t *testing.T) {
	account := resourceSourceAccount(false)
	nm := networkMapFromComponents(t, account, "peer-target", allPeersValidated(account))

	var found bool
	for _, r := range nm.Routes {
		if r.Network.String() == lanPrefix {
			found = true
			assert.Equal(t, "key-router", r.Peer, "the route must point at the resource's routing peer")
			assert.Equal(t, "peer-router", r.PeerID)
			assert.True(t, r.Enabled)
		}
	}
	require.True(t, found, "peer-target should receive a route for %s, got %+v", lanPrefix, nm.Routes)

	assert.Contains(t, peerIDs(nm.Peers), "peer-router",
		"the routing peer must be reachable, or the route has no tunnel to use")
}

// TestResourceSource_BystanderGetsNothing checks the rule does not leak to peers
// the policy never names.
func TestResourceSource_BystanderGetsNothing(t *testing.T) {
	account := resourceSourceAccount(true)
	nm := networkMapFromComponents(t, account, "peer-bystander", allPeersValidated(account))

	assert.Empty(t, prefixRules(nm.FirewallRules, lanPrefix),
		"a peer outside the policy destinations must not get the prefix rule")

	for _, r := range nm.Routes {
		assert.NotEqual(t, lanPrefix, r.Network.String(),
			"a peer outside the policy destinations must not get the resource route")
	}
}

// TestResourceSource_RoutingPeerForwardRules pins the routing peer's forward
// chain. Traffic from the LAN into the overlay does not traverse it, and the
// return path is accepted as an established connection, so only the
// bidirectional form needs a rule there.
func TestResourceSource_RoutingPeerForwardRules(t *testing.T) {
	t.Run("non-bidirectional needs no forward rule", func(t *testing.T) {
		account := resourceSourceAccount(false)
		nm := networkMapFromComponents(t, account, "peer-router", allPeersValidated(account))

		for _, r := range nm.RoutesFirewallRules {
			assert.NotEqual(t, lanPrefix, r.Destination,
				"a one-way resource-sourced policy grants no peer-to-resource traffic")
		}
	})

	t.Run("bidirectional allows the target peer toward the resource", func(t *testing.T) {
		account := resourceSourceAccount(true)
		nm := networkMapFromComponents(t, account, "peer-router", allPeersValidated(account))

		var found bool
		for _, r := range nm.RoutesFirewallRules {
			if r.Destination != lanPrefix {
				continue
			}
			found = true
			assert.Contains(t, r.SourceRanges, targetPeerIP+"/32",
				"the forward rule must name the destination peer as its source")
		}
		require.True(t, found, "expected a forward rule toward %s, got %+v", lanPrefix, nm.RoutesFirewallRules)
	})
}

// TestResourceSource_RoutingPeerSeesTargetPeer verifies the routing peer can
// actually build a tunnel to the peer it forwards for.
func TestResourceSource_RoutingPeerSeesTargetPeer(t *testing.T) {
	account := resourceSourceAccount(false)
	nm := networkMapFromComponents(t, account, "peer-router", allPeersValidated(account))

	assert.Contains(t, peerIDs(nm.Peers), "peer-target",
		"the routing peer must see the peer it forwards LAN traffic to")
}

// TestResourceSource_DisabledObjectsProduceNoRule confirms the feature fails
// closed on every disable switch.
func TestResourceSource_DisabledObjectsProduceNoRule(t *testing.T) {
	tests := []struct {
		name    string
		disable func(*types.Account)
	}{
		{
			name:    "policy disabled",
			disable: func(a *types.Account) { a.Policies[0].Enabled = false },
		},
		{
			name:    "rule disabled",
			disable: func(a *types.Account) { a.Policies[0].Rules[0].Enabled = false },
		},
		{
			name:    "resource disabled",
			disable: func(a *types.Account) { a.NetworkResources[0].Enabled = false },
		},
		{
			name:    "router disabled",
			disable: func(a *types.Account) { a.NetworkRouters[0].Enabled = false },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			account := resourceSourceAccount(true)
			tc.disable(account)

			nm := networkMapFromComponents(t, account, "peer-target", allPeersValidated(account))
			assert.Empty(t, prefixRules(nm.FirewallRules, lanPrefix))
		})
	}
}

// TestResourceSource_DomainResourceProducesNoRule: a domain resource has no
// static prefix, so no source-matching rule can be built and none must appear.
func TestResourceSource_DomainResourceProducesNoRule(t *testing.T) {
	account := resourceSourceAccount(true)
	account.NetworkResources[0].Type = resourceTypes.Domain
	account.NetworkResources[0].Domain = "branch.example.com"
	account.NetworkResources[0].Prefix = netip.Prefix{}
	account.Policies[0].Rules[0].SourceResource.Type = types.ResourceTypeDomain

	nm := networkMapFromComponents(t, account, "peer-target", allPeersValidated(account))

	for _, r := range nm.FirewallRules {
		assert.False(t, r.SourcePrefix.IsValid(),
			"a domain resource must not produce a prefix-sourced rule")
	}
}

// TestResourceSource_HostResource covers the /32 shape of a host resource,
// which the client should install through the address path.
func TestResourceSource_HostResource(t *testing.T) {
	account := resourceSourceAccount(false)
	account.NetworkResources[0].Type = resourceTypes.Host
	account.NetworkResources[0].Prefix = netip.MustParsePrefix("10.20.0.11/32")
	account.NetworkResources[0].Address = "10.20.0.11/32"
	account.Policies[0].Rules[0].SourceResource.Type = types.ResourceTypeHost

	nm := networkMapFromComponents(t, account, "peer-target", allPeersValidated(account))

	rules := prefixRules(nm.FirewallRules, "10.20.0.11/32")
	require.Len(t, rules, 1)
	assert.Equal(t, types.FirewallRuleDirectionIN, rules[0].Direction)
}

// TestResourceSource_PortScopedRule checks the rule is narrowed to the policy's
// ports rather than opening the whole peer.
func TestResourceSource_PortScopedRule(t *testing.T) {
	account := resourceSourceAccount(false)
	account.Policies[0].Rules[0].Protocol = types.PolicyRuleProtocolTCP
	account.Policies[0].Rules[0].Ports = []string{"443"}

	nm := networkMapFromComponents(t, account, "peer-target", allPeersValidated(account))

	rules := prefixRules(nm.FirewallRules, lanPrefix)
	require.Len(t, rules, 1)
	assert.Equal(t, "443", rules[0].Port)
	assert.Equal(t, string(types.PolicyRuleProtocolTCP), rules[0].Protocol)
}

// TestResourceSource_DestinationPeerResource covers naming the destination as a
// peer resource instead of a group.
func TestResourceSource_DestinationPeerResource(t *testing.T) {
	account := resourceSourceAccount(false)
	account.Policies[0].Rules[0].Destinations = nil
	account.Policies[0].Rules[0].DestinationResource = types.Resource{ID: "peer-target", Type: types.ResourceTypePeer}

	nm := networkMapFromComponents(t, account, "peer-target", allPeersValidated(account))

	require.Len(t, prefixRules(nm.FirewallRules, lanPrefix), 1,
		"a peer-typed destination resource must be honoured like a destination group")

	bystanderNM := networkMapFromComponents(t, account, "peer-bystander", allPeersValidated(account))
	assert.Empty(t, prefixRules(bystanderNM.FirewallRules, lanPrefix))
}

// TestResourceSource_ClassicPolicyUnchanged is the regression guard: a normal
// peer-to-resource policy must keep producing address-sourced rules only.
func TestResourceSource_ClassicPolicyUnchanged(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	for _, peerID := range []string{"peer-src-1", "peer-dst-1", "peer-router-1"} {
		nm := networkMapFromComponents(t, account, peerID, validated)
		for _, r := range nm.FirewallRules {
			assert.False(t, r.SourcePrefix.IsValid(),
				"peer %s: classic policies must not emit prefix-sourced rules", peerID)
		}
	}
}

// TestResourceSource_PolicyIsAppliedToResource pins the lookup the routing and
// router-distribution paths both rely on.
func TestResourceSource_PolicyIsAppliedToResource(t *testing.T) {
	account := resourceSourceAccount(false)

	policies := account.GetPoliciesForNetworkResource("resource-lan")
	require.Len(t, policies, 1, "a policy naming the resource as its source applies to it")
	assert.Equal(t, "policy-lan-initiates", policies[0].ID)
}
