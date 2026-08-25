package networkmap_test

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goproto "google.golang.org/protobuf/proto"

	mgmtgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/types"
	nbnetworkmap "github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
	"github.com/netbirdio/netbird/shared/netiputil"
)

const resourceLANPrefix = "10.20.0.0/24"

// buildResourceSourceComponents assembles the component set management ships to
// a peer that a network resource is allowed to initiate toward: the resource
// itself, its routing peer, the routers map, and the policy naming the resource
// as its source.
func buildResourceSourceComponents(t *testing.T, bidirectional bool) (*types.NetworkMapComponents, string, string) {
	t.Helper()

	targetKey := randomWgKey(t)
	routerKey := randomWgKey(t)

	target := &nmdata.Peer{
		ID: "peer-target", Key: targetKey,
		IP:       netip.AddrFrom4([4]byte{100, 64, 0, 3}),
		DNSLabel: "target",
		Meta:     nmdata.PeerSystemMeta{Capabilities: []int32{nmdata.PeerCapabilitySourcePrefixes}},
		// The whole feature is gated on this: a peer that cannot read
		// SourcePrefixes is not sent prefix-sourced rules at all.
	}
	router := &nmdata.Peer{
		ID: "peer-router", Key: routerKey,
		IP:       netip.AddrFrom4([4]byte{100, 64, 0, 10}),
		DNSLabel: "router",
		Meta:     nmdata.PeerSystemMeta{Capabilities: []int32{nmdata.PeerCapabilitySourcePrefixes}},
	}

	policy := &nmdata.Policy{
		ID: "pol-lan-initiates", PublicID: "7", Enabled: true,
		Rules: []*nmdata.PolicyRule{{
			ID:             "rule-lan-initiates",
			Enabled:        true,
			Action:         string(types.PolicyTrafficActionAccept),
			Protocol:       string(types.PolicyRuleProtocolALL),
			Bidirectional:  bidirectional,
			SourceResource: nmdata.Resource{ID: "resource-lan", Type: string(types.ResourceTypeSubnet)},
			Destinations:   []string{"group-target"},
		}},
	}

	resource := &nmdata.NetworkResource{
		ID: "resource-lan", PublicID: "res-1", NetworkID: "net-1",
		Name:    "Branch LAN",
		Type:    string(types.ResourceTypeSubnet),
		Address: resourceLANPrefix,
		Prefix:  netip.MustParsePrefix(resourceLANPrefix),
		Enabled: true,
	}

	c := &types.NetworkMapComponents{
		PeerID: "peer-target",
		Network: &nmdata.Network{
			Identifier: "net-resource-source",
			Net:        net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)},
			Serial:     1,
		},
		AccountSettings: &nmdata.AccountSettingsInfo{},
		DNSSettings:     &nmdata.DNSSettings{},
		Peers: map[string]*nmdata.Peer{
			"peer-target": target,
			"peer-router": router,
		},
		Groups: map[string]*nmdata.Group{
			"group-target": {ID: "group-target", PublicID: "1", Name: "Targets", Peers: []string{"peer-target"}},
		},
		Policies:         []*nmdata.Policy{policy},
		NetworkResources: []*nmdata.NetworkResource{resource},
		ResourcePoliciesMap: map[string][]*nmdata.Policy{
			"resource-lan": {policy},
		},
		RoutersMap: map[string]map[string]*nmdata.NetworkRouter{
			"net-1": {
				"peer-router": {
					PublicID: "rtr-1", Masquerade: false, Metric: 9999, Enabled: true,
				},
			},
		},
		RouterPeers: map[string]*nmdata.Peer{
			"peer-router": router,
		},
		NetworkXIDToPublicID: map[string]string{"net-1": "net-pub-1"},
	}

	return c, targetKey, routerKey
}

// roundTripEnvelope encodes, marshals, unmarshals and decodes the components,
// mirroring exactly what a component-capable client does.
func roundTripEnvelope(t *testing.T, c *types.NetworkMapComponents, localKey string) *nbnetworkmap.EnvelopeResult {
	t.Helper()

	envelope := mgmtgrpc.EncodeNetworkMapEnvelope(mgmtgrpc.ComponentsEnvelopeInput{
		Components: c,
		DNSDomain:  "netbird.cloud",
	})

	wire, err := goproto.Marshal(envelope)
	require.NoError(t, err, "marshal envelope")

	var decoded proto.NetworkMapEnvelope
	require.NoError(t, goproto.Unmarshal(wire, &decoded), "unmarshal envelope")

	result, err := nbnetworkmap.EnvelopeToNetworkMap(context.Background(), &decoded, localKey, "netbird.cloud")
	require.NoError(t, err, "EnvelopeToNetworkMap")
	require.NotNil(t, result)
	return result
}

// TestEnvelope_ResourceSourceSurvivesWire is the assertion that the wire format
// carries enough to rebuild the rule on the client. Without the resource
// reference the client silently produces no rule at all, and the peer quietly
// loses the access the policy granted.
func TestEnvelope_ResourceSourceSurvivesWire(t *testing.T) {
	c, localKey, _ := buildResourceSourceComponents(t, false)
	result := roundTripEnvelope(t, c, localKey)

	require.NotNil(t, result.Components)
	require.Len(t, result.Components.Policies, 1)

	rule := result.Components.Policies[0].Rules[0]
	resourceID, ok := sharedtypes.NetworkResourceSourceID(rule)
	require.True(t, ok, "the decoded rule must still name a network resource as its source")

	resolved := result.Components.NetworkResources
	require.Len(t, resolved, 1)
	assert.Equal(t, resolved[0].ID, resourceID,
		"the decoded resource reference must match the shipped resource's id")
	assert.Equal(t, resourceLANPrefix, resolved[0].Prefix.String())
}

// TestEnvelope_ResourceSourceProducesClientRule walks the whole client pipeline
// and checks the firewall rule that comes out the far end.
func TestEnvelope_ResourceSourceProducesClientRule(t *testing.T) {
	c, localKey, _ := buildResourceSourceComponents(t, false)
	result := roundTripEnvelope(t, c, localKey)
	require.NotNil(t, result.NetworkMap)

	var prefixRules []*proto.FirewallRule
	for _, r := range result.NetworkMap.FirewallRules {
		if len(r.SourcePrefixes) == 0 {
			continue
		}
		prefix, err := netiputil.DecodePrefix(r.SourcePrefixes[0])
		require.NoError(t, err)
		if prefix.String() == resourceLANPrefix {
			prefixRules = append(prefixRules, r)
		}
	}

	require.Len(t, prefixRules, 1, "expected one prefix-sourced rule, got %+v", result.NetworkMap.FirewallRules)
	assert.Equal(t, proto.RuleDirection_IN, prefixRules[0].Direction)
	assert.Equal(t, proto.RuleAction_ACCEPT, prefixRules[0].Action)
}

// TestEnvelope_ResourceSourcePushesRoute checks the client also derives the
// route back toward the resource network.
func TestEnvelope_ResourceSourcePushesRoute(t *testing.T) {
	c, localKey, _ := buildResourceSourceComponents(t, false)
	result := roundTripEnvelope(t, c, localKey)

	var found bool
	for _, r := range result.NetworkMap.Routes {
		if r.Network == resourceLANPrefix {
			found = true
		}
	}
	require.True(t, found, "client should derive a route for %s, got %+v", resourceLANPrefix, result.NetworkMap.Routes)
}

// TestEnvelope_ResourceSourceBidirectional checks both directions survive the
// wire, since the reverse rule is what stateless backends need.
func TestEnvelope_ResourceSourceBidirectional(t *testing.T) {
	c, localKey, _ := buildResourceSourceComponents(t, true)
	result := roundTripEnvelope(t, c, localKey)

	dirs := map[proto.RuleDirection]int{}
	for _, r := range result.NetworkMap.FirewallRules {
		if len(r.SourcePrefixes) == 0 {
			continue
		}
		prefix, err := netiputil.DecodePrefix(r.SourcePrefixes[0])
		require.NoError(t, err)
		if prefix.String() == resourceLANPrefix {
			dirs[r.Direction]++
		}
	}

	assert.Equal(t, 1, dirs[proto.RuleDirection_IN], "inbound rule expected")
	assert.Equal(t, 1, dirs[proto.RuleDirection_OUT], "outbound rule expected for a bidirectional policy")
}

// TestEnvelope_PeerResourceReferenceUnaffected is the regression guard for the
// ResourceCompact change: a peer-typed resource must keep travelling as a peer
// index and must not pick up a resource id.
func TestEnvelope_PeerResourceReferenceUnaffected(t *testing.T) {
	c, localKey, routerKey := buildResourceSourceComponents(t, false)
	c.Policies[0].Rules[0].SourceResource = nmdata.Resource{}
	c.Policies[0].Rules[0].Sources = []string{"group-target"}
	c.Policies[0].Rules[0].Destinations = nil
	c.Policies[0].Rules[0].DestinationResource = nmdata.Resource{ID: "peer-router", Type: string(types.ResourceTypePeer)}

	result := roundTripEnvelope(t, c, localKey)
	require.Len(t, result.Components.Policies, 1)

	dest := result.Components.Policies[0].Rules[0].DestinationResource
	assert.Equal(t, string(types.ResourceTypePeer), dest.Type)
	// The wire ships no peer xid; the decoder rebuilds peer ids from the WG key,
	// so that is what a peer-typed resource resolves to on the client.
	assert.Equal(t, routerKey, dest.ID, "a peer-typed resource must resolve back to its peer")
}

// TestEnvelope_ResourceSourceDroppedWithoutCapability is the security guard: a
// peer that cannot read SourcePrefixes must receive no rule rather than one
// narrowed to the prefix's network address, which would grant the wrong hosts.
func TestEnvelope_ResourceSourceDroppedWithoutCapability(t *testing.T) {
	c, localKey, _ := buildResourceSourceComponents(t, false)
	// Strip the capability rather than a boolean field: support is advertised
	// through the peer's meta now.
	c.Peers["peer-target"].Meta.Capabilities = nil

	result := roundTripEnvelope(t, c, localKey)

	for _, r := range result.NetworkMap.FirewallRules {
		assert.NotEqual(t, "10.20.0.0", r.PeerIP, //nolint:staticcheck // asserting the legacy field stays clean
			"a peer without prefix support must not receive the prefix's network address as a peer rule")
		assert.Empty(t, r.SourcePrefixes)
	}
}
