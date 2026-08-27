package server

import (
	"context"
	"net/netip"
	"testing"

	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/types"
)

// seedNetworkResource stores a network and one resource on it, returning the
// resource id. Policy validation resolves resources straight from the store, so
// the test needs them persisted rather than only present in memory.
func seedNetworkResource(t *testing.T, am *DefaultAccountManager, accountID string, resType resourceTypes.NetworkResourceType, prefix string) string {
	t.Helper()
	return seedNetworkResourceWithRouter(t, am, accountID, resType, prefix, false)
}

// seedNetworkResourceWithRouter stores a network, one resource on it, and a
// router whose masquerade setting the caller chooses.
func seedNetworkResourceWithRouter(t *testing.T, am *DefaultAccountManager, accountID string, resType resourceTypes.NetworkResourceType, prefix string, masquerade bool) string {
	t.Helper()

	ctx := context.Background()
	network := &networkTypes.Network{
		ID:        xid.New().String(),
		AccountID: accountID,
		Name:      "Branch LAN",
	}
	require.NoError(t, am.Store.SaveNetwork(ctx, network))

	if masquerade {
		require.NoError(t, am.Store.CreateNetworkRouter(ctx, &routerTypes.NetworkRouter{
			ID:         xid.New().String(),
			NetworkID:  network.ID,
			AccountID:  accountID,
			Peer:       "some-peer",
			Enabled:    true,
			Masquerade: true,
		}))
	}

	resource := &resourceTypes.NetworkResource{
		ID:        xid.New().String(),
		NetworkID: network.ID,
		AccountID: accountID,
		Name:      "lan",
		Type:      resType,
		Enabled:   true,
	}
	if prefix != "" {
		resource.Prefix = netip.MustParsePrefix(prefix)
	}
	require.NoError(t, am.Store.SaveNetworkResource(ctx, resource))

	return resource.ID
}

func resourceSourcePolicy(accountID, resourceID string, resType types.ResourceType, destinations []string) *types.Policy {
	return &types.Policy{
		AccountID: accountID,
		Name:      "lan initiates",
		Enabled:   true,
		Rules: []*types.PolicyRule{{
			Enabled:        true,
			Action:         types.PolicyTrafficActionAccept,
			Protocol:       types.PolicyRuleProtocolALL,
			SourceResource: types.Resource{ID: resourceID, Type: resType},
			Destinations:   destinations,
		}},
	}
}

// TestSavePolicy_SubnetSourceResourceAccepted is the happy path: a subnet
// resource may be a rule source, and the reference survives the round trip.
func TestSavePolicy_SubnetSourceResourceAccepted(t *testing.T) {
	manager, _, account, _, _, _ := setupNetworkMapTest(t)
	ctx := context.Background()

	require.NoError(t, manager.CreateGroup(ctx, account.Id, userID, &types.Group{ID: "groupTargets", Name: "Targets"}))
	resourceID := seedNetworkResource(t, manager, account.Id, resourceTypes.Subnet, "10.20.0.0/24")

	saved, err := manager.SavePolicy(ctx, account.Id, userID,
		resourceSourcePolicy(account.Id, resourceID, types.ResourceTypeSubnet, []string{"groupTargets"}), true)
	require.NoError(t, err)

	stored, err := manager.GetPolicy(ctx, account.Id, saved.ID, userID)
	require.NoError(t, err)
	require.Len(t, stored.Rules, 1)

	gotID, ok := stored.Rules[0].NetworkResourceSourceID()
	require.True(t, ok, "the stored rule must still name the resource as its source")
	assert.Equal(t, resourceID, gotID)
}

// TestSavePolicy_HostSourceResourceAccepted covers the other prefix-carrying
// resource type.
func TestSavePolicy_HostSourceResourceAccepted(t *testing.T) {
	manager, _, account, _, _, _ := setupNetworkMapTest(t)
	ctx := context.Background()

	require.NoError(t, manager.CreateGroup(ctx, account.Id, userID, &types.Group{ID: "groupTargets", Name: "Targets"}))
	resourceID := seedNetworkResource(t, manager, account.Id, resourceTypes.Host, "10.20.0.11/32")

	_, err := manager.SavePolicy(ctx, account.Id, userID,
		resourceSourcePolicy(account.Id, resourceID, types.ResourceTypeHost, []string{"groupTargets"}), true)
	require.NoError(t, err)
}

// TestSavePolicy_RejectsInvalidSourceResources checks every way the reference
// can be wrong. Each must be refused rather than stored as a rule that silently
// matches nothing.
func TestSavePolicy_RejectsInvalidSourceResources(t *testing.T) {
	tests := []struct {
		name         string
		resType      resourceTypes.NetworkResourceType
		prefix       string
		declaredType types.ResourceType
		useUnknownID bool
		destinations []string
		wantMsg      string
	}{
		{
			name:         "domain resource cannot be a source",
			resType:      resourceTypes.Domain,
			declaredType: types.ResourceTypeDomain,
			destinations: []string{"groupTargets"},
			wantMsg:      "cannot be a rule source",
		},
		{
			name:         "unknown resource id",
			resType:      resourceTypes.Subnet,
			prefix:       "10.20.0.0/24",
			declaredType: types.ResourceTypeSubnet,
			useUnknownID: true,
			destinations: []string{"groupTargets"},
			wantMsg:      "unknown network resource",
		},
		{
			name:         "declared type does not match the stored resource",
			resType:      resourceTypes.Subnet,
			prefix:       "10.20.0.0/24",
			declaredType: types.ResourceTypeHost,
			destinations: []string{"groupTargets"},
			wantMsg:      "not \"host\"",
		},
		{
			name:         "source resource without any destination",
			resType:      resourceTypes.Subnet,
			prefix:       "10.20.0.0/24",
			declaredType: types.ResourceTypeSubnet,
			destinations: nil,
			wantMsg:      "needs at least one destination",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manager, _, account, _, _, _ := setupNetworkMapTest(t)
			ctx := context.Background()

			require.NoError(t, manager.CreateGroup(ctx, account.Id, userID, &types.Group{ID: "groupTargets", Name: "Targets"}))
			resourceID := seedNetworkResource(t, manager, account.Id, tc.resType, tc.prefix)
			if tc.useUnknownID {
				resourceID = xid.New().String()
			}

			_, err := manager.SavePolicy(ctx, account.Id, userID,
				resourceSourcePolicy(account.Id, resourceID, tc.declaredType, tc.destinations), true)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantMsg)
		})
	}
}

// TestSavePolicy_RejectsResourceToResource: neither side of such a rule is a
// peer, so no client would ever install anything for it.
func TestSavePolicy_RejectsResourceToResource(t *testing.T) {
	manager, _, account, _, _, _ := setupNetworkMapTest(t)
	ctx := context.Background()

	sourceID := seedNetworkResource(t, manager, account.Id, resourceTypes.Subnet, "10.20.0.0/24")
	destID := seedNetworkResource(t, manager, account.Id, resourceTypes.Subnet, "10.30.0.0/24")

	policy := resourceSourcePolicy(account.Id, sourceID, types.ResourceTypeSubnet, nil)
	policy.Rules[0].DestinationResource = types.Resource{ID: destID, Type: types.ResourceTypeSubnet}

	_, err := manager.SavePolicy(ctx, account.Id, userID, policy, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "both source and destination")
}

// TestSavePolicy_RejectsUnknownPeerResource guards the peer-typed reference the
// same way, which was previously unvalidated.
func TestSavePolicy_RejectsUnknownPeerResource(t *testing.T) {
	manager, _, account, _, _, _ := setupNetworkMapTest(t)
	ctx := context.Background()

	require.NoError(t, manager.CreateGroup(ctx, account.Id, userID, &types.Group{ID: "groupSources", Name: "Sources"}))

	_, err := manager.SavePolicy(ctx, account.Id, userID, &types.Policy{
		AccountID: account.Id,
		Name:      "bad peer destination",
		Enabled:   true,
		Rules: []*types.PolicyRule{{
			Enabled:             true,
			Action:              types.PolicyTrafficActionAccept,
			Protocol:            types.PolicyRuleProtocolALL,
			Sources:             []string{"groupSources"},
			DestinationResource: types.Resource{ID: "no-such-peer", Type: types.ResourceTypePeer},
		}},
	}, true)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown peer resource")
}

// TestSavePolicy_ExistingShapesStillAccepted is the regression guard: the new
// validation must not start rejecting policies that saved fine before.
func TestSavePolicy_ExistingShapesStillAccepted(t *testing.T) {
	manager, _, account, peer1, _, _ := setupNetworkMapTest(t)
	ctx := context.Background()

	require.NoError(t, manager.CreateGroup(ctx, account.Id, userID, &types.Group{ID: "groupSources", Name: "Sources", Peers: []string{peer1.ID}}))
	require.NoError(t, manager.CreateGroup(ctx, account.Id, userID, &types.Group{ID: "groupTargets", Name: "Targets"}))
	resourceID := seedNetworkResource(t, manager, account.Id, resourceTypes.Subnet, "10.20.0.0/24")

	t.Run("groups only", func(t *testing.T) {
		_, err := manager.SavePolicy(ctx, account.Id, userID, &types.Policy{
			AccountID: account.Id, Name: "groups only", Enabled: true,
			Rules: []*types.PolicyRule{{
				Enabled: true, Bidirectional: true,
				Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
				Sources: []string{"groupSources"}, Destinations: []string{"groupTargets"},
			}},
		}, true)
		require.NoError(t, err)
	})

	t.Run("peers toward a resource destination", func(t *testing.T) {
		_, err := manager.SavePolicy(ctx, account.Id, userID, &types.Policy{
			AccountID: account.Id, Name: "peers to resource", Enabled: true,
			Rules: []*types.PolicyRule{{
				Enabled: true,
				Action:  types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
				Sources:             []string{"groupSources"},
				DestinationResource: types.Resource{ID: resourceID, Type: types.ResourceTypeSubnet},
			}},
		}, true)
		require.NoError(t, err)
	})

	t.Run("peer-typed source resource", func(t *testing.T) {
		_, err := manager.SavePolicy(ctx, account.Id, userID, &types.Policy{
			AccountID: account.Id, Name: "peer source", Enabled: true,
			Rules: []*types.PolicyRule{{
				Enabled: true,
				Action:  types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
				SourceResource: types.Resource{ID: peer1.ID, Type: types.ResourceTypePeer},
				Destinations:   []string{"groupTargets"},
			}},
		}, true)
		require.NoError(t, err)
	})
}

// TestSavePolicy_AcceptsSourceResourceUnderMasquerade: masquerading no longer
// rules the shape out. The destination peer is told to admit the routing peer
// instead of the prefix, and the routing peer only forwards the granted prefix,
// so the grant still means what it says.
func TestSavePolicy_AcceptsSourceResourceUnderMasquerade(t *testing.T) {
	manager, _, account, _, _, _ := setupNetworkMapTest(t)
	ctx := context.Background()

	require.NoError(t, manager.CreateGroup(ctx, account.Id, userID, &types.Group{ID: "groupTargets", Name: "Targets"}))
	resourceID := seedNetworkResourceWithRouter(t, manager, account.Id, resourceTypes.Subnet, "10.20.0.0/24", true)

	_, err := manager.SavePolicy(ctx, account.Id, userID,
		resourceSourcePolicy(account.Id, resourceID, types.ResourceTypeSubnet, []string{"groupTargets"}), true)

	require.NoError(t, err)
}

// TestSavePolicy_AcceptsSourceResourceWithoutMasquerade is the counterpart.
func TestSavePolicy_AcceptsSourceResourceWithoutMasquerade(t *testing.T) {
	manager, _, account, _, _, _ := setupNetworkMapTest(t)
	ctx := context.Background()

	require.NoError(t, manager.CreateGroup(ctx, account.Id, userID, &types.Group{ID: "groupTargets", Name: "Targets"}))
	resourceID := seedNetworkResourceWithRouter(t, manager, account.Id, resourceTypes.Subnet, "10.20.0.0/24", false)

	_, err := manager.SavePolicy(ctx, account.Id, userID,
		resourceSourcePolicy(account.Id, resourceID, types.ResourceTypeSubnet, []string{"groupTargets"}), true)

	require.NoError(t, err)
}
