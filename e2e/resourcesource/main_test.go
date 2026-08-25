//go:build e2e

// Package resourcesource holds the end-to-end suite for network-resource-sourced
// ACLs: an agentless host on a branch LAN initiating a connection toward a
// NetBird peer, through a routing peer that does not masquerade.
//
// The topology built by TestMain:
//
//	docker net "nb-e2e"                         docker net lanSubnet
//	┌──────────┐  ┌────────┐  ┌────────┐        ┌──────────────┐
//	│ combined │──│ target │  │ router │────────│   lanhost    │
//	│ mgmt+sig │  │  peer  │  │  peer  │        │ (no NetBird) │
//	└──────────┘  └────────┘  └────────┘        └──────────────┘
//
// lanhost routes the overlay range through router's LAN address. Nothing else
// connects the two sides, so anything the suite observes on target arrived
// through the routing peer.
package resourcesource

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	// overlayCIDR is the NetBird address range the LAN host routes through the
	// routing peer.
	overlayCIDR = "100.64.0.0/10"

	targetName = "target"
	routerName = "router"
	lanHost    = "lanhost"

	// probePort is the port the suite listens on inside the target peer.
	probePort = "8443"

	// overlayIface is the agent's interface name on Linux, and
	// netbirdRouteTable the policy-routing table it installs routes into.
	overlayIface      = "wt0"
	netbirdRouteTable = "7120"

	setupTimeout = 20 * time.Minute
)

var (
	srv    *harness.Combined
	lanNet *testcontainers.DockerNetwork
	target *harness.Client
	router *harness.Client
	lan    *harness.LANHost
	env    testEnv

	// lanSubnet is the branch LAN Docker handed us, and the address of the
	// NetBird network resource the policies name as their source.
	lanSubnet string
)

// testEnv carries the identifiers the tests need to drive the API.
type testEnv struct {
	targetPeerID   string
	routerPeerID   string
	targetOverlay  string
	networkID      string
	resourceID     string
	targetGroupID  string
	lanHostAddress string
}

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel()

	code, err := setup(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: setup: %v\n", err)
		teardown()
		return code
	}
	defer teardown()

	return m.Run()
}

func setup(ctx context.Context) (int, error) {
	var err error
	if srv, err = harness.StartCombined(ctx); err != nil {
		return 1, fmt.Errorf("start combined server: %w", err)
	}
	if _, err = srv.Bootstrap(ctx); err != nil {
		return 1, fmt.Errorf("bootstrap admin PAT: %w", err)
	}

	if lanNet, lanSubnet, err = harness.NewLANNetwork(ctx, "branch-lan"); err != nil {
		return 1, fmt.Errorf("create LAN network: %w", err)
	}

	setupKey, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-resource-source",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{},
	})
	if err != nil {
		return 1, fmt.Errorf("create setup key: %w", err)
	}

	if target, err = harness.StartClient(ctx, srv, setupKey.Key, harness.WithClientName(targetName)); err != nil {
		return 1, fmt.Errorf("start target client: %w", err)
	}
	// The routing peer forwards LAN traffic into the overlay, which the kernel
	// only does with forwarding on.
	if router, err = harness.StartClient(ctx, srv, setupKey.Key,
		harness.WithClientName(routerName), harness.WithExtraNetwork(lanNet),
		harness.WithIPForwarding()); err != nil {
		return 1, fmt.Errorf("start router client: %w", err)
	}

	if err := target.WaitConnected(ctx, 3*time.Minute); err != nil {
		return 1, fmt.Errorf("target never connected: %w\n%s", err, target.Logs(ctx))
	}
	if err := router.WaitConnected(ctx, 3*time.Minute); err != nil {
		return 1, fmt.Errorf("router never connected: %w\n%s", err, router.Logs(ctx))
	}

	routerLANIP, err := router.IPOnNetwork(ctx, lanNet.Name)
	if err != nil {
		return 1, fmt.Errorf("router LAN address: %w", err)
	}

	if lan, err = harness.StartLANHost(ctx, lanNet, lanHost, overlayCIDR, routerLANIP); err != nil {
		return 1, fmt.Errorf("start LAN host: %w", err)
	}
	env.lanHostAddress = lan.IP

	if err := resolvePeers(ctx); err != nil {
		return 1, err
	}
	if err := createNetworkAndResource(ctx); err != nil {
		return 1, err
	}

	return 0, nil
}

// resolvePeers records the two peers' IDs and the target's overlay address.
func resolvePeers(ctx context.Context) error {
	peers, err := srv.API().Peers.List(ctx)
	if err != nil {
		return fmt.Errorf("list peers: %w", err)
	}

	for i := range peers {
		switch peers[i].Hostname {
		case targetName:
			env.targetPeerID = peers[i].Id
			env.targetOverlay = peers[i].Ip
		case routerName:
			env.routerPeerID = peers[i].Id
		}
	}

	if env.targetPeerID == "" || env.routerPeerID == "" {
		return fmt.Errorf("peers not registered: target=%q router=%q", env.targetPeerID, env.routerPeerID)
	}
	if env.targetOverlay == "" {
		return fmt.Errorf("target peer has no overlay address")
	}

	group, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{
		Name:  "targets",
		Peers: &[]string{env.targetPeerID},
	})
	if err != nil {
		return fmt.Errorf("create target group: %w", err)
	}
	env.targetGroupID = group.Id

	return nil
}

// createNetworkAndResource models the branch LAN in NetBird: a network, the
// routing peer that serves it WITHOUT masquerading, and the subnet resource.
func createNetworkAndResource(ctx context.Context) error {
	network, err := srv.API().Networks.Create(ctx, api.PostApiNetworksJSONRequestBody{Name: "branch"})
	if err != nil {
		return fmt.Errorf("create network: %w", err)
	}
	env.networkID = network.Id

	peerID := env.routerPeerID
	if _, err := srv.API().Networks.Routers(network.Id).Create(ctx, api.PostApiNetworksNetworkIdRoutersJSONRequestBody{
		Peer:    &peerID,
		Enabled: true,
		Metric:  9999,
		// The whole point: without SNAT the peer sees the LAN host's own
		// address, which is what the prefix-sourced ACL has to admit.
		Masquerade: false,
	}); err != nil {
		return fmt.Errorf("create network router: %w", err)
	}

	resource, err := srv.API().Networks.Resources(network.Id).Create(ctx, api.PostApiNetworksNetworkIdResourcesJSONRequestBody{
		Name:    "branch-lan",
		Address: lanSubnet,
		Enabled: true,
		Groups:  []string{},
	})
	if err != nil {
		return fmt.Errorf("create network resource: %w", err)
	}
	env.resourceID = resource.Id

	return nil
}

func teardown() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if lan != nil {
		_ = lan.Terminate(ctx)
	}
	if router != nil {
		_ = router.Terminate(ctx)
	}
	if target != nil {
		_ = target.Terminate(ctx)
	}
	if lanNet != nil {
		_ = lanNet.Remove(ctx)
	}
	if srv != nil {
		_ = srv.Terminate(ctx)
	}
}

// createResourceSourcePolicy creates the policy under test and returns a
// cleanup that removes it, so each test starts from no access.
func createResourceSourcePolicy(t *testing.T, ctx context.Context, bidirectional bool) string {
	t.Helper()

	resourceID := env.resourceID
	policy, err := srv.API().Policies.Create(ctx, api.PostApiPoliciesJSONRequestBody{
		Name:    "lan initiates toward target",
		Enabled: true,
		Rules: []api.PolicyRuleUpdate{{
			Name:          "lan -> target",
			Enabled:       true,
			Action:        api.PolicyRuleUpdateActionAccept,
			Protocol:      api.PolicyRuleUpdateProtocolAll,
			Bidirectional: bidirectional,
			SourceResource: &api.Resource{
				Id:   resourceID,
				Type: api.ResourceTypeSubnet,
			},
			Destinations: &[]string{env.targetGroupID},
		}},
	})
	if err != nil {
		t.Fatalf("create resource-source policy: %v", err)
	}

	if policy.Id == nil {
		t.Fatal("management returned a policy without an id")
	}
	policyID := *policy.Id

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := srv.API().Policies.Delete(cleanupCtx, policyID); err != nil {
			t.Logf("delete policy %s: %v", policyID, err)
		}
		// Give the agents a moment to apply the revocation before the next test
		// asserts on a clean baseline.
		time.Sleep(5 * time.Second)
	})

	return policyID
}

// waitForCondition polls fn until it returns true or the window elapses.
func waitForCondition(ctx context.Context, window time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		timer := time.NewTimer(3 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
	return false
}
