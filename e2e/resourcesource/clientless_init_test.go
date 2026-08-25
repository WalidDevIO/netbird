//go:build e2e

package resourcesource

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// probeResult is what one LAN-to-peer connection attempt observed.
type probeResult struct {
	// reached is true when the LAN host completed a TCP connection.
	reached bool
	// payload is what the listener inside the target peer received.
	payload string
	// observedPeers holds the established connections the target saw on the
	// probe port, as `ss` reported them. This is where the source address the
	// peer actually sees shows up.
	observedPeers string
	// transcript is the raw command output, for failure messages.
	transcript string
}

// probeFromLAN opens a listener inside the target peer, dials it from the
// agentless LAN host, and records both whether the connection landed and which
// source address the peer saw it come from.
func probeFromLAN(t *testing.T, ctx context.Context) probeResult {
	t.Helper()

	const marker = "hello-from-lan"

	var (
		wg      sync.WaitGroup
		dialOut string
		result  probeResult
	)

	// Listener: writes what it receives, then exits. `timeout` bounds it so a
	// blocked probe cannot hang the suite.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, _ = target.Exec(ctx, "sh", "-c",
			fmt.Sprintf("rm -f /tmp/probe-in; timeout 25 nc -l -p %s > /tmp/probe-in 2>/dev/null; true", probePort))
	}()

	// Watcher: samples the established connections on the probe port while the
	// dial is in flight.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, out, _ := target.Exec(ctx, "sh", "-c",
			fmt.Sprintf("rm -f /tmp/probe-ss; for i in $(seq 1 20); do ss -tn 2>/dev/null | grep ':%s' >> /tmp/probe-ss; sleep 1; done; cat /tmp/probe-ss 2>/dev/null || true", probePort))
		result.observedPeers = out
	}()

	// Let the listener bind before dialing.
	time.Sleep(3 * time.Second)

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, out, _ := lan.Exec(ctx, "sh", "-c",
			fmt.Sprintf("(echo %s; sleep 6) | nc -w 8 %s %s && echo REACHED || echo BLOCKED", marker, env.targetOverlay, probePort))
		dialOut = out
	}()

	wg.Wait()

	_, payload, _ := target.Exec(ctx, "sh", "-c", "cat /tmp/probe-in 2>/dev/null || true")

	result.reached = strings.Contains(dialOut, "REACHED") || strings.Contains(payload, marker)
	result.payload = payload
	result.transcript = fmt.Sprintf("dial=%q payload=%q ss=%q", strings.TrimSpace(dialOut),
		strings.TrimSpace(payload), strings.TrimSpace(result.observedPeers))

	return result
}

// routesViaOverlay reports whether the target peer currently resolves dst
// through the NetBird interface.
//
// The agent installs its routes in a policy-routing table rather than the main
// one, so `ip route show` would come back empty even with the route in place.
// `ip route get` applies the rules and answers with the route the kernel would
// actually use.
func routesViaOverlay(ctx context.Context, dst string) (bool, string) {
	_, out, err := target.Exec(ctx, "ip", "route", "get", dst)
	if err != nil {
		return false, fmt.Sprintf("ip route get failed: %v", err)
	}
	return strings.Contains(out, "dev "+overlayIface), strings.TrimSpace(out)
}

// routeDiagnostics dumps everything needed to explain a routing assertion.
func routeDiagnostics(ctx context.Context) string {
	_, main, _ := target.Exec(ctx, "ip", "route")
	_, nbTable, _ := target.Exec(ctx, "ip", "route", "show", "table", netbirdRouteTable)
	_, rules, _ := target.Exec(ctx, "ip", "rule")
	return fmt.Sprintf("main table:\n%s\nnetbird table %s:\n%s\nrules:\n%s", main, netbirdRouteTable, nbTable, rules)
}

// waitForPolicyToApply gives management and the agents time to converge on the
// new rule set. Both peers pull a fresh network map on a policy change, so this
// is propagation delay, not a race being papered over.
func waitForPolicyToApply(t *testing.T, ctx context.Context) {
	t.Helper()

	if !waitForCondition(ctx, 90*time.Second, func() bool {
		via, _ := routesViaOverlay(ctx, env.lanHostAddress)
		return via
	}) {
		t.Fatalf("target never installed an overlay route to %s (%s)\n%s",
			env.lanHostAddress, lanSubnet, routeDiagnostics(ctx))
	}

	// The firewall rule rides the same network map as the route, but the agent
	// applies them in separate steps.
	time.Sleep(5 * time.Second)
}

// TestLANHostBlockedWithoutPolicy is the baseline. Without a policy naming the
// LAN as a source, the peer must refuse traffic from it — otherwise every later
// assertion proves nothing.
func TestLANHostBlockedWithoutPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	result := probeFromLAN(t, ctx)

	assert.False(t, result.reached,
		"an agentless LAN host must not reach a peer with no policy granting it: %s", result.transcript)
}

// TestLANHostReachesPeerWithResourceSourcePolicy is the feature: a policy whose
// source is the branch-LAN resource lets the agentless host open a connection to
// the peer, with no agent on the host and no masquerading on the routing peer.
func TestLANHostReachesPeerWithResourceSourcePolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	createResourceSourcePolicy(t, ctx, false)
	waitForPolicyToApply(t, ctx)

	result := probeFromLAN(t, ctx)

	require.True(t, result.reached,
		"the LAN host should reach the peer once the resource-source policy exists: %s\ntarget logs:\n%s",
		result.transcript, target.Logs(ctx))
	assert.Contains(t, result.payload, "hello-from-lan",
		"the peer should have received the payload the LAN host sent")
}

// TestTargetPeerSeesRealSourceAddress is the traceability claim that motivates
// the feature: the peer sees the agentless host's own address, not the routing
// peer's overlay address that a SNAT would have substituted.
func TestTargetPeerSeesRealSourceAddress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	createResourceSourcePolicy(t, ctx, false)
	waitForPolicyToApply(t, ctx)

	result := probeFromLAN(t, ctx)
	require.True(t, result.reached, "connection did not land: %s", result.transcript)

	require.NotEmpty(t, result.observedPeers,
		"no established connection observed on port %s: %s", probePort, result.transcript)

	assert.Contains(t, result.observedPeers, env.lanHostAddress,
		"the peer must see the LAN host's own address (%s), not a masqueraded one: %s",
		env.lanHostAddress, result.transcript)

	// The routing peer's overlay address appearing as the source would mean the
	// packet was SNATed on the way in, which is exactly what this feature exists
	// to avoid.
	routerOverlay := peerOverlayAddress(t, ctx, routerName)
	if routerOverlay != "" {
		assert.NotContains(t, result.observedPeers, routerOverlay,
			"the connection was masqueraded to the routing peer's address: %s", result.transcript)
	}
}

// TestTargetPeerGetsResourceRoute checks the routing half of the feature: the
// destination peer must learn a route back to the LAN, or its replies never
// return through the routing peer.
func TestTargetPeerGetsResourceRoute(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	viaOverlayBefore, beforeRoute := routesViaOverlay(ctx, env.lanHostAddress)
	require.False(t, viaOverlayBefore,
		"the target should not route %s over the overlay before the policy exists: %s",
		lanSubnet, beforeRoute)

	createResourceSourcePolicy(t, ctx, false)
	waitForPolicyToApply(t, ctx)

	viaOverlayAfter, afterRoute := routesViaOverlay(ctx, env.lanHostAddress)
	require.True(t, viaOverlayAfter,
		"the target should route %s over the overlay once the policy exists: %s\n%s",
		lanSubnet, afterRoute, routeDiagnostics(ctx))

	_, nbTable, _ := target.Exec(ctx, "ip", "route", "show", "table", netbirdRouteTable)
	assert.Contains(t, nbTable, lanSubnet,
		"the resource prefix should appear in the agent's routing table:\n%s", nbTable)
}

// TestTargetPeerInstallsPrefixFirewallRule inspects the peer's firewall directly,
// so a pass in the traffic tests cannot be explained by a permissive default.
func TestTargetPeerInstallsPrefixFirewallRule(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	createResourceSourcePolicy(t, ctx, false)
	waitForPolicyToApply(t, ctx)

	dump := firewallDump(t, ctx)
	assert.Contains(t, dump, lanSubnet,
		"the peer's firewall should carry a rule matching the LAN prefix:\n%s", dump)
}

// TestPolicyRevocationRemovesAccess closes the loop: deleting the policy has to
// take the access away again, not leave a rule behind.
func TestPolicyRevocationRemovesAccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	policyID := createResourceSourcePolicy(t, ctx, false)
	waitForPolicyToApply(t, ctx)

	granted := probeFromLAN(t, ctx)
	require.True(t, granted.reached, "precondition: access should be granted first: %s", granted.transcript)

	require.NoError(t, srv.API().Policies.Delete(ctx, policyID))

	// Wait for the route to disappear, which travels with the same update as
	// the firewall rule.
	if !waitForCondition(ctx, 90*time.Second, func() bool {
		via, _ := routesViaOverlay(ctx, env.lanHostAddress)
		return !via
	}) {
		t.Logf("route to the LAN still present after revocation; continuing to the traffic assertion\n%s",
			routeDiagnostics(ctx))
	}
	time.Sleep(5 * time.Second)

	revoked := probeFromLAN(t, ctx)
	assert.False(t, revoked.reached,
		"revoking the policy must take the access away: %s", revoked.transcript)
}

// TestBidirectionalPolicyAllowsPeerToReachLAN covers the other half of the
// feature. A one-way rule lets the LAN initiate and nothing more; marking it
// bidirectional additionally lets the peer open connections into the LAN, which
// needs a forward rule on the routing peer rather than an ACL on the peer.
func TestBidirectionalPolicyAllowsPeerToReachLAN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	t.Run("one-way policy does not let the peer reach the LAN", func(t *testing.T) {
		createResourceSourcePolicy(t, ctx, false)
		waitForPolicyToApply(t, ctx)

		reached, transcript := dialLANFromPeer(t, ctx)
		assert.False(t, reached,
			"a one-way resource-source policy grants no peer-to-LAN traffic: %s", transcript)
	})

	t.Run("bidirectional policy lets the peer reach the LAN", func(t *testing.T) {
		createResourceSourcePolicy(t, ctx, true)
		waitForPolicyToApply(t, ctx)

		reached, transcript := dialLANFromPeer(t, ctx)
		require.True(t, reached,
			"a bidirectional policy should let the peer reach the LAN host: %s\nrouter logs:\n%s",
			transcript, router.Logs(ctx))
	})
}

// dialLANFromPeer opens a listener on the agentless LAN host and connects to it
// from the target peer, which is the peer-to-resource direction.
func dialLANFromPeer(t *testing.T, ctx context.Context) (bool, string) {
	t.Helper()

	const marker = "hello-from-peer"

	var (
		wg      sync.WaitGroup
		dialOut string
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, _ = lan.Exec(ctx, "sh", "-c",
			fmt.Sprintf("rm -f /tmp/peer-in; timeout 25 nc -l -p %s > /tmp/peer-in 2>/dev/null; true", probePort))
	}()

	time.Sleep(3 * time.Second)

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, out, _ := target.Exec(ctx, "sh", "-c",
			fmt.Sprintf("(echo %s; sleep 4) | nc -w 8 %s %s && echo REACHED || echo BLOCKED",
				marker, env.lanHostAddress, probePort))
		dialOut = out
	}()

	wg.Wait()

	_, payload, _ := lan.Exec(context.Background(), "sh", "-c", "cat /tmp/peer-in 2>/dev/null || true")
	reached := strings.Contains(dialOut, "REACHED") || strings.Contains(payload, marker)

	return reached, fmt.Sprintf("dial=%q payload=%q", strings.TrimSpace(dialOut), strings.TrimSpace(payload))
}

// peerOverlayAddress looks up a peer's overlay address by hostname.
func peerOverlayAddress(t *testing.T, ctx context.Context, hostname string) string {
	t.Helper()

	peers, err := srv.API().Peers.List(ctx)
	if err != nil {
		t.Logf("list peers: %v", err)
		return ""
	}
	for i := range peers {
		if peers[i].Hostname == hostname {
			return peers[i].Ip
		}
	}
	return ""
}

// firewallDump returns whichever backend's ruleset the peer actually programmed.
func firewallDump(t *testing.T, ctx context.Context) string {
	t.Helper()

	var b strings.Builder
	for _, cmd := range [][]string{
		{"sh", "-c", "nft list ruleset 2>/dev/null || true"},
		{"sh", "-c", "iptables-save 2>/dev/null || true"},
	} {
		_, out, err := target.Exec(ctx, cmd...)
		if err == nil {
			b.WriteString(out)
			b.WriteString("\n")
		}
	}
	return b.String()
}
