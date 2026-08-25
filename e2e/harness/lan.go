//go:build e2e

package harness

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	dockernetwork "github.com/docker/docker/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/network"
)

// lanHostImage is a plain distro image: the point of a LAN host is that it runs
// no NetBird agent, so whatever it needs must come from the base image.
const lanHostImage = "alpine:3.24"

// Network returns the shared docker network the combined server and its clients
// sit on. Suites that attach extra containers to the overlay side need it.
func (c *Combined) Network() *testcontainers.DockerNetwork {
	return c.network
}

// NewLANNetwork creates an isolated docker network standing in for a branch LAN
// behind a routing peer, and reports the subnet it was given so the caller can
// name it in a NetBird network resource.
//
// The subnet is left to Docker rather than pinned: a run that dies before
// teardown leaves its network behind, and a pinned subnet then makes every
// later run fail with a pool overlap before any test gets to execute.
func NewLANNetwork(ctx context.Context, name string) (*testcontainers.DockerNetwork, string, error) {
	net, err := network.New(ctx,
		network.WithDriver("bridge"),
		network.WithLabels(map[string]string{"nb-e2e-lan": name}),
	)
	if err != nil {
		return nil, "", fmt.Errorf("create LAN network %s: %w", name, err)
	}

	subnet, err := networkSubnet(ctx, net)
	if err != nil {
		_ = net.Remove(ctx)
		return nil, "", err
	}

	return net, subnet, nil
}

// networkSubnet reads back the IPv4 subnet Docker assigned to a network.
func networkSubnet(ctx context.Context, net *testcontainers.DockerNetwork) (string, error) {
	provider, err := testcontainers.NewDockerProvider()
	if err != nil {
		return "", fmt.Errorf("docker provider: %w", err)
	}
	defer func() { _ = provider.Close() }()

	inspect, err := provider.Client().NetworkInspect(ctx, net.ID, dockernetwork.InspectOptions{})
	if err != nil {
		return "", fmt.Errorf("inspect network %s: %w", net.Name, err)
	}

	for _, cfg := range inspect.IPAM.Config {
		if cfg.Subnet != "" && !strings.Contains(cfg.Subnet, ":") {
			return cfg.Subnet, nil
		}
	}
	return "", fmt.Errorf("network %s has no IPv4 subnet", net.Name)
}

// LANHost is an agentless container on a LAN network — the "clientless device"
// the resource-source policies exist for.
type LANHost struct {
	container testcontainers.Container
	// IP is the host's address on the LAN network.
	IP string
}

// StartLANHost boots a plain container on lanNet and routes overlayCIDR through
// gatewayIP, which is the routing peer's address on that LAN. Nothing NetBird
// runs inside it: reaching a peer has to work purely through the routing peer.
func StartLANHost(ctx context.Context, lanNet *testcontainers.DockerNetwork, name, overlayCIDR, gatewayIP string) (*LANHost, error) {
	req := testcontainers.ContainerRequest{
		Image:          lanHostImage,
		Hostname:       name,
		Networks:       []string{lanNet.Name},
		NetworkAliases: map[string][]string{lanNet.Name: {name}},
		Cmd:            []string{"sleep", "infinity"},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.CapAdd = append(hc.CapAdd, "NET_ADMIN")
		},
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("start LAN host %s: %w", name, err)
	}

	host := &LANHost{container: ctr}

	// Busybox nc is enough to open and accept TCP connections; iproute2 gives a
	// route command that reports failures clearly.
	if code, out, err := host.Exec(ctx, "apk", "add", "--no-cache", "iproute2"); err != nil || code != 0 {
		return nil, fmt.Errorf("install iproute2 on %s: %v (exit %d): %s", name, err, code, out)
	}

	if code, out, err := host.Exec(ctx, "ip", "route", "replace", overlayCIDR, "via", gatewayIP); err != nil || code != 0 {
		return nil, fmt.Errorf("route %s via %s on %s: %v (exit %d): %s", overlayCIDR, gatewayIP, name, err, code, out)
	}

	ip, err := containerIPOnNetwork(ctx, ctr, lanNet.Name)
	if err != nil {
		return nil, err
	}
	host.IP = ip

	return host, nil
}

// Exec runs a command inside the LAN host and returns its exit code and output.
func (h *LANHost) Exec(ctx context.Context, cmd ...string) (int, string, error) {
	return execInContainer(ctx, h.container, cmd...)
}

// Terminate removes the container.
func (h *LANHost) Terminate(ctx context.Context) error {
	return h.container.Terminate(ctx)
}

// Exec runs a command inside the client container and returns its exit code and
// output, for assertions the CLI does not cover.
func (cl *Client) Exec(ctx context.Context, cmd ...string) (int, string, error) {
	return execInContainer(ctx, cl.container, cmd...)
}

// IPOnNetwork returns the client's address on the named docker network. A
// routing peer has one per network it bridges, and the LAN-side one is what its
// LAN hosts use as their gateway.
func (cl *Client) IPOnNetwork(ctx context.Context, networkName string) (string, error) {
	return containerIPOnNetwork(ctx, cl.container, networkName)
}

func execInContainer(ctx context.Context, ctr testcontainers.Container, cmd ...string) (int, string, error) {
	code, reader, err := ctr.Exec(ctx, cmd, tcexec.Multiplexed())
	if err != nil {
		return code, "", err
	}
	out, _ := io.ReadAll(reader)
	return code, string(out), nil
}

func containerIPOnNetwork(ctx context.Context, ctr testcontainers.Container, networkName string) (string, error) {
	inspect, err := ctr.Inspect(ctx)
	if err != nil {
		return "", fmt.Errorf("inspect container: %w", err)
	}
	settings, ok := inspect.NetworkSettings.Networks[networkName]
	if !ok || settings.IPAddress == "" {
		var have []string
		for name := range inspect.NetworkSettings.Networks {
			have = append(have, name)
		}
		return "", fmt.Errorf("container has no address on %s (attached to %s)", networkName, strings.Join(have, ", "))
	}
	return settings.IPAddress, nil
}

// WaitForRoute polls until the client's routing table covers dst, which is how a
// test knows management has pushed a network-resource route and the agent has
// installed it.
func (cl *Client) WaitForRoute(ctx context.Context, dst string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		_, out, err := cl.Exec(ctx, "ip", "route", "get", dst)
		if err == nil {
			last = out
			// A route through the overlay interface is the one we are waiting
			// for; the container's default route would answer otherwise.
			if strings.Contains(out, "dev wt") || strings.Contains(out, "dev nb") || strings.Contains(out, "dev utun") {
				return nil
			}
		}
		if !waitABit(ctx, 2*time.Second) {
			break
		}
	}
	return fmt.Errorf("timed out waiting for a route to %s; last: %s", dst, last)
}

func waitABit(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
