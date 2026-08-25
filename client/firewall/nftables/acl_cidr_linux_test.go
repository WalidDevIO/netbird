//go:build privileged

package nftables

import (
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

const cidrTestPrefix = "10.20.0.0/24"

// newCIDRManager brings up a real nftables manager against the kernel and tears
// it down afterwards.
func newCIDRManager(t *testing.T) *Manager {
	t.Helper()

	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))
	time.Sleep(time.Second)

	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil))
		time.Sleep(time.Second)
	})

	return manager
}

// TestNftablesPeerCIDRFiltering checks the kernel accepts the prefix match and
// that the rule read back from netlink really masks the source address.
//
// A flush that returns no error is already meaningful here: nftables validates
// the expression chain, so a malformed bitwise/compare pair would be rejected
// rather than silently installed.
func TestNftablesPeerCIDRFiltering(t *testing.T) {
	manager := newCIDRManager(t)
	prefix := netip.MustParsePrefix(cidrTestPrefix)

	rules, err := manager.AddPeerCIDRFiltering(nil, prefix, fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err, "kernel rejected the prefix rule")
	require.Len(t, rules, 1)
	require.NoError(t, manager.Flush())

	testClient := &nftables.Conn{}
	installed, err := testClient.GetRules(manager.aclManager.workTable, manager.aclManager.chainInputRules)
	require.NoError(t, err)
	require.NotEmpty(t, installed)

	// ACCEPT rules are appended, so the prefix rule is the last one; the chain
	// always opens with the established/related return-traffic rule.
	last := installed[len(installed)-1]
	assertPrefixMatch(t, last.Exprs, prefix)

	t.Run("nft renders it as a prefix match", func(t *testing.T) {
		out, err := exec.Command("nft", "list", "table", "ip", tableNameNetbird).CombinedOutput()
		if err != nil {
			t.Skipf("nft binary unavailable: %v", err)
		}
		assert.Contains(t, string(out), "ip saddr "+cidrTestPrefix,
			"the kernel should render the rule as a prefix match:\n%s", out)
	})

	require.NoError(t, manager.DeletePeerRule(rules[0]))
	require.NoError(t, manager.Flush())

	remaining, err := testClient.GetRules(manager.aclManager.workTable, manager.aclManager.chainInputRules)
	require.NoError(t, err)
	for _, r := range remaining {
		assert.False(t, hasPrefixMatch(r.Exprs, prefix), "the prefix rule should be gone after delete")
	}
}

// TestNftablesPeerCIDRFilteringWithPort narrows the grant to one port, the shape
// a policy with ports produces.
func TestNftablesPeerCIDRFilteringWithPort(t *testing.T) {
	manager := newCIDRManager(t)
	prefix := netip.MustParsePrefix(cidrTestPrefix)

	rules, err := manager.AddPeerCIDRFiltering(nil, prefix, fw.ProtocolTCP, nil, &fw.Port{Values: []uint16{443}}, fw.ActionAccept)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.NoError(t, manager.Flush())

	testClient := &nftables.Conn{}
	installed, err := testClient.GetRules(manager.aclManager.workTable, manager.aclManager.chainInputRules)
	require.NoError(t, err)

	last := installed[len(installed)-1]
	assertPrefixMatch(t, last.Exprs, prefix)

	var sawPort bool
	for _, e := range last.Exprs {
		cmp, ok := e.(*expr.Cmp)
		if ok && len(cmp.Data) == 2 && cmp.Data[0] == 0x01 && cmp.Data[1] == 0xbb {
			sawPort = true
		}
	}
	assert.True(t, sawPort, "the rule should also match destination port 443")
}

// TestNftablesPeerCIDRFilteringDropIsInsertedFirst mirrors the ordering
// guarantee the address-based path has: a drop must precede the accepts.
func TestNftablesPeerCIDRFilteringDropIsInsertedFirst(t *testing.T) {
	manager := newCIDRManager(t)

	acceptPrefix := netip.MustParsePrefix(cidrTestPrefix)
	denyPrefix := netip.MustParsePrefix("10.20.0.128/25")

	_, err := manager.AddPeerCIDRFiltering(nil, acceptPrefix, fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err)
	_, err = manager.AddPeerCIDRFiltering(nil, denyPrefix, fw.ProtocolALL, nil, nil, fw.ActionDrop)
	require.NoError(t, err)
	require.NoError(t, manager.Flush())

	testClient := &nftables.Conn{}
	installed, err := testClient.GetRules(manager.aclManager.workTable, manager.aclManager.chainInputRules)
	require.NoError(t, err)

	denyIdx, acceptIdx := -1, -1
	for i, r := range installed {
		switch {
		case hasPrefixMatch(r.Exprs, denyPrefix):
			denyIdx = i
		case hasPrefixMatch(r.Exprs, acceptPrefix):
			acceptIdx = i
		}
	}

	require.NotEqual(t, -1, denyIdx, "deny rule not found")
	require.NotEqual(t, -1, acceptIdx, "accept rule not found")
	assert.Less(t, denyIdx, acceptIdx, "the deny prefix rule must be evaluated before the accept one")
}

// TestNftablesPeerCIDRFilteringHostPrefix covers a /32 host resource, whose mask
// leaves the address untouched.
func TestNftablesPeerCIDRFilteringHostPrefix(t *testing.T) {
	manager := newCIDRManager(t)
	prefix := netip.MustParsePrefix("10.20.0.11/32")

	rules, err := manager.AddPeerCIDRFiltering(nil, prefix, fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.NoError(t, manager.Flush())

	testClient := &nftables.Conn{}
	installed, err := testClient.GetRules(manager.aclManager.workTable, manager.aclManager.chainInputRules)
	require.NoError(t, err)
	assertPrefixMatch(t, installed[len(installed)-1].Exprs, prefix)
}

// TestNftablesPeerCIDRFilteringRejectsV6WithoutIPv6 checks the manager refuses a
// v6 prefix when the v6 firewall was never initialized, instead of installing it
// into the v4 table.
func TestNftablesPeerCIDRFilteringRejectsV6WithoutIPv6(t *testing.T) {
	manager := newCIDRManager(t)

	_, err := manager.AddPeerCIDRFiltering(nil, netip.MustParsePrefix("fd11:2233::/64"), fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.ErrorIs(t, err, fw.ErrIPv6NotInitialized)
}

// TestNftablesPeerCIDRFilteringIPv6 exercises the v6 ACL manager, which is a
// separate table and a different header layout from the v4 path.
func TestNftablesPeerCIDRFilteringIPv6(t *testing.T) {
	ifaceMockV6 := &iFaceMock{
		NameFunc: func() string { return "wt-test" },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.96.0.1"),
				Network: netip.MustParsePrefix("100.96.0.0/16"),
				IPv6:    netip.MustParseAddr("fd00::1"),
				IPv6Net: netip.MustParsePrefix("fd00::/64"),
			}
		},
	}

	manager, err := Create(ifaceMockV6, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))
	time.Sleep(time.Second)
	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil))
		time.Sleep(time.Second)
	})

	prefix := netip.MustParsePrefix("fd11:2233::/64")
	rules, err := manager.AddPeerCIDRFiltering(nil, prefix, fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err, "kernel rejected the v6 prefix rule")
	require.Len(t, rules, 1)
	require.NoError(t, manager.Flush())

	testClient := &nftables.Conn{}
	installed, err := testClient.GetRules(manager.aclManager6.workTable, manager.aclManager6.chainInputRules)
	require.NoError(t, err)
	require.NotEmpty(t, installed, "the v6 rule should live in the v6 table")
	assertPrefixMatch(t, installed[len(installed)-1].Exprs, prefix)

	// The v4 table must stay untouched: a v6 grant is not a v4 grant.
	v4Rules, err := testClient.GetRules(manager.aclManager.workTable, manager.aclManager.chainInputRules)
	require.NoError(t, err)
	for _, r := range v4Rules {
		assert.False(t, hasPrefixMatch(r.Exprs, prefix), "a v6 prefix must not appear in the v4 table")
	}

	require.NoError(t, manager.DeletePeerRule(rules[0]))
	require.NoError(t, manager.Flush())
}

// TestNftablesPeerCIDRFilteringInvalidPrefix asserts a zero prefix is refused.
func TestNftablesPeerCIDRFilteringInvalidPrefix(t *testing.T) {
	manager := newCIDRManager(t)

	_, err := manager.AddPeerCIDRFiltering(nil, netip.Prefix{}, fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.Error(t, err)
}

// assertPrefixMatch fails the test unless the expressions mask the source
// address down to prefix and compare it against the network address.
func assertPrefixMatch(t *testing.T, exprs []expr.Any, prefix netip.Prefix) {
	t.Helper()

	if hasPrefixMatch(exprs, prefix) {
		return
	}

	var rendered []string
	for _, e := range exprs {
		rendered = append(rendered, describeExpr(e))
	}
	t.Fatalf("expected a source-prefix match for %s, got: %s", prefix, strings.Join(rendered, " | "))
}

// hasPrefixMatch reports whether the expression list loads the source address,
// masks it with the prefix's netmask, and compares it to the network address.
func hasPrefixMatch(exprs []expr.Any, prefix netip.Prefix) bool {
	masked := prefix.Masked()
	wantNetwork := masked.Addr().AsSlice()
	wantMask := prefixMaskFor(masked)

	for i := 0; i+2 < len(exprs); i++ {
		payload, ok := exprs[i].(*expr.Payload)
		if !ok || payload.Base != expr.PayloadBaseNetworkHeader {
			continue
		}
		if int(payload.Len) != len(wantNetwork) {
			continue
		}

		bitwise, ok := exprs[i+1].(*expr.Bitwise)
		if !ok || !bytesEqual(bitwise.Mask, wantMask) {
			continue
		}

		cmp, ok := exprs[i+2].(*expr.Cmp)
		if !ok || cmp.Op != expr.CmpOpEq || !bytesEqual(cmp.Data, wantNetwork) {
			continue
		}
		return true
	}
	return false
}

func prefixMaskFor(prefix netip.Prefix) []byte {
	total := 32
	if prefix.Addr().Is6() {
		total = 128
	}
	mask := make([]byte, total/8)
	bits := prefix.Bits()
	for i := range mask {
		switch {
		case bits >= 8:
			mask[i] = 0xff
			bits -= 8
		case bits > 0:
			mask[i] = byte(0xff << (8 - bits))
			bits = 0
		}
	}
	return mask
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func describeExpr(e expr.Any) string {
	switch v := e.(type) {
	case *expr.Payload:
		return "payload(base=" + itoa(int(v.Base)) + ",off=" + itoa(int(v.Offset)) + ",len=" + itoa(int(v.Len)) + ")"
	case *expr.Bitwise:
		return "bitwise(mask=" + hexBytes(v.Mask) + ")"
	case *expr.Cmp:
		return "cmp(op=" + itoa(int(v.Op)) + ",data=" + hexBytes(v.Data) + ")"
	case *expr.Verdict:
		return "verdict(" + itoa(int(v.Kind)) + ")"
	default:
		return "other"
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf []byte
	for v > 0 {
		buf = append([]byte{byte('0' + v%10)}, buf...)
		v /= 10
	}
	if neg {
		return "-" + string(buf)
	}
	return string(buf)
}

func hexBytes(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, digits[v>>4], digits[v&0x0f])
	}
	return string(out)
}
