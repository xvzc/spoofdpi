package route

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifyEgress(t *testing.T) {
	en0 := LinkInfo{Index: 4, Name: "en0", Kind: LinkPhysical, Detail: "IFT_ETHER"}
	en1 := LinkInfo{Index: 5, Name: "en1", Kind: LinkPhysical, Detail: "IFT_ETHER"}
	utun := LinkInfo{Index: 20, Name: "utun4", Kind: LinkVPN, Detail: "IFT_OTHER p2p"}
	wg := LinkInfo{Index: 7, Name: "wg0", Kind: LinkVPN, Detail: "kind=wireguard"}
	ppp := LinkInfo{Index: 8, Name: "ppp0", Kind: LinkPPP, Detail: "ARPHRD_PPP"}
	sit := LinkInfo{Index: 9, Name: "sit1", Kind: LinkIPTunnel, Detail: "kind=sit"}
	unk := LinkInfo{Index: 10, Name: "x0", Kind: LinkUnknown, Detail: "kind=dummy"}
	lo := LinkInfo{Index: 1, Name: "lo0", Kind: LinkLoopback, Detail: "IFT_LOOP"}

	tcs := []struct {
		name       string
		link       LinkInfo
		others     []LinkInfo
		want       EgressClass
		wantReason string
	}{
		{
			name:       "physical alone is direct",
			link:       en0,
			others:     []LinkInfo{en0},
			want:       EgressDirect,
			wantReason: "physical link en0 (IFT_ETHER)",
		},
		{
			name:   "physical next to another physical default is direct",
			link:   en0,
			others: []LinkInfo{en0, en1},
			want:   EgressDirect,
		},
		{
			name:       "strong vpn next to a physical default is vpn",
			link:       utun,
			others:     []LinkInfo{utun, en0},
			want:       EgressVPN,
			wantReason: "VPN link utun4 (IFT_OTHER p2p)",
		},
		{
			name: "strong vpn alone is vpn",
			link: wg,
			want: EgressVPN,
		},
		{
			name:   "ppp next to a physical default is vpn",
			link:   ppp,
			others: []LinkInfo{ppp, en0},
			want:   EgressVPN,
			wantReason: "ppp link ppp0 (ARPHRD_PPP) carries the traffic " +
				"while physical link en0 (IFT_ETHER) also has a default route",
		},
		{
			name:       "ppp alone is the uplink",
			link:       ppp,
			others:     []LinkInfo{ppp},
			want:       EgressUplink,
			wantReason: "ppp link ppp0 (ARPHRD_PPP) is the only default route",
		},
		{
			name:   "ip tunnel next to a physical default is vpn",
			link:   sit,
			others: []LinkInfo{en0},
			want:   EgressVPN,
		},
		{
			name: "ip tunnel alone is the uplink",
			link: sit,
			want: EgressUplink,
		},
		{
			name:   "ambiguous link next to non-physical defaults is the uplink",
			link:   ppp,
			others: []LinkInfo{ppp, utun, unk, lo},
			want:   EgressUplink,
		},
		{
			name: "the egress itself listed as physical does not count as another",
			link: LinkInfo{Index: 8, Name: "ppp0", Kind: LinkPPP},
			others: []LinkInfo{
				{Index: 8, Name: "ppp0", Kind: LinkPhysical},
			},
			want: EgressUplink,
		},
		{
			name:   "unknown next to a physical default is vpn",
			link:   unk,
			others: []LinkInfo{unk, en0},
			want:   EgressVPN,
		},
		{
			name:       "unknown alone stays unknown",
			link:       unk,
			others:     []LinkInfo{unk},
			want:       EgressUnknown,
			wantReason: "cannot tell whether x0 (kind=dummy) is a VPN",
		},
		{
			name:       "unknown without a name or detail",
			link:       LinkInfo{Index: 12},
			want:       EgressUnknown,
			wantReason: "cannot tell whether #12 is a VPN",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := ClassifyEgress(tc.link, tc.others)
			assert.Equal(t, tc.want, got)
			if tc.wantReason != "" {
				assert.Equal(t, tc.wantReason, reason)
			} else {
				assert.NotEmpty(t, reason)
			}
		})
	}
}

func TestClassifyEgress_Loopback(t *testing.T) {
	lo := LinkInfo{Index: 1, Name: "lo0", Kind: LinkLoopback, Detail: "IFT_LOOP"}
	en0 := LinkInfo{Index: 4, Name: "en0", Kind: LinkPhysical}

	for _, others := range [][]LinkInfo{nil, {en0}} {
		got, reason := ClassifyEgress(lo, others)
		assert.Equal(t, EgressUnknown, got)
		assert.Equal(t, "loopback link lo0 (IFT_LOOP)", reason)
	}
}

func TestLinkKind_String(t *testing.T) {
	assert.Equal(t, "unknown", LinkUnknown.String())
	assert.Equal(t, "physical", LinkPhysical.String())
	assert.Equal(t, "ppp", LinkPPP.String())
	assert.Equal(t, "ip-tunnel", LinkIPTunnel.String())
	assert.Equal(t, "vpn", LinkVPN.String())
	assert.Equal(t, "loopback", LinkLoopback.String())
}

func TestEgressClass_String(t *testing.T) {
	assert.Equal(t, "direct", EgressDirect.String())
	assert.Equal(t, "uplink", EgressUplink.String())
	assert.Equal(t, "vpn", EgressVPN.String())
	assert.Equal(t, "unknown", EgressUnknown.String())
}
