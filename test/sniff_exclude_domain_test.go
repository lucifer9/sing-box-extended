package main

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestRouteSniffExcludeDomain(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		exclude  string
		excluded bool
	}{
		{"none", ``, false},
		{"domain", `,"exclude_domain":"cdn.example.org"`, true},
		{"domain-mismatch", `,"exclude_domain":"example.org"`, false},
		{"suffix", `,"exclude_domain_suffix":["example.org"]`, true},
		{"keyword", `,"exclude_domain_keyword":"xampl"`, true},
		{"regex", `,"exclude_domain_regex":"^cdn\\..+\\.org$"`, true},
		{"regex-mismatch", `,"exclude_domain_regex":"^img\\."`, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			proxy, requests := sniffedHTTPProxy(t)
			fallback := proxy
			fallback.Tag = "fallback"
			var routeOptions option.RouteOptions
			require.NoError(t, json.UnmarshalContextDisallowUnknownFields(globalCtx, fmt.Appendf(nil,
				`{"use_sniffed_destination":true,"rules":[{"action":"sniff"%s},{"domain_suffix":"example.org","outbound":"selected"}]}`,
				testCase.exclude,
			), &routeOptions))
			instance := startInstance(t, option.Options{Outbounds: []option.Outbound{fallback, proxy}, Route: &routeOptions})
			tracker := &sniffedRouteTracker{metadata: make(chan adapter.InboundContext, 1)}
			instance.Router().AppendTracker(tracker)
			client, inbound := net.Pipe()
			t.Cleanup(func() { client.Close() })
			require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
			go instance.Router().RouteConnectionEx(t.Context(), inbound, adapter.InboundContext{
				Destination:          M.ParseSocksaddr("[2001:db8::1]:8443"),
				DestinationAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.20")},
			}, nil)
			payload := "GET / HTTP/1.1\r\nHost: cdn.example.org\r\n\r\n"
			_, err := io.WriteString(client, payload)
			require.NoError(t, err)
			response := make([]byte, len(payload))
			_, err = io.ReadFull(client, response)
			require.NoError(t, err)
			request := <-requests
			require.NoError(t, request.err)
			metadata := <-tracker.metadata
			require.Equal(t, C.ProtocolHTTP, metadata.Protocol)
			if testCase.excluded {
				require.Equal(t, "fallback", metadata.RouteOutbound)
				require.Equal(t, "192.0.2.20:8443", request.target)
				require.Empty(t, metadata.Domain)
				require.Empty(t, metadata.SniffedDomain)
			} else {
				require.Equal(t, "selected", metadata.RouteOutbound)
				require.Equal(t, "cdn.example.org:8443", request.target)
				require.Equal(t, "cdn.example.org", metadata.SniffedDomain)
			}
		})
	}
}

func TestRouteSniffExcludeDomainPreMatch(t *testing.T) {
	packet := sniffedQUICInitial(t)
	for _, testCase := range []struct {
		exclude  string
		outbound string
	}{
		{``, "selected"},
		{`,"exclude_domain_suffix":"example.org"`, "fallback"},
	} {
		router, _ := sniffedFlowRouter(t, fmt.Sprintf(
			`{"rules":[{"action":"sniff"%s},{"domain_suffix":"example.org","outbound":"selected"}],"final":"fallback"}`,
			testCase.exclude,
		))
		result := router.PreMatch(adapter.InboundContext{
			InboundType: C.TypeTun, Network: N.NetworkUDP, Destination: M.ParseSocksaddr("[2001:db8::1]:8443"),
		}, packet)
		require.Equal(t, adapter.PreMatchFlow, result.Action, testCase.exclude)
		require.Equal(t, testCase.outbound, result.Outbound.Tag(), testCase.exclude)
	}
}

func TestRouteSniffExcludeDomainConfig(t *testing.T) {
	for input, message := range map[string]string{
		`{"route":{"rules":[{"action":"sniff","exclude_domain":""}]}}`:        "empty item",
		`{"route":{"rules":[{"action":"sniff","exclude_domain_regex":"("}]}}`: "exclude domain_regex",
	} {
		var options option.Options
		require.NoError(t, json.UnmarshalContext(globalCtx, []byte(input), &options))
		_, err := box.New(box.Options{Context: globalCtx, Options: options})
		require.ErrorContains(t, err, message)
	}
}
