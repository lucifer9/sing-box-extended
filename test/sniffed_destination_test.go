package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"github.com/sagernet/sing/service"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type sniffedRouteTracker struct {
	metadata chan adapter.InboundContext
}

func (t *sniffedRouteTracker) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	t.metadata <- metadata
	return conn
}

func (t *sniffedRouteTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	t.metadata <- metadata
	return conn
}

func (t *sniffedRouteTracker) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

type sniffedProxyRequest struct {
	target string
	err    error
}

// The endpoint records the CONNECT authority and echoes tunnel data without
// resolving it, so the test cannot accidentally succeed through local DNS.
func sniffedHTTPProxy(t *testing.T) (option.Outbound, <-chan sniffedProxyRequest) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	requests := make(chan sniffedProxyRequest, 1)
	done := make(chan struct{})
	t.Cleanup(func() {
		listener.Close()
		<-done
	})
	go func() {
		defer close(done)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			requests <- sniffedProxyRequest{err: acceptErr}
			return
		}
		defer conn.Close()
		if deadlineErr := conn.SetDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
			requests <- sniffedProxyRequest{err: deadlineErr}
			return
		}
		reader := bufio.NewReader(conn)
		request, readErr := http.ReadRequest(reader)
		if readErr != nil {
			requests <- sniffedProxyRequest{err: readErr}
			return
		}
		_, writeErr := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		requests <- sniffedProxyRequest{target: request.Host, err: writeErr}
		if writeErr == nil {
			_, _ = io.Copy(conn, reader)
		}
	}()
	return option.Outbound{
		Type: C.TypeHTTP,
		Tag:  "selected",
		Options: &option.HTTPOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     "127.0.0.1",
				ServerPort: M.SocksaddrFromNet(listener.Addr()).Port,
			},
		},
	}, requests
}

func TestRouteUseSniffedDestinationConfig(t *testing.T) {
	for _, input := range []string{
		`{"route":{"rules":[{"outbound":"direct","use_sniffed_destination":true,"override_address":"example.org"}]}}`,
		`{"route":{"rules":[{"type":"logical","mode":"and","rules":[{"domain":"example.org","use_sniffed_destination":true}],"outbound":"direct"}]}}`,
		`{"inbounds":[{"type":"mixed","sniff_override_destination":true}]}`,
	} {
		var options option.Options
		require.Error(t, json.UnmarshalContext(globalCtx, []byte(input), &options), input)
	}
	var legacyTUN option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(`{"inbounds":[{"type":"tun","sniff_override_destination":true}]}`), &legacyTUN))
	_, err := box.New(box.Options{Context: globalCtx, Options: legacyTUN})
	require.ErrorContains(t, err, "legacy inbound fields")
	_, err = box.New(box.Options{
		Context: globalCtx,
		Options: option.Options{Route: &option.RouteOptions{Rules: []option.Rule{{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{RuleAction: option.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: "direct", UseSniffedDestination: new(true),
					RawRouteOptionsActionOptions: option.RawRouteOptionsActionOptions{OverrideAddress: "example.org"},
				},
			}},
		}}}},
	})
	require.ErrorContains(t, err, "`use_sniffed_destination` and `override_address` are mutually exclusive")
}

func TestRouteUseSniffedDestinationHTTP(t *testing.T) {
	proxy, requests := sniffedHTTPProxy(t)
	fallback := proxy
	fallback.Tag = "fallback"
	instance := startInstance(t, option.Options{
		Outbounds: []option.Outbound{fallback, proxy},
		Route: &option.RouteOptions{Rules: []option.Rule{
			{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RuleAction: option.RuleAction{
				Action: C.RuleActionTypeSniff,
			}}},
			{Type: C.RuleTypeLogical, LogicalOptions: option.LogicalRule{
				RawLogicalRule: option.RawLogicalRule{
					Mode: "and",
					Rules: []option.Rule{
						{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RawDefaultRule: option.RawDefaultRule{IPCIDR: []string{"2001:db8::/32"}}}},
						{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RawDefaultRule: option.RawDefaultRule{Domain: []string{"cdn.example.org"}}}},
					},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{
						Outbound:              "selected",
						UseSniffedDestination: new(true),
					},
				},
			}},
		}},
	})
	tracker := &sniffedRouteTracker{metadata: make(chan adapter.InboundContext, 1)}
	instance.Router().AppendTracker(tracker)
	client, inbound := net.Pipe()
	t.Cleanup(func() { client.Close() })
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	original := M.ParseSocksaddr("[2001:db8::1]:8443")
	go instance.Router().RouteConnectionEx(t.Context(), inbound, adapter.InboundContext{
		Destination:          original,
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.20")},
	}, nil)
	payload := "GET / HTTP/1.1\r\nHost: cdn.example.org\r\n\r\n"
	_, err := io.WriteString(client, payload)
	require.NoError(t, err)
	response := make([]byte, len(payload))
	_, err = io.ReadFull(client, response)
	require.NoError(t, err)
	require.Equal(t, payload, string(response))
	request := <-requests
	require.NoError(t, request.err)
	require.Equal(t, "cdn.example.org:8443", request.target)
	metadata := <-tracker.metadata
	require.Equal(t, "selected", metadata.RouteOutbound)
	require.Equal(t, original, metadata.RouteOriginalDestination)
	require.Empty(t, metadata.DestinationAddresses)
}

type sniffedDestinationPolicy struct {
	name     string
	route    string
	enabled  bool
	outbound string
}

func sniffedDestinationPolicies() []sniffedDestinationPolicy {
	var policies []sniffedDestinationPolicy
	for _, global := range []bool{false, true} {
		for _, policy := range []struct {
			name     string
			rule     string
			final    string
			enabled  bool
			outbound string
		}{
			{"inherit", `{"ip_cidr":"2001:db8::/32","outbound":"selected"}`, "", global, "selected"},
			{"enable", `{"ip_cidr":"2001:db8::/32","outbound":"selected","use_sniffed_destination":true}`, "", true, "selected"},
			{"disable", `{"ip_cidr":"2001:db8::/32","outbound":"selected","use_sniffed_destination":false}`, "", false, "selected"},
			{"final", `{"domain":"unmatched.example.org","action":"reject"}`, "selected", global, "selected"},
			{"default-outbound", `{"domain":"unmatched.example.org","action":"reject"}`, "", global, "fallback"},
		} {
			policies = append(policies, sniffedDestinationPolicy{
				name:     fmt.Sprintf("global=%v/%s", global, policy.name),
				route:    fmt.Sprintf(`{"use_sniffed_destination":%v,"rules":[{"action":"sniff"},%s],"final":%q}`, global, policy.rule, policy.final),
				enabled:  policy.enabled,
				outbound: policy.outbound,
			})
		}
	}
	return policies
}

func TestRouteUseSniffedDestinationPolicyTCP(t *testing.T) {
	for _, policy := range sniffedDestinationPolicies() {
		t.Run(policy.name, func(t *testing.T) {
			proxy, requests := sniffedHTTPProxy(t)
			fallback := proxy
			fallback.Tag = "fallback"
			var routeOptions option.RouteOptions
			require.NoError(t, json.UnmarshalContextDisallowUnknownFields(globalCtx, []byte(policy.route), &routeOptions))
			instance := startInstance(t, option.Options{Outbounds: []option.Outbound{fallback, proxy}, Route: &routeOptions})
			tracker := &sniffedRouteTracker{metadata: make(chan adapter.InboundContext, 1)}
			instance.Router().AppendTracker(tracker)
			client, inbound := net.Pipe()
			t.Cleanup(func() { client.Close() })
			require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
			original := M.ParseSocksaddr("[2001:db8::1]:8443")
			candidates := []netip.Addr{netip.MustParseAddr("192.0.2.20")}
			go instance.Router().RouteConnectionEx(t.Context(), inbound, adapter.InboundContext{
				Destination: original, DestinationAddresses: candidates,
			}, nil)
			payload := "GET / HTTP/1.1\r\nHost: cdn.example.org\r\n\r\n"
			_, err := io.WriteString(client, payload)
			require.NoError(t, err)
			response := make([]byte, len(payload))
			_, err = io.ReadFull(client, response)
			require.NoError(t, err)
			require.Equal(t, payload, string(response))
			request := <-requests
			require.NoError(t, request.err)
			metadata := <-tracker.metadata
			require.Equal(t, policy.outbound, metadata.RouteOutbound)
			if policy.enabled {
				require.Equal(t, "cdn.example.org:8443", request.target)
				require.Equal(t, original, metadata.RouteOriginalDestination)
				require.Empty(t, metadata.DestinationAddresses)
			} else {
				require.Equal(t, "192.0.2.20:8443", request.target)
				require.False(t, metadata.RouteOriginalDestination.IsValid())
				require.Equal(t, candidates, metadata.DestinationAddresses)
			}
		})
	}
}

func TestRouteUseSniffedDestinationTLS(t *testing.T) {
	proxy, requests := sniffedHTTPProxy(t)
	var rules []option.Rule
	require.NoError(t, json.Unmarshal([]byte(`[
		{"action":"sniff","sniffer":"tls"},
		{"type":"logical","mode":"and","rules":[{"ip_cidr":"2001:db8::/32"},{"domain":"cdn.example.org"}],"outbound":"selected","use_sniffed_destination":true},
		{"action":"reject"}
	]`), &rules))
	instance := startInstance(t, option.Options{Outbounds: []option.Outbound{proxy}, Route: &option.RouteOptions{Rules: rules}})
	client, inbound := net.Pipe()
	t.Cleanup(func() { client.Close() })
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	go instance.Router().RouteConnectionEx(t.Context(), inbound, adapter.InboundContext{Destination: M.ParseSocksaddr("[2001:db8::1]:8443")}, nil)
	tlsClient := tls.Client(client, &tls.Config{ServerName: "cdn.example.org", CurvePreferences: []tls.CurveID{tls.X25519}})
	// The controlled proxy echoes the ClientHello instead of completing TLS.
	// The observable contract here is its CONNECT target, before any TLS reply.
	require.Error(t, tlsClient.HandshakeContext(t.Context()))
	select {
	case request := <-requests:
		require.NoError(t, request.err)
		require.Equal(t, "cdn.example.org:8443", request.target)
	case <-time.After(5 * time.Second):
		t.Fatal("TLS sniff did not reach the proxy")
	}
}

func sniffedEchoListener(t *testing.T, network, address string) (net.Listener, <-chan error) {
	t.Helper()
	listener, err := net.Listen(network, address)
	require.NoError(t, err)
	result := make(chan error, 1)
	done := make(chan struct{})
	t.Cleanup(func() {
		listener.Close()
		<-done
	})
	go func() {
		defer close(done)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			result <- acceptErr
			return
		}
		defer conn.Close()
		if deadlineErr := conn.SetDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
			result <- deadlineErr
			return
		}
		_, readErr := http.ReadRequest(bufio.NewReader(conn))
		if readErr != nil {
			result <- readErr
			return
		}
		_, writeErr := io.WriteString(conn, network)
		result <- writeErr
	}()
	return listener, result
}

func TestRouteUseSniffedDestinationDirect(t *testing.T) {
	for _, test := range []struct {
		name        string
		strategy    C.DomainStrategy
		ipv4        bool
		ipv6        bool
		wantNetwork string
		final       bool
	}{
		{"ipv4-only-fallback", C.DomainStrategyPreferIPv6, true, false, "tcp4", false},
		{"ipv6-only-fallback", C.DomainStrategyPreferIPv4, false, true, "tcp6", false},
		{"dual-stack-prefer-ipv4", C.DomainStrategyPreferIPv4, true, true, "tcp4", false},
		{"dual-stack-prefer-ipv6", C.DomainStrategyPreferIPv6, true, true, "tcp6", false},
		{"final-ipv4-fallback", C.DomainStrategyPreferIPv6, true, false, "tcp4", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var port uint16
			results := make(map[string]<-chan error)
			if test.ipv4 {
				listener, result := sniffedEchoListener(t, "tcp4", "127.0.0.1:0")
				port = M.SocksaddrFromNet(listener.Addr()).Port
				results["tcp4"] = result
			}
			if test.ipv6 {
				listener, result := sniffedEchoListener(t, "tcp6", M.SocksaddrFrom(netip.IPv6Loopback(), port).String())
				port = M.SocksaddrFromNet(listener.Addr()).Port
				results["tcp6"] = result
			}
			predefined := new(badjson.TypedMap[string, badoption.Listable[netip.Addr]])
			// Both records remain available even when only one family is listening.
			predefined.Put("cdn.example.org", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()})
			var rules []option.Rule
			require.NoError(t, json.Unmarshal([]byte(`[
				{"action":"sniff"},
				{"ip_cidr":"2001:db8::/32","outbound":"selected"},
				{"action":"reject"}
			]`), &rules))
			if test.final {
				rules = rules[:1]
			}
			instance := startInstance(t, option.Options{
				DNS: &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
					Servers: []option.DNSServerOptions{{Type: C.DNSTypeHosts, Tag: "controlled", Options: &option.HostsDNSServerOptions{Predefined: predefined}}},
				}},
				Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "selected", Options: &option.DirectOutboundOptions{
					DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{
						DomainResolver: &option.DomainResolveOptions{Server: "controlled", Strategy: option.DomainStrategy(test.strategy)},
						FallbackDelay:  badoption.Duration(10 * time.Millisecond),
					}},
				}}},
				Route: &option.RouteOptions{Rules: rules, Final: "selected", UseSniffedDestination: true},
			})
			tracker := &sniffedRouteTracker{metadata: make(chan adapter.InboundContext, 1)}
			instance.Router().AppendTracker(tracker)
			client, inbound := net.Pipe()
			t.Cleanup(func() { client.Close() })
			require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
			original := M.SocksaddrFrom(netip.MustParseAddr("2001:db8::1"), port)
			go instance.Router().RouteConnectionEx(t.Context(), inbound, adapter.InboundContext{
				Destination:          original,
				DestinationAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.20")},
			}, nil)
			_, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: cdn.example.org\r\n\r\n")
			require.NoError(t, err)
			response := make([]byte, 4)
			_, err = io.ReadFull(client, response)
			require.NoError(t, err)
			require.Equal(t, test.wantNetwork, string(response))
			require.NoError(t, <-results[test.wantNetwork])
			metadata := <-tracker.metadata
			require.Equal(t, "selected", metadata.RouteOutbound)
			require.Equal(t, "cdn.example.org", metadata.Destination.Fqdn)
			require.Equal(t, original, metadata.RouteOriginalDestination)
		})
	}
}

func sniffedSOCKSProxy(t *testing.T) (option.Outbound, <-chan sniffedProxyRequest) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	requests := make(chan sniffedProxyRequest, 1)
	done := make(chan struct{})
	t.Cleanup(func() {
		listener.Close()
		udp.Close()
		<-done
	})
	go func() {
		defer close(done)
		request := sniffedProxyRequest{}
		request.err = func() error {
			control, err := listener.Accept()
			if err != nil {
				return err
			}
			defer control.Close()
			if err = control.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return err
			}
			reader := bufio.NewReader(control)
			if _, err = socks5.ReadAuthRequest(reader); err != nil {
				return err
			}
			if err = socks5.WriteAuthResponse(control, socks5.AuthResponse{Method: socks5.AuthTypeNotRequired}); err != nil {
				return err
			}
			handshake, err := socks5.ReadRequest(reader)
			if err != nil {
				return err
			}
			if handshake.Command != socks5.CommandUDPAssociate {
				return fmt.Errorf("unexpected SOCKS command: %d", handshake.Command)
			}
			if err = socks5.WriteResponse(control, socks5.Response{Bind: M.SocksaddrFromNet(udp.LocalAddr())}); err != nil {
				return err
			}
			if err = udp.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return err
			}
			packet := make([]byte, 2048)
			n, source, err := udp.ReadFrom(packet)
			if err != nil {
				return err
			}
			if n < 3 {
				return io.ErrUnexpectedEOF
			}
			target, err := M.SocksaddrSerializer.ReadAddrPort(bytes.NewReader(packet[3:n]))
			if err != nil {
				return err
			}
			request.target = target.String()
			if _, err = udp.WriteTo(packet[:n], source); err != nil {
				return err
			}
			// Keep the association alive until the routed connection closes.
			requests <- request
			_, _ = io.Copy(io.Discard, control)
			return nil
		}()
		if request.err != nil {
			requests <- request
		}
	}()
	return option.Outbound{
		Type: C.TypeSOCKS, Tag: "selected",
		Options: &option.SOCKSOutboundOptions{ServerOptions: option.ServerOptions{
			Server: "127.0.0.1", ServerPort: M.SocksaddrFromNet(listener.Addr()).Port,
		}},
	}, requests
}

type sniffedPacket struct {
	destination M.Socksaddr
	payload     []byte
}

// Model the TUN packet boundary: reads carry the original client destination,
// and writes expose the source address that will be returned to that client.
type sniffedInboundPacketConn struct {
	net.Conn
	destination M.Socksaddr
	responses   chan sniffedPacket
}

func (c *sniffedInboundPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	_, err := buffer.ReadOnceFrom(c.Conn)
	return c.destination, err
}

func (c *sniffedInboundPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	c.responses <- sniffedPacket{destination: destination, payload: append([]byte(nil), buffer.Bytes()...)}
	return nil
}

func TestRouteUseSniffedDestinationUDP(t *testing.T) {
	for _, policy := range sniffedDestinationPolicies() {
		for _, connected := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/udp-connect=%v", policy.name, connected), func(t *testing.T) {
				proxy, requests := sniffedSOCKSProxy(t)
				fallback := proxy
				fallback.Tag = "fallback"
				var routeOptions option.RouteOptions
				require.NoError(t, json.UnmarshalContext(globalCtx, []byte(policy.route), &routeOptions))
				if connected {
					var udpOptions option.Rule
					require.NoError(t, json.Unmarshal([]byte(`{"action":"route-options","udp_connect":true}`), &udpOptions))
					routeOptions.Rules = append([]option.Rule{udpOptions}, routeOptions.Rules...)
				}
				instance := startInstance(t, option.Options{Outbounds: []option.Outbound{fallback, proxy}, Route: &routeOptions})
				tracker := &sniffedRouteTracker{metadata: make(chan adapter.InboundContext, 1)}
				instance.Router().AppendTracker(tracker)
				client, pipe := net.Pipe()
				t.Cleanup(func() { client.Close() })
				require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
				original := M.ParseSocksaddr("[2001:db8::1]:8443")
				inbound := &sniffedInboundPacketConn{Conn: pipe, destination: original, responses: make(chan sniffedPacket, 1)}
				go instance.Router().RoutePacketConnectionEx(t.Context(), inbound, adapter.InboundContext{
					InboundType: C.TypeTun, Destination: original, Domain: "cdn.example.org", SniffedDomain: "cdn.example.org", Protocol: C.ProtocolQUIC,
					DestinationAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.20")},
				}, nil)
				_, err := io.WriteString(client, "ping")
				require.NoError(t, err)
				select {
				case response := <-inbound.responses:
					require.Equal(t, "ping", string(response.payload))
					require.Equal(t, original, response.destination)
				case <-time.After(5 * time.Second):
					t.Fatal("no UDP response mapped to the original client destination")
				}
				request := <-requests
				require.NoError(t, request.err)
				metadata := <-tracker.metadata
				require.Equal(t, policy.outbound, metadata.RouteOutbound)
				if policy.enabled {
					require.Equal(t, "cdn.example.org:8443", request.target)
					require.Equal(t, original, metadata.RouteOriginalDestination)
					require.Empty(t, metadata.DestinationAddresses)
				} else {
					require.Equal(t, "192.0.2.20:8443", request.target)
					require.False(t, metadata.RouteOriginalDestination.IsValid())
					require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.20")}, metadata.DestinationAddresses)
				}
			})
		}
	}
}

type sniffedDNSWriter chan []byte

func (w sniffedDNSWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	defer buffer.Release()
	w <- append([]byte(nil), buffer.Bytes()...)
	return nil
}

func TestRouteUseSniffedDestinationReverseMapping(t *testing.T) {
	for _, test := range []struct {
		name       string
		sniff      bool
		payload    string
		wantTarget string
	}{
		{"no-sniff", false, "GET / HTTP/1.1\r\nHost: cdn.example.org\r\n\r\n", "[2001:db8::1]:8443"},
		{"failed-sniff", true, "not http\r\n\r\n", "[2001:db8::1]:8443"},
		{"sniff-without-host", true, "GET / HTTP/1.0\r\n\r\n", "[2001:db8::1]:8443"},
		{"sniff-same-host", true, "GET / HTTP/1.1\r\nHost: cached.example.org\r\n\r\n", "cached.example.org:8443"},
		{"sniff-different-host", true, "GET / HTTP/1.1\r\nHost: cdn.example.org\r\n\r\n", "cdn.example.org:8443"},
	} {
		t.Run(test.name, func(t *testing.T) {
			proxy, requests := sniffedHTTPProxy(t)
			var options option.Options
			require.NoError(t, json.UnmarshalContext(globalCtx, []byte(`{
				"dns":{"reverse_mapping":true,"servers":[{"type":"hosts","tag":"controlled","predefined":{"cached.example.org":"2001:db8::1"}}]},
				"route":{"use_sniffed_destination":true,"final":"selected"}
			}`), &options))
			options.Outbounds = []option.Outbound{proxy}
			if test.sniff {
				options.Route.Rules = append([]option.Rule{{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RuleAction: option.RuleAction{
					Action: C.RuleActionTypeSniff, SniffOptions: option.RouteActionSniff{Sniffer: []string{"http"}, Timeout: badoption.Duration(20 * time.Millisecond)},
				}}}}, options.Route.Rules...)
			}
			instance := startInstance(t, options)
			query := new(dns.Msg)
			query.SetQuestion("cached.example.org.", dns.TypeAAAA)
			payload, err := query.Pack()
			require.NoError(t, err)
			writer := make(sniffedDNSWriter, 1)
			instance.Router().HijackDNSPacket(t.Context(), payload, writer, adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.53:53")})
			select {
			case packet := <-writer:
				var response dns.Msg
				require.NoError(t, response.Unpack(packet))
				require.Len(t, response.Answer, 1)
			case <-time.After(5 * time.Second):
				t.Fatal("no response to populate DNS reverse mapping")
			}
			client, inbound := net.Pipe()
			t.Cleanup(func() { client.Close() })
			require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
			go instance.Router().RouteConnectionEx(t.Context(), inbound, adapter.InboundContext{Destination: M.ParseSocksaddr("[2001:db8::1]:8443")}, nil)
			_, err = io.WriteString(client, test.payload)
			require.NoError(t, err)
			response := make([]byte, len(test.payload))
			_, err = io.ReadFull(client, response)
			require.NoError(t, err)
			require.Equal(t, test.payload, string(response))
			request := <-requests
			require.NoError(t, request.err)
			require.Equal(t, test.wantTarget, request.target)
		})
	}
}

func sniffedQUICInitial(t *testing.T) []byte {
	t.Helper()
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	require.NoError(t, listener.SetReadDeadline(time.Now().Add(5*time.Second)))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := quic.DialAddr(ctx, listener.LocalAddr().String(), &tls.Config{
			ServerName: "cdn.example.org", NextProtos: []string{"h3"}, CurvePreferences: []tls.CurveID{tls.X25519},
		}, &quic.Config{})
		if conn != nil {
			conn.CloseWithError(0, "test complete")
		}
		done <- err
	}()
	packet := make([]byte, 2048)
	n, _, err := listener.ReadFrom(packet)
	cancel()
	require.NoError(t, err)
	require.Error(t, <-done) // No server handshake was sent.
	return packet[:n]
}

// A controlled IP-flow boundary that explicitly rejects domain dialing.
type sniffedFlowOutbound struct {
	outbound.Adapter
	targets chan M.Socksaddr
}

func (o *sniffedFlowOutbound) PreMatchFlow(string, netip.Addr) adapter.PreMatchAction {
	return adapter.PreMatchFlow
}

func (o *sniffedFlowOutbound) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.Addr{}, netip.Addr{}
}
func (o *sniffedFlowOutbound) PortMTU() uint32 { return 1500 }
func (o *sniffedFlowOutbound) AttachReturn(tun.Return) error {
	return fmt.Errorf("unexpected flow attachment")
}

func (o *sniffedFlowOutbound) DetachReturn(tun.Return) error {
	return fmt.Errorf("unexpected flow detachment")
}

func (o *sniffedFlowOutbound) WritePackets([][]byte) error {
	return fmt.Errorf("unexpected IP flow forwarding")
}

func (o *sniffedFlowOutbound) DialContext(_ context.Context, _ string, target M.Socksaddr) (net.Conn, error) {
	o.targets <- target
	return nil, fmt.Errorf("domain targets unsupported: %s", target)
}

func (o *sniffedFlowOutbound) ListenPacket(_ context.Context, target M.Socksaddr) (net.PacketConn, error) {
	o.targets <- target
	return nil, fmt.Errorf("domain targets unsupported: %s", target)
}

func sniffedFlowRouter(t *testing.T, route string) (adapter.Router, map[string]*sniffedFlowOutbound) {
	t.Helper()
	ctx := include.Context(t.Context())
	registry := service.FromContext[adapter.OutboundRegistry](ctx).(*outbound.Registry)
	controlled := make(map[string]*sniffedFlowOutbound)
	outbound.Register[struct{}](registry, "test-flow", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ struct{}) (adapter.Outbound, error) {
		flow := &sniffedFlowOutbound{Adapter: outbound.NewAdapter("test-flow", tag, []string{N.NetworkTCP, N.NetworkUDP}, nil), targets: make(chan M.Socksaddr, 1)}
		controlled[tag] = flow
		return flow, nil
	})
	var options option.Options
	require.NoError(t, json.UnmarshalContext(ctx, []byte(fmt.Sprintf(`{
		"outbounds":[{"type":"test-flow","tag":"fallback"},{"type":"test-flow","tag":"selected"}],
		"route":%s
	}`, route)), &options))
	options.Log = &option.LogOptions{Level: "warning"}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	t.Cleanup(func() { instance.Close() })
	require.NoError(t, instance.Start())
	return instance.Router(), controlled
}

func TestRouteUseSniffedDestinationPreMatch(t *testing.T) {
	packet := sniffedQUICInitial(t)
	for _, policy := range sniffedDestinationPolicies() {
		t.Run(policy.name, func(t *testing.T) {
			router, controlled := sniffedFlowRouter(t, policy.route)
			original := M.ParseSocksaddr("[2001:db8::1]:8443")
			metadata := adapter.InboundContext{InboundType: C.TypeTun, Network: N.NetworkUDP, Destination: original}
			result := router.PreMatch(metadata, packet)
			if !policy.enabled {
				require.Equal(t, adapter.PreMatchFlow, result.Action)
				require.Equal(t, policy.outbound, result.Outbound.Tag())
				return
			}
			require.Equal(t, adapter.PreMatchContinue, result.Action)
			client, pipe := net.Pipe()
			t.Cleanup(func() { client.Close() })
			require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
			inbound := &sniffedInboundPacketConn{Conn: pipe, destination: original, responses: make(chan sniffedPacket, 1)}
			closed := make(chan error, 1)
			go router.RoutePacketConnectionEx(t.Context(), inbound, metadata, func(err error) { closed <- err })
			_, err := client.Write(packet)
			require.NoError(t, err)
			select {
			case err := <-closed:
				require.ErrorContains(t, err, "domain targets unsupported: cdn.example.org:8443")
			case <-time.After(5 * time.Second):
				t.Fatal("domain capability error was not reported")
			}
			select {
			case target := <-controlled[policy.outbound].targets:
				require.Equal(t, "cdn.example.org:8443", target.String())
			case <-time.After(5 * time.Second):
				t.Fatal("the configured outbound did not receive the domain target")
			}
		})
	}
}

func TestRouteUseSniffedDestinationPreMatchCompatibility(t *testing.T) {
	for _, test := range []struct {
		name        string
		action      string
		domain      string
		wantAction  adapter.PreMatchAction
		wantAddress netip.AddrPort
	}{
		{name: "final-no-sniff", wantAction: adapter.PreMatchFlow},
		{name: "final-invalid-domain", domain: "bad..example.org", wantAction: adapter.PreMatchFlow},
		{name: "final-valid-domain", domain: "cdn.example.org", wantAction: adapter.PreMatchContinue},
		{name: "static-ip", action: `{"outbound":"selected","override_address":"192.0.2.5"}`, domain: "cdn.example.org", wantAction: adapter.PreMatchFlow, wantAddress: netip.MustParseAddrPort("192.0.2.5:8443")},
		{name: "bypass-outbound", action: `{"action":"bypass","outbound":"selected"}`, domain: "cdn.example.org", wantAction: adapter.PreMatchFlow},
		{name: "bypass", action: `{"action":"bypass"}`, domain: "cdn.example.org", wantAction: adapter.PreMatchBypass},
		{name: "reject", action: `{"action":"reject"}`, domain: "cdn.example.org", wantAction: adapter.PreMatchReject},
		{name: "drop", action: `{"action":"reject","method":"drop"}`, domain: "cdn.example.org", wantAction: adapter.PreMatchDrop},
		{name: "hijack-dns", action: `{"action":"hijack-dns"}`, domain: "cdn.example.org", wantAction: adapter.PreMatchHijackDNS},
	} {
		t.Run(test.name, func(t *testing.T) {
			router, _ := sniffedFlowRouter(t, fmt.Sprintf(`{"use_sniffed_destination":true,"final":"selected","rules":[%s]}`, test.action))
			result := router.PreMatch(adapter.InboundContext{
				InboundType: C.TypeTun, Network: N.NetworkUDP, Destination: M.ParseSocksaddr("[2001:db8::1]:8443"),
				Domain: "cached.example.org", SniffedDomain: test.domain,
			}, nil)
			require.Equal(t, test.wantAction, result.Action)
			require.Equal(t, test.wantAddress, result.Destination)
			if test.wantAction == adapter.PreMatchFlow {
				require.Equal(t, "selected", result.Outbound.Tag())
			}
		})
	}
}

func TestRouteUseSniffedDestinationFakeIP(t *testing.T) {
	proxy, requests := sniffedSOCKSProxy(t)
	var dnsOptions option.DNSOptions
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(`{"servers":[{"type":"hosts","tag":"hosts"},{"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15"}],"rules":[{"query_type":"A","server":"fake"}]}`), &dnsOptions))
	instance := startInstance(t, option.Options{
		DNS: &dnsOptions, Outbounds: []option.Outbound{proxy}, Route: &option.RouteOptions{Final: "selected", UseSniffedDestination: true},
	})
	tracker := &sniffedRouteTracker{metadata: make(chan adapter.InboundContext, 1)}
	instance.Router().AppendTracker(tracker)
	client, pipe := net.Pipe()
	t.Cleanup(func() { client.Close() })
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	inbound := &sniffedInboundPacketConn{Conn: pipe, responses: make(chan sniffedPacket, 1)}
	query := new(dns.Msg)
	query.SetQuestion("original.example.org.", dns.TypeA)
	payload, err := query.Pack()
	require.NoError(t, err)
	instance.Router().HijackDNSPacket(t.Context(), payload, inbound, adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.53:53")})
	var response dns.Msg
	select {
	case packet := <-inbound.responses:
		require.NoError(t, response.Unpack(packet.payload))
	case <-time.After(5 * time.Second):
		t.Fatal("no FakeIP DNS response")
	}
	require.Len(t, response.Answer, 1)
	answer, ok := response.Answer[0].(*dns.A)
	require.True(t, ok)
	original := M.SocksaddrFrom(M.AddrFromIP(answer.A), 8443)
	require.True(t, netip.MustParsePrefix("198.18.0.0/15").Contains(original.Addr))
	inbound.destination = original
	go instance.Router().RoutePacketConnectionEx(t.Context(), inbound, adapter.InboundContext{
		InboundType: C.TypeTun, Destination: original, Domain: "cdn.example.org", SniffedDomain: "cdn.example.org", Protocol: C.ProtocolQUIC,
	}, nil)
	_, err = io.WriteString(client, "ping")
	require.NoError(t, err)
	select {
	case packet := <-inbound.responses:
		require.Equal(t, "ping", string(packet.payload))
		require.Equal(t, original, packet.destination)
	case <-time.After(5 * time.Second):
		t.Fatal("no UDP response mapped to FakeIP")
	}
	request := <-requests
	require.NoError(t, request.err)
	require.Equal(t, "original.example.org:8443", request.target)
	metadata := <-tracker.metadata
	require.True(t, metadata.FakeIP)
	require.Equal(t, original, metadata.OriginDestination)
	require.False(t, metadata.RouteOriginalDestination.IsValid())
}

func TestRouteUseSniffedDestinationDirectUDP(t *testing.T) {
	for _, connected := range []bool{false, true} {
		t.Run(fmt.Sprintf("udp-connect=%v", connected), func(t *testing.T) {
			server, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { server.Close() })
			require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))
			serverResult := make(chan error, 1)
			go func() {
				packet := make([]byte, 1024)
				n, source, err := server.ReadFrom(packet)
				if err == nil {
					_, err = server.WriteTo(packet[:n], source)
				}
				serverResult <- err
			}()
			var options option.Options
			require.NoError(t, json.UnmarshalContext(globalCtx, []byte(fmt.Sprintf(`{
				"dns":{"servers":[{"type":"hosts","tag":"controlled","predefined":{"cdn.example.org":"127.0.0.1"}}]},
				"outbounds":[{"type":"direct","tag":"selected","domain_resolver":"controlled"}],
				"route":{"rules":[
					{"ip_cidr":"2001:db8::/32","outbound":"selected","use_sniffed_destination":true,"udp_connect":%v},
					{"action":"reject"}
				]}
			}`, connected)), &options))
			instance := startInstance(t, options)
			client, pipe := net.Pipe()
			t.Cleanup(func() { client.Close() })
			require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
			original := M.SocksaddrFrom(netip.MustParseAddr("2001:db8::1"), M.SocksaddrFromNet(server.LocalAddr()).Port)
			inbound := &sniffedInboundPacketConn{Conn: pipe, destination: original, responses: make(chan sniffedPacket, 1)}
			go instance.Router().RoutePacketConnectionEx(t.Context(), inbound, adapter.InboundContext{
				InboundType: C.TypeTun, Destination: original, Domain: "cdn.example.org", SniffedDomain: "cdn.example.org", Protocol: C.ProtocolQUIC,
			}, nil)
			_, err = io.WriteString(client, "ping")
			require.NoError(t, err)
			select {
			case response := <-inbound.responses:
				require.Equal(t, "ping", string(response.payload))
				require.Equal(t, original, response.destination)
			case <-time.After(5 * time.Second):
				t.Fatal("no direct UDP response mapped to the original client destination")
			}
			require.NoError(t, <-serverResult)
		})
	}
}

func TestRouteUseSniffedDestinationCompatibility(t *testing.T) {
	for _, test := range []struct {
		name          string
		action        string
		priorRule     string
		destination   string
		domain        string
		candidate     bool
		origin        string
		wantTarget    string
		wantOrigin    string
		wantCandidate bool
		global        bool
		final         bool
	}{
		{name: "default", action: `{"outbound":"selected"}`, domain: "cdn.example.org", wantTarget: "[2001:db8::1]:8443"},
		{name: "disabled", action: `{"outbound":"selected","use_sniffed_destination":false}`, domain: "cdn.example.org", candidate: true, wantTarget: "192.0.2.20:8443", wantCandidate: true},
		{name: "missing-domain", domain: "", wantTarget: "[2001:db8::1]:8443"},
		{name: "invalid-domain", domain: "bad..example.org", candidate: true, wantTarget: "192.0.2.20:8443", wantCandidate: true},
		{name: "malformed-host", domain: "example.org/path", wantTarget: "[2001:db8::1]:8443"},
		{name: "ipv4-host", domain: "192.0.2.1", wantTarget: "[2001:db8::1]:8443"},
		{name: "ipv6-host", domain: "2001:db8::2", wantTarget: "[2001:db8::1]:8443"},
		{name: "already-domain", destination: "original.example.org:8443", domain: "cdn.example.org", wantTarget: "original.example.org:8443"},
		{name: "already-resolved-domain", destination: "original.example.org:8443", domain: "cdn.example.org", candidate: true, wantTarget: "192.0.2.20:8443", wantCandidate: true},
		{name: "ipv4-destination", destination: "192.0.2.1:8443", domain: "cdn.example.org", wantTarget: "cdn.example.org:8443", wantOrigin: "192.0.2.1:8443"},
		{name: "override-port", action: `{"outbound":"selected","use_sniffed_destination":true,"override_port":9443}`, domain: "cdn.example.org", wantTarget: "cdn.example.org:9443", wantOrigin: "[2001:db8::1]:8443"},
		{name: "static-override", action: `{"outbound":"selected","override_address":"static.example.org","override_port":9443}`, domain: "cdn.example.org", candidate: true, wantTarget: "static.example.org:9443", wantOrigin: "[2001:db8::1]:8443"},
		{name: "earlier-domain-override", priorRule: `{"action":"route-options","override_address":"static.example.org"}`, domain: "cdn.example.org", candidate: true, wantTarget: "static.example.org:8443", wantOrigin: "[2001:db8::1]:8443"},
		{name: "earlier-port-override", priorRule: `{"action":"route-options","override_port":9443}`, domain: "cdn.example.org", wantTarget: "cdn.example.org:9443", wantOrigin: "[2001:db8::1]:8443"},
		{name: "preserve-origin", domain: "cdn.example.org", origin: "192.0.2.30:443", wantTarget: "cdn.example.org:8443", wantOrigin: "192.0.2.30:443"},
		{name: "global-static-ip", global: true, action: `{"outbound":"selected","override_address":"192.0.2.5"}`, domain: "cdn.example.org", candidate: true, wantTarget: "192.0.2.5:8443", wantOrigin: "[2001:db8::1]:8443"},
		{name: "global-static-domain", global: true, action: `{"outbound":"selected","override_address":"static.example.org"}`, domain: "cdn.example.org", candidate: true, wantTarget: "static.example.org:8443", wantOrigin: "[2001:db8::1]:8443"},
		{name: "global-disabled-static", global: true, action: `{"outbound":"selected","use_sniffed_destination":false,"override_address":"192.0.2.5"}`, domain: "cdn.example.org", wantTarget: "192.0.2.5:8443", wantOrigin: "[2001:db8::1]:8443"},
		{name: "global-override-port", global: true, action: `{"outbound":"selected","override_port":9443}`, domain: "cdn.example.org", wantTarget: "cdn.example.org:9443", wantOrigin: "[2001:db8::1]:8443"},
		{name: "global-missing-domain", global: true, action: `{"outbound":"selected"}`, wantTarget: "[2001:db8::1]:8443"},
		{name: "global-invalid-domain", global: true, action: `{"outbound":"selected"}`, domain: "bad..example.org", candidate: true, wantTarget: "192.0.2.20:8443", wantCandidate: true},
		{name: "global-already-domain", global: true, action: `{"outbound":"selected"}`, destination: "original.example.org:8443", domain: "cdn.example.org", wantTarget: "original.example.org:8443"},
		{name: "final-missing-domain", global: true, final: true, wantTarget: "[2001:db8::1]:8443"},
		{name: "final-invalid-domain", global: true, final: true, domain: "bad..example.org", candidate: true, wantTarget: "192.0.2.20:8443", wantCandidate: true},
		{name: "final-already-domain", global: true, final: true, destination: "original.example.org:8443", domain: "cdn.example.org", wantTarget: "original.example.org:8443"},
		{name: "final-earlier-domain-override", global: true, final: true, priorRule: `{"action":"route-options","override_address":"static.example.org"}`, domain: "cdn.example.org", candidate: true, wantTarget: "static.example.org:8443", wantOrigin: "[2001:db8::1]:8443"},
		{name: "final-earlier-ip-override", global: true, final: true, priorRule: `{"action":"route-options","override_address":"192.0.2.5"}`, domain: "cdn.example.org", wantTarget: "cdn.example.org:8443", wantOrigin: "[2001:db8::1]:8443"},
		{name: "final-earlier-port-override", global: true, final: true, priorRule: `{"action":"route-options","override_port":9443}`, domain: "cdn.example.org", wantTarget: "cdn.example.org:9443", wantOrigin: "[2001:db8::1]:8443"},
		{name: "global-bypass", global: true, action: `{"action":"bypass","outbound":"selected"}`, domain: "cdn.example.org", candidate: true, wantTarget: "192.0.2.20:8443", wantCandidate: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			proxy, requests := sniffedHTTPProxy(t)
			if test.action == "" {
				test.action = `{"outbound":"selected","use_sniffed_destination":true}`
			}
			var rules []option.Rule
			if !test.final {
				var rule option.Rule
				require.NoError(t, json.Unmarshal([]byte(test.action), &rule))
				rules = []option.Rule{rule}
			}
			if test.priorRule != "" {
				var prior option.Rule
				require.NoError(t, json.Unmarshal([]byte(test.priorRule), &prior))
				rules = append([]option.Rule{prior}, rules...)
			}
			instance := startInstance(t, option.Options{
				Outbounds: []option.Outbound{proxy},
				Route:     &option.RouteOptions{Rules: rules, Final: "selected", UseSniffedDestination: test.global},
			})
			tracker := &sniffedRouteTracker{metadata: make(chan adapter.InboundContext, 1)}
			instance.Router().AppendTracker(tracker)
			if test.destination == "" {
				test.destination = "[2001:db8::1]:8443"
			}
			metadata := adapter.InboundContext{
				Destination:   M.ParseSocksaddr(test.destination),
				Domain:        test.domain,
				SniffedDomain: test.domain,
				Protocol:      C.ProtocolTLS,
			}
			if test.candidate {
				metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr("192.0.2.20")}
			}
			if test.origin != "" {
				metadata.RouteOriginalDestination = M.ParseSocksaddr(test.origin)
			}
			client, inbound := net.Pipe()
			t.Cleanup(func() { client.Close() })
			require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
			go instance.Router().RouteConnectionEx(t.Context(), inbound, metadata, nil)
			_, err := io.WriteString(client, "ping")
			require.NoError(t, err)
			response := make([]byte, 4)
			_, err = io.ReadFull(client, response)
			require.NoError(t, err)
			require.Equal(t, "ping", string(response))
			request := <-requests
			require.NoError(t, request.err)
			require.Equal(t, test.wantTarget, request.target)
			routed := <-tracker.metadata
			require.Equal(t, "selected", routed.RouteOutbound)
			if test.wantOrigin == "" {
				require.False(t, routed.RouteOriginalDestination.IsValid())
			} else {
				require.Equal(t, test.wantOrigin, routed.RouteOriginalDestination.String())
			}
			if test.wantCandidate {
				require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.20")}, routed.DestinationAddresses)
			} else {
				require.Empty(t, routed.DestinationAddresses)
			}
		})
	}
}
