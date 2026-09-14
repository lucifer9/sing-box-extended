//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"net"
	"testing"

	"github.com/sagernet/sing/common/logger"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

func TestRealityRandomizedApplicationProtocols(t *testing.T) {
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	for _, test := range []struct {
		name      string
		protocols []string
		omitALPN  bool
		wantALPS  bool
	}{
		{name: "defaults", wantALPS: true},
		{name: "HTTP2", protocols: []string{"h2", "http/1.1"}, wantALPS: true},
		{name: "HTTP1", protocols: []string{"http/1.1"}},
		{name: "ALPN omitted", protocols: []string{"h2", "http/1.1"}, omitALPN: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := realityTestOptions("randomized")
			options.Reality.PublicKey = base64.RawURLEncoding.EncodeToString(serverKey.PublicKey().Bytes())
			options.Reality.ShortID = "0102030405060708"
			options.ALPN = test.protocols
			config, err := NewRealityClient(context.Background(), logger.NOP(), "", options)
			require.NoError(t, err)
			candidate := config.(*RealityClientConfig)
			candidate.uClient.id.Seed = &utls.PRNGSeed{}
			weights := *candidate.uClient.id.Weights
			weights.Extensions_Append_ALPN = 1
			weights.Extensions_Append_ALPS = 1
			if test.omitALPN {
				weights.Extensions_Append_ALPN = 0
			}
			candidate.uClient.id.Weights = &weights
			raw, err := captureRealityClientHello(t, func(conn net.Conn) error {
				_, err := candidate.ClientHandshake(context.Background(), conn)
				return err
			})
			require.NotEmpty(t, raw, "ClientHello must reach the wire: %v", err)
			hello := checkRealityWireAuthentication(t, raw, serverKey)
			if test.omitALPN {
				require.Empty(t, hello.AlpnProtocols)
			} else if len(test.protocols) > 0 {
				require.Equal(t, test.protocols, hello.AlpnProtocols)
			} else {
				require.Equal(t, []string{"h2", "http/1.1"}, hello.AlpnProtocols)
			}
			require.Equal(t, options.ServerName, hello.ServerName)
			// Parse the emitted TLS record to include ALPS, which PubClientHelloMsg
			// does not expose. Its protocols must be a subset of the wire ALPN.
			record := append([]byte{22, 3, 1, byte(len(raw) >> 8), byte(len(raw))}, raw...)
			spec, err := (&utls.Fingerprinter{}).RawClientHello(record)
			require.NoError(t, err)
			var foundALPS bool
			for _, extension := range spec.Extensions {
				if alps, ok := extension.(*utls.ApplicationSettingsExtension); ok {
					foundALPS = true
					require.NotEmpty(t, alps.SupportedProtocols)
					require.Subset(t, hello.AlpnProtocols, alps.SupportedProtocols)
				}
			}
			require.Equal(t, test.wantALPS, foundALPS)
		})
	}
}
