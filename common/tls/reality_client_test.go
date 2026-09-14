//go:build with_utls

package tls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func realityTestOptions(fingerprint string) option.OutboundTLSOptions {
	return option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.com",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		},
	}
}

func TestRealityClientFingerprintConfiguration(t *testing.T) {
	for _, fingerprint := range []string{"", "chrome", "random"} {
		t.Run(fingerprint, func(t *testing.T) {
			_, err := NewRealityClient(context.Background(), logger.NOP(), "", realityTestOptions(fingerprint))
			require.NoError(t, err)
		})
	}
	for _, fingerprint := range []string{"firefox", "edge", "safari", "360", "qq", "ios", "android"} {
		t.Run(fingerprint, func(t *testing.T) {
			_, err := NewRealityClient(context.Background(), logger.NOP(), "", realityTestOptions(fingerprint))
			require.ErrorContains(t, err, "X25519MLKEM768")
			require.ErrorContains(t, err, "chrome")
		})
	}
}

// Read the bytes emitted by the real uTLS handshake, rather than inspecting its
// mutable public state. The peer closes after ClientHello (no external network).
func captureRealityClientHello(t *testing.T, handshake func(net.Conn) error) ([]byte, error) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	require.NoError(t, client.SetDeadline(time.Now().Add(3*time.Second)))
	require.NoError(t, server.SetDeadline(time.Now().Add(3*time.Second)))
	errChan := make(chan error, 1)
	go func() {
		errChan <- handshake(client)
		client.Close()
	}()
	var header [5]byte
	_, readErr := io.ReadFull(server, header[:])
	var raw []byte
	if readErr == nil {
		require.Equal(t, byte(22), header[0])
		raw = make([]byte, binary.BigEndian.Uint16(header[3:]))
		_, readErr = io.ReadFull(server, raw)
		require.NoError(t, readErr)
	}
	server.Close()
	return raw, <-errChan
}

// Authentication layout and share preference are pinned to Xray v26.9.9:
// XTLS/Xray-core@52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120,
// XTLS/REALITY@8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8 (tls.go).
func checkRealityWireAuthentication(t *testing.T, raw []byte, serverKey *ecdh.PrivateKey) *utls.PubClientHelloMsg {
	t.Helper()
	hello := utls.UnmarshalClientHello(raw)
	require.NotNil(t, hello)
	var hybrid, independent []byte
	for _, share := range hello.KeyShares {
		require.Contains(t, hello.SupportedCurves, share.Group)
		switch share.Group {
		case utls.X25519MLKEM768:
			require.Nil(t, independent, "hybrid must precede optional X25519")
			require.Len(t, share.Data, 1216)
			hybrid = share.Data[1184:]
		case utls.X25519:
			require.Len(t, share.Data, 32)
			independent = share.Data
		}
	}
	require.NotNil(t, hybrid)
	peerBytes := hybrid
	if independent != nil {
		peerBytes = independent
	}
	peer, err := ecdh.X25519().NewPublicKey(peerBytes)
	require.NoError(t, err)
	secret, err := serverKey.ECDH(peer)
	require.NoError(t, err)
	_, err = io.ReadFull(hkdf.New(sha256.New, secret, hello.Random[:20], []byte("REALITY")), secret)
	require.NoError(t, err)
	block, err := aes.NewCipher(secret)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	aad := slices.Clone(raw)
	clear(aad[39:71])
	plaintext, err := aead.Open(nil, hello.Random[20:], hello.SessionId, aad)
	require.NoError(t, err, "session ID must authenticate against the actual sent ClientHello")
	require.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, plaintext[8:16])
	return hello
}

func TestRealityClientSendsAuthenticatedHybridClientHello(t *testing.T) {
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	for _, fingerprint := range []string{"", "chrome", "random"} {
		t.Run(fingerprint, func(t *testing.T) {
			options := realityTestOptions(fingerprint)
			options.Reality.PublicKey = base64.RawURLEncoding.EncodeToString(serverKey.PublicKey().Bytes())
			options.Reality.ShortID = "0102030405060708"
			options.ALPN = []string{"http/1.1"}
			config, err := NewRealityClient(context.Background(), logger.NOP(), "", options)
			require.NoError(t, err)
			for _, config := range []Config{config, config.Clone()} {
				raw, err := captureRealityClientHello(t, func(conn net.Conn) error {
					_, err := config.(*RealityClientConfig).ClientHandshake(context.Background(), conn)
					return err
				})
				require.Error(t, err, "capture peer closes without a ServerHello")
				hello := checkRealityWireAuthentication(t, raw, serverKey)
				require.Equal(t, []string{"http/1.1"}, hello.AlpnProtocols)
			}
		})
	}
}

func TestRealityClientCustomWireShares(t *testing.T) {
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	cases := []struct {
		name      string
		change    func(*utls.UConn)
		wantError string
	}{
		{name: "hybrid and independent X25519"},
		{name: "hybrid only", change: func(conn *utls.UConn) {
			for _, ext := range conn.Extensions {
				if shares, ok := ext.(*utls.KeyShareExtension); ok {
					shares.KeyShares = slices.DeleteFunc(shares.KeyShares, func(share utls.KeyShare) bool { return share.Group == utls.X25519 })
				}
			}
			conn.HandshakeState.State13.KeyShareKeys.Ecdhe = nil
		}},
		{name: "missing hybrid", wantError: "missing hybrid", change: func(conn *utls.UConn) {
			for _, ext := range conn.Extensions {
				if shares, ok := ext.(*utls.KeyShareExtension); ok {
					shares.KeyShares = slices.DeleteFunc(shares.KeyShares, func(share utls.KeyShare) bool { return share.Group == utls.X25519MLKEM768 })
				}
			}
		}},
		{name: "reverse shares", wantError: "order", change: func(conn *utls.UConn) {
			for _, ext := range conn.Extensions {
				if shares, ok := ext.(*utls.KeyShareExtension); ok {
					slices.Reverse(shares.KeyShares)
				}
			}
		}},
		{name: "hybrid wrong length", wantError: "length", change: func(conn *utls.UConn) {
			for _, ext := range conn.Extensions {
				if shares, ok := ext.(*utls.KeyShareExtension); ok {
					for i := range shares.KeyShares {
						if shares.KeyShares[i].Group == utls.X25519MLKEM768 {
							shares.KeyShares[i].Data = shares.KeyShares[i].Data[:1215]
						}
					}
				}
			}
		}},
		{name: "X25519 wrong length", wantError: "length", change: func(conn *utls.UConn) {
			for _, ext := range conn.Extensions {
				if shares, ok := ext.(*utls.KeyShareExtension); ok {
					for i := range shares.KeyShares {
						if shares.KeyShares[i].Group == utls.X25519 {
							shares.KeyShares[i].Data = shares.KeyShares[i].Data[:31]
						}
					}
				}
			}
		}},
		{name: "hybrid not supported", wantError: "supported_groups", change: func(conn *utls.UConn) {
			for _, ext := range conn.Extensions {
				if curves, ok := ext.(*utls.SupportedCurvesExtension); ok {
					curves.Curves = slices.DeleteFunc(curves.Curves, func(group utls.CurveID) bool { return group == utls.X25519MLKEM768 })
				}
			}
		}},
		{name: "independent not supported", wantError: "supported_groups", change: func(conn *utls.UConn) {
			for _, ext := range conn.Extensions {
				if curves, ok := ext.(*utls.SupportedCurvesExtension); ok {
					curves.Curves = slices.DeleteFunc(curves.Curves, func(group utls.CurveID) bool { return group == utls.X25519 })
				}
			}
		}},
		{name: "supported groups absent from wire", wantError: "supported_groups", change: func(conn *utls.UConn) {
			conn.Extensions = slices.DeleteFunc(conn.Extensions, func(ext utls.TLSExtension) bool {
				_, ok := ext.(*utls.SupportedCurvesExtension)
				return ok
			})
		}},
		{name: "hybrid public key changed", wantError: "private keys", change: func(conn *utls.UConn) {
			for _, ext := range conn.Extensions {
				if shares, ok := ext.(*utls.KeyShareExtension); ok {
					for i := range shares.KeyShares {
						if shares.KeyShares[i].Group == utls.X25519MLKEM768 {
							shares.KeyShares[i].Data[1215] ^= 1
						}
					}
				}
			}
		}},
		{name: "ML-KEM public key changed", wantError: "private keys", change: func(conn *utls.UConn) {
			for _, ext := range conn.Extensions {
				if shares, ok := ext.(*utls.KeyShareExtension); ok {
					for i := range shares.KeyShares {
						if shares.KeyShares[i].Group == utls.X25519MLKEM768 {
							shares.KeyShares[i].Data[0] ^= 1
						}
					}
				}
			}
		}},
		{name: "duplicate shares", wantError: "duplicate", change: func(conn *utls.UConn) {
			for _, ext := range conn.Extensions {
				if shares, ok := ext.(*utls.KeyShareExtension); ok {
					shares.KeyShares = append(shares.KeyShares, shares.KeyShares[len(shares.KeyShares)-1])
				}
			}
		}},
		{name: "nil private keys", wantError: "private keys", change: func(conn *utls.UConn) { conn.HandshakeState.State13.KeyShareKeys = nil }},
		{name: "missing hybrid private key", wantError: "private keys", change: func(conn *utls.UConn) { conn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe = nil }},
		{name: "wrong hybrid private key", wantError: "private keys", change: func(conn *utls.UConn) { conn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe = serverKey }},
		{name: "wrong independent private key", wantError: "private key", change: func(conn *utls.UConn) { conn.HandshakeState.State13.KeyShareKeys.Ecdhe = serverKey }},
		{name: "malformed raw key share vector", wantError: "malformed", change: func(conn *utls.UConn) {
			for i, ext := range conn.Extensions {
				if _, ok := ext.(*utls.KeyShareExtension); ok {
					conn.Extensions[i] = &utls.GenericExtension{Id: 51, Data: []byte{0, 1, 0}}
				}
			}
		}},
		{name: "malformed raw supported groups", wantError: "malformed", change: func(conn *utls.UConn) {
			for i, ext := range conn.Extensions {
				if _, ok := ext.(*utls.SupportedCurvesExtension); ok {
					conn.Extensions[i] = &utls.GenericExtension{Id: 10, Data: []byte{0, 3, 0, 29}}
				}
			}
		}},
		{name: "short session ID", wantError: "session ID", change: func(conn *utls.UConn) { conn.HandshakeState.Hello.SessionId = make([]byte, 8) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			options := realityTestOptions("chrome")
			options.Reality.PublicKey = base64.RawURLEncoding.EncodeToString(serverKey.PublicKey().Bytes())
			options.Reality.ShortID = "0102030405060708"
			config, err := NewRealityClient(context.Background(), logger.NOP(), "", options)
			require.NoError(t, err)
			realityConfig := config.(*RealityClientConfig)
			raw, err := captureRealityClientHello(t, func(conn net.Conn) error {
				uConfig := realityConfig.uClient.config.Clone()
				uConn := utls.UClient(conn, uConfig, utls.HelloCustom)
				spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
				if err != nil {
					return err
				}
				if err = uConn.ApplyPreset(&spec); err != nil {
					return err
				}
				if test.change != nil {
					test.change(uConn)
				}
				_, err = realityConfig.clientHandshake(context.Background(), uConn, uConfig)
				return err
			})
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				require.Empty(t, raw, "invalid ClientHello must not reach the wire")
				return
			}
			hello := checkRealityWireAuthentication(t, raw, serverKey)
			require.Equal(t, utls.CurveID(0x0a0a), hello.KeyShares[0].Group&0x0f0f, "GREASE may precede hybrid")
		})
	}
}

func TestRealityClientRejectsRetiredFingerprints(t *testing.T) {
	for _, fingerprint := range []string{"chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk"} {
		t.Run(fingerprint, func(t *testing.T) {
			_, err := NewRealityClient(context.Background(), logger.NOP(), "", realityTestOptions(fingerprint))
			require.ErrorContains(t, err, "retired")
			require.ErrorContains(t, err, "chrome")
			_, err = NewUTLSClient(context.Background(), logger.NOP(), "", realityTestOptions(fingerprint))
			require.NoError(t, err, "ordinary uTLS retains legacy aliases")
		})
	}
}

func TestRealityClientRejectsTLS12Configuration(t *testing.T) {
	options := realityTestOptions("chrome")
	options.MaxVersion = "1.2"
	_, err := NewRealityClient(context.Background(), logger.NOP(), "", options)
	require.ErrorContains(t, err, "TLS 1.3")
}

func TestRealityClientRandomizedFailsClosed(t *testing.T) {
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	options := realityTestOptions("randomized")
	options.Reality.PublicKey = base64.RawURLEncoding.EncodeToString(serverKey.PublicKey().Bytes())
	options.Reality.ShortID = "0102030405060708"
	config, err := NewRealityClient(context.Background(), logger.NOP(), "", options)
	require.NoError(t, err)
	realityConfig := config.(*RealityClientConfig)
	// Include the process-wide production seed, followed by deterministic seeds.
	var sent, rejected int
	for i := -1; i < 32; i++ {
		candidate := realityConfig.Clone().(*RealityClientConfig)
		if i >= 0 {
			var seed utls.PRNGSeed
			seed[0] = byte(i)
			candidate.uClient.id.Seed = &seed
		}
		raw, err := captureRealityClientHello(t, func(conn net.Conn) error {
			_, err := candidate.ClientHandshake(context.Background(), conn)
			return err
		})
		if len(raw) == 0 {
			require.ErrorContains(t, err, "X25519MLKEM768")
			rejected++
		} else {
			checkRealityWireAuthentication(t, raw, serverKey)
			sent++
		}
	}
	require.Positive(t, sent, "native compliant randomized output must retain its shares")
	require.Positive(t, rejected, "noncompliant randomized output must fail before sending")
}

func TestRealityPolicyDoesNotChangeOrdinaryUTLS(t *testing.T) {
	for _, fingerprint := range []string{"firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"} {
		t.Run(fingerprint, func(t *testing.T) {
			options := realityTestOptions(fingerprint)
			options.Reality = nil
			config, err := NewUTLSClient(context.Background(), logger.NOP(), "", options)
			require.NoError(t, err)
			raw, _ := captureRealityClientHello(t, func(conn net.Conn) error {
				wrapped, err := config.Client(conn)
				if err != nil {
					return err
				}
				return wrapped.HandshakeContext(context.Background())
			})
			require.NotNil(t, utls.UnmarshalClientHello(raw))
		})
	}
}
