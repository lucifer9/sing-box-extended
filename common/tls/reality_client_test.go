//go:build with_utls

package tls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
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
			_, err := mlkem.NewEncapsulationKey768(share.Data[:1184])
			require.NoError(t, err, "wire ML-KEM encapsulation key must be valid")
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

// Preserve all wire fields, including extension order, except fresh cryptographic
// material. cryptobyte slices alias the copy, never the captured authentication AAD.
func realityRandomizedWireShape(t *testing.T, raw []byte) []byte {
	t.Helper()
	shape := slices.Clone(raw)
	input := cryptobyte.String(shape)
	require.True(t, input.Skip(6)) // handshake header and legacy version
	var random []byte
	var session, ciphers, compression, extensions cryptobyte.String
	require.True(t, input.ReadBytes(&random, 32))
	require.True(t, input.ReadUint8LengthPrefixed(&session))
	clear(random)
	clear(session)
	require.True(t, input.ReadUint16LengthPrefixed(&ciphers))
	require.True(t, input.ReadUint8LengthPrefixed(&compression))
	require.True(t, input.ReadUint16LengthPrefixed(&extensions))
	require.True(t, input.Empty())
	for !extensions.Empty() {
		var id uint16
		var data cryptobyte.String
		require.True(t, extensions.ReadUint16(&id))
		require.True(t, extensions.ReadUint16LengthPrefixed(&data))
		if id != 51 {
			continue
		}
		var shares cryptobyte.String
		require.True(t, data.ReadUint16LengthPrefixed(&shares))
		require.True(t, data.Empty())
		for !shares.Empty() {
			var group uint16
			var public cryptobyte.String
			require.True(t, shares.ReadUint16(&group))
			require.True(t, shares.ReadUint16LengthPrefixed(&public))
			clear(public)
		}
	}
	return shape
}

func TestRealityClientRandomizedSendsAuthenticatedHybridClientHello(t *testing.T) {
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	globalID := randomizedFingerprint
	globalSeed, globalWeights, defaults := *globalID.Seed, *globalID.Weights, utls.DefaultWeights
	defer func() {
		require.Equal(t, globalID, randomizedFingerprint)
		require.Equal(t, globalSeed, *randomizedFingerprint.Seed)
		require.Equal(t, globalWeights, *randomizedFingerprint.Weights)
		require.Equal(t, defaults, utls.DefaultWeights)
	}()
	shapes := make(map[string]bool)
	p256 := make(map[bool]bool)
	for i := -1; i < 32; i++ {
		seed := globalSeed
		name := "process"
		if i >= 0 {
			seed = utls.PRNGSeed{}
			seed[0] = byte(i)
			name = fmt.Sprintf("seed-%02x", i)
		}
		t.Run(name, func(t *testing.T) {
			options := realityTestOptions("randomized")
			options.Reality.PublicKey = base64.RawURLEncoding.EncodeToString(serverKey.PublicKey().Bytes())
			options.Reality.ShortID = "0102030405060708"
			options.ALPN = []string{"h2", "http/1.1"}
			originalOptions := options
			originalUTLS, originalReality := *options.UTLS, *options.Reality
			originalOptions.UTLS, originalOptions.Reality = &originalUTLS, &originalReality
			originalOptions.ALPN = slices.Clone(options.ALPN)
			ordinaryShape := func() []byte {
				config, err := NewUTLSClient(context.Background(), logger.NOP(), "", options)
				require.NoError(t, err)
				localSeed := seed
				config.(*UTLSClientConfig).id.Seed = &localSeed
				raw, err := captureRealityClientHello(t, func(conn net.Conn) error {
					wrapped, err := config.Client(conn)
					if err != nil {
						return err
					}
					return wrapped.HandshakeContext(context.Background())
				})
				require.Error(t, err)
				require.NotNil(t, utls.UnmarshalClientHello(raw))
				require.Equal(t, seed, localSeed)
				return realityRandomizedWireShape(t, raw)
			}
			before := ordinaryShape()
			config, err := NewRealityClient(context.Background(), logger.NOP(), "", options)
			require.NoError(t, err)
			candidate := config.(*RealityClientConfig)
			localSeed := seed
			candidate.uClient.id.Seed = &localSeed
			clone := candidate.Clone().(*RealityClientConfig)
			var firstShape []byte
			seenCrypto := make(map[string]bool)
			for _, client := range []*RealityClientConfig{candidate, clone} {
				for range 2 {
					raw, err := captureRealityClientHello(t, func(conn net.Conn) error {
						_, err := client.ClientHandshake(context.Background(), conn)
						return err
					})
					require.Error(t, err, "capture peer closes without a ServerHello")
					hello := checkRealityWireAuthentication(t, raw, serverKey)
					shape := realityRandomizedWireShape(t, raw)
					if firstShape == nil {
						firstShape = shape
					}
					require.Equal(t, firstShape, shape)
					material := [][]byte{hello.Random, hello.SessionId}
					hasP256 := false
					for _, share := range hello.KeyShares {
						hasP256 = hasP256 || share.Group == utls.CurveP256
						if share.Group == utls.X25519MLKEM768 {
							material = append(material, share.Data[:1184], share.Data[1184:])
						} else {
							material = append(material, share.Data)
						}
					}
					for _, public := range material {
						require.False(t, seenCrypto[string(public)], "ephemeral material must be fresh")
						seenCrypto[string(public)] = true
					}
					if i >= 0 {
						p256[hasP256] = true
						shapes[string(shape)] = true
					}
					require.Equal(t, seed, *client.uClient.id.Seed)
					require.Equal(t, seed, localSeed)
				}
			}
			require.Equal(t, before, ordinaryShape(), "REALITY must not change ordinary randomized uTLS")
			require.Equal(t, originalOptions, options, "caller options must remain unchanged")
		})
	}
	require.Len(t, p256, 2, "fixed corpus must exercise optional P-256 both present and absent")
	require.Greater(t, len(shapes), 1, "different seeds must retain different fingerprints")
}

func TestRealityRandomizedGenerationBoundaries(t *testing.T) {
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	for _, name := range []string{"missing-hybrid", "TLS12", "nil-seed"} {
		t.Run(name, func(t *testing.T) {
			options := realityTestOptions("randomized")
			options.Reality.PublicKey = base64.RawURLEncoding.EncodeToString(serverKey.PublicKey().Bytes())
			options.Reality.ShortID = "0102030405060708"
			config, err := NewRealityClient(context.Background(), logger.NOP(), "", options)
			require.NoError(t, err)
			candidate := config.(*RealityClientConfig)
			seed := utls.PRNGSeed{}
			weights := *candidate.uClient.id.Weights
			candidate.uClient.id.Seed, candidate.uClient.id.Weights = &seed, &weights
			wantError := ""
			switch name {
			case "missing-hybrid":
				weights.CurveIDs_Append_X25519 = 0
				weights.KeyShare_Append_RandomGroups = 0
				ordinary, err := NewUTLSClient(context.Background(), logger.NOP(), "", options)
				require.NoError(t, err)
				ordinary.(*UTLSClientConfig).id = candidate.uClient.id
				raw, err := captureRealityClientHello(t, func(conn net.Conn) error {
					wrapped, err := ordinary.Client(conn)
					if err != nil {
						return err
					}
					return wrapped.HandshakeContext(context.Background())
				})
				require.Error(t, err)
				hello := utls.UnmarshalClientHello(raw)
				require.NotNil(t, hello)
				require.NotContains(t, hello.SupportedCurves, utls.X25519MLKEM768)
				for _, share := range hello.KeyShares {
					require.NotEqual(t, utls.X25519MLKEM768, share.Group)
				}
			case "TLS12":
				weights.TLSVersMax_Set_VersionTLS13 = 0
				wantError = "TLS 1.3"
			case "nil-seed":
				candidate.uClient.id.Seed = nil
				wantError = "seed"
			}
			raw, err := captureRealityClientHello(t, func(conn net.Conn) error {
				_, err := candidate.ClientHandshake(context.Background(), conn)
				return err
			})
			if wantError != "" {
				require.ErrorContains(t, err, wantError)
				require.Empty(t, raw, "invalid generated hello must fail before sending")
				return
			}
			require.Error(t, err)
			checkRealityWireAuthentication(t, raw, serverKey)
			require.Equal(t, utls.PRNGSeed{}, seed)
			require.Equal(t, float64(0), weights.CurveIDs_Append_X25519)
			require.Equal(t, float64(0), weights.KeyShare_Append_RandomGroups)
		})
	}
}

func TestRealityRandomizedRetainsGenerationWeights(t *testing.T) {
	id := randomizedFingerprint
	weights := *id.Weights
	seed := *id.Seed
	defaults := utls.DefaultWeights
	options := realityTestOptions("randomized")
	config, err := NewRealityClient(context.Background(), logger.NOP(), "", options)
	require.NoError(t, err)
	candidate := config.(*RealityClientConfig)
	require.Equal(t, weights, *candidate.uClient.id.Weights)
	require.Same(t, id.Seed, candidate.uClient.id.Seed)
	require.Same(t, id.Seed, candidate.Clone().(*RealityClientConfig).uClient.id.Seed)
	require.Equal(t, weights, *randomizedFingerprint.Weights)
	require.Equal(t, seed, *randomizedFingerprint.Seed)
	require.Equal(t, defaults, utls.DefaultWeights)
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
