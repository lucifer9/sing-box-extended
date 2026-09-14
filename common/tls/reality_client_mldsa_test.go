//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/stretchr/testify/require"
)

func TestRealityMLDSAHandshake(t *testing.T) {
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	publicKey, signingKey, err := mldsa65.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyBytes, err := publicKey.MarshalBinary()
	require.NoError(t, err)
	wrongKey, _, err := mldsa65.GenerateKey(rand.Reader)
	require.NoError(t, err)
	wrongBytes, err := wrongKey.MarshalBinary()
	require.NoError(t, err)
	for _, clone := range []bool{false, true} {
		for _, test := range []struct {
			name, fault              string
			disabled, wrong, success bool
		}{
			{name: "signed", success: true},
			{name: "disabled signed", disabled: true, success: true},
			{name: "disabled unsigned", fault: "missing extension", disabled: true, success: true},
			{name: "wrong key", wrong: true},
			{name: "missing extension", fault: "missing extension"},
			{name: "signature", fault: "signature"},
			{name: "short signature", fault: "short signature"},
			{name: "wrapped signature", fault: "wrapped signature"},
			{name: "second extension", fault: "second extension"},
			{name: "client hello", fault: "client hello"},
			{name: "server hello", fault: "server hello"},
			{name: "base signature", fault: "base signature"},
			{name: "empty certificate", fault: "empty certificate"},
			{name: "malformed certificate", fault: "malformed certificate"},
		} {
			name := test.name
			if clone {
				name = "clone/" + name
			}
			t.Run(name, func(t *testing.T) {
				options := realityTestOptions("chrome")
				options.Reality.PublicKey = base64.RawURLEncoding.EncodeToString(serverKey.PublicKey().Bytes())
				if !test.disabled {
					options.Reality.MLDSA65Verify = base64.RawURLEncoding.EncodeToString(keyBytes)
				}
				if test.wrong {
					options.Reality.MLDSA65Verify = base64.RawURLEncoding.EncodeToString(wrongBytes)
				}
				config, err := NewRealityClient(context.Background(), logger.NOP(), "", options)
				require.NoError(t, err)
				if clone {
					config = config.Clone()
				}
				client, server := net.Pipe()
				defer client.Close()
				require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
				peer := realityMLDSAPeer{key: serverKey, signingKey: signingKey, fault: test.fault}
				done := make(chan error, 1)
				go func() { done <- peer.serve(server) }()
				conn, err := ClientHandshake(context.Background(), client, config)
				if !test.success {
					if conn != nil {
						conn.Close()
					}
					client.Close()
					<-done
					require.Error(t, err, "additional authentication must reject before returning a proxy connection")
					require.Nil(t, conn)
					return
				}
				require.NoError(t, err)
				defer conn.Close()
				payload := []byte("authenticated REALITY payload")
				_, err = conn.Write(payload)
				require.NoError(t, err)
				reply := make([]byte, len(payload))
				_, err = io.ReadFull(conn, reply)
				require.NoError(t, err)
				require.Equal(t, payload, reply)
				require.NoError(t, <-done)
			})
		}
	}
}

// A successful ordinary X.509 fallback must never return a proxy connection.
// Root installation is process-global, so isolate it from every other test.
func TestRealityMLDSATrustedFallback(t *testing.T) {
	if os.Getenv("REALITY_TEST_TRUSTED_FALLBACK") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRealityMLDSATrustedFallback$", "-test.count=1")
		cmd.Env = append(os.Environ(), "REALITY_TEST_TRUSTED_FALLBACK=1", "GODEBUG=x509usefallbackroots=1")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", output)
		return
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	require.NoError(t, err)
	packed, err := pub.MarshalBinary()
	require.NoError(t, err)
	options := realityTestOptions("chrome")
	options.Reality.PublicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	options.Reality.MLDSA65Verify = base64.RawURLEncoding.EncodeToString(packed)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config, err := NewRealityClient(ctx, logger.NOP(), "", options)
	require.NoError(t, err)
	client, server := net.Pipe()
	defer client.Close()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	done := make(chan error, 1)
	go func() {
		done <- (realityMLDSAPeer{key: key, signingKey: priv, fault: "signature", trusted: true}).serve(server)
	}()
	conn, err := ClientHandshake(ctx, client, config.Clone())
	require.ErrorContains(t, err, "reality verification failed")
	require.Nil(t, conn)
	cancel()
	client.Close()
	<-done
}

func TestRealityMLDSAConfiguration(t *testing.T) {
	for _, test := range []struct {
		name    string
		key     string
		invalid bool
	}{
		{name: "disabled"},
		{name: "public key", key: base64.RawURLEncoding.EncodeToString(make([]byte, 1952))},
		{name: "invalid encoding", key: "not+a/url-safe-key", invalid: true},
		{name: "padded", key: base64.URLEncoding.EncodeToString(make([]byte, 1952)), invalid: true},
		{name: "seed", key: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), invalid: true},
		{name: "short key", key: base64.RawURLEncoding.EncodeToString(make([]byte, 1951)), invalid: true},
		{name: "long key", key: base64.RawURLEncoding.EncodeToString(make([]byte, 1953)), invalid: true},
		{name: "private key", key: base64.RawURLEncoding.EncodeToString(make([]byte, 4032)), invalid: true},
		{name: "PEM", key: "-----BEGIN PUBLIC KEY-----", invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := realityTestOptions("chrome")
			data, err := json.Marshal(map[string]any{"enabled": true, "public_key": options.Reality.PublicKey, "mldsa65_verify": test.key})
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(data, options.Reality))
			config, err := NewRealityClient(context.Background(), logger.NOP(), "", options)
			if test.invalid {
				require.ErrorContains(t, err, "mldsa65_verify")
				require.Nil(t, config)
				return
			}
			require.NoError(t, err)
			encoded, err := json.Marshal(options.Reality)
			require.NoError(t, err)
			var roundTrip map[string]any
			require.NoError(t, json.Unmarshal(encoded, &roundTrip))
			if test.key != "" {
				require.Equal(t, test.key, roundTrip["mldsa65_verify"])
			}
			var decoded option.OutboundRealityOptions
			require.NoError(t, json.Unmarshal(encoded, &decoded))
			require.Equal(t, *options.Reality, decoded)
		})
	}
}
