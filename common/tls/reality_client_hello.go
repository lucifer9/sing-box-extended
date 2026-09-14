//go:build with_utls

package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"encoding/binary"
	"slices"

	E "github.com/sagernet/sing/common/exceptions"

	utls "github.com/metacubex/utls"
)

// Each spec owns its extensions: uTLS ApplyPreset fills them with fresh keys.
// Do not constrain shared weights: even weight 1 can return false in uTLS v1.8.7
// (u_prng.go, FlipWeightedCoin). Constrain the generated spec before key generation.
func realityRandomizedSpec(id utls.ClientHelloID, nextProtos []string) (*utls.ClientHelloSpec, error) {
	if id.Seed == nil {
		return nil, E.New("REALITY randomized fingerprint: missing seed")
	}
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return nil, E.Cause(err, "REALITY randomized fingerprint")
	}
	if spec.TLSVersMax != utls.VersionTLS13 {
		return nil, E.New("REALITY randomized fingerprint: TLS 1.3 is required")
	}
	var curves *utls.SupportedCurvesExtension
	var shares *utls.KeyShareExtension
	for _, extension := range spec.Extensions {
		switch extension := extension.(type) {
		case *utls.SupportedCurvesExtension:
			curves = extension
		case *utls.KeyShareExtension:
			shares = extension
		case *utls.ALPNExtension:
			if len(nextProtos) > 0 {
				extension.AlpnProtocols = slices.Clone(nextProtos)
			}
		}
	}
	if len(nextProtos) > 0 {
		// UTLSIdToSpec assumes h2/http1.1. Keep ALPS consistent with the
		// configured ALPN without adding ALPN when this seed omitted it.
		spec.Extensions = slices.DeleteFunc(spec.Extensions, func(extension utls.TLSExtension) bool {
			alps, ok := extension.(*utls.ApplicationSettingsExtension)
			if !ok {
				return false
			}
			alps.SupportedProtocols = slices.DeleteFunc(alps.SupportedProtocols, func(protocol string) bool {
				return !slices.Contains(nextProtos, protocol)
			})
			return len(alps.SupportedProtocols) == 0
		})
	}
	if curves == nil || shares == nil {
		return nil, E.New("REALITY randomized fingerprint: missing supported_groups or key_share")
	}
	if !slices.Contains(curves.Curves, utls.X25519MLKEM768) {
		curves.Curves = append([]utls.CurveID{utls.X25519MLKEM768}, curves.Curves...)
	}
	shares.KeyShares = append([]utls.KeyShare{{Group: utls.X25519MLKEM768}},
		slices.DeleteFunc(shares.KeyShares, func(share utls.KeyShare) bool {
			return share.Group == utls.X25519MLKEM768
		})...)
	return &spec, nil
}

// The wire layout and authentication preference follow Xray-core v26.9.9
// (52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120, transport/internet/reality/reality.go)
// and XTLS/REALITY (8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8, tls.go).
// In uTLS v1.8.7 the hybrid share is ML-KEM's encapsulation key followed by
// X25519's public key. The ML-KEM shared secret is NOT the REALITY auth key.
func realityAuthenticationKey(raw []byte, keys *utls.KeySharePrivateKeys) (*ecdh.PrivateKey, error) {
	invalid := func(reason string) (*ecdh.PrivateKey, error) {
		return nil, E.New("REALITY ClientHello: ", reason, "; requires X25519MLKEM768 before optional X25519; use a compliant fingerprint such as chrome")
	}
	if len(raw) < 4 || raw[0] != 1 || int(binary.BigEndian.Uint32(raw[:4])&0xffffff) != len(raw)-4 {
		return invalid("malformed handshake length")
	}
	hello := utls.UnmarshalClientHello(raw)
	if hello == nil || len(hello.Random) != 32 || len(hello.SessionId) != 32 {
		return invalid("malformed handshake or session ID")
	}
	if !slices.Contains(hello.SupportedVersions, utls.VersionTLS13) {
		return invalid("TLS 1.3 is required")
	}
	var hybrid, independent []byte
	seen := make(map[utls.CurveID]bool)
	for _, share := range hello.KeyShares {
		if seen[share.Group] || !slices.Contains(hello.SupportedCurves, share.Group) {
			return invalid("duplicate key share or key share absent from supported_groups")
		}
		seen[share.Group] = true
		switch share.Group {
		case utls.X25519MLKEM768:
			if independent != nil || len(share.Data) != mlkem.EncapsulationKeySize768+32 {
				return invalid("invalid hybrid key share length or order")
			}
			hybrid = share.Data
		case utls.X25519:
			if len(share.Data) != 32 {
				return invalid("invalid X25519 key share length")
			}
			independent = share.Data
		}
	}
	if hybrid == nil {
		return invalid("missing hybrid key share")
	}
	if keys == nil || keys.Mlkem == nil || keys.MlkemEcdhe == nil ||
		keys.MlkemEcdhe.Curve() != ecdh.X25519() ||
		!bytes.Equal(keys.Mlkem.EncapsulationKey().Bytes(), hybrid[:mlkem.EncapsulationKeySize768]) ||
		!bytes.Equal(keys.MlkemEcdhe.PublicKey().Bytes(), hybrid[mlkem.EncapsulationKeySize768:]) {
		return invalid("hybrid private keys do not match the sent public key")
	}
	if independent != nil {
		if keys.Ecdhe == nil || keys.Ecdhe.Curve() != ecdh.X25519() || !bytes.Equal(keys.Ecdhe.PublicKey().Bytes(), independent) {
			return invalid("X25519 private key does not match the sent public key")
		}
		return keys.Ecdhe, nil
	}
	return keys.MlkemEcdhe, nil
}
