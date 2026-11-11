//go:build with_utls

package tls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
)

// This bounded wire peer supports only TLS 1.3/X25519/AES-128-GCM. Keeping
// CertificateVerify and Finished valid while changing REALITY authentication
// distinguishes authentication rejection from an unrelated TLS failure. The
// signature contract is pinned to XTLS/REALITY@8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8.
type realityMLDSAPeer struct {
	key        *ecdh.PrivateKey
	signingKey *mldsa65.PrivateKey
	fault      string
	trusted    bool
}

func realityVector(n int, data []byte) []byte {
	header := make([]byte, n)
	for i := n - 1; i >= 0; i-- {
		header[i] = byte(len(data) >> (8 * (n - 1 - i)))
	}
	return append(header, data...)
}

func realityHandshakeMessage(kind byte, body []byte) []byte {
	return append([]byte{kind}, realityVector(3, body)...)
}

func realityExpand(secret []byte, label string, context []byte, size int) []byte {
	info := binary.BigEndian.AppendUint16(nil, uint16(size))
	info = append(info, realityVector(1, []byte("tls13 "+label))...)
	info = append(info, realityVector(1, context)...)
	result := make([]byte, size)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, secret, info), result); err != nil {
		panic(err)
	}
	return result
}

func realityDigest(data []byte) []byte { h := sha256.Sum256(data); return h[:] }
func realityMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

type realityRecordCipher struct {
	aead cipher.AEAD
	iv   []byte
	seq  uint64
}

func newRealityRecordCipher(secret []byte) *realityRecordCipher {
	block, err := aes.NewCipher(realityExpand(secret, "key", nil, 16))
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return &realityRecordCipher{aead: aead, iv: realityExpand(secret, "iv", nil, 12)}
}

func (c *realityRecordCipher) nonce() []byte {
	nonce := bytes.Clone(c.iv)
	binary.BigEndian.PutUint64(nonce[4:], binary.BigEndian.Uint64(nonce[4:])^c.seq)
	c.seq++
	return nonce
}

func realityReadRecord(conn net.Conn) ([]byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(header[3:]))
	_, err := io.ReadFull(conn, body)
	return header, body, err
}

func realityWriteRecord(conn net.Conn, kind byte, body []byte) error {
	record := append([]byte{kind, 3, 3}, realityVector(2, body)...)
	_, err := conn.Write(record)
	return err
}

func (c *realityRecordCipher) write(conn net.Conn, kind byte, body []byte) error {
	plain := append(bytes.Clone(body), kind)
	header := binary.BigEndian.AppendUint16([]byte{23, 3, 3}, uint16(len(plain)+c.aead.Overhead()))
	_, err := conn.Write(append(header, c.aead.Seal(nil, c.nonce(), plain, header)...))
	return err
}

func (c *realityRecordCipher) read(conn net.Conn) (byte, []byte, error) {
	for {
		header, body, err := realityReadRecord(conn)
		if err != nil {
			return 0, nil, err
		}
		if header[0] == 20 {
			continue
		} // TLS compatibility ChangeCipherSpec.
		if header[0] != 23 {
			return 0, nil, fmt.Errorf("unexpected record type %d", header[0])
		}
		plain, err := c.aead.Open(nil, c.nonce(), body, header)
		if err != nil {
			return 0, nil, err
		}
		for len(plain) > 0 && plain[len(plain)-1] == 0 {
			plain = plain[:len(plain)-1]
		}
		if len(plain) == 0 {
			return 0, nil, fmt.Errorf("empty TLSInnerPlaintext")
		}
		return plain[len(plain)-1], plain[:len(plain)-1], nil
	}
}

func (p realityMLDSAPeer) serve(conn net.Conn) error {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	header, ch, err := realityReadRecord(conn)
	if err != nil {
		return err
	}
	if header[0] != 22 {
		return fmt.Errorf("expected ClientHello")
	}
	hello := utls.UnmarshalClientHello(ch)
	if hello == nil {
		return fmt.Errorf("malformed ClientHello")
	}
	var share []byte
	for _, candidate := range hello.KeyShares {
		if candidate.Group == utls.X25519 {
			share = candidate.Data
		}
	}
	if share == nil {
		return fmt.Errorf("fixture requires independent X25519 share")
	}
	peer, err := ecdh.X25519().NewPublicKey(share)
	if err != nil {
		return err
	}
	authKey, err := p.key.ECDH(peer)
	if err != nil {
		return err
	}
	if _, err = io.ReadFull(hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")), authKey); err != nil {
		return err
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	shared, err := ephemeral.ECDH(peer)
	if err != nil {
		return err
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return err
	}
	serverHello := &utls.PubServerHelloMsg{Vers: utls.VersionTLS12, Random: random, SessionId: hello.SessionId, CipherSuite: utls.TLS_AES_128_GCM_SHA256, SupportedVersion: utls.VersionTLS13, ServerShare: utls.KeyShare{Group: utls.X25519, Data: ephemeral.PublicKey().Bytes()}}
	sh, err := serverHello.Marshal()
	if err != nil {
		return err
	}
	transcript := append(bytes.Clone(ch), sh...)
	zero := make([]byte, 32)
	early := hkdf.Extract(sha256.New, zero, nil)
	handshakeSecret := hkdf.Extract(sha256.New, shared, realityExpand(early, "derived", realityDigest(nil), 32))
	serverSecret := realityExpand(handshakeSecret, "s hs traffic", realityDigest(transcript), 32)
	clientSecret := realityExpand(handshakeSecret, "c hs traffic", realityDigest(transcript), 32)
	serverRecords, clientRecords := newRealityRecordCipher(serverSecret), newRealityRecordCipher(clientSecret)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	h := hmac.New(sha512.New, authKey)
	h.Write(pub)
	baseSignature := h.Sum(nil)
	signedCH, signedSH := bytes.Clone(ch), bytes.Clone(sh)
	if p.fault == "client hello" {
		signedCH[len(signedCH)-1] ^= 1
	}
	if p.fault == "server hello" {
		signedSH[len(signedSH)-1] ^= 1
	}
	h.Write(signedCH)
	h.Write(signedSH)
	signature := make([]byte, mldsa65.SignatureSize)
	if err = mldsa65.SignTo(p.signingKey, h.Sum(nil), nil, false, signature); err != nil {
		return err
	}
	switch p.fault {
	case "signature":
		signature[0] ^= 1
	case "short signature":
		signature = signature[:len(signature)-1]
	case "wrapped signature":
		signature = append([]byte{4, 130, 12, 237}, signature...)
	case "base signature":
		baseSignature[0] ^= 1
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), ExtraExtensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}, Value: signature}}}
	if p.fault == "missing extension" {
		cert.ExtraExtensions = nil
	}
	if p.fault == "second extension" {
		cert.ExtraExtensions = append([]pkix.Extension{{Id: []int{1, 2, 3, 5}, Value: []byte{0}}}, cert.ExtraExtensions...)
	}
	if p.trusted {
		cert.DNSNames = []string{"example.com"}
		cert.NotBefore = time.Now().Add(-time.Hour)
		cert.NotAfter = time.Now().Add(time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, priv)
	if err != nil {
		return err
	}
	copy(der[len(der)-ed25519.SignatureSize:], baseSignature)
	if p.trusted {
		parsed, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			return parseErr
		}
		roots := x509.NewCertPool()
		roots.AddCert(parsed)
		// Only invoked in a subprocess: never alter the parent test suite's roots.
		x509.SetFallbackRoots(roots)
		if _, verifyErr := parsed.Verify(x509.VerifyOptions{DNSName: "example.com"}); verifyErr != nil {
			return fmt.Errorf("trusted fixture: %w", verifyErr)
		}
	}
	certEntry := append(realityVector(3, der), 0, 0)
	certMessage := realityHandshakeMessage(11, append([]byte{0}, realityVector(3, certEntry)...))
	if p.fault == "empty certificate" {
		certMessage = realityHandshakeMessage(11, []byte{0, 0, 0, 0})
	}
	if p.fault == "malformed certificate" {
		certMessage = realityHandshakeMessage(11, append([]byte{0}, realityVector(3, []byte{0, 0, 1, 0, 0, 0})...))
	}
	encryptedExtensions := realityHandshakeMessage(8, []byte{0, 0})
	transcript = append(transcript, encryptedExtensions...)
	transcript = append(transcript, certMessage...)
	cvInput := append(bytes.Repeat([]byte{32}, 64), []byte("TLS 1.3, server CertificateVerify\x00")...)
	cvInput = append(cvInput, realityDigest(transcript)...)
	cv := realityHandshakeMessage(15, append([]byte{8, 7}, realityVector(2, ed25519.Sign(priv, cvInput))...))
	transcript = append(transcript, cv...)
	finished := realityHandshakeMessage(20, realityMAC(realityExpand(serverSecret, "finished", nil, 32), realityDigest(transcript)))
	transcript = append(transcript, finished...)
	master := hkdf.Extract(sha256.New, zero, realityExpand(handshakeSecret, "derived", realityDigest(nil), 32))
	serverApp := newRealityRecordCipher(realityExpand(master, "s ap traffic", realityDigest(transcript), 32))
	clientApp := newRealityRecordCipher(realityExpand(master, "c ap traffic", realityDigest(transcript), 32))
	if err = realityWriteRecord(conn, 22, sh); err != nil {
		return err
	}
	flight := append(bytes.Clone(encryptedExtensions), certMessage...)
	flight = append(flight, cv...)
	flight = append(flight, finished...)
	if err = serverRecords.write(conn, 22, flight); err != nil {
		return err
	}
	kind, clientFinished, err := clientRecords.read(conn)
	if err != nil {
		return err
	}
	expected := realityHandshakeMessage(20, realityMAC(realityExpand(clientSecret, "finished", nil, 32), realityDigest(transcript)))
	if kind != 22 || !hmac.Equal(clientFinished, expected) {
		return fmt.Errorf("invalid client Finished")
	}
	kind, payload, err := clientApp.read(conn)
	if err != nil {
		return err
	}
	if kind != 23 {
		return fmt.Errorf("expected application payload, got %d", kind)
	}
	return serverApp.write(conn, 23, payload)
}
