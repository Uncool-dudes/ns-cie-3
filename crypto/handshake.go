package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/hkdf"
)

const hkdfInfo = "p2p-chat-v1"

// handshakeMsg is what each side sends:
//
//	[identity_pub (32 B)] [ephemeral_x25519_pub (32 B)] [sig (64 B)] = 128 bytes total
//
// sig = Ed25519Sign(identity_priv, ephemeral_x25519_pub)
const handshakeMsgSize = ed25519.PublicKeySize + 32 + ed25519.SignatureSize // 128

// Handshake performs an authenticated X25519 ECDH key exchange.
//
// Each side:
//  1. Generates an ephemeral X25519 keypair.
//  2. Signs the ephemeral public key with its Ed25519 identity key.
//  3. Sends [identity_pub | x25519_pub | sig] to the peer.
//  4. Reads the peer's message and verifies the signature against peerIdentity.
//  5. Derives the shared AES-256 session key via HKDF.
//
// The handshake is rejected (conn should be closed by the caller) if the peer's
// identity key doesn't match peerIdentity or the signature is invalid.
func Handshake(conn net.Conn, identity ed25519.PrivateKey, peerIdentity ed25519.PublicKey) ([32]byte, error) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return [32]byte{}, err
	}
	ephemeralPub := ephemeral.PublicKey().Bytes() // 32 bytes

	sig := ed25519.Sign(identity, ephemeralPub) // 64 bytes

	var msg [handshakeMsgSize]byte
	identityPub := identity.Public().(ed25519.PublicKey)
	copy(msg[0:32], identityPub)
	copy(msg[32:64], ephemeralPub)
	copy(msg[64:128], sig)

	// Send our message and receive the peer's message concurrently.
	type result struct {
		data [handshakeMsgSize]byte
		err  error
	}
	peerCh := make(chan result, 1)

	go func() {
		var buf [handshakeMsgSize]byte
		_, err := io.ReadFull(conn, buf[:])
		peerCh <- result{buf, err}
	}()

	if _, err := conn.Write(msg[:]); err != nil {
		return [32]byte{}, err
	}

	res := <-peerCh
	if res.err != nil {
		return [32]byte{}, res.err
	}

	peerIdentityGot := ed25519.PublicKey(res.data[0:32])
	peerEphemeralPub := res.data[32:64]
	peerSig := res.data[64:128]

	// Verify the peer's identity key matches who we expect.
	if !peerIdentityGot.Equal(peerIdentity) {
		return [32]byte{}, fmt.Errorf("handshake: peer identity mismatch — possible MITM")
	}

	// Verify the peer signed their ephemeral key with their identity key.
	if !ed25519.Verify(peerIdentity, peerEphemeralPub, peerSig) {
		return [32]byte{}, fmt.Errorf("handshake: invalid signature — possible MITM")
	}

	peerPub, err := ecdh.X25519().NewPublicKey(peerEphemeralPub)
	if err != nil {
		return [32]byte{}, err
	}

	shared, err := ephemeral.ECDH(peerPub)
	if err != nil {
		return [32]byte{}, err
	}

	r := hkdf.New(sha256.New, shared, nil, []byte(hkdfInfo))
	var aesKey [32]byte
	if _, err := io.ReadFull(r, aesKey[:]); err != nil {
		return [32]byte{}, err
	}

	return aesKey, nil
}
