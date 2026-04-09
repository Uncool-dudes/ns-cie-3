package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"

	"golang.org/x/crypto/hkdf"
)

const hkdfInfo = "p2p-chat-v1"

// DHKeys holds all key material produced during a DH handshake for logging/inspection.
type DHKeys struct {
	OurPriv []byte
	OurPub  []byte
	PeerPub []byte
	AESKey  [32]byte
}

// Handshake performs an X25519 ECDH key exchange over conn and returns the
// derived 32-byte AES-256 key. Both sides call this concurrently after the
// TCP connection is established; the exchange is symmetric so order doesn't matter.
func Handshake(conn net.Conn) ([32]byte, error) {
	keys, err := HandshakeDetailed(conn)
	return keys.AESKey, err
}

// HandshakeDetailed is like Handshake but also returns all intermediate key material
// so callers can log private keys, public keys, and the derived session key.
func HandshakeDetailed(conn net.Conn) (DHKeys, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return DHKeys{}, err
	}

	pubBytes := privKey.PublicKey().Bytes() // 32 bytes

	// Send our public key, receive peer's public key concurrently.
	type result struct {
		data [32]byte
		err  error
	}
	peerCh := make(chan result, 1)

	go func() {
		var buf [32]byte
		_, err := io.ReadFull(conn, buf[:])
		peerCh <- result{buf, err}
	}()

	if _, err := conn.Write(pubBytes); err != nil {
		return DHKeys{}, err
	}

	res := <-peerCh
	if res.err != nil {
		return DHKeys{}, res.err
	}

	peerPub, err := ecdh.X25519().NewPublicKey(res.data[:])
	if err != nil {
		return DHKeys{}, err
	}

	shared, err := privKey.ECDH(peerPub)
	if err != nil {
		return DHKeys{}, err
	}

	r := hkdf.New(sha256.New, shared, nil, []byte(hkdfInfo))
	var aesKey [32]byte
	if _, err := io.ReadFull(r, aesKey[:]); err != nil {
		return DHKeys{}, err
	}

	return DHKeys{
		OurPriv: privKey.Bytes(),
		OurPub:  pubBytes,
		PeerPub: res.data[:],
		AESKey:  aesKey,
	}, nil
}

// NaiveHandshake is an intentionally insecure key exchange for demos.
// The listener generates a random AES-256 key and sends it in plaintext;
// the dialer reads it back. A passive sniffer on the wire can see the key
// and decrypt every subsequent message — which is exactly the point.
//
// isListener must be true on the accepting side and false on the dialing side.
func NaiveHandshake(conn net.Conn, isListener bool) ([32]byte, error) {
	var key [32]byte
	if isListener {
		if _, err := rand.Read(key[:]); err != nil {
			return [32]byte{}, err
		}
		if _, err := conn.Write(key[:]); err != nil {
			return [32]byte{}, err
		}
	} else {
		if _, err := io.ReadFull(conn, key[:]); err != nil {
			return [32]byte{}, err
		}
	}
	return key, nil
}
