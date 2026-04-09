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

// Handshake performs an X25519 ECDH key exchange over conn and returns the
// derived 32-byte AES-256 key. Both sides call this concurrently after the
// TCP connection is established; the exchange is symmetric so order doesn't matter.
func Handshake(conn net.Conn) ([32]byte, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return [32]byte{}, err
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
		return [32]byte{}, err
	}

	res := <-peerCh
	if res.err != nil {
		return [32]byte{}, res.err
	}

	peerPub, err := ecdh.X25519().NewPublicKey(res.data[:])
	if err != nil {
		return [32]byte{}, err
	}

	shared, err := privKey.ECDH(peerPub)
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
