package p2p

import (
	"crypto/ed25519"
	"fmt"
	"net"

	appcrypto "github.io/uncool-dudes/p2p-chat/crypto"
)

// Listen waits for a single incoming TCP connection on addr, performs the
// authenticated DH handshake, and returns an encrypted Session.
func Listen(addr string, identity ed25519.PrivateKey, peerIdentity ed25519.PublicKey) (*Session, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	defer ln.Close()

	conn, err := ln.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept: %w", err)
	}

	key, err := appcrypto.Handshake(conn, identity, peerIdentity)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	return &Session{conn: conn, aesKey: key}, nil
}

// Dial connects to a peer at addr, performs the authenticated DH handshake,
// and returns an encrypted Session.
func Dial(addr string, identity ed25519.PrivateKey, peerIdentity ed25519.PublicKey) (*Session, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	key, err := appcrypto.Handshake(conn, identity, peerIdentity)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	return &Session{conn: conn, aesKey: key}, nil
}
