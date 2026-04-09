package p2p

import (
	"fmt"
	"log"
	"net"

	appcrypto "github.io/uncool-dudes/p2p-chat/crypto"
	"github.io/uncool-dudes/p2p-chat/logger"
)

// Listen waits for a single incoming TCP connection on addr and returns a Session.
func Listen(addr string, mode Mode) (*Session, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	defer ln.Close()

	conn, err := ln.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept: %w", err)
	}

	cl, err := logger.NewConnLogger(conn.LocalAddr().String(), conn.RemoteAddr().String())
	if err != nil {
		log.Printf("warning: could not create conn logger: %v", err)
	}

	var key [32]byte
	switch mode {
	case ModeEncrypted:
		keys, err := appcrypto.HandshakeDetailed(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("handshake: %w", err)
		}
		key = keys.AESKey
		if cl != nil {
			cl.LogDHHandshake(keys.OurPriv, keys.OurPub, keys.PeerPub, keys.AESKey[:])
		}
	case ModeNaiveKey:
		key, err = appcrypto.NaiveHandshake(conn, true)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("naive handshake: %w", err)
		}
		if cl != nil {
			cl.LogNaiveHandshake(key[:], true)
		}
	}

	return &Session{conn: conn, aesKey: key, mode: mode, log: cl}, nil
}

// Dial connects to a peer at addr and returns a Session.
func Dial(addr string, mode Mode) (*Session, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	cl, err := logger.NewConnLogger(conn.LocalAddr().String(), conn.RemoteAddr().String())
	if err != nil {
		log.Printf("warning: could not create conn logger: %v", err)
	}

	var key [32]byte
	switch mode {
	case ModeEncrypted:
		keys, err := appcrypto.HandshakeDetailed(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("handshake: %w", err)
		}
		key = keys.AESKey
		if cl != nil {
			cl.LogDHHandshake(keys.OurPriv, keys.OurPub, keys.PeerPub, keys.AESKey[:])
		}
	case ModeNaiveKey:
		key, err = appcrypto.NaiveHandshake(conn, false)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("naive handshake: %w", err)
		}
		if cl != nil {
			cl.LogNaiveHandshake(key[:], false)
		}
	}

	return &Session{conn: conn, aesKey: key, mode: mode, log: cl}, nil
}
