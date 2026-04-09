package p2p

import (
	"encoding/json"
	"net"

	"github.io/uncool-dudes/p2p-chat/chat"
	appcrypto "github.io/uncool-dudes/p2p-chat/crypto"
)

// Session is a live, encrypted connection to a single peer.
type Session struct {
	conn   net.Conn
	aesKey [32]byte
}

// Send encodes msg as JSON, encrypts it, and writes a framed message to the peer.
func (s *Session) Send(msg chat.Message) error {
	plaintext, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	frame, err := appcrypto.Encrypt(s.aesKey, plaintext)
	if err != nil {
		return err
	}
	_, err = s.conn.Write(frame)
	return err
}

// Recv blocks until a framed message arrives, decrypts and decodes it.
func (s *Session) Recv() (chat.Message, error) {
	plaintext, err := appcrypto.Decrypt(s.aesKey, s.conn)
	if err != nil {
		return chat.Message{}, err
	}
	var msg chat.Message
	if err := json.Unmarshal(plaintext, &msg); err != nil {
		return chat.Message{}, err
	}
	return msg, nil
}

// Close closes the underlying connection.
func (s *Session) Close() error {
	return s.conn.Close()
}
