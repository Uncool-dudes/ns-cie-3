package p2p

import (
	"bytes"
	"encoding/json"
	"io"
	"net"

	"github.io/uncool-dudes/p2p-chat/chat"
	appcrypto "github.io/uncool-dudes/p2p-chat/crypto"
	"github.io/uncool-dudes/p2p-chat/logger"
)

// Mode controls how a Session exchanges keys and encrypts messages.
type Mode int

const (
	// ModeEncrypted uses X25519 DH key exchange + AES-256-GCM. Default.
	ModeEncrypted Mode = iota
	// ModePlaintext skips both key exchange and encryption. A sniffer sees raw JSON.
	ModePlaintext
	// ModeNaiveKey sends the AES key in plaintext then encrypts messages with it.
	// Traffic looks encrypted but a sniffer that captured the handshake can decrypt
	// everything — demonstrating what DH actually protects against.
	ModeNaiveKey
)

// Session is a live connection to a single peer.
type Session struct {
	conn   net.Conn
	aesKey [32]byte
	mode   Mode
	log    *logger.ConnLogger
}

// Send encodes msg as JSON and writes it to the peer.
func (s *Session) Send(msg chat.Message) error {
	plaintext, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	switch s.mode {
	case ModeEncrypted, ModeNaiveKey:
		frame, err := appcrypto.Encrypt(s.aesKey, plaintext)
		if err != nil {
			return err
		}
		if s.log != nil {
			s.log.LogSent(plaintext, frame)
		}
		_, err = s.conn.Write(frame)
		return err
	default: // ModePlaintext
		if s.log != nil {
			s.log.LogPlaintextSent(plaintext)
		}
		return appcrypto.WriteFrame(s.conn, plaintext)
	}
}

// Recv blocks until a framed message arrives and decodes it.
func (s *Session) Recv() (chat.Message, error) {
	var plaintext []byte
	var err error
	switch s.mode {
	case ModeEncrypted, ModeNaiveKey:
		// TeeReader captures the raw wire bytes (length prefix + nonce + ciphertext)
		// so we can log exactly what Wireshark would see on the wire.
		var captured bytes.Buffer
		tee := io.TeeReader(s.conn, &captured)
		plaintext, err = appcrypto.Decrypt(s.aesKey, tee)
		if err == nil && s.log != nil {
			s.log.LogReceived(captured.Bytes(), plaintext)
		}
	default: // ModePlaintext
		plaintext, err = appcrypto.ReadFrame(s.conn)
		if err == nil && s.log != nil {
			s.log.LogPlaintextReceived(plaintext)
		}
	}
	if err != nil {
		return chat.Message{}, err
	}
	var msg chat.Message
	if err := json.Unmarshal(plaintext, &msg); err != nil {
		return chat.Message{}, err
	}
	return msg, nil
}

// Close closes the underlying connection and flushes the log.
func (s *Session) Close() error {
	if s.log != nil {
		s.log.Sync()
	}
	return s.conn.Close()
}
