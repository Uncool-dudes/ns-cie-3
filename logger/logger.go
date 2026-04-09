package logger

import (
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ConnLogger writes structured JSON logs for a single connection to its own file.
type ConnLogger struct {
	log  *zap.Logger
	file *os.File
}

// NewConnLogger creates a new log file under ./logs/ named by timestamp and remote address.
// A fresh file is created for every call, so each connection gets its own log.
func NewConnLogger(localAddr, remoteAddr string) (*ConnLogger, error) {
	if err := os.MkdirAll("logs", 0755); err != nil {
		return nil, fmt.Errorf("create logs dir: %w", err)
	}

	ts := time.Now().Format("20060102_150405")
	safe := strings.NewReplacer(":", "_", ".", "_", "/", "_").Replace(remoteAddr)
	path := fmt.Sprintf("logs/conn_%s_%s.log", ts, safe)

	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create log file %s: %w", path, err)
	}

	enc := zapcore.NewJSONEncoder(zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		MessageKey:     "event",
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
	})
	core := zapcore.NewCore(enc, zapcore.AddSync(f), zapcore.DebugLevel)
	log := zap.New(core)

	log.Info("connection_opened",
		zap.String("local_addr", localAddr),
		zap.String("remote_addr", remoteAddr),
		zap.String("log_file", path),
	)

	return &ConnLogger{log: log, file: f}, nil
}

// LogDHHandshake records all X25519 key material produced during the DH handshake.
func (l *ConnLogger) LogDHHandshake(ourPriv, ourPub, peerPub, aesKey []byte) {
	l.log.Info("dh_handshake",
		zap.String("our_private_key_hex", fmt.Sprintf("%x", ourPriv)),
		zap.String("our_public_key_hex", fmt.Sprintf("%x", ourPub)),
		zap.String("peer_public_key_hex", fmt.Sprintf("%x", peerPub)),
		zap.String("derived_aes256_key_hex", fmt.Sprintf("%x", aesKey)),
		zap.String("note", "private key logged for Wireshark verification only — never share this"),
	)
}

// LogNaiveHandshake records the plaintext key exchange used in --no-diffie mode.
func (l *ConnLogger) LogNaiveHandshake(aesKey []byte, isListener bool) {
	role := "dialer (received key)"
	if isListener {
		role = "listener (generated and sent key)"
	}
	l.log.Info("naive_handshake",
		zap.String("role", role),
		zap.String("aes256_key_hex", fmt.Sprintf("%x", aesKey)),
		zap.String("note", "key transmitted in plaintext — any sniffer with this log can decrypt all frames"),
	)
}

// LogSent records an outgoing encrypted frame alongside its plaintext.
// wireFrame is the exact bytes written to the TCP stream (4-byte len + nonce + ciphertext+tag).
func (l *ConnLogger) LogSent(plaintext, wireFrame []byte) {
	l.log.Info("sent",
		zap.String("plaintext", string(plaintext)),
		zap.String("wire_frame_hex", fmt.Sprintf("%x", wireFrame)),
		zap.Int("wire_bytes", len(wireFrame)),
	)
}

// LogReceived records an incoming encrypted frame alongside its decrypted plaintext.
// wireFrame is the exact bytes read from the TCP stream.
func (l *ConnLogger) LogReceived(wireFrame, plaintext []byte) {
	l.log.Info("received",
		zap.String("wire_frame_hex", fmt.Sprintf("%x", wireFrame)),
		zap.Int("wire_bytes", len(wireFrame)),
		zap.String("plaintext", string(plaintext)),
	)
}

// LogPlaintextSent records an outgoing frame in --no-encrypt mode (no encryption).
func (l *ConnLogger) LogPlaintextSent(data []byte) {
	l.log.Info("sent_plaintext_mode",
		zap.String("content", string(data)),
		zap.String("wire_data_hex", fmt.Sprintf("%x", data)),
	)
}

// LogPlaintextReceived records an incoming frame in --no-encrypt mode.
func (l *ConnLogger) LogPlaintextReceived(data []byte) {
	l.log.Info("received_plaintext_mode",
		zap.String("wire_data_hex", fmt.Sprintf("%x", data)),
		zap.String("content", string(data)),
	)
}

// Sync flushes and closes the log file.
func (l *ConnLogger) Sync() {
	_ = l.log.Sync()
	_ = l.file.Close()
}
