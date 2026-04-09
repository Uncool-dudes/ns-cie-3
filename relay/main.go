package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.io/uncool-dudes/p2p-chat/chat"
	appcrypto "github.io/uncool-dudes/p2p-chat/crypto"
)

func main() {
	addr := flag.String("listen", ":5000", "relay listen address")
	logFile := flag.String("log", "", "path to log file (default: stdout only)")
	noEncrypt := flag.Bool("no-encrypt", false, "disable DH key exchange — relay passes plaintext frames (demo/sniffer mode)")
	noDiffie := flag.Bool("no-diffie", false, "naive key exchange — relay exchanges AES keys in plaintext then re-encrypts")
	flag.Parse()

	type relayMode int
	const (
		modeEncrypted relayMode = iota
		modePlaintext
		modeNaiveKey
	)
	mode := modeEncrypted
	switch {
	case *noEncrypt:
		mode = modePlaintext
	case *noDiffie:
		mode = modeNaiveKey
	}
	encrypt := mode == modeEncrypted || mode == modeNaiveKey

	log := buildLogger(*logFile)
	defer log.Sync() //nolint:errcheck

	log.Info("relay starting", zap.String("addr", *addr))

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal("listen failed", zap.Error(err))
	}
	defer ln.Close()

	log.Info("waiting for peer A")
	connA, err := ln.Accept()
	if err != nil {
		log.Fatal("accept peer A failed", zap.Error(err))
	}
	log.Info("peer A connected", zap.String("remote", connA.RemoteAddr().String()))

	log.Info("waiting for peer B")
	connB, err := ln.Accept()
	if err != nil {
		log.Fatal("accept peer B failed", zap.Error(err))
	}
	log.Info("peer B connected", zap.String("remote", connB.RemoteAddr().String()))

	log.Info("performing handshakes")

	type handshakeResult struct {
		key [32]byte
		err error
	}

	chA := make(chan handshakeResult, 1)
	chB := make(chan handshakeResult, 1)

	go func() {
		var key [32]byte
		var err error
		switch mode {
		case modeEncrypted:
			key, err = appcrypto.Handshake(connA)
		case modeNaiveKey:
			// Relay acts as listener toward A: sends the key in plaintext.
			key, err = appcrypto.NaiveHandshake(connA, true)
		}
		chA <- handshakeResult{key, err}
	}()
	go func() {
		var key [32]byte
		var err error
		switch mode {
		case modeEncrypted:
			key, err = appcrypto.Handshake(connB)
		case modeNaiveKey:
			// Relay acts as listener toward B: sends a different key in plaintext.
			key, err = appcrypto.NaiveHandshake(connB, true)
		}
		chB <- handshakeResult{key, err}
	}()

	resA := <-chA
	if resA.err != nil {
		log.Fatal("handshake with peer A failed", zap.Error(resA.err))
	}
	resB := <-chB
	if resB.err != nil {
		log.Fatal("handshake with peer B failed", zap.Error(resB.err))
	}

	log.Info("both handshakes complete — relaying messages")

	done := make(chan struct{}, 2)

	// A → B
	go relay(log, "A", "B", connA, connB, resA.key, resB.key, encrypt, done)
	// B → A
	go relay(log, "B", "A", connB, connA, resB.key, resA.key, encrypt, done)

	// Block until one direction closes.
	<-done
	log.Info("a relay direction closed — shutting down")
	connA.Close()
	connB.Close()
	<-done
	log.Info("relay done")
}

// relay reads encrypted frames from src (using srcKey), logs the plaintext,
// then re-encrypts with dstKey and writes to dst.
func relay(log *zap.Logger, srcName, dstName string, src, dst net.Conn, srcKey, dstKey [32]byte, encrypt bool, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()

	log.Info("relay direction started",
		zap.String("from", srcName),
		zap.String("to", dstName),
	)

	for {
		var plaintext []byte
		var err error
		if encrypt {
			plaintext, err = appcrypto.Decrypt(srcKey, src)
		} else {
			plaintext, err = appcrypto.ReadFrame(src)
		}
		if err != nil {
			log.Warn("read error (connection likely closed)",
				zap.String("from", srcName),
				zap.Error(err),
			)
			return
		}

		var msg chat.Message
		if err := json.Unmarshal(plaintext, &msg); err != nil {
			log.Error("failed to decode message",
				zap.String("from", srcName),
				zap.ByteString("raw", plaintext),
				zap.Error(err),
			)
			// Still forward so the peer isn't stuck.
		} else {
			log.Info("message",
				zap.String("from", srcName),
				zap.String("to", dstName),
				zap.String("sender", msg.Sender),
				zap.String("content", msg.Content),
				zap.Time("sent_at", msg.Time),
				zap.Duration("latency", time.Since(msg.Time)),
			)
		}

		if encrypt {
			frame, err := appcrypto.Encrypt(dstKey, plaintext)
			if err != nil {
				log.Error("encrypt error", zap.String("to", dstName), zap.Error(err))
				return
			}
			if _, err := dst.Write(frame); err != nil {
				log.Warn("write error (connection likely closed)", zap.String("to", dstName), zap.Error(err))
				return
			}
		} else {
			if err := appcrypto.WriteFrame(dst, plaintext); err != nil {
				log.Warn("write error (connection likely closed)", zap.String("to", dstName), zap.Error(err))
				return
			}
		}

		log.Debug("frame forwarded",
			zap.String("from", srcName),
			zap.String("to", dstName),
			zap.Int("bytes", len(plaintext)),
		)
	}
}

func buildLogger(logFile string) *zap.Logger {
	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	consoleCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderCfg),
		zapcore.AddSync(os.Stdout),
		zapcore.DebugLevel,
	)

	cores := []zapcore.Core{consoleCore}

	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: could not open log file %s: %v\n", logFile, err)
		} else {
			fileCore := zapcore.NewCore(
				zapcore.NewJSONEncoder(encoderCfg),
				zapcore.AddSync(f),
				zapcore.DebugLevel,
			)
			cores = append(cores, fileCore)
		}
	}

	return zap.New(zapcore.NewTee(cores...), zap.AddCaller())
}
