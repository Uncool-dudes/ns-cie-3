package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.io/uncool-dudes/p2p-chat/chat"
	"github.io/uncool-dudes/p2p-chat/p2p"
	"github.io/uncool-dudes/p2p-chat/ui"
)

const reconnectDelay = 3 * time.Second

func main() {
	listen := flag.String("listen", "", "address to listen on (e.g. :4242)")
	connect := flag.String("connect", "", "peer address to connect to (e.g. 192.168.1.5:4242)")
	name := flag.String("name", "you", "your display name")
	noEncrypt := flag.Bool("no-encrypt", false, "send raw plaintext — no key exchange, no encryption")
	noDiffie := flag.Bool("no-diffie", false, "send AES key in plaintext instead of DH — traffic is encrypted but key is sniffable")
	flag.Parse()

	if *listen == "" && *connect == "" {
		fmt.Fprintln(os.Stderr, "usage: p2p-chat --listen :4242 | --connect host:port [--name yourname]")
		os.Exit(1)
	}

	mode := p2p.ModeEncrypted
	switch {
	case *noEncrypt:
		mode = p2p.ModePlaintext
	case *noDiffie:
		mode = p2p.ModeNaiveKey
	}

	// dial returns a new session, retrying until it succeeds.
	dial := func() *p2p.Session {
		for {
			var (
				session *p2p.Session
				err     error
			)
			if *listen != "" {
				log.Printf("waiting for peer on %s ...", *listen)
				session, err = p2p.Listen(*listen, mode)
			} else {
				log.Printf("connecting to %s ...", *connect)
				session, err = p2p.Dial(*connect, mode)
			}
			if err != nil {
				log.Printf("connection failed: %v — retrying in %s", err, reconnectDelay)
				time.Sleep(reconnectDelay)
				continue
			}
			switch mode {
			case p2p.ModePlaintext:
				log.Println("connected — plaintext mode")
			case p2p.ModeNaiveKey:
				log.Println("connected — naive key exchange (key sent in plaintext)")
			default:
				log.Println("connected — DH handshake complete, session encrypted")
			}
			return session
		}
	}

	recv := make(chan chat.Message, 32)
	send := make(chan chat.Message, 32)

	var (
		mu      sync.Mutex
		session = dial()
	)

	// Receive loop: on disconnect, reconnect and resume.
	go func() {
		for {
			mu.Lock()
			s := session
			mu.Unlock()

			msg, err := s.Recv()
			if err != nil {
				log.Printf("peer disconnected: %v", err)
				s.Close()
				newSession := dial() // block outside the lock so send loop isn't stuck
				mu.Lock()
				session = newSession
				mu.Unlock()
				continue
			}
			recv <- msg
		}
	}()

	// Send loop: always sends on the current session.
	go func() {
		for msg := range send {
			mu.Lock()
			s := session
			mu.Unlock()

			if err := s.Send(msg); err != nil {
				log.Printf("send error: %v", err)
			}
		}
	}()

	model := ui.New(*name, recv, send)
	p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
