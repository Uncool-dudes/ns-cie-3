package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.io/uncool-dudes/p2p-chat/chat"
	"github.io/uncool-dudes/p2p-chat/p2p"
	"github.io/uncool-dudes/p2p-chat/ui"
)

func main() {
	listen := flag.String("listen", "", "address to listen on (e.g. :4242)")
	connect := flag.String("connect", "", "peer address to connect to (e.g. 192.168.1.5:4242)")
	name := flag.String("name", "you", "your display name")
	flag.Parse()

	if *listen == "" && *connect == "" {
		fmt.Fprintln(os.Stderr, "usage: p2p-chat --listen :4242 | --connect host:port [--name yourname]")
		os.Exit(1)
	}

	recv := make(chan chat.Message, 32)
	send := make(chan chat.Message, 32)

	// Establish the encrypted P2P session before starting the TUI.
	var session *p2p.Session
	var err error

	if *listen != "" {
		log.Printf("waiting for peer on %s ...", *listen)
		session, err = p2p.Listen(*listen)
	} else {
		log.Printf("connecting to %s ...", *connect)
		session, err = p2p.Dial(*connect)
	}
	if err != nil {
		log.Fatalf("p2p: %v", err)
	}
	log.Println("handshake complete — session encrypted")

	// Receive loop: peer → recv channel → UI.
	go func() {
		defer session.Close()
		for {
			msg, err := session.Recv()
			if err != nil {
				return
			}
			recv <- msg
		}
	}()

	// Send loop: UI → send channel → peer.
	go func() {
		for msg := range send {
			if err := session.Send(msg); err != nil {
				return
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
