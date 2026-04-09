package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"

	"github.io/uncool-dudes/p2p-chat/chat"
	appcrypto "github.io/uncool-dudes/p2p-chat/crypto"
	"github.io/uncool-dudes/p2p-chat/p2p"
	"github.io/uncool-dudes/p2p-chat/ui"
)

func main() {
	listen := flag.String("listen", "", "address to listen on (e.g. :4242)")
	connect := flag.String("connect", "", "peer address to connect to (e.g. 192.168.1.5:4242)")
	name := flag.String("name", "you", "your display name")
	identityPath := flag.String("identity", defaultIdentityPath(), "path to your Ed25519 identity key file")
	peerKeyHex := flag.String("peer-key", "", "peer's identity public key (hex) — share yours with them first")
	flag.Parse()

	if *listen == "" && *connect == "" {
		fmt.Fprintln(os.Stderr, "usage: p2p-chat --listen :4242 | --connect host:port [--name yourname] --peer-key <hex>")
		os.Exit(1)
	}
	if *peerKeyHex == "" {
		fmt.Fprintln(os.Stderr, "error: --peer-key is required (exchange identity keys with your peer first)")
		os.Exit(1)
	}

	identity, err := appcrypto.LoadOrCreateIdentityKey(*identityPath)
	if err != nil {
		log.Fatalf("identity: %v", err)
	}
	log.Printf("your identity key: %s", appcrypto.PublicKeyHex(identity))

	peerIdentity, err := appcrypto.ParsePublicKey(*peerKeyHex)
	if err != nil {
		log.Fatalf("--peer-key: %v", err)
	}

	recv := make(chan chat.Message, 32)
	send := make(chan chat.Message, 32)

	var session *p2p.Session

	if *listen != "" {
		log.Printf("waiting for peer on %s ...", *listen)
		session, err = p2p.Listen(*listen, identity, peerIdentity)
	} else {
		log.Printf("connecting to %s ...", *connect)
		session, err = p2p.Dial(*connect, identity, peerIdentity)
	}
	if err != nil {
		log.Fatalf("p2p: %v", err)
	}
	log.Println("handshake complete — session authenticated and encrypted")

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

func defaultIdentityPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".p2p-chat-identity.key"
	}
	return filepath.Join(home, ".p2p-chat", "identity.key")
}
