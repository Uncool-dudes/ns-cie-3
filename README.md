# p2p-chat

A peer-to-peer terminal chat application with three encryption modes, built to demonstrate what network-layer security actually protects — and what it doesn't. Includes a relay server that sits in the middle and decrypts/re-encrypts traffic for logging.

---

## Building

```bash
# Build the client
go build -o p2p-chat .

# Build the relay server
go build -o relay/relay-server ./relay
```

---

## Architecture

Two topologies are supported:

**Direct (peer-to-peer)**
```
Alice ──────────────────── Bob
      TCP :4242
```

**Relayed**
```
Alice ── TCP :5000 ── relay-server ── TCP :5000 ── Bob
```

In relay mode the server sits in the middle, decrypts every message to log the plaintext, then re-encrypts before forwarding. This lets you observe traffic contents server-side even when end-to-end encryption is active.

---

## Encryption Modes

All three modes use the same length-prefixed framing on the wire:
`[4-byte big-endian length][body]`

| Mode | Flag | Key Exchange | Wire Traffic |
|------|------|-------------|-------------|
| **Encrypted** | *(default)* | X25519 ECDH + HKDF | AES-256-GCM ciphertext — Wireshark sees random bytes |
| **Naive Key** | `--no-diffie` | AES key sent in plaintext | AES-256-GCM ciphertext — key visible on wire, messages decryptable by any sniffer |
| **Plaintext** | `--no-encrypt` | None | Raw JSON — Wireshark sees message content directly |

---

## Running: Direct (Peer-to-Peer)

Open two terminals.

**Terminal 1 — listener:**
```bash
./p2p-chat --listen :4242 --name Alice
```

**Terminal 2 — dialer:**
```bash
./p2p-chat --connect localhost:4242 --name Bob
```

### All flags (client)

| Flag | Default | Description |
|------|---------|-------------|
| `--listen <addr>` | — | Address to listen on, e.g. `:4242`. Mutually exclusive with `--connect`. |
| `--connect <host:port>` | — | Peer address to dial. Mutually exclusive with `--listen`. |
| `--name <string>` | `you` | Display name shown in the chat UI and in log files. |
| `--no-encrypt` | `false` | Disable encryption entirely. Messages are sent as raw JSON. Wireshark can read them directly. |
| `--no-diffie` | `false` | Skip Diffie-Hellman. The AES-256 session key is transmitted in plaintext. Messages are encrypted but any sniffer that captured the handshake can decrypt all traffic. |

One of `--listen` or `--connect` is required. Using neither prints usage and exits.

### Mode examples

```bash
# Default — full DH + AES-256-GCM (safest)
./p2p-chat --listen :4242 --name Alice
./p2p-chat --connect localhost:4242 --name Bob

# Naive key exchange — encrypted traffic, key sniffable on wire
./p2p-chat --listen :4242 --name Alice --no-diffie
./p2p-chat --connect localhost:4242 --name Bob --no-diffie

# Plaintext — no encryption, messages readable in Wireshark
./p2p-chat --listen :4242 --name Alice --no-encrypt
./p2p-chat --connect localhost:4242 --name Bob --no-encrypt
```

---

## Running: Relay Server

The relay accepts exactly two clients, performs a handshake with each, and forwards messages between them while logging plaintext to stdout (and optionally a file).

**Terminal 1 — relay:**
```bash
./relay/relay-server --listen :5000
```

**Terminal 2 — Alice:**
```bash
./p2p-chat --connect localhost:5000 --name Alice
```

**Terminal 3 — Bob:**
```bash
./p2p-chat --connect localhost:5000 --name Bob
```

Alice connects first, then Bob. The relay prints a log line when each peer connects and when handshakes complete.

### All flags (relay)

| Flag | Default | Description |
|------|---------|-------------|
| `--listen <addr>` | `:5000` | Address for the relay to bind on. |
| `--log <path>` | — | Path to a JSON log file. If omitted, logs go to stdout only. |
| `--no-encrypt` | `false` | Pass frames through without decryption. Relay logs raw bytes only. Both clients must also use `--no-encrypt`. |
| `--no-diffie` | `false` | Naive key mode. Relay exchanges AES keys in plaintext with each peer, logs plaintext messages, re-encrypts for the other side. Both clients must also use `--no-diffie`. |

### Relay mode examples

```bash
# Full DH — relay decrypts to log, re-encrypts before forwarding
./relay/relay-server --listen :5000
./relay/relay-server --listen :5000 --log relay.log

# Naive key — relay exchanges keys in plaintext (key visible in Wireshark)
./relay/relay-server --listen :5000 --no-diffie

# Plaintext — no encryption, relay forwards raw frames
./relay/relay-server --listen :5000 --no-encrypt
```

---

## Log Files

### Client logs (`./logs/`)

Each client connection writes a structured JSON log to `./logs/conn_<timestamp>_<remote_addr>.log`. A new file is created per connection, so reconnects produce separate logs.

**Events logged:**

| Event | Fields | When |
|-------|--------|------|
| `connection_opened` | `local_addr`, `remote_addr` | On connect |
| `dh_handshake` | `our_private_key_hex`, `our_public_key_hex`, `peer_public_key_hex`, `derived_aes256_key_hex` | After DH handshake (default mode) |
| `naive_handshake` | `role`, `aes256_key_hex` | After naive handshake (`--no-diffie`) |
| `sent` | `plaintext`, `wire_frame_hex`, `wire_bytes` | Each outgoing encrypted message |
| `received` | `wire_frame_hex`, `wire_bytes`, `plaintext` | Each incoming encrypted message |
| `sent_plaintext_mode` | `content`, `wire_data_hex` | Outgoing message in `--no-encrypt` mode |
| `received_plaintext_mode` | `wire_data_hex`, `content` | Incoming message in `--no-encrypt` mode |

**Reading a log:**
```bash
cat logs/conn_20260410_153000_127_0_0_1_4242.log | jq .
```

### Relay logs (stdout + optional file)

The relay logs to stdout in human-readable format and, if `--log` is given, also writes JSON to that file.

**Key relay log events:**
- `relay starting` — bind address
- `peer A/B connected` — remote address of each peer
- `both handshakes complete` — relay loop starts
- `message` — plaintext of every forwarded message (sender, content, latency)
- `frame forwarded` — byte count per frame (debug level)

```bash
# Watch relay log file in real time
tail -f relay.log | jq .

# Filter only message events
tail -f relay.log | jq 'select(.event == "message")'
```

---

## Wireshark

### Capturing

Start a capture on the loopback interface before launching any peers.

**macOS:**
```
Interface: lo0
Filter: tcp port 4242
```

**Linux:**
```
Interface: lo
Filter: tcp port 4242
```

For relay sessions use the relay port instead (default `5000`).

### What you see per mode

**`--no-encrypt` (plaintext)**

Each TCP segment payload is a 4-byte length prefix followed by raw JSON. In the packet bytes pane you can read the message text directly. Use the filter:
```
tcp.port == 4242
```
Follow the TCP stream (right-click → Follow → TCP Stream) to see the full conversation as text.

**`--no-diffie` (naive key)**

The first 32 bytes of the session are the AES key, transmitted in plaintext. You can see them in the hex pane of the first data packet. All subsequent frames are AES-256-GCM ciphertext — opaque in Wireshark — but because the key was on the wire, you can decrypt them manually using the `derived_aes256_key_hex` value from the client log.

**Default (DH encrypted)**

The handshake exchanges two 32-byte X25519 public keys — visible in the first two data packets. All subsequent frames are AES-256-GCM ciphertext. The session key is never on the wire; Wireshark cannot decrypt messages. Cross-reference against the `dh_handshake` log entry to verify the key material matches what you see in the capture.

### Wire frame layout (encrypted modes)

```
Offset  Length  Contents
------  ------  --------
0       4       Body length (big-endian uint32)
4       12      AES-GCM nonce (random per message)
16      N+16    Ciphertext + GCM authentication tag
```

In Wireshark's hex pane: the first 4 bytes are the length, the next 12 are the nonce, everything after is ciphertext+tag. The `wire_frame_hex` field in the client log is the exact hex of this entire structure for cross-referencing.

### Wireshark filter cheatsheet

```
# All traffic on the chat port
tcp.port == 4242

# Only packets with data (no pure ACKs)
tcp.port == 4242 && tcp.len > 0

# Show the first packet of each TCP stream (handshake)
tcp.port == 4242 && tcp.flags.syn == 1

# Relay port
tcp.port == 5000 && tcp.len > 0
```

---

## Reconnection

The client reconnects automatically if the peer disconnects. It retries every 3 seconds, printing a log line each attempt. The relay does not reconnect — it exits when either connection drops.

---

## Project Structure

```
.
├── main.go              # Client entry point, flag parsing, reconnect loop
├── p2p/
│   ├── peer.go          # Listen() and Dial() — TCP + handshake setup
│   └── session.go       # Session.Send/Recv — framing and encryption
├── crypto/
│   ├── handshake.go     # X25519 DH and naive plaintext key exchange
│   └── aead.go          # AES-256-GCM encrypt/decrypt, frame read/write
├── logger/
│   └── logger.go        # Per-connection structured JSON log files
├── chat/
│   └── message.go       # Message struct (Sender, Content, Time)
├── ui/
│   └── ui.go            # Bubble Tea terminal UI
└── relay/
    └── main.go          # Relay server — two-peer broker with logging
```
