package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	labelStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62"))
	errorStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	resultStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("236")).
			Padding(0, 1).
			Foreground(lipgloss.Color("10"))
	dimStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	titleStyle = lipgloss.NewStyle().Bold(true).
			Foreground(lipgloss.Color("62")).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(lipgloss.Color("238"))
)

const (
	fieldKey = iota
	fieldFrame
)

type model struct {
	inputs  [2]textinput.Model
	focused int
	result  string
	err     string
}

func initialModel() model {
	keyInput := textinput.New()
	keyInput.Placeholder = "paste aes256_key_hex here"
	keyInput.Focus()
	keyInput.Width = 80

	frameInput := textinput.New()
	frameInput.Placeholder = "paste wire_frame_hex here"
	frameInput.Width = 80

	return model{
		inputs:  [2]textinput.Model{keyInput, frameInput},
		focused: fieldKey,
	}
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit

		case tea.KeyTab, tea.KeyShiftTab:
			if m.focused == fieldKey {
				m.focused = fieldFrame
				m.inputs[fieldKey].Blur()
				m.inputs[fieldFrame].Focus()
			} else {
				m.focused = fieldKey
				m.inputs[fieldFrame].Blur()
				m.inputs[fieldKey].Focus()
			}
			return m, textinput.Blink

		case tea.KeyEnter:
			m.result = ""
			m.err = ""

			keyHex := normalizeHex(m.inputs[fieldKey].Value())
			frameHex := normalizeHex(m.inputs[fieldFrame].Value())

			if keyHex == "" || frameHex == "" {
				m.err = "both fields are required"
				return m, nil
			}

			plaintext, err := decrypt(keyHex, frameHex)
			if err != nil {
				m.err = err.Error()
			} else {
				m.result = plaintext
			}
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.inputs[m.focused], cmd = m.inputs[m.focused].Update(msg)
	return m, cmd
}

func (m model) View() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("  p2p-chat decryptor") + "\n\n")

	sb.WriteString(labelStyle.Render("AES Key (hex)") + "\n")
	sb.WriteString(m.inputs[fieldKey].View() + "\n\n")

	sb.WriteString(labelStyle.Render("Wire Frame (hex)") + "\n")
	sb.WriteString(m.inputs[fieldFrame].View() + "\n\n")

	sb.WriteString(dimStyle.Render("tab to switch fields   enter to decrypt   esc to quit") + "\n\n")

	if m.err != "" {
		sb.WriteString(errorStyle.Render("error: "+m.err) + "\n")
	}

	if m.result != "" {
		sb.WriteString(labelStyle.Render("plaintext:") + "\n")
		sb.WriteString(resultStyle.Render(m.result) + "\n")
	}

	return sb.String()
}

func decrypt(keyHex, frameHex string) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("invalid key hex: %w", err)
	}
	if len(key) != 32 {
		return "", fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}

	frame, err := hex.DecodeString(frameHex)
	if err != nil {
		return "", fmt.Errorf("invalid frame hex: %w", err)
	}
	if len(frame) < 4+12+16 {
		return "", fmt.Errorf("frame too short")
	}

	body := frame[4:] // strip 4-byte length header
	nonce := body[:12]
	ciphertext := body[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm init: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed (wrong key or corrupted frame)")
	}

	return string(plaintext), nil
}

// normalizeHex accepts either plain hex (with optional whitespace) or a
// Wireshark-style hex dump ("0000  aa bb cc ...") and returns a clean hex string.
func normalizeHex(input string) string {
	lines := strings.Split(input, "\n")

	// Detect Wireshark dump: first non-empty line's first token is a 4-char hex offset
	isWireshark := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && len(parts[0]) == 4 {
			if _, err := hex.DecodeString(parts[0]); err == nil {
				isWireshark = true
			}
		}
		break
	}

	if isWireshark {
		var sb strings.Builder
		for _, line := range lines {
			parts := strings.Fields(strings.TrimSpace(line))
			if len(parts) < 2 {
				continue
			}
			// parts[0] is the offset; collect 2-char hex tokens after it
			for _, p := range parts[1:] {
				if len(p) == 2 {
					if _, err := hex.DecodeString(p); err == nil {
						sb.WriteString(p)
					} else {
						break // hit the ASCII section
					}
				} else {
					break
				}
			}
		}
		return sb.String()
	}

	return strings.Join(strings.Fields(input), "")
}

func main() {
	p := tea.NewProgram(initialModel())
	if _, err := p.Run(); err != nil {
		fmt.Println("error:", err)
	}
}
