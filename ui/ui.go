package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.io/uncool-dudes/p2p-chat/chat"
)

var (
	senderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("5"))

	otherStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("2"))

	timestampStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240"))

	bubbleStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("236")).
			Padding(0, 1)

	inputBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("62"))

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Italic(true)
)

// incomingMsg is a tea.Msg that carries a message received from the peer.
type incomingMsg chat.Message

// Model is the bubbletea UI model for the chat application.
type Model struct {
	viewport viewport.Model
	textarea textarea.Model
	messages []chat.Message
	username string
	width    int
	height   int
	ready    bool

	recv <-chan chat.Message
	send chan<- chat.Message
}

const gap = 1

// New creates a Model wired to recv (incoming messages from peer) and send
// (outgoing messages typed by the local user).
func New(username string, recv <-chan chat.Message, send chan<- chat.Message) Model {
	ta := textarea.New()
	ta.Placeholder = "Type a message..."
	ta.Focus()
	ta.SetWidth(80)
	ta.SetHeight(3)
	ta.ShowLineNumbers = false
	ta.KeyMap.InsertNewline.SetEnabled(false)

	return Model{
		textarea: ta,
		username: username,
		recv:     recv,
		send:     send,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(textarea.Blink, m.waitForIncoming())
}

// waitForIncoming returns a Cmd that blocks until a message arrives on recv.
func (m Model) waitForIncoming() tea.Cmd {
	return func() tea.Msg {
		msg := <-m.recv
		return incomingMsg(msg)
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		taCmd tea.Cmd
		vpCmd tea.Cmd
	)

	switch msg := msg.(type) {
	case incomingMsg:
		m.messages = append(m.messages, chat.Message(msg))
		if m.ready {
			m.viewport.SetContent(m.renderMessages())
			m.viewport.GotoBottom()
		}
		return m, m.waitForIncoming()

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		inputHeight := 5
		headerHeight := 2
		vpHeight := m.height - inputHeight - headerHeight - gap

		if !m.ready {
			m.viewport = viewport.New(m.width, vpHeight)
			m.viewport.SetContent(m.renderMessages())
			m.viewport.GotoBottom()
			m.ready = true
		} else {
			m.viewport.Width = m.width
			m.viewport.Height = vpHeight
			m.viewport.SetContent(m.renderMessages())
		}

		m.textarea.SetWidth(m.width - 2)

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit
		case tea.KeyEnter:
			text := strings.TrimSpace(m.textarea.Value())
			if text != "" {
				outMsg := chat.Message{
					Sender:  m.username,
					Content: text,
					Time:    time.Now(),
				}
				m.messages = append(m.messages, outMsg)
				m.textarea.Reset()
				if m.ready {
					m.viewport.SetContent(m.renderMessages())
					m.viewport.GotoBottom()
				}
				// non-blocking send; drop if p2p layer is not connected yet
				select {
				case m.send <- outMsg:
				default:
				}
			}
			return m, nil
		}
	}

	m.textarea, taCmd = m.textarea.Update(msg)
	m.viewport, vpCmd = m.viewport.Update(msg)

	return m, tea.Batch(taCmd, vpCmd)
}

func (m Model) renderMessages() string {
	if len(m.messages) == 0 {
		return statusStyle.Render("  No messages yet.")
	}

	width := m.width
	if width <= 0 {
		width = 80
	}

	var sb strings.Builder
	for _, msg := range m.messages {
		ts := timestampStyle.Render(msg.Time.Format("15:04"))
		isMine := msg.Sender == m.username

		var nameStyle lipgloss.Style
		if isMine {
			nameStyle = senderStyle
		} else {
			nameStyle = otherStyle
		}

		name := nameStyle.Render(msg.Sender)
		content := bubbleStyle.Render(msg.Content)

		if isMine {
			// Right-align: meta line and bubble pushed to the right
			meta := fmt.Sprintf("%s %s", ts, name)
			metaLine := lipgloss.NewStyle().Width(width).Align(lipgloss.Right).Render(meta)
			bubbleLine := lipgloss.NewStyle().Width(width).Align(lipgloss.Right).Render(content)
			sb.WriteString(metaLine + "\n" + bubbleLine + "\n\n")
		} else {
			// Left-align: name then timestamp, bubble below
			meta := fmt.Sprintf("%s %s", name, ts)
			sb.WriteString(meta + "\n" + content + "\n\n")
		}
	}

	return sb.String()
}

func (m Model) View() string {
	if !m.ready {
		return "\n  Initializing..."
	}

	header := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("62")).
		Border(lipgloss.NormalBorder(), false, false, true, false).
		BorderForeground(lipgloss.Color("238")).
		Width(m.width).
		Render("  p2p-chat")

	scrollPct := int(m.viewport.ScrollPercent() * 100)
	scrollInfo := statusStyle.Render(fmt.Sprintf("  %d%%  ↑/↓ or scroll to navigate", scrollPct))

	input := inputBorderStyle.Width(m.width - 2).Render(m.textarea.View())

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		m.viewport.View(),
		scrollInfo,
		input,
	)
}
