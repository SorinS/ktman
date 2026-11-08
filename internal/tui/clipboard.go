package tui

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// copyToClipboard puts s on the system clipboard: through the platform's tool
// (pbcopy, wl-copy, xclip or xsel), else an OSC 52 escape, which most
// terminals (and tmux, over ssh too) turn into a clipboard write. It says
// which it used.
func copyToClipboard(s string) (string, error) {
	tools := [][]string{
		{"pbcopy"},
		{"wl-copy"},
		{"xclip", "-selection", "clipboard"},
		{"xsel", "--clipboard", "--input"},
	}

	for _, t := range tools {
		path, err := exec.LookPath(t[0])
		if err != nil {
			continue
		}

		cmd := exec.Command(path, t[1:]...)
		cmd.Stdin = strings.NewReader(s)

		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("%s: %w", t[0], err)
		}

		return t[0], nil
	}

	if _, err := fmt.Fprintf(os.Stdout, "\x1b]52;c;%s\x07", base64.StdEncoding.EncodeToString([]byte(s))); err != nil {
		return "", err
	}

	return "the terminal (OSC 52)", nil
}
