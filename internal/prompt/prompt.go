// Package prompt reads answers from the terminal. The terminal is put in raw mode
// so Ctrl+C / Ctrl+D cancel the prompt instead of killing the process, which would
// leave the terminal with echo switched off.
package prompt

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

var ErrCancelled = errors.New("cancelled")

// Secret reads a line without echo.
func Secret(in *os.File, out io.Writer, prompt string) ([]byte, error) {
	return read(in, out, prompt, false)
}

// Line reads a line with echo.
func Line(in *os.File, out io.Writer, prompt string) (string, error) {
	b, err := read(in, out, prompt, true)
	return string(b), err
}

func read(in *os.File, out io.Writer, prompt string, echo bool) ([]byte, error) {
	fmt.Fprint(out, prompt)
	fd := int(in.Fd())
	if !term.IsTerminal(fd) {
		return readPiped(in)
	}
	old, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	defer term.Restore(fd, old)

	buf := make([]byte, 0, 256) // preallocated so secrets are rarely copied by append
	b := make([]byte, 1)
	for {
		n, err := in.Read(b)
		if err != nil {
			clear(buf)
			fmt.Fprint(out, "\r\n")
			if err == io.EOF {
				err = ErrCancelled
			}
			return nil, err
		}
		if n == 0 {
			continue
		}
		switch c := b[0]; {
		case c == '\r' || c == '\n':
			fmt.Fprint(out, "\r\n")
			return buf, nil
		case c == 3 || (c == 4 && len(buf) == 0): // Ctrl+C, or Ctrl+D on an empty line
			clear(buf)
			fmt.Fprint(out, "\r\n")
			return nil, ErrCancelled
		case c == 127 || c == 8: // backspace
			if len(buf) > 0 {
				_, size := utf8.DecodeLastRune(buf)
				clear(buf[len(buf)-size:])
				buf = buf[:len(buf)-size]
				if echo {
					fmt.Fprint(out, "\b \b")
				}
			}
		case c == 21: // Ctrl+U clears the line
			if echo {
				fmt.Fprint(out, strings.Repeat("\b \b", utf8.RuneCount(buf)))
			}
			clear(buf)
			buf = buf[:0]
		case c >= 32:
			buf = append(buf, c)
			if echo {
				out.Write(b)
			}
		}
	}
}

// readPiped reads byte-by-byte so nothing past the newline is consumed.
func readPiped(in io.Reader) ([]byte, error) {
	var buf []byte
	b := make([]byte, 1)
	for {
		n, err := in.Read(b)
		if n > 0 {
			if b[0] == '\n' {
				break
			}
			buf = append(buf, b[0])
		}
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				break
			}
			if err == io.EOF {
				err = ErrCancelled
			}
			return nil, err
		}
	}
	if len(buf) > 0 && buf[len(buf)-1] == '\r' {
		buf = buf[:len(buf)-1]
	}
	return buf, nil
}
