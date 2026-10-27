package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"os"
	"strings"

	"github.com/tailscale/hujson"
)

// A config is the contents of a configuration file.
type config struct {
	// Server is the host and port to submit to, over TLS.
	Server string `json:"server"`
	// Username and PasswordFile are the credentials for SASL PLAIN.
	// The password is the first line of the file.
	Username     string `json:"username"`
	PasswordFile string `json:"passwordFile"`
	// Header holds fields, by name, to add to a message that lacks them.
	Header map[string]string `json:"header"`
}

// loadConfig reads and checks the configuration file at path.
func loadConfig(path string) (*config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err = hujson.Standardize(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	if err := c.check(); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return &c, nil
}

func (c *config) check() error {
	if _, _, err := net.SplitHostPort(c.Server); err != nil {
		return fmt.Errorf("server: %v", err)
	}
	if c.Username == "" {
		return errors.New("username is not set")
	}
	if c.PasswordFile == "" {
		return errors.New("passwordFile is not set")
	}
	for name, value := range c.Header {
		if !isValidFieldName(name) {
			return fmt.Errorf("header: %q: not a field name", name)
		}
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("header: %s: value spans lines", name)
		}
	}
	return nil
}

// isValidFieldName reports whether name can name a header field:
// printable ASCII, with no colon.
func isValidFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; c <= ' ' || c > '~' || c == ':' {
			return false
		}
	}
	return true
}

// checkAddr reports whether s is a bare address, with no display name
// and no angle brackets, as the envelope and the command line take.
func checkAddr(s string) error {
	a, err := mail.ParseAddress(s)
	if err != nil {
		return fmt.Errorf("%q: %v", s, err)
	}
	if a.Name != "" || a.Address != s {
		return fmt.Errorf("%q: not a bare address", s)
	}
	return nil
}

// readPassword returns the first line of the file at path,
// which must be readable by its owner alone.
func readPassword(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("%s: accessible to others (mode %04o)", path, perm)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	if !s.Scan() {
		if err := s.Err(); err != nil {
			return "", fmt.Errorf("%s: %v", path, err)
		}
		return "", fmt.Errorf("%s: empty", path)
	}
	if s.Text() == "" {
		return "", fmt.Errorf("%s: empty", path)
	}
	return s.Text(), nil
}
