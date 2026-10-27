package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/textproto"
	"strings"
)

// fill adds to h each field in fields that h lacks.
func fill(h mail.Header, fields map[string]string) {
	for name, value := range fields {
		if h.Get(name) == "" {
			textproto.MIMEHeader(h).Set(name, value)
		}
	}
}

// sender returns the envelope sender, the one address in h's From field.
func sender(h mail.Header) (string, error) {
	list, err := mail.ParseAddressList(h.Get("From"))
	if err != nil {
		return "", fmt.Errorf("From: %v", err)
	}
	if len(list) != 1 {
		return "", errors.New("From: not exactly one address")
	}
	return list[0].Address, nil
}

// write writes m to w as it goes on the wire:
// the header in canonical form, then the body as given.
func write(w io.Writer, m *mail.Message) error {
	for name, values := range m.Header {
		for _, value := range values {
			if _, err := fmt.Fprintf(w, "%s: %s\r\n", name, value); err != nil {
				return err
			}
		}
	}
	if _, err := io.WriteString(w, "\r\n"); err != nil {
		return err
	}
	_, err := io.Copy(w, m.Body)
	return err
}

// messageID returns a fresh Message-ID in the domain of addr.
func messageID(addr string) string {
	_, domain, _ := strings.CutLast(addr, "@")
	return fmt.Sprintf("<%s@%s>", rand.Text(), domain)
}
