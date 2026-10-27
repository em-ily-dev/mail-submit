package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"time"
)

// timeout bounds a whole submission, from dialing to the server's goodbye.
const timeout = time.Minute

// submit sends m to the server in c,
// from the address from to each address in to,
// authenticating with c's username and password.
// tlsConfig, when not nil, overrides how the server is trusted.
func submit(c *config, tlsConfig *tls.Config, password, from string, to []string, m *mail.Message) error {
	host, _, err := net.SplitHostPort(c.Server)
	if err != nil {
		return err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	d := tls.Dialer{Config: tlsConfig}
	conn, err := d.DialContext(ctx, "tcp", c.Server)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	s, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Hello(hostname); err != nil {
		return err
	}
	if err := s.Auth(smtp.PlainAuth("", c.Username, password, host)); err != nil {
		return fmt.Errorf("authentication: %v", err)
	}
	if err := s.Mail(from); err != nil {
		return err
	}
	for _, a := range to {
		if err := s.Rcpt(a); err != nil {
			return fmt.Errorf("%s: %v", a, err)
		}
	}
	w, err := s.Data()
	if err != nil {
		return err
	}
	if err := write(w, m); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return s.Quit()
}
