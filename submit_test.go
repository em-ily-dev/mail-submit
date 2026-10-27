package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/mail"
	"net/textproto"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// A submission is what the test server saw of one session.
type submission struct {
	user, pass string
	from       string
	to         []string
	data       string
}

// startServer runs an SMTP server over TLS on the loopback interface
// that accepts one session and reports it on the returned channel.
// The returned pool trusts the server's certificate.
func startServer(t *testing.T) (addr string, pool *x509.CertPool, got <-chan submission) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(cert)

	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	ch := make(chan submission, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		ch <- serve(textproto.NewConn(conn))
	}()
	return l.Addr().String(), pool, ch
}

// serve speaks just enough SMTP to take one message.
func serve(c *textproto.Conn) (s submission) {
	c.PrintfLine("220 test ESMTP")
	for {
		line, err := c.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO":
			c.PrintfLine("250-test")
			c.PrintfLine("250 AUTH PLAIN")
		case "AUTH":
			_, resp, _ := strings.Cut(arg, " ")
			b, _ := base64.StdEncoding.DecodeString(resp)
			parts := strings.Split(string(b), "\x00")
			if len(parts) == 3 {
				s.user, s.pass = parts[1], parts[2]
			}
			c.PrintfLine("235 ok")
		case "MAIL":
			s.from = strings.TrimSuffix(strings.TrimPrefix(arg, "FROM:<"), ">")
			c.PrintfLine("250 ok")
		case "RCPT":
			s.to = append(s.to, strings.TrimSuffix(strings.TrimPrefix(arg, "TO:<"), ">"))
			c.PrintfLine("250 ok")
		case "DATA":
			c.PrintfLine("354 go")
			b, _ := c.ReadDotBytes()
			s.data = string(b)
			c.PrintfLine("250 queued")
		case "QUIT":
			c.PrintfLine("221 bye")
			return
		default:
			c.PrintfLine("500 what")
		}
	}
}

func TestSubmit(t *testing.T) {
	addr, pool, got := startServer(t)
	c := &config{Server: addr, Username: "u@example.org"}
	m, err := mail.ReadMessage(strings.NewReader("Subject: hi\n\n.leading dot\nbody\n"))
	if err != nil {
		t.Fatal(err)
	}
	to := []string{"a@example.org", "b@example.org"}
	if err := submit(c, &tls.Config{RootCAs: pool}, "hunter2", "sender@example.org", to, m); err != nil {
		t.Fatal(err)
	}
	s := <-got
	if s.user != "u@example.org" || s.pass != "hunter2" {
		t.Errorf("authenticated as %q, %q", s.user, s.pass)
	}
	if s.from != "sender@example.org" {
		t.Errorf("MAIL FROM = %q", s.from)
	}
	if !slices.Equal(s.to, to) {
		t.Errorf("RCPT TO = %q", s.to)
	}
	// Bare newlines go out as CRLF and dots are stuffed;
	// the server's reader undoes both.
	if want := "Subject: hi\n\n.leading dot\nbody\n"; s.data != want {
		t.Errorf("data:\n%q\nwant:\n%q", s.data, want)
	}
}

func TestSubmitRejectsUntrustedServer(t *testing.T) {
	addr, _, _ := startServer(t)
	c := &config{Server: addr, Username: "u@example.org"}
	m, err := mail.ReadMessage(strings.NewReader("Subject: hi\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	err = submit(c, nil, "hunter2", "sender@example.org", []string{"a@example.org"}, m)
	if err == nil {
		t.Fatal("submitted to a server with a certificate nothing trusts")
	}
}

// TestRun drives the whole program, from configuration file to server.
func TestRun(t *testing.T) {
	addr, pool, got := startServer(t)
	dir := t.TempDir()
	password := filepath.Join(dir, "password")
	if err := os.WriteFile(password, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "mail-submit.jwcc")
	err := os.WriteFile(conf, []byte(`{
		"server": "`+addr+`",
		"username": "u@example.org",
		"passwordFile": "`+password+`",
		"header": {"From": "root <sender@example.org>"},
	}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	msg := "Subject: hi\nTo: a@example.org\n\nbody\n"
	err = run(conf, []string{"a@example.org"}, strings.NewReader(msg), &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	s := <-got
	if s.from != "sender@example.org" {
		t.Errorf("MAIL FROM = %q, want the From address", s.from)
	}
	for _, line := range []string{"From: root <sender@example.org>\n", "Subject: hi\n", "To: a@example.org\n", "Date: ", "Message-Id: <"} {
		if !strings.Contains(s.data, line) {
			t.Errorf("no %q in:\n%q", line, s.data)
		}
	}
	if !strings.HasSuffix(s.data, "\n\nbody\n") {
		t.Errorf("body was altered:\n%q", s.data)
	}
}

func TestRunRejectsBadAddress(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "mail-submit.jwcc")
	err := os.WriteFile(conf, []byte(`{
		"server": "mail.example.org:465",
		"username": "u@example.org",
		"passwordFile": "/nonexistent",
	}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	err = run(conf,
		[]string{"Someone <a@example.org>"}, strings.NewReader(""), nil)
	if err == nil || !strings.Contains(err.Error(), "bare address") {
		t.Errorf("error = %v", err)
	}
}
