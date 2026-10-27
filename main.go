// Command mail-submit sends a mail message to a mail submission server.
//
// Usage:
//
//	mail-submit [-c config] address ...
//
// The message is read from standard input
// and submitted once, over TLS, to the server named in config,
// for delivery to each address.
// Nothing is queued.
// Either the server accepts the message before mail-submit exits,
// or the message is not sent.
//
// A message that lacks a Date or Message-ID field is given one.
// Header fields set in config are added only to a message that lacks them,
// so what the caller writes always stands.
// The address in the From field is the envelope sender.
// The header is sent in canonical form and the body as it was given.
//
// The config is a JWCC file, /etc/mail-submit.jwcc by default.
// It names the server, the credentials,
// and the header fields to add by default.
// Header field keys are the RFC 5322 field names.
// The password is read from a separate file,
// which must not be readable by group or world.
//
// mail-submit prints nothing on success.
// On failure it prints one line to standard error and exits nonzero.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/mail"
	"os"
	"time"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("mail-submit: ")

	path := flag.String("c", "/etc/mail-submit.jwcc", "configuration `file`")
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() == 0 {
		usage()
		os.Exit(100)
	}
	if err := run(*path, flag.Args(), os.Stdin, nil); err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: mail-submit [-c config] address ...")
	flag.PrintDefaults()
}

// run sends the message in r to each address in to,
// as the configuration file at path directs.
// tlsConfig, when not nil, overrides how the server is trusted.
func run(path string, to []string, r io.Reader, tlsConfig *tls.Config) error {
	c, err := loadConfig(path)
	if err != nil {
		return err
	}
	for _, a := range to {
		if err := checkAddr(a); err != nil {
			return err
		}
	}
	password, err := readPassword(c.PasswordFile)
	if err != nil {
		return err
	}
	m, err := mail.ReadMessage(r)
	if err != nil {
		return fmt.Errorf("message: %v", err)
	}
	fill(m.Header, c.Header)
	from, err := sender(m.Header)
	if err != nil {
		return err
	}
	fill(m.Header, map[string]string{
		"Date":       time.Now().Format(time.RFC1123Z),
		"Message-ID": messageID(from),
	})
	return submit(c, tlsConfig, password, from, to, m)
}
