package main

import (
	"bytes"
	"net/mail"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestFill(t *testing.T) {
	m, err := mail.ReadMessage(strings.NewReader("Subject: hi\nFrom: me <me@example.org>\n\nbody\n"))
	if err != nil {
		t.Fatal(err)
	}
	fill(m.Header, map[string]string{
		"From":     "root <root@example.org>",
		"Reply-To": "r@example.org",
	})
	var b bytes.Buffer
	if err := write(&b, m); err != nil {
		t.Fatal(err)
	}
	header, body, _ := strings.Cut(b.String(), "\r\n\r\n")
	lines := strings.Split(header, "\r\n")
	slices.Sort(lines)
	want := []string{"From: me <me@example.org>", "Reply-To: r@example.org", "Subject: hi"}
	if !slices.Equal(lines, want) {
		t.Errorf("header:\n%q\nwant:\n%q", lines, want)
	}
	if body != "body\n" {
		t.Errorf("body = %q", body)
	}
}

func TestSender(t *testing.T) {
	tests := []struct {
		from string
		want string // the address, or "" for an error
	}{
		{"sender@example.org", "sender@example.org"},
		{"root <root@example.org>", "root@example.org"},
		{"", ""},
		{"a@example.org, b@example.org", ""},
	}
	for _, tt := range tests {
		h := mail.Header{}
		if tt.from != "" {
			h["From"] = []string{tt.from}
		}
		got, err := sender(h)
		if tt.want == "" {
			if err == nil {
				t.Errorf("From %q: accepted as %q", tt.from, got)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("From %q: got %q, %v; want %q", tt.from, got, err, tt.want)
		}
	}
}

func TestMessageID(t *testing.T) {
	pattern := regexp.MustCompile(`^<[A-Z2-7]{26}@example\.org>$`)
	a, b := messageID("root@example.org"), messageID("root@example.org")
	if !pattern.MatchString(a) || !pattern.MatchString(b) {
		t.Errorf("malformed: %q, %q", a, b)
	}
	if a == b {
		t.Errorf("repeated: %q", a)
	}
}
