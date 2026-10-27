package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	const good = `{
		// Comments and trailing commas are fine.
		"server": "mail.example.org:465",
		"username": "u@example.org",
		"passwordFile": "/nonexistent",
		"header": {"From": "Sender <sender@example.org>", "Reply-To": "r@example.org"},
	}`
	tests := []struct {
		name string
		edit func(string) string
		want string // substring of the error, or "" for success
	}{
		{"good", func(s string) string { return s }, ""},
		{"unknown key", func(s string) string {
			return strings.Replace(s, `"server"`, `"mailhub"`, 1)
		}, "mailhub"},
		{"no port", func(s string) string {
			return strings.Replace(s, "mail.example.org:465", "mail.example.org", 1)
		}, "server"},
		{"header name with colon", func(s string) string {
			return strings.Replace(s, `"Reply-To"`, `"Reply-To:"`, 1)
		}, "field name"},
		{"header value spanning lines", func(s string) string {
			return strings.Replace(s, `"r@example.org"`, `"r@example.org\nBcc: x@example.org"`, 1)
		}, "spans lines"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "c.jwcc")
			if err := os.WriteFile(path, []byte(tt.edit(good)), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := loadConfig(path)
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				if c.Header["Reply-To"] != "r@example.org" {
					t.Errorf("Reply-To = %q", c.Header["Reply-To"])
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want one mentioning %q", err, tt.want)
			}
		})
	}
}

func TestReadPassword(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, perm os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), perm); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if p, err := readPassword(write("ok", "hunter2\n", 0o600)); err != nil || p != "hunter2" {
		t.Errorf("readPassword = %q, %v", p, err)
	}
	if p, err := readPassword(write("crlf", "hunter2\r\nsecond line\n", 0o400)); err != nil || p != "hunter2" {
		t.Errorf("readPassword = %q, %v", p, err)
	}
	if _, err := readPassword(write("group", "hunter2\n", 0o640)); err == nil {
		t.Error("group-readable file was accepted")
	}
	if _, err := readPassword(write("empty", "\n", 0o600)); err == nil {
		t.Error("empty file was accepted")
	}
	if _, err := readPassword(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file was accepted")
	}
}
