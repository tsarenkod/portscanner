package portscan

import (
	"fmt"
	"strings"
	"testing"
)

func TestNormalizeHosts(t *testing.T) {
	targets, err := normalizeHosts([]string{" 127.0.0.1 ", "127.0.0.1", "LOCALHOST.", "localhost", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 3 {
		t.Fatalf("normalizeHosts() returned %d targets, want 3: %#v", len(targets), targets)
	}
	if targets[0].host != "127.0.0.1" || targets[0].ip.String() != "127.0.0.1" {
		t.Fatalf("IPv4 target = %#v", targets[0])
	}
	if targets[1].host != "LOCALHOST." || targets[1].ip != nil {
		t.Fatalf("DNS target = %#v", targets[1])
	}
	if targets[2].ip.String() != "::1" {
		t.Fatalf("IPv6 target = %#v", targets[2])
	}

	for _, host := range []string{"", "  ", "bad host", "-bad.example", "bad-.example", "a..b", strings.Repeat("a", 64) + ".com"} {
		t.Run(fmt.Sprintf("invalid %q", host), func(t *testing.T) {
			if _, err := normalizeHosts([]string{host}); err == nil {
				t.Fatal("normalizeHosts() error = nil, want error")
			}
		})
	}
}

func TestValidDNSName(t *testing.T) {
	for name, want := range map[string]bool{
		"localhost": true, "example.org": true, "example.org.": true,
		"": false, ".": false, "a..b": false, "-a.example": false,
		"a-.example": false, "a_b.example": false,
	} {
		t.Run(name, func(t *testing.T) {
			if got := validDNSName(name); got != want {
				t.Fatalf("validDNSName(%q) = %v, want %v", name, got, want)
			}
		})
	}
}
