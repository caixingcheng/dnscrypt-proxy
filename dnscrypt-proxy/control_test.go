package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

func seedCache(t *testing.T, qname string, qtype uint16, flags byte, expiration time.Time) {
	t.Helper()
	cachedResponses.Insert(cacheKey(qtype, dns.ClassINET, flags, qname), CachedResponse{expiration: expiration, msg: new(dns.Msg)})
}

func cached(qname string, qtype uint16, flags byte) bool {
	_, ok := cachedResponses.Get(cacheKey(qtype, dns.ClassINET, flags, qname))
	return ok
}

func TestControlFlush(t *testing.T) {
	cachedResponses = nil
	if err := initCachedResponses(1024); err != nil {
		t.Fatal(err)
	}
	defer func() { cachedResponses = nil }()

	now := time.Now()
	seedCache(t, "firewalla.encipher.io.", dns.TypeA, 0, now.Add(time.Hour))
	seedCache(t, "Firewalla.Encipher.IO.", dns.TypeA, 2, now.Add(-time.Hour)) // stale, CD, mixed case
	seedCache(t, "firewalla.encipher.io.", dns.TypeAAAA, 1, now.Add(time.Hour))
	seedCache(t, "github.com.", dns.TypeA, 0, now.Add(time.Hour))

	if got := runControlCommand("flush_type firewalla.encipher.io aaaa"); got != "ok 1" {
		t.Fatalf("flush_type: got %q", got)
	}
	if cached("firewalla.encipher.io.", dns.TypeAAAA, 1) || !cached("firewalla.encipher.io.", dns.TypeA, 0) {
		t.Fatal("flush_type removed the wrong entries")
	}

	if got := runControlCommand("flush FIREWALLA.encipher.io"); got != "ok 2" {
		t.Fatalf("flush: got %q", got)
	}
	if cached("firewalla.encipher.io.", dns.TypeA, 0) || cached("firewalla.encipher.io.", dns.TypeA, 2) {
		t.Fatal("flush left an entry behind")
	}
	if !cached("github.com.", dns.TypeA, 0) {
		t.Fatal("flush removed an unrelated name")
	}

	if got := runControlCommand("flush firewalla.encipher.io."); got != "ok 0" {
		t.Fatalf("flush of an absent name: got %q", got)
	}
	for _, bad := range []string{"", "flush", "flush_type a.com BOGUS", "purge a.com"} {
		if got := runControlCommand(bad); len(got) < 5 || got[:5] != "error" {
			t.Fatalf("%q: expected an error, got %q", bad, got)
		}
	}
}

func TestControlUnixSocket(t *testing.T) {
	cachedResponses = nil
	if err := initCachedResponses(1024); err != nil {
		t.Fatal(err)
	}
	defer func() { cachedResponses = nil }()
	seedCache(t, "firewalla.encipher.io.", dns.TypeA, 0, time.Now().Add(time.Hour))

	path := t.TempDir() + "/control.sock"
	// a stale socket from a previous run must not prevent the bind
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()

	proxy := &Proxy{}
	if err := proxy.startControl(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode %o, want 600", perm)
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "flush firewalla.encipher.io\n")
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if reply != "ok 1\n" {
		t.Fatalf("got %q", reply)
	}

	// never remove something that is not a socket
	file := t.TempDir() + "/not-a-socket"
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := proxy.startControl(file); err == nil {
		t.Fatal("expected an error for a regular file")
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("regular file was removed")
	}
}

func TestControlFlushClient(t *testing.T) {
	cachedResponses = nil
	if err := initCachedResponses(1024); err != nil {
		t.Fatal(err)
	}
	defer func() { cachedResponses = nil }()
	seedCache(t, "example.com.", dns.TypeA, 0, time.Now().Add(time.Hour))
	seedCache(t, "example.com.", dns.TypeAAAA, 0, time.Now().Add(time.Hour))

	path := t.TempDir() + "/control.sock"
	if err := (&Proxy{}).startControl(path); err != nil {
		t.Fatal(err)
	}
	if code := Flush(path, "example.com,AAAA"); code != 0 {
		t.Fatalf("flush with a type: exit %d", code)
	}
	if cached("example.com.", dns.TypeAAAA, 0) || !cached("example.com.", dns.TypeA, 0) {
		t.Fatal("<name>,<type> did not flush exactly that type")
	}
	if code := Flush(path, "example.com"); code != 0 || cached("example.com.", dns.TypeA, 0) {
		t.Fatalf("flush: exit %d", code)
	}
	if code := Flush(path, "example.com,BOGUS"); code != 1 {
		t.Fatalf("an error reply must exit 1, got %d", code)
	}
	if code := Flush("", "example.com"); code != 1 {
		t.Fatalf("no control address must exit 1, got %d", code)
	}
	if code := Flush(t.TempDir()+"/absent.sock", "example.com"); code != 1 {
		t.Fatalf("an unreachable proxy must exit 1, got %d", code)
	}
}
