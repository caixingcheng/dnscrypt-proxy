package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
)

// A minimal control channel, in the spirit of unbound-control: one line-based
// command per connection, one line of reply. It exists so that a health check
// can drop a name from the cache before probing it - otherwise the probe is
// answered from the cache (or from a stale entry once the upstream is gone)
// and never notices that the upstream is unreachable.
//
//	flush <name>              drop <name> for the common record types
//	flush_type <name> <type>  drop <name> for one record type
//
// The same is available from the command line, against the proxy that runs
// with the given configuration file:
//
//	dnscrypt-proxy -config <file> -flush <name>[,<type>]
//
// Replies are "ok <removed entries>" or "error <reason>". There is no
// authentication, so access control is left to where it listens: an address
// starting with "/" is a unix socket, made readable and writable by its owner
// only; anything else is a TCP address and should be a loopback one.

const (
	controlReadTimeout = 2 * time.Second
	controlMaxLine     = 512
)

// The same set unbound-control's "flush" removes.
var controlFlushTypes = []uint16{
	dns.TypeA, dns.TypeAAAA, dns.TypeNS, dns.TypeSOA, dns.TypeCNAME, dns.TypeDNAME,
	dns.TypeMX, dns.TypePTR, dns.TypeSRV, dns.TypeNAPTR, dns.TypeSVCB, dns.TypeHTTPS, dns.TypeTXT,
}

func (proxy *Proxy) startControl(address string) error {
	listener, err := listenControl(address)
	if err != nil {
		return err
	}
	dlog.Noticef("Control channel listening on %s", address)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				dlog.Warnf("Control channel accept: %v", err)
				time.Sleep(time.Second)
				continue
			}
			go handleControlConn(conn)
		}
	}()
	return nil
}

func listenControl(address string) (net.Listener, error) {
	if !strings.HasPrefix(address, "/") {
		return net.Listen("tcp", address)
	}
	// A socket left behind by a previous instance that did not exit cleanly
	// makes the bind fail. Only ever remove a socket, never another file.
	if fi, err := os.Lstat(address); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", address)
		}
		if err := os.Remove(address); err != nil {
			return nil, err
		}
	}
	listener, err := net.Listen("unix", address)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(address, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

func handleControlConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(controlReadTimeout))
	reader := bufio.NewReaderSize(conn, controlMaxLine)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return
	}
	fmt.Fprintf(conn, "%s\n", runControlCommand(strings.TrimSpace(line)))
}

// Flush implements the -flush command line switch: it asks the running proxy,
// through its control channel, to drop "<name>" or "<name>,<type>" from the
// cache, prints the reply and returns the exit code.
func Flush(address string, arg string) int {
	if address == "" {
		fmt.Fprintln(os.Stderr, "control_listen_address is not set in the configuration file")
		return 1
	}
	command := "flush " + arg
	if name, qtype, found := strings.Cut(arg, ","); found {
		command = "flush_type " + strings.TrimSpace(name) + " " + strings.TrimSpace(qtype)
	}
	reply, err := sendControlCommand(address, command)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(reply)
	if !strings.HasPrefix(reply, "ok") {
		return 1
	}
	return 0
}

func sendControlCommand(address string, command string) (string, error) {
	network := "tcp"
	if strings.HasPrefix(address, "/") {
		network = "unix"
	}
	conn, err := net.DialTimeout(network, address, controlReadTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(controlReadTimeout))
	if _, err := fmt.Fprintf(conn, "%s\n", command); err != nil {
		return "", err
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && len(reply) == 0 {
		return "", err
	}
	return strings.TrimSpace(reply), nil
}

func runControlCommand(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "error empty command"
	}
	switch fields[0] {
	case "flush":
		if len(fields) != 2 {
			return "error usage: flush <name>"
		}
		return fmt.Sprintf("ok %d", flushCachedName(fields[1], controlFlushTypes))
	case "flush_type":
		if len(fields) != 3 {
			return "error usage: flush_type <name> <type>"
		}
		qtype, ok := dns.StringToType[strings.ToUpper(fields[2])]
		if !ok {
			return "error unknown type " + fields[2]
		}
		return fmt.Sprintf("ok %d", flushCachedName(fields[1], []uint16{qtype}))
	default:
		return "error unknown command " + fields[0]
	}
}

// flushCachedName removes every cached entry for name and the given types,
// fresh or stale, under each combination of the DNSSEC and CD flags that are
// part of the cache key. Returns the number of entries removed.
func flushCachedName(name string, qtypes []uint16) int {
	if cachedResponses == nil {
		return 0
	}
	// cache keys use the question name as sent: fully qualified, any case
	qname := name
	if !strings.HasSuffix(qname, ".") {
		qname += "."
	}
	removed := 0
	for _, qtype := range qtypes {
		for flags := byte(0); flags < 4; flags++ {
			if _, ok := cachedResponses.Remove(cacheKey(qtype, dns.ClassINET, flags, qname)); ok {
				removed++
			}
		}
	}
	return removed
}
