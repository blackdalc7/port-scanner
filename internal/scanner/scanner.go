// Package scanner implements a small, concurrent TCP connect scanner.
//
// It performs ordinary TCP "connect" scans (a full three-way handshake, the
// same thing any client does when it opens a socket). It sends no crafted or
// malformed packets and needs no elevated privileges. It is meant for checking
// hosts you own or are explicitly authorised to test.
package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Options controls a scan run.
type Options struct {
	// Timeout is how long to wait for a single connection attempt.
	Timeout time.Duration
	// Concurrency is the maximum number of simultaneous connection attempts.
	Concurrency int
	// Grab, when true, reads a short banner from each open port.
	Grab bool
}

// DefaultOptions returns sensible, conservative defaults.
func DefaultOptions() Options {
	return Options{Timeout: 2 * time.Second, Concurrency: 100, Grab: false}
}

// Result is the outcome of probing a single port.
type Result struct {
	Port   int    `json:"port"`
	Open   bool   `json:"open"`
	Banner string `json:"banner,omitempty"`
}

// ParsePorts turns a specification such as "22,80,443" or "1-1024" (or a mix,
// "22,80,8000-8010") into a sorted, de-duplicated slice of port numbers.
//
// Every port must be in the range 1-65535; an empty or malformed spec is an
// error.
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port specification")
	}
	set := make(map[int]struct{})
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, err := parseRange(part)
		if err != nil {
			return nil, err
		}
		for p := lo; p <= hi; p++ {
			set[p] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("no ports in specification %q", spec)
	}
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

func parseRange(part string) (lo, hi int, err error) {
	if i := strings.IndexByte(part, '-'); i >= 0 {
		lo, err = parsePort(part[:i])
		if err != nil {
			return 0, 0, err
		}
		hi, err = parsePort(part[i+1:])
		if err != nil {
			return 0, 0, err
		}
		if lo > hi {
			return 0, 0, fmt.Errorf("range %q is reversed", part)
		}
		return lo, hi, nil
	}
	p, err := parsePort(part)
	if err != nil {
		return 0, 0, err
	}
	return p, p, nil
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("port %d out of range 1-65535", p)
	}
	return p, nil
}

// Scan probes every port on host and returns results ordered by port.
//
// Attempts run on a bounded worker pool so a wide scan does not open thousands
// of sockets at once. The scan stops early if ctx is cancelled.
func Scan(ctx context.Context, host string, ports []int, opts Options) []Result {
	if opts.Concurrency < 1 {
		opts.Concurrency = 1
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}

	jobs := make(chan int)
	results := make(chan Result)

	var dialer net.Dialer
	worker := func() {
		for port := range jobs {
			select {
			case <-ctx.Done():
				return
			default:
			}
			results <- probe(ctx, &dialer, host, port, opts)
		}
	}

	workers := opts.Concurrency
	if workers > len(ports) {
		workers = len(ports)
	}
	done := make(chan struct{})
	for i := 0; i < workers; i++ {
		go func() {
			worker()
			done <- struct{}{}
		}()
	}

	go func() {
		defer close(jobs)
		for _, p := range ports {
			select {
			case <-ctx.Done():
				return
			case jobs <- p:
			}
		}
	}()

	go func() {
		for i := 0; i < workers; i++ {
			<-done
		}
		close(results)
	}()

	collected := make([]Result, 0, len(ports))
	for r := range results {
		collected = append(collected, r)
	}
	sort.Slice(collected, func(i, j int) bool { return collected[i].Port < collected[j].Port })
	return collected
}

func probe(ctx context.Context, dialer *net.Dialer, host string, port int, opts Options) Result {
	dctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := dialer.DialContext(dctx, "tcp", address)
	if err != nil {
		return Result{Port: port, Open: false}
	}
	defer conn.Close()

	res := Result{Port: port, Open: true}
	if opts.Grab {
		res.Banner = grabBanner(conn, opts.Timeout)
	}
	return res
}

// grabBanner reads whatever a service sends in the first moment after connect.
// Many services (SSH, SMTP, FTP) announce themselves; many others stay silent,
// in which case the banner is simply empty.
func grabBanner(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	return sanitise(string(buf[:n]))
}

// sanitise keeps a banner to one printable line so terminal output stays clean.
func sanitise(s string) string {
	s = strings.SplitN(s, "\n", 2)[0]
	var b strings.Builder
	for _, r := range s {
		if r == '\r' || r == '\t' {
			continue
		}
		if r < 32 || r == 127 {
			b.WriteByte('.')
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}
