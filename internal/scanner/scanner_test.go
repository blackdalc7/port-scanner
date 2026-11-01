package scanner

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"22", []int{22}},
		{"22,80,443", []int{22, 80, 443}},
		{"1-5", []int{1, 2, 3, 4, 5}},
		{"80,20-22,80", []int{20, 21, 22, 80}}, // dedup + sort
		{" 443 , 80 ", []int{80, 443}},         // whitespace tolerated
	}
	for _, c := range cases {
		got, err := ParsePorts(c.in)
		if err != nil {
			t.Fatalf("ParsePorts(%q) returned error: %v", c.in, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParsePorts(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParsePortsErrors(t *testing.T) {
	for _, in := range []string{"", "   ", "0", "70000", "abc", "10-5", "22,", "-"} {
		if in == "22," {
			// trailing comma is tolerated (empty segment skipped); skip here.
			continue
		}
		if _, err := ParsePorts(in); err == nil {
			t.Errorf("ParsePorts(%q) expected error, got nil", in)
		}
	}
}

func TestParsePortsTrailingComma(t *testing.T) {
	got, err := ParsePorts("22,")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, []int{22}) {
		t.Errorf("got %v, want [22]", got)
	}
}

func TestScanDetectsOpenAndClosed(t *testing.T) {
	// Open a real listener on a free port, then find a closed one.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	openPort := ln.Addr().(*net.TCPAddr).Port

	// A second listener gives us a port we can guarantee is closed by closing it.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen2: %v", err)
	}
	closedPort := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()

	opts := Options{Timeout: time.Second, Concurrency: 4}
	results := Scan(context.Background(), "127.0.0.1", []int{openPort, closedPort}, opts)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	byPort := map[int]Result{}
	for _, r := range results {
		byPort[r.Port] = r
	}
	if !byPort[openPort].Open {
		t.Errorf("port %d should be open", openPort)
	}
	if byPort[closedPort].Open {
		t.Errorf("port %d should be closed", closedPort)
	}
}

func TestScanResultsSortedByPort(t *testing.T) {
	ports := []int{9, 7, 8}
	results := Scan(context.Background(), "127.0.0.1", ports, Options{Timeout: 100 * time.Millisecond, Concurrency: 3})
	for i := 1; i < len(results); i++ {
		if results[i-1].Port > results[i].Port {
			t.Fatalf("results not sorted: %v", results)
		}
	}
}

func TestBannerGrab(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("SSH-2.0-TestServer\r\nextra"))
		time.Sleep(50 * time.Millisecond)
		c.Close()
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	results := Scan(context.Background(), "127.0.0.1", []int{port}, Options{Timeout: time.Second, Concurrency: 1, Grab: true})
	if len(results) != 1 || !results[0].Open {
		t.Fatalf("expected one open result, got %v", results)
	}
	if results[0].Banner != "SSH-2.0-TestServer" {
		t.Errorf("banner = %q, want %q", results[0].Banner, "SSH-2.0-TestServer")
	}
}

func TestSanitise(t *testing.T) {
	if got := sanitise("hello\x00\x07world\r\nignored"); got != "hello..world" {
		t.Errorf("sanitise = %q, want %q", got, "hello..world")
	}
}
