// Command portscan is a small concurrent TCP connect scanner.
//
// Authorised use only. Scan hosts you own or have written permission to test.
// Unauthorised port scanning may be against the law and against the acceptable
// use policy of most networks.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/blackdalc7/port-scanner/internal/scanner"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "portscan:", err)
		os.Exit(1)
	}
}

func run(args []string, out *os.File) error {
	fs := flag.NewFlagSet("portscan", flag.ContinueOnError)
	host := fs.String("host", "", "target host or IP (required)")
	portsSpec := fs.String("ports", "1-1024", "ports, e.g. 22,80,443 or 1-1024")
	timeout := fs.Duration("timeout", 2*time.Second, "per-port connection timeout")
	concurrency := fs.Int("concurrency", 100, "maximum simultaneous connections")
	grab := fs.Bool("banner", false, "read a short banner from each open port")
	asJSON := fs.Bool("json", false, "emit results as JSON")
	showClosed := fs.Bool("all", false, "also print closed ports")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" {
		fs.Usage()
		return fmt.Errorf("the -host flag is required")
	}

	ports, err := scanner.ParsePorts(*portsSpec)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	opts := scanner.Options{Timeout: *timeout, Concurrency: *concurrency, Grab: *grab}
	start := time.Now()
	results := scanner.Scan(ctx, *host, ports, opts)
	elapsed := time.Since(start)

	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}

	open := 0
	for _, r := range results {
		if r.Open {
			open++
			line := fmt.Sprintf("%5d/tcp  open", r.Port)
			if r.Banner != "" {
				line += "   " + r.Banner
			}
			fmt.Fprintln(out, line)
		} else if *showClosed {
			fmt.Fprintf(out, "%5d/tcp  closed\n", r.Port)
		}
	}
	fmt.Fprintf(out, "\nscanned %d port(s) on %s in %s: %d open\n",
		len(ports), *host, elapsed.Round(time.Millisecond), open)
	return nil
}
