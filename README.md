# port-scanner

A small, concurrent **TCP connect** port scanner written in Go, using only the
standard library. It is a learning project: enough to be genuinely useful on a
home lab, small enough to read in one sitting.

> ⚠️ **Authorised use only.** Only scan hosts you own or have explicit written
> permission to test. Unauthorised port scanning can breach computer-misuse
> laws and almost every network's acceptable-use policy. This tool performs
> ordinary TCP handshakes (nothing crafted, nothing privileged) precisely so it
> stays on the right side of that line.

## What it does

- Opens a normal TCP connection to each target port (a "connect scan") and
  reports **open** or **closed**.
- Runs attempts on a bounded worker pool, so scanning 1,024 ports does not open
  1,024 sockets at once.
- Optional **banner grab**: reads the first line a service announces on connect
  (SSH, SMTP and FTP usually say hello; most others stay quiet).
- Cancels cleanly on Ctrl-C, and can print results as text or JSON.

## Quick start

```bash
go build -o portscan ./cmd/portscan

# scan the common ports on your own machine
./portscan -host 127.0.0.1 -ports 1-1024

# a specific set, with banners, as JSON
./portscan -host 192.168.1.10 -ports 22,80,443,8080 -banner -json
```

Example output:

```text
   22/tcp  open   SSH-2.0-OpenSSH_9.6
   80/tcp  open
  443/tcp  open

scanned 1024 port(s) on 127.0.0.1 in 412ms: 3 open
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `-host` | *(required)* | Target host or IP |
| `-ports` | `1-1024` | Ports: `22,80,443`, `1-1024`, or a mix `22,8000-8010` |
| `-timeout` | `2s` | Per-port connection timeout |
| `-concurrency` | `100` | Maximum simultaneous connection attempts |
| `-banner` | `false` | Read a short banner from each open port |
| `-json` | `false` | Emit results as JSON |
| `-all` | `false` | Also print closed ports |

## How it works

```text
cmd/portscan/main.go        flag parsing, output formatting, Ctrl-C handling
internal/scanner/
    scanner.go              ParsePorts + the concurrent Scan worker pool
    scanner_test.go         unit tests (run against real local listeners)
```

The core is `Scan`, which fans ports out to a fixed number of workers over a
channel. Each worker calls `net.DialContext` with a timeout; a successful dial
means the port is open. Results are collected and sorted by port number so the
output is deterministic regardless of the order attempts finish in.

`ParsePorts` accepts individual ports and ranges, de-duplicates, sorts, and
rejects anything outside 1-65535 — the kind of input handling that is easy to
get subtly wrong, so it has the most tests.

## Tests

```bash
go test ./...          # or: go test -race ./...
```

The tests spin up real loopback listeners (`net.Listen` on `127.0.0.1:0`) so the
scanner is exercised end to end without mocking the network: an open port, a
port that has been closed, result ordering, and the banner grab path.

## Limitations (on purpose)

- TCP connect only — no SYN/stealth scanning, no UDP, no OS fingerprinting.
  Those need raw sockets and root, and are out of scope for a small learning
  tool.
- No host discovery; give it one host at a time.

## Licence

MIT. See [LICENSE](LICENSE).
