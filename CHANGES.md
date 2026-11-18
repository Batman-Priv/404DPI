# Changes (second round)

- `-fake-packet` rewritten: decoys are forged with a raw socket and the
  connection's real seq/ack (Linux `TCP_REPAIR`), new `-fake-method`
  (`ttl`, `badsum`, `badseq`, `md5`). Needs root on Linux; otherwise a warning.
- `-front-map` rewritten as real domain fronting: local name-constrained CA
  (`-front-ca-dir`), TLS termination, upstream SNI=front (`-front-upstream-ca`
  for private test CAs). The old SNI-rewrite that could never work is gone.
- Bug: `-fragment-method none` with the (default) adaptive mode silently
  started with `sni`; it now really starts with `none`.
- New `lab/`: network-namespace test network with a configurable DPI
  simulator and a scripted scenario matrix (`lab/run-lab.sh test`).

# Changes in this revision

## Build
- Restored the missing `//go:build` constraints (`transparent_*.go`, `sockopts_*.go`): the project did not compile on Linux (duplicate definitions).
- Dropped the `golang.org/x/net` dependency (TTL is now set through `syscall`, with unix/windows/other variants); `go.mod` needs Go 1.22 instead of 1.25. Cross-builds for linux, windows, darwin, freebsd pass.

## Bugs fixed
- **Blacklist semantics were inverted**: listed domains got `403`/SOCKS "not allowed" instead of the bypass, so the shipped list and `-autoblacklist` defeated themselves. Now the list = destinations that need the bypass; others go direct; `-no-blacklist` bypasses everything. Counters renamed Bypassed/Direct (JSON keeps `allowed`/`blocked` as aliases).
- **Download counter was always 0** (both directions counted as upload) and only updated at connection end; now counted live in both directions, incl. plain HTTP.
- **Ctrl+C hung** while any tunnel was open (and a second Ctrl+C was swallowed). Shutdown now waits at most 3 s per server; a second signal exits immediately.
- **`Proxy-Authorization` (and `Proxy-Connection`) were forwarded to origin servers** on plain HTTP requests.
- **204/304 (and interim 1xx) responses stalled** the keep-alive connection; `101 Switching Protocols` is now tunnelled.
- **HTTP CONNECT to non-TLS ports (e.g. SSH) stalled** waiting for a ClientHello; fragmentation is now only attempted on TLS ports (443, 8443), as SOCKS5 already did.
- **Fragmenter re-serialised the ClientHello** even when nothing was to be changed; it now forwards the original bytes, only re-chunked (tested byte-for-byte).
- **Presets `aggressive`/`stealth` broke every HTTPS connection** (they enabled `-tls-profile`; any ClientHello rewrite makes the handshake fail — verified with a local TLS server). Presets no longer enable rewriting options or `-fake-packet`; startup prints a warning if you enable them yourself.
- Adaptive escalation no longer force-enables `-fake-packet`.
- Strategy cache: data race on the record, success statistics polluted by other strategies' failures, non-atomic file writes.
- Auto-blacklist: unbounded duplicate probes per request, probes of IP literals.
- SOCKS5 UDP ASSOCIATE kept its relay socket for up to 2 min after the control connection closed.
- QUIC inspector: missing bounds checks; a crafted CRYPTO frame could force a huge allocation.
- Upstream proxies: no handshake deadline, IPv6 / IP literals mishandled, unknown `-out-type` silently meant "raw TCP forward" (now validated; default `socks5`).
- `-scan`: DNS mismatch on a working site was reported as DPI; suggestions no longer recommend options that break TLS.
- Proxy/SOCKS5 credentials compared in constant time; warning when listening on a non-loopback address without auth; stats HTTP server has a header timeout.
- Duplicate `padding`/`ECH` extension no longer added; removed deprecated `rand.Seed`; invalid flag values (`-fragment-method`, `-quic-mode`, ...) are rejected instead of silently ignored.

## Not changed (design limits, documented in README)
- ClientHello-rewriting options and `-front-map` cannot work in a relaying proxy; `-fake-packet` needs raw sockets to be reliable.

## Tests
`go test -race ./...`: new tests for real TLS through the proxy (all fragment methods), byte-exact fragments, blacklist semantics, header leak, 204/304 stalls, traffic counters, shutdown, strategy records, QUIC bounds.
