# Probe

spoofdpi sends fake packets with a TTL low enough that they expire before the server, so the hop count it learns has to match the real path. `spoofdpi probe` measures the hop counts to sites on your network, shows them next to the hop count spoofdpi would learn, checks whether a DPI on the path blocks each site over QUIC, checks how it blocks the site's TLS connections and whether fake packets fool it, and checks how the server handles fake packets that reach it:

```console
$ sudo spoofdpi probe --url www.example.com --url example.org --url blocked.example
probe: dns: udp (8.8.8.8:53), config /home/user/.config/spoofdpi/spoofdpi.toml
www.example.com (203.0.113.10)
  https
    status      clear
    hops(tcp)   11 actual / 11 learned
    server
      bad_sni      answers
      seq_offset   drops at -1024 or below; breaks (alert 50) at -512
      ack_offset   drops at -32768 or below; breaks (bad sni) at -16384
      bad_md5      drops
  quic
    status      clear
    hops(udp)   11 actual / 11 learned

example.org (203.0.113.20)
  https
    status      censored
    hops(tcp)   10 actual / 9 learned (gap -1)
    dpi
      type      RST
      chunks    reassembled, passes at 8 bytes or less
      disorder  ok
      position  4
      fake
        ttl          ok
        seq_offset   ok up to -8192 (x at -16384)
        ack_offset   ok up to -65536 (x at -131072)
        bad_md5      x
    server
      bad_sni      answers
      seq_offset   drops at every offset
      ack_offset   drops at -131072 or below; breaks (reset) at -65536
      bad_md5      drops
  quic
    status      censored
    hops(udp)   10 actual / 9 learned (gap -1)

blocked.example (198.51.100.40)
  https
    status      unreachable
  quic
    status      unknown (no reply)
    hops(udp)   no reply
```

!!! warning
    Stop spoofdpi before you probe if it runs in TUN mode. A spoofdpi in TUN mode routes the probe's own packets, so the probe measures spoofdpi instead of the network. A spoofdpi in HTTP or SOCKS5 mode does not affect the probe.

## What It Measures

Every hop count is a number of routers between this host and the server, the unit spoofdpi learns hop counts in. A server on the local link is `0` hops away. spoofdpi sends fake packets with a TTL of the hop count plus `hop-count-offset`, which is the hop count minus 1 by default, so that they expire at the last router before the server.

| Value | How it is measured |
| :--- | :--- |
| `hops(tcp)` actual | Connects to port 443 of the server with every TTL from 1 to `--max-ttl`. The hop count is the smallest TTL whose SYN completes the handshake, minus 1. |
| `hops(tcp)` learned | Captures the SYN/ACK of a connection at the default TTL and estimates the hop count from the TTL it arrives with, the same way spoofdpi's TCP sniffer does. |
| `hops(udp)` actual | Sends a QUIC packet of a reserved version to UDP port 443 of the server with every TTL from 1 to `--max-ttl`. A TTL reaches the server when the server answers with a QUIC Version Negotiation packet, or its host answers with an ICMP port unreachable. The hop count is the smallest TTL that reaches it, minus 1. |
| `hops(udp)` learned | Captures the UDP reply to the packet at the default TTL and estimates the hop count from the TTL it arrives with, the same way spoofdpi's UDP sniffer does. |

- The learned hop counts are the values before `hop-count-offset`, `hop-count-min` and `hop-count-max` apply.
- spoofdpi keeps the TCP and UDP hop counts of a server apart. Its fake packets use the hop count learned over their own protocol, or else the one learned over the other protocol, or else `hop-count-default`.
- A connection, or a UDP packet, at the default TTL is tried first, up to 5 times until one reaches the server. Only when one does is the TTL scan run.
- The TTL scan tries every TTL at once, then retries the TTLs that did not get through, for up to 5 rounds in all, and stops early when every TTL got through. A packet lost at the threshold therefore does not raise the result.
- An ICMP port unreachable comes only from the server's host, so a server without QUIC is measured too, as long as it rejects the packet instead of dropping it.
- When a learned hop count differs from the actual one, the server's reply took a different path back, or its TTL started from a value other than 64, 128 or 255. spoofdpi then sends fake packets with a wrong TTL.
- A transparent proxy or SYN proxy on the path, which some DPI systems and CDNs run, completes the handshake itself. both TCP values then measure the distance to the proxy, not to the server, and the DPI checks talk to the proxy.

### UDP Learned Hop Count

spoofdpi learns a UDP hop count from any UDP packet the server sends. probe takes the UDP packet from the server's address and port to the local port of the packet at the default TTL that reached the server, the latest one if several arrive. The learned UDP value is `-` when:

- The server answered only with an ICMP port unreachable. spoofdpi does not learn from ICMP, so its UDP fake packets to the server use the TCP hop count it learned, or else `hop-count-default`. The line ends with `(not learned)`.
- The UDP reply was not captured. The line ends with `(not learned)`.
- Packet capture is unavailable. See [Root and Packet Capture](#root-and-packet-capture).

## QUIC Status

After the hop counts, probe checks whether a DPI on the path blocks the site over QUIC. The `status` line of the `quic` section is its verdict.

probe sends a QUIC v1 Initial packet, which carries a TLS ClientHello, to UDP port 443 of the server, first one for `example.com`, a name the DPI is not expected to block, then one for the site's host. Each is sent from a socket of its own, up to 3 times until the server answers it, and each waits up to `--timeout` for the answer. The server answers when it sends a QUIC v1 Initial, Handshake or Retry packet to the connection ID of the probe's Initial, or a Version Negotiation packet that echoes its connection IDs. A Version Negotiation packet that lists version 1 is ignored, as QUIC requires. probe does not decrypt the answer. The `example.com` Initial goes first, so that a block the site's Initial sets off cannot spoil it.

| Value | Meaning |
| :--- | :--- |
| `clear` | The server answered the site's Initial. |
| `censored` | The server answered the `example.com` Initial, but not the site's: no answer came back, or an ICMP error did. |
| `unreachable` | Both Initials got an ICMP host or network unreachable. |
| `unknown (no QUIC v1)` | The server answered the site's Initial with a Version Negotiation packet: it does not speak QUIC v1. |
| `unknown (no QUIC)` | The server's host answered the `example.com` Initial with an ICMP port unreachable: nothing listens on UDP port 443. |
| `unknown (no reply)` | The server answered neither Initial: no answer came back, or ICMP errors that fit no other row did. |
| `unknown (local error <ERRNO>)` | Building or sending an Initial failed on this host, for example `local error EMFILE`. A failure to build the Initial shows as `local error` followed by its message. |
| `?` | A residual block from an earlier target at the same address did not clear. The `note` line says why. |

A `note` line, under `status`, holds notes about the check, separated by `; `.

Targets at the same address share a QUIC block, which probe tracks apart from the TLS one. When the QUIC check of an earlier target at the address was `censored` or `?`, a later target sends the `example.com` Initial until the server answers it, every 5 seconds for up to 60 seconds, then sends the site's Initial:

- When it is answered after a wait, the note says `waited <N>s for residual block from <URL>`.
- When it is still not answered after 60 seconds, the `status` is `?`, the note says `residual block from <URL> (not cleared after 60s)`, and the site's Initial is not sent.

A `clear` target at the address shows that the block is gone, so the targets after it do not wait.

### QUIC Caveats

- The ClientHello is Go's own, with ALPN `h3` and a single X25519 key share, so that it fits one 1200-byte Initial packet. Browsers send a post-quantum key share, which splits their ClientHello over two Initial packets, and some DPI systems do not reassemble it. A `censored` site may then still work in a browser.
- The `hops(udp)` probe is not a QUIC v1 packet. A network that blocks all QUIC v1 traffic therefore gives `unknown (no reply)` while `hops(udp)` is still measured.
- A server that ignores Initials for names it does not serve gives `unknown (no reply)`.
- A QUIC residual block that lasts longer than 60 seconds gives `?` for the later targets at the same address.
- If the site's Initial is lost 3 times in a row while the `example.com` one gets through, the site shows as `censored`. With 3 tries this is rare.

## DPI Checks

After the QUIC check, probe checks how a DPI on the path treats the site's TLS ClientHello, on TCP port 443. Their results make up the rest of the `https` section. Each check sends a fresh ClientHello for the URL's host on a connection of its own, once for each case it tries, and waits up to `--timeout` for the answer. Only the first connect is retried. A ServerHello means the ClientHello got through.

The checks run in this order, and stop early when there is nothing more to learn:

1. block: connects, up to 5 times until one completes, sends the benign ClientHello once as the baseline for the [residual block](#residual-block) checks, then sends the site's ClientHello in one piece. If it gets through, the site is `clear` and the other checks do not run. The `type` line, with how the site is blocked, shows only for a site that is not `clear`.
2. `chunks`: sends the ClientHello in chunks of 35, 32, 29 and so on down to 2 bytes, as spoofdpi's `split-mode = "chunk"` does, until a size gets through.
3. `disorder`: sends the ClientHello in chunks of the smallest size that was blocked in the `chunks` check, or 35 bytes if none was, with spoofdpi's `disorder`. Every other chunk leaves with TTL 1 and reaches the server only when it is retransmitted, so this check waits twice `--timeout`.
4. `position`: finds the hop the DPI is at, by sending the ClientHello with TTL 1, 2, 3 and so on up to the hop count, so that it dies at a router before the server. A DPI that resets reveals itself with an RST at the first TTL that reaches it. For a DPI that drops silently, probe sends one byte past the ClientHello with a TTL that reaches the server: until the ClientHello reaches the DPI, the server acknowledges the byte with a duplicate ACK; from the TTL that reaches the DPI on, the DPI drops the connection and the duplicate ACK stops. This needs packet capture, usually root.
5. `fake`: only for a `censored` site. Sends a fake ClientHello before the site's ClientHello, as spoofdpi's `fake-preflight = 1` does, with a TTL that dies before the server: the hop of the DPI from the `position` check, or else the actual TCP hop count minus 1 (at least 1). If the DPI takes the fake for the connection's ClientHello, the real one gets through. The fake is first sent with the connection's own sequence numbers (`ttl`). Only if that gets through, probe [searches](#offset-search) for the `fake-seq-offset` values, then the `fake-ack-offset` values, whose fakes still fool the DPI, and last sends the fake with `fake-bad-md5sig`. This needs root. See [Fake Packets](#fake-packets).

After the DPI checks, the [server check](#server-check) runs for every site that is `clear` or `censored`.

### Lines

The `status` line is the verdict of the checks, the first line of the `https` section. The `dpi` subsection, with the lines below, is there only when the status is `censored`. The `server` subsection is described in [Server Check](#server-check).

| Line | Value | Meaning |
| :--- | :--- | :--- |
| `status` | `clear` | The ClientHello got through. No other DPI check runs, and there is no `dpi` subsection. The server check still runs. |
| `status` | `censored` | The ClientHello was blocked. The `dpi` subsection says how. |
| `status` | `unreachable` | None of the 5 connections completed, and neither did those of the TCP hop count. No other check runs, there is no `dpi` subsection, and the `hops(tcp)` line is left out. |
| `status` | `unknown (connect failed)` | None of the 5 connections completed, although one of the TCP hop count did. No other check runs, and there is no `dpi` subsection. |
| `status` | `unknown (<reason>)` | The connection or the block check failed on this host, for example `local error EMFILE`. No other check runs, and there is no `dpi` subsection. |
| `status` | `?` | A residual block kept the checks from running. The `note` line, right under `status`, says why. |
| `type` | `RST` | The connection was reset. |
| `type` | `silent` | Nothing came back within `--timeout`. |
| `type` | `other (<detail>)` | Another answer, such as `TLS alert 40`, `closed` for a FIN, or `unexpected reply` for an injected page. It counts as blocked in the `chunks` and `disorder` checks. |
| `chunks` | `not reassembled` | 35-byte chunks already get through: the DPI looks at single segments. |
| `chunks` | `reassembled, passes at N bytes or less` | The DPI reassembles larger chunks, but not chunks of `N` bytes. spoofdpi's `split-mode = "chunk"` with a size of `N` or less should get through. |
| `chunks` | `reassembled` | Even 2-byte chunks are blocked. |
| `chunks` | `unknown (<reason>)` | Every try of a size failed on this host. Failures on this host never count as blocked. |
| `disorder` | `ok` | The disordered chunks got through. |
| `disorder` | `x (DPI reorders segments)` | Blocked, although the DPI also reassembles chunks sent in order: it reorders segments too. |
| `disorder` | `x (blocked on out-of-order segments)` | Blocked, although chunks sent in order are not reassembled: the DPI blocks the disorder itself. |
| `disorder` | `unknown (<reason>)` | Every try failed on this host, for example `cannot set TTL`. |
| `position` | `N` | The DPI is `N` hops away. |
| `position` | `unknown` | A DPI that resets sent no RST at any TTL up to the hop count. |
| `position` | `unknown (<reason>)` | `needs root` without packet capture; `block is neither RST nor silent`; `no dup ACK` when the server does not acknowledge the byte even at TTL 1; `per-packet drop` when the duplicate ACK comes back at every TTL; `could not control TTL` when the capture did not show the packets leaving with their TTL; or a failure on this host, such as `cannot set TTL`. |
| `fake` | | A subsection with one line per fake tried, in the order above: `ttl`, `seq_offset`, `ack_offset` and `bad_md5`. Only `ttl` is shown when it is not `ok`, as the other fakes are not tried then. |
| `fake` | `unknown (<reason>)` | The check could not run: `needs root` without packet capture, `fake packets unavailable` when the fake packets cannot be sent on the interface (see [Fake Packets](#fake-packets)), `hop count unknown` when the actual TCP hop count was not measured, or `server on local link`. |
| `ttl`, `bad_md5` | `ok` | The site's ClientHello got through after the fake: the DPI took the fake for the connection's ClientHello. spoofdpi with this fake, and a TTL like this one, should get through. |
| `ttl`, `bad_md5` | `x` | The site's ClientHello was blocked as without the fake. |
| `seq_offset`, `ack_offset` | `ok up to -M (x at -F)` | The fakes of every power of two tried from `-1` to `-M` fooled the DPI, and those of `-F`, which is `-2 M`, and `-2 F` did not. When `-F` is `-2147483648`, there is no `-2 F` to try. The true boundary lies between `-M` and `-F`. spoofdpi with an offset from `-1` to `-M`, and a TTL like this one, should get through. |
| `seq_offset`, `ack_offset` | `ok at every offset` | The fakes of every power of two tried, down to `-2147483648` (-2^31), fooled the DPI. |
| `seq_offset`, `ack_offset` | `x` | The fakes of the offsets `-1` and `-2` did not fool the DPI. |
| `ttl`, `seq_offset`, `ack_offset`, `bad_md5` | `unknown (<reason>)` | The attempt of a fake failed on this host: `fake not sent` when the fake packet could not be sent, `seq not learned` when the fake was not crafted with the connection's sequence numbers, `seq not verified` when the capture did not show the ClientHello leaving, `fake reached server` when the server answered the fake although its TTL should have stopped it, or another local error. An attempt with `seq not verified` or `seq not learned` is made again on a new connection, up to 3 connections in all, and the reason is that of the last one; one with `fake not sent` is not made again. A search ends at the first offset whose attempt failed on this host. |
| `seq_offset`, `ack_offset` | `UNSTABLE` | The outcome flipped back at the offset past the boundary. See [Offset Search](#offset-search). |
| `chunks`, `disorder`, `position`, `fake` | `?` | A residual block spoiled the check or kept it from running. The note says why. |
| `note` | | Notes about the checks, separated by `; `. It is a line of the `dpi` subsection, or, when there is no `dpi` subsection, right under `status`. |

### Residual Block

Many DPI systems keep blocking a server address for a while after they block a connection, even connections they would otherwise let through. probe checks for this with a ClientHello for `example.com`, a name the DPI is not expected to block, sent to the same server.

Before the site's first ClientHello, probe sends the `example.com` ClientHello once and keeps how the server answers it as the baseline: a ServerHello or a TLS alert, a close, a reset, or no answer. Some front ends close or reset connections for names they do not serve, so the baseline is not always an answer; when it is not, the note says so, for example `benign baseline: closed`.

After each check that sent the site's ClientHello or fake packets, probe sends the `example.com` ClientHello again. A ServerHello and a TLS alert count as the same answer. If the answer differs from the baseline, a residual block is left, and the note says `residual block after the <line> check`:

- After the block check, the `status` and `type` lines keep their value, as its attempt ran before any block it left. The later checks show `?`.
- After the `chunks`, `disorder`, `position` or `fake` check, that check and the ones after it show `?`, as the block may have spoiled its later attempts.
- The residual check runs after the whole `fake` check and after the whole server check, not after each offset of their [searches](#offset-search). A residual block that starts during a search makes the later offsets look blocked, or, in the server check, broken, which may move the boundary. When the block is still there at the residual check, the check shows `?` as above. A block that has cleared by then is not noticed: the boundary may then be off, or the line `UNSTABLE` when the outcome flipped back.
- A connection that fails during the `position` check gives `?` with the note `residual block during the position check`, and `fake` shows `?` too.
- After any of these, the [server check](#server-check) does not run, and the `server` line shows `?`.
- After the server check, the `server` line shows `?`, with the note `residual block after the server check`.

Targets at the same address share the block. When an earlier target at the address had its ClientHello blocked, a later target first connects, then sends the `example.com` ClientHello until the server answers it with a ServerHello or a TLS alert, every 5 seconds for up to 60 seconds. That answer is its baseline.

- When it gets through, the checks run, and the note says `waited <N>s for residual block from <URL>`, if probe had to wait.
- When it is still not answered after 60 seconds, the `status` is `?`, and the note says `residual block from <URL> (not cleared after 60s)`. A server that never answers `example.com` with TLS gives this result too.
- When none of the 5 connections completes, the `status` is `unreachable`, or `unknown (connect failed)` if one of the target's own TCP hop count measurement did.

A clear target at the address shows that the block is gone, so the targets after it do not wait, unless its own [server check](#server-check) left a residual block: the targets after it then wait as after a blocked one.

### Server Check

spoofdpi's fake packets are meant to die before the server, but with a wrong hop count, or a path that changes, they reach it. The server check shows what the server does with each fake when it does: whether it drops the fake, so that the connection goes on as without it, or takes it and breaks the connection. A fake option the server drops is safe to use even when the TTL is too high.

The server check runs for every site that is `clear` or `censored`, after the DPI checks. It sends a fake with TTL 64, so that it reaches the server, then a real ClientHello in one piece. Without the fake, the server answers that ClientHello with a ServerHello; a fake `drops` when it still does. It [searches](#offset-search) for the `fake-seq-offset` values, then the `fake-ack-offset` values, whose fakes the server drops, then sends the fake with `fake-bad-md5sig`. This needs root, like the `fake` check.

- For a `clear` site, the real ClientHello is the site's own, which the DPI lets through.
- For a `censored` site, the DPI would block the site's own, so the real ClientHello is the `example.com` one of the [residual block](#residual-block) checks. This works only when the server answers `example.com` with a ServerHello, which the `bad_sni` line shows as `answers`. A server that rejects names it does not host would reject the fake's `www.google.com` the same way, so a fake it took could not be told from one it dropped. Otherwise the whole subsection is `server      unknown (server rejects unknown SNI)`, and no fake is sent.

The subsection starts with the `bad_sni` line, the server's answer to the `example.com` ClientHello of the residual block baseline, then has the `seq_offset`, `ack_offset` and `bad_md5` lines. For a `clear` site, `bad_sni` is shown for reference only.

| Line | Value | Meaning |
| :--- | :--- | :--- |
| `bad_sni` | `answers` | The server answers a ClientHello for a name it does not host with a ServerHello. |
| `bad_sni` | `alert N (<name>)` | It answers with a TLS alert, such as `alert 112 (unrecognized_name)`. The name is shown for common alerts. |
| `bad_sni` | `closed`, `reset`, `silent` | It closes the connection, resets it, or does not answer within `--timeout`. |
| `bad_sni` | `unknown (<reason>)` | The ClientHello failed on this host, for example `local error EMFILE`, so the server's answer is not known. A `clear` site's check still runs. |
| `bad_md5` | `drops` | The server answered the real ClientHello with a ServerHello, as it does without the fake: it dropped the fake. |
| `bad_md5` | `breaks (<what happened>)` | The connection went otherwise: `reset`, `alert N` for any TLS alert, `timeout`, `closed`, `unexpected reply`, or `bad sni` when the server answered the fake's own ClientHello, for `www.google.com`. |
| `seq_offset`, `ack_offset` | `drops at -N or below; breaks (<what happened>) at -B` | The server dropped the fakes of the powers of two `-N` and `-2 N`, and took those of every power of two tried from `-1` to `-B`, which is `-N / 2`. The true boundary lies between `-B` and `-N`. What happened is as for `bad_md5`, at `-B`. When `-N` is `-2147483648`, there is no `-2 N` to try, and the line says `drops at -2147483648; breaks (<what happened>) at -1073741824`. |
| `seq_offset`, `ack_offset` | `drops at every offset` | The server dropped the fakes of the offsets `-1` and `-2`. |
| `seq_offset`, `ack_offset` | `breaks at every offset (<what happened>)` | The server took the fakes of every power of two tried, down to `-2147483648` (-2^31). What happened is that of `-2147483648`. |
| `seq_offset`, `ack_offset` | `UNSTABLE` | The outcome flipped back at the offset past the boundary. |
| `seq_offset`, `ack_offset`, `bad_md5` | `unknown (<reason>)` | The attempt of a fake failed on this host, with the reasons of the `fake` check. |
| `server` | `unknown (<reason>)` | The check could not run: `server rejects unknown SNI` for a `censored` site whose `bad_sni` is not `answers`; the local error of the `example.com` ClientHello, such as `local error EMFILE`, when it failed on this host for such a site; `needs root`; or `fake packets unavailable`. This is the whole subsection. |
| `server` | `?` | A residual block spoiled the check or kept it from running. The note says why. This is the whole subsection. |

A server answers a ClientHello with the session ID of the ClientHello it answers. A ServerHello that carries the fake's session ID is `bad sni`. A TLS 1.2 server picks a session ID of its own, so after its ServerHello probe keeps reading for four round trips plus 200 ms, at least 500 ms and at most `--timeout`, but not past the attempt's own `--timeout`: a server that took the fake rejects the ClientHello that follows it with an alert, a close or a reset, which is then the `breaks` value. A server that stays silent then is taken to have dropped the fake.

### Offset Search

The `fake` and server checks do not try a fixed list of `fake-seq-offset` and `fake-ack-offset` values. For each of the two options, with the other at `0` and without `fake-bad-md5sig`, they search the negative offsets from `-1` to `-2147483648` (-2^31) for the boundary where the outcome changes:

1. They try the offsets `-1`, `-2`, `-4` and so on, each power of two once, until the outcome changes at `-2^k`, or up to `-2^31`.
2. They try `-2^(k+1)` too, if it is not past `-2^31`. Its outcome must be the same as that of `-2^k`; otherwise the line is `UNSTABLE`, as the outcome does not depend on the offset alone.

The search ends early, with `unknown (<reason>)`, when the attempt at an offset fails on this host. Only powers of two are tried, so each line shows the last one before the change and the first one after it: the true boundary lies between the two, and offsets between those tried are assumed to behave like those around them.

- In the `fake` check, `-M` of `ok up to -M (x at -F)` is the last power of two whose fake fools the DPI, and `-F`, which is `-2 M`, the first whose fake does not.
- In the server check, `-N` of `drops at -N or below; breaks (...) at -B` is the first power of two whose fake the server drops, and `-B`, which is `-N / 2`, the last whose fake it takes.

A TCP stack drops a segment that lies entirely before the data it has already received. With a `seq_offset` of at least the length of the fake in magnitude, 517 bytes for probe's fake, the server typically sees the fake as old data and drops it, so its `seq_offset` boundary typically lies between `-512` and `-1024`. A smaller offset still overlaps the real ClientHello. An `ack_offset` boundary depends on how strictly the server checks acknowledgment numbers.

An offset inside both ranges, that is, one from `-1` to `-M` in the `fake` check and at `-N` or below in the server check, fools the DPI and is safe even when the fake reaches the server, for example because the hop count is wrong. In the example above, the server of `example.org` drops the `seq_offset` fakes at every offset, so any `fake-seq-offset` from `-1` to `-8192` is both. Its `ack_offset` ranges do not meet: the DPI is fooled down to `-65536`, and the server drops the fakes from `-131072` down. Whether an offset between them is both is not known, so test one there, such as `-100000`, before relying on it.

### Fake Packets

The `fake` and server checks send their fake packets with spoofdpi's own code, as spoofdpi does without `--gateway`: on the interface of the default route, to the MAC address of the gateway, which probe looks up with ARP once per run, for up to 10 seconds. The fake is spoofdpi's default fake ClientHello, 517 bytes with the name `www.google.com`, sent in one packet.

probe learns the connection's sequence numbers from its SYN/ACK, as spoofdpi does, and checks that the fake was crafted with the sequence numbers the capture shows the real ClientHello leaving with, plus the fake's offsets. A fake that was not is no test of the fake, so probe makes the try again on a new connection, up to 3 connections in all, before it gives `unknown (seq not learned)`.

### Caveats

- The ClientHello is Go's own, with ALPN `h2` and `http/1.1` and a post-quantum key share, about 1.3 to 1.8 KB. A DPI that tells clients apart by their ClientHello fingerprint may treat a browser's differently.
- An IP address in `--url` sends a ClientHello with no SNI, as browsers do.
- The chunks are written as spoofdpi writes them. On Linux, the kernel may merge small writes into one segment while earlier ones are still queued, so with small chunk sizes not every chunk leaves as a segment of its own. spoofdpi's own `chunk` split behaves the same way, so the result still predicts it.
- On macOS, the disordered chunks may be retransmitted only after a retransmission timeout of a second or more. With a short `--timeout`, `disorder` may show `x` for a DPI that lets them through.
- The TTL of the `fake` check comes from the actual TCP hop count, not from the learned one: `ok` says that spoofdpi gets through with a fake TTL like it, which needs a learned hop count without a gap.
- A blocked site gets a few dozen ClientHellos, the `chunks` check with 2-byte chunks sends hundreds of tiny segments, the `position` check opens one connection per hop, and the `fake` and server checks send a fake packet and a ClientHello per offset tried, up to 66 and 65. Probing a blocked site is visible to the network operator.

## Targets

`--url` is a host name or an IPv4 address, such as `www.example.com` or `192.0.2.1`. A host name is lowercased, and an internationalized name, such as `bücher.example`, is converted to its ASCII form, `xn--bcher-kva.example`, as a browser sends it; the report shows the `--url` as given. A trailing dot is kept. Every target measures the same things: the TCP hop counts and the [DPI checks](#dpi-checks) on TCP port 443, and the UDP hop counts and the [QUIC check](#quic-status) on UDP port 443.

- A scheme, a port, a path, a query or user info is an error, for example `"https://a.test": give the host only, without a scheme` or `"a.test:443": give the host only, without a port (443 is used)`.
- A value of digits and dots only must be a valid IPv4 address, otherwise it is an error, for example `"1.2.3": not an IPv4 address`.
- An internationalized name that cannot be converted is an error, `"<name>": not a valid host name: <reason>`.
- Only IPv4 is probed. An IPv6 address is an error. A host name with no IPv4 address gets a block with a note and no measurements.

Up to four targets are probed at the same time, except that targets at the same address are probed one after another: first the hop counts of all of them, then, per target, its QUIC check and its DPI checks, so that a residual block left by the checks does not spoil a hop count. The blocks stay in the order of the `--url` options.

## Report

The report has one block per `--url`, separated by blank lines. The block starts with the URL and the probed address, or why there is none: `resolve failed: <error>` or `no IPv4 address`. A section per protocol follows, `https` then `quic`:

- `https`: the `status` line of the [DPI checks](#dpi-checks), a `note` line when there is no `dpi` subsection to hold it, the `hops(tcp)` line, a `dpi` subsection with what the DPI checks found, and a `server` line or subsection with what the [server check](#server-check) found.
- `quic`: the `status` line of the [QUIC check](#quic-status), a `note` line, and the `hops(udp)` line.

A line or section with nothing to show is left out.

A hop line is `ACTUAL / LEARNED`, the hop count measured and the one spoofdpi would learn, followed by notes in one parenthesis, separated by `, `:

| Part | Meaning |
| :--- | :--- |
| `N actual` | The actual hop count. |
| `over N actual` | Nothing got through within `--max-ttl`: the actual hop count is more than `N`, `--max-ttl` minus 1. |
| `N learned` | The learned hop count. |
| `-` | There is no learned hop count: packet capture is unavailable, the reply was not captured, or there was no reply to learn from. |
| `no handshake (<reason>)` | No TCP connection at the default TTL completed, because of a `timeout`, a `reset` (refused or reset), or a `local error`. The whole line, with no learned part. |
| `unreachable` | An ICMP error said the host or network is unreachable. The whole line. |
| `no reply` | No UDP packet at the default TTL got an answer. The whole line. |

| Note | Meaning |
| :--- | :--- |
| `gap -1`, `gap +2` | The learned hop count minus the actual one, with its sign. A negative gap means spoofdpi would learn fewer hops than there are, so its fake packets may expire before they reach the DPI. A positive gap means it would learn more, so its fake packets may reach the server. |
| `path varies` | Some TTL above the actual hop count did not get through in any of the 5 rounds, in an attempt that did not fail on this host. The path probably differs between connections, for example under load balancing, so spoofdpi's own connections may take a longer path. |
| `local error <ERRNO>` | A socket call failed on this host itself, for example `EMFILE` when it runs out of file descriptors. Such an attempt says nothing about the path, so it is not counted as a TTL that did not get through. During the TTL scan, the hop count is still shown but may be too high. |
| `not learned` | Packet capture is available, but the learned hop count is `-`: the reply was not captured, including when the capture stopped with an error, or, for UDP, the server answered only with an ICMP port unreachable. |
| `learned varies 11,12` | spoofdpi would learn different values from the replies of the server during the measurement. spoofdpi keeps the latest one. |

When packet capture is unavailable, the learned values are `-` without a note. The single warning on the standard error says so.

`no reply` does not prove that the server is unreachable over UDP: a network that blocks or drops UDP looks the same as a server that drops the packet, as some QUIC servers do with packets of an unknown version.

## Progress

A blocked site can take minutes. When the standard error is a terminal, probe shows one line there, rewritten in place about ten times a second: a spinner, a progress bar with the percent done, how many targets are done, and short words for what the targets that are not done are doing, such as `⠹ [████████░░░░░░░░░░░░]  41%  2/5  measuring hops · checking DPI`.

The words are `resolving`, `measuring hops`, `checking QUIC`, `checking DPI`, `testing fake packets`, `checking server` and `waiting for residual block`. Each is shown once, however many targets are doing it, always in that order. They carry no numbers and no URLs, and there are none when no target is active. The percentage is approximate: it averages how far each target has got through its checks, and the checks do not take equal time, so it can move unevenly, and it does not predict the time left. A target that waits for a residual block to end keeps its place meanwhile.

On a narrow terminal the words are dropped from the end first, then the bar, and then the line is cut. The line is cleared before a warning and before the report. When the standard error is not a terminal, nothing is shown.

## DNS

Host names are resolved the way `spoofdpi run` resolves them, with the `[dns]` section of the config file it would load: the file given with `--config` or `$SPOOFDPI_CONFIG`, or otherwise the first file found in the [default locations](overview.md#config-file-path). `--clean` reads no config file. The `--dns-addr`, `--dns-mode`, `--dns-https-url` and `--dns-timeout` options override the file, as for the server. The first line on the standard error shows the DNS used and the file it was read from.

- The rest of the config file, including `[[rules]]`, is not read, so DNS settings of a rule do not apply. Use the `--dns-*` options, or an IP address in `--url`, to probe the address a rule resolves to.
- Lookups always ask for IPv4 addresses (there is no `--dns-qtype`), and their results are not cached.
- The first IPv4 address of a host is probed and shown next to the URL.

## Root and Packet Capture

The learned hop counts, the `position` of a DPI that drops silently, and the `fake` and server checks need packet capture, which usually needs root, for example `sudo`. Without it, probe prints one warning, shows the learned hop counts as `-`, the position as `unknown (needs root)`, `fake` as `unknown (needs root)` and `server` as `unknown (needs root)`, and measures the rest. The actual hop counts, the QUIC check and the other DPI checks do not need root.

When packet capture works but the fake packets cannot be sent, for example because the gateway does not answer ARP, as on some VPN interfaces, probe prints one warning of its own, without the advice to run as root, and shows `fake` and `server` as `unknown (fake packets unavailable)`. spoofdpi cannot send fake packets on such an interface either.

The capture runs on the interface of the default route, as spoofdpi does without `--gateway`. A server reached through another interface, such as a split-routed VPN, gets the note `not learned`, as does a capture that stops with an error during the probe, and its silent `position` is `unknown (could not control TTL)`.

## Timing

How long a target takes depends on the system:

- On Linux, a router that drops a TTL-limited SYN usually reports it at once, so a target takes about one `--timeout` per round.
- On macOS and FreeBSD, the connection keeps retrying until `--timeout`, so each round of the TCP scan takes the full `--timeout`.
- The TTLs below the hop count never get through, so a scan of a server that is not on the local link runs all 5 rounds.
- A TTL that does not get through on UDP waits for `--timeout` on Linux, and ends early on macOS.

With the default options, the hop counts of a target usually take about 10 seconds on macOS, 5 rounds of `--timeout`, and less on Linux. A blocked server takes 5 times `--timeout` for each protocol before it is reported.

The QUIC check, with `--timeout` T, takes two round trips for a `clear` site, about 3 T for a `censored` one, and up to 6 T, 12 seconds with the defaults, when neither Initial is answered.

The DPI checks of a clear site take a few round trips. A blocked site takes much longer, with `--timeout` T:

- A site whose DPI drops silently, and where no chunk size gets through, takes about 19 T without root: T for the block check, 12 T for `chunks`, 2 T for `disorder`, and T for the baseline and for each of three residual checks. That is about 38 seconds with the defaults.
- With root, the silent `position` check adds a short wait for each hop, and one more residual check. The wait is four round trips plus 200 ms, at least 500 ms and at most T, so usually 10 to 15 seconds more.
- A DPI that resets ends each blocked attempt at once, so its site is faster; its `position` check still waits for each hop below the DPI.
- An [offset search](#offset-search) whose outcome changes at `-2^k` makes k + 2 attempts: the powers of two up to `-2^k` and the one after it, or k + 1 when `-2^k` is `-2^31`. That is 2 when the outcome changes at `-1`, 16 for a change at `-16384`, and 32 at most, when it never changes.
- The `fake` check makes up to 66 attempts: `ttl`, `bad_md5` and its two searches. With a DPI that resets, each takes a few round trips, so the check usually takes 5 to 15 seconds. With a DPI that drops silently, a search has at most 2 blocked attempts, at the change and past it, each of which waits T, so the check takes up to about 5 T more, 10 seconds with the defaults. If `ttl` is `x`, the check takes one attempt.
- The server check makes up to 65 attempts: `bad_md5` and its two searches. An attempt the server drops takes a few round trips, or, with a TLS 1.2 server, up to the wait after its ServerHello. One that ends in `breaks (timeout)` takes T, so a search whose fakes all break that way takes 32 T, about a minute with the defaults. The check usually takes 5 to 30 seconds.
- With root, a blocked site thus usually takes under a minute more than without, and about 2 minutes more when most attempts wait T.
- Looking up the gateway's MAC address for the fake packets takes up to 10 seconds, once per run.
- A target at the address of one checked before may wait up to 60 seconds for a residual block, once for the QUIC check and once for the DPI checks.

Lower `--timeout` to make a run shorter.

## Options

| Option | Default | Description |
| :--- | :--- | :--- |
| `--url` | | Site to probe: a host name or IPv4 address, without scheme, port or path. Repeatable; at least one is required. |
| `--max-ttl` | `32` | Highest TTL to try, from 1 to 255. |
| `--timeout` | `2s` | Timeout of each connection attempt, each wait for a UDP answer, and each wait for an answer in the DPI checks. |
| `--config` | | spoofdpi config file to read the `[dns]` section from. Also read from `$SPOOFDPI_CONFIG`. |
| `--clean` | `false` | Reads no config file. |
| `--dns-addr` | | As for the server. See [DNS](dns.md). |
| `--dns-mode` | | As for the server. |
| `--dns-https-url` | | As for the server. |
| `--dns-timeout` | | As for the server. |

## Exit Status

probe exits with a non-zero status only when it cannot run, or when it is interrupted:

- An invalid option, such as a `--url` with a scheme or a port, or a `--config` file that does not exist, exits with `1` before anything is probed.
- Once the probe runs, it exits with `0` whatever the measurements show.
- Ctrl+C (`SIGINT`), `SIGTERM` or `SIGHUP` stops the probe and prints the blocks of the targets that finished, including their QUIC and DPI checks. probe then exits with 128 plus the signal number: `130` for `SIGINT`, `143` for `SIGTERM` and `129` for `SIGHUP`. A probe started with `SIGHUP` ignored, for example under `nohup`, keeps ignoring it.
