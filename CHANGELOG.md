# Changelog

## [1.5.2](https://github.com/xvzc/spoofdpi/compare/v1.5.1...v1.5.2) (2026-05-14)


### Bug Fixes

* **config:** preserve defaults when partial TOML sections are present ([0714ed1](https://github.com/xvzc/spoofdpi/commit/0714ed10568b0fb877c303705fb3f97000b99fd8))
* **desync:** sort segment plans before slicing ([f92bac7](https://github.com/xvzc/spoofdpi/commit/f92bac7eb1df4aa9c164509c2babd8786026b296))
* **nix:** update vendorHash for new go modules ([daaa803](https://github.com/xvzc/spoofdpi/commit/daaa8033f69839553c44bafe25d46a3afc0277f5))
* **packet,socks5:** fix BPF load missing in non-Ethernet path and bind timeout handling ([2354354](https://github.com/xvzc/spoofdpi/commit/23543547686f6588684f9b5eb81ca02a30b8d7c5))
* **packet:** restrict sniffer TTL updates to registered destinations ([9e2dc90](https://github.com/xvzc/spoofdpi/commit/9e2dc902fd32f3edbb1d6929ae4030e6a7333fd8))
* **packet:** suppress duplicate ttl sniff logs when nhops is unchanged ([5d68874](https://github.com/xvzc/spoofdpi/commit/5d688745b99f05271ab5f2d5bb3a92794a046b37))
* **socks5:** correct BIND handler implementation ([bbc45d8](https://github.com/xvzc/spoofdpi/commit/bbc45d8d58c02b0bd2812601ecfb44a6bdc7ea51))
* **socks5:** drain accept channel on context cancellation to prevent fd leak ([82d58e7](https://github.com/xvzc/spoofdpi/commit/82d58e771827d05a0097ab120743d5d2a4a7c1c5))
* **tun:** remove host route for gateway on Darwin ([e0cfa04](https://github.com/xvzc/spoofdpi/commit/e0cfa041f2c3cd589ebde77566dd160d6b0b60bc))
* **tun:** return error on non-numeric port in connToDst ([9b7c847](https://github.com/xvzc/spoofdpi/commit/9b7c847b85ef0a8d236e0485d2ae3af80604dce0))

## [1.5.1](https://github.com/xvzc/spoofdpi/compare/v1.5.0...v1.5.1) (2026-05-05)


### Bug Fixes

* **release:** drop bogus mips64 hardfloat suffix from archive names ([e6acdcf](https://github.com/xvzc/spoofdpi/commit/e6acdcf26aecdb5567104f0301267913d921a59d))

## [1.5.0](https://github.com/xvzc/spoofdpi/compare/v1.4.1...v1.5.0) (2026-05-04)


### Features

* **config:** eager-resolve policy overrides at load time ([fc4cafd](https://github.com/xvzc/spoofdpi/commit/fc4cafd3c5ae734a44d4a84cec0a35e314b9f6fd))
* **config:** pretty-print rules in trace logs via per-type MarshalJSON ([c16a9c5](https://github.com/xvzc/spoofdpi/commit/c16a9c5be32539ac0b222481ae4c9f6fc0f9fed1))
* **config:** summarize match domains/addrs and segments as "N items" ([0908cd5](https://github.com/xvzc/spoofdpi/commit/0908cd50c1c950c174d0a67034a154f1b81164bd))
* **server:** register UDP destinations with sniffer for fake-packet TTL ([4c2fb3b](https://github.com/xvzc/spoofdpi/commit/4c2fb3b0e390d8672ac2d338cbf5fe28a5c36362))


### Bug Fixes

* **config:** reset rule https.skip when not explicitly set ([6715b21](https://github.com/xvzc/spoofdpi/commit/6715b21983a732ea1b1734529f64fa1ccfa4ae74))
* **matcher:** resolve duplicate-domain rules by priority ([894b6ae](https://github.com/xvzc/spoofdpi/commit/894b6ae28acddaec89e99d8ba0f63cb56d00cc43))
* **matcher:** tighten conflict error format to avoid escaped quotes ([b5e82df](https://github.com/xvzc/spoofdpi/commit/b5e82dfa80467c1e2a42e12b8d092e7a5d808a30))
* **tui:** keep TUI alive on startup errors so user can read them ([956eb9c](https://github.com/xvzc/spoofdpi/commit/956eb9c5c6409d2bb342bc8fad3383ba8f4a23d4))
* **tui:** preserve log line color across wrapped continuations ([22bac0b](https://github.com/xvzc/spoofdpi/commit/22bac0b922d82d81ea7e6bf449117d23fcc14be6))
* **tui:** switch log wrap from word-wrap to hardwrap ([041cf52](https://github.com/xvzc/spoofdpi/commit/041cf52cb20a3845d1af6e61afc48f5853d5bb4e))
* **tui:** wrap log lines to viewport width ([2b76cde](https://github.com/xvzc/spoofdpi/commit/2b76cde984977a92cdab22dc96f5d209183cc556))

## [1.4.1](https://github.com/xvzc/spoofdpi/compare/v1.4.0...v1.4.1) (2026-05-03)


### Bug Fixes

* **main:** return early when createServer fails to avoid nil-deref on ListenAndServe ([#382](https://github.com/xvzc/spoofdpi/issues/382)) ([2aa53d0](https://github.com/xvzc/spoofdpi/commit/2aa53d091bd20b31f14659fd0a3a8cf216175544))

## [1.4.0](https://github.com/xvzc/spoofdpi/compare/v1.3.1...v1.4.0) (2026-04-29)


### Features

* support TUI mode ([#378](https://github.com/xvzc/spoofdpi/issues/378)) ([b0c489b](https://github.com/xvzc/spoofdpi/commit/b0c489bfebabac6adf2e0028ed9594de150cb22e))
