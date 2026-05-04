# Changelog

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
