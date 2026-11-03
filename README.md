# pytr (hardened fork)

Fork of [pytr-org/pytr](https://github.com/pytr-org/pytr), a CLI and library for the private API of the Trade Republic
online brokerage (not affiliated with Trade Republic Bank GmbH). Usage, commands and login options are the same as
upstream; see its README for documentation.

## What is different

pytr runs with your phone number, PIN and session cookies in memory, and those cookies alone are as good as a
completed 2FA login. This fork reduces how much of that can leak, and how much third-party code runs next to it.

- **No plaintext secrets on disk.** `--store_credentials` encrypts phone, PIN and session cookies with AES-256-GCM
  (`~/.pytr/*.enc`), with the key held in the OS keyring. Without a usable keyring nothing is stored; there is no
  plaintext fallback. Legacy plaintext files are migrated and deleted on first read.
- **Redacted logs.** Phone numbers, tokens, cookies, login process ids and JWTs are scrubbed from log output.
  Account settings are no longer logged, and websocket payloads (portfolio, transactions, personal data) only reach the
  debug log with `PYTR_LOG_PAYLOADS=1`.
- **Fewer dependencies.** `coloredlogs`, `pygments`, `packaging` and `requests_futures` are gone; `shtab` and
  `curl_cffi` (which ships a precompiled binary) are optional extras. Every remaining dependency is pinned with hashes
  in `uv.lock`.
- **Read-only.** pytr reads your portfolio, timeline, documents and savings plans but cannot trade or move money: the
  order, savings-plan, payout and watchlist write calls are removed, and the websocket client refuses any message type
  that is not on a read-only allowlist. The single exception is `set_price_alarms`, which explicitly opts in to
  creating and removing price alarms (they cannot trade or move money).
- **No phoning home.** `pytr -V` no longer queries GitHub for the latest version.
- **Locked-down CI.** GitHub Actions are pinned by commit SHA with least-privilege permissions, and Renovate waits
  7 days after a release before proposing an update.
- **No PyPI release.** CI only runs checks. Install from a specific commit you have reviewed, using the locked
  dependencies as described below.

These protect against stolen disks, backups, shared logs and other local users. They do not protect against malware
running as your user, which can ask the unlocked keyring for the key just like pytr does. Likewise, the read-only
allowlist stops mistakes and crafted input from placing orders, not code that already runs inside pytr's process.

## Installation and development

With [uv](https://docs.astral.sh/uv/) installed, check out a full commit SHA you have reviewed and use the lock file:

```sh
git clone https://github.com/ToSokolowski/pytr.git
cd pytr
git checkout <commit-sha>
uv sync --locked
uv run --locked pytr --help
```

On NixOS, enter `nix develop` before running the uv commands. The Linux-only development shell provides the FHS
layout required by uv's prebuilt Python interpreters and tools. Run tests with `uv run --locked pytest`.

Installing directly with `pip install git+https://github.com/ToSokolowski/pytr@<commit-sha>` pins this project's code,
but **does not use `uv.lock`**: pip resolves dependency versions from `pyproject.toml` instead.

## License

MIT, see [LICENSE](LICENSE). Original code remains copyright its respective authors. Contributions by Tobias
Sokolowski are copyright © 2026 Tobias Sokolowski and are provided under the same MIT License.
