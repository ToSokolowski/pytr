# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`pytr` is a CLI + library for the private (unofficial) Trade Republic brokerage API. This checkout is a fork
(`ToSokolowski/pytr`) of upstream `pytr-org/pytr`; the fork does **not** publish to PyPI (CI is checks-only).

## Commands

All tooling runs through `uv`; use `--locked` so `uv.lock` (hash-pinned) is never re-resolved.

On NixOS (no nix-ld), uv's prebuilt binaries don't run directly; use the FHS env from `flake.nix`: `nix develop`
for a shell, or `nix run . -- -c 'uv run --locked pytest'` for one command.

```sh
uv sync --locked                          # set up dev env
uv run --locked pytest                    # all tests
uv run --locked pytest tests/test_events.py -k aktiendividende   # single test / case
uv run --locked ruff check                # lint (ruff 0.9.6, line length 120, isort rules)
uv run --locked ruff format               # format (CI runs --check --diff)
uv run --locked mypy .                    # type check (target py3.10)
uv run --locked pytr <command> --help     # run the CLI from source
```

CI (`.github/workflows/ci.yml`) runs pytest, ruff check, ruff format check, mypy on Python 3.10–3.13, verifies the
README generated content is current, and builds the wheel. The current README has no generated sections, so the
mksync check is currently a no-op. Maintain README instructions manually when changing installation or CLI behavior.

## Architecture

- **`main.py`** — argparse CLI. Each subcommand calls `account.login(...)` to obtain an authenticated
  `TradeRepublicApi`, then hands it to a feature class (`Portfolio`, `DL`, `Details`, `Alarms`, `SavingsPlans`, …).
  Shared login/date-range options are built once and attached to subcommands.
- **`api.py` — `TradeRepublicApi`** — two transports:
  - HTTP (`requests`) for web login. v1 login needs an AWS WAF token (`--waf-token playwright` default, or the
    pure-Python `awswaf` solver in `pytr/awswaf/`); `--v2` login (`api/v2`, app/authenticator code) skips WAF.
    `APP_VERSION`, `WEB_PLATFORM`, `USER_AGENT` are pinned constants overridable via `PYTR_TR_*` env vars because TR
    breaks them without notice. `--account` / `switch_account` selects other accounts (company/child) of a login.
  - Websocket (`websockets`, async) for all data: `subscribe(payload)` returns a subscription id; `recv()` yields
    `(subscription_id, subscription, response)`; the server sends deltas that `_calculate_delta` applies to the
    previous payload. Most data methods are thin `subscribe({"type": ...})` wrappers.
  - `playwright`, `curl_cffi`, `pytr.awswaf` are optional extras and **must stay lazily imported** inside the
    `_fetch_waf_token_*` methods (see comment block at top of `api.py`).
- **Timeline → Event → export pipeline** (core of `dl_docs` / `export_transactions`):
  - `timeline.py` `Timeline` pages through `timelineTransactions` + `timelineActivityLog`, requests
    `timelineDetailV2` for each, dedupes, and fires `event_callback`. Can also replay from a saved JSON event
    database (`load_event_database`, used by tests — no network).
  - `event.py` `Event.from_dict` classifies a raw TR timeline event into a `PPEventType` (Portfolio Performance
    types) via `tr_event_type_mapping`, or a `ConditionalEventType` resolved from detail sections; parses ISIN,
    shares, value, fees, taxes from German-labelled detail sections. Supporting a new TR event type = add mapping/
    parsing here plus a fixture.
  - `transactions.py` `TransactionExporter` turns `Event`s into CSV/JSON rows with localized column names and
    decimal formatting (babel). Translations live in `pytr/locale/*/LC_MESSAGES/messages.po`; `.mo` files are
    compiled at build time by `hatch-babel` (not committed).
  - `dl.py` `DL` downloads timeline PDFs into sorted folders, concurrently via a thread-pool requests session.
- **`credential_store.py`** — phone/PIN and session cookies are stored only AES-256-GCM encrypted
  (`~/.pytr/credentials.enc`, `cookies.<hash>.enc`) with the key in the OS keyring. No plaintext fallback by design;
  legacy plaintext files are migrated and deleted on first read.
- **`utils.py`** — `get_logger` installs its own handler (`propagate=False`) with a `RedactingFormatter`; secrets
  passed to `register_secret` are redacted from logs. Websocket payloads are only logged when `PYTR_LOG_PAYLOADS=1`.
  Keep new logging of tokens/cookies/phone/process ids routed through this redaction.

## Security posture

Recent commits deliberately hardened credential storage, logging and the supply chain. Keep the dependency list
minimal (every dependency runs next to the PIN and cookies), keep GitHub Actions pinned by commit SHA, and don't add
plaintext persistence of credentials/cookies or unredacted logging.

pytr is **read-only** by design: no orders, savings-plan changes, payouts or watchlist edits. `api.py`
`TradeRepublicApi.subscribe` rejects any websocket `type` not in `READ_ONLY_SUBSCRIPTION_TYPES`; price alarm writes
(`PRICE_ALARM_WRITE_TYPES`) pass only when `allow_price_alarm_writes` is set, which only `Alarms.set_alarms` does. A
new read endpoint must be added to the allowlist; don't add write endpoints.

## Tests

- `tests/test_events.py` — parametrized table: each case names a raw event JSON in `tests/events/` and the expected
  `Event` fields plus exported German-localized transaction rows. New event handling should add a fixture + case here
  (including a `*_no_eventType.json` variant where TR omits `eventType`).
- `tests/test_export_transactions.py` — replays `tests/all_events_test.json` through `Timeline` and compares against
  `all_events_test_golden.csv`.
- Root `conftest.py` forces pytr loggers to WARNING since they bypass pytest capture.
