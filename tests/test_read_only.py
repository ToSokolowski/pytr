"""Pin that pytr only sends read-only websocket subscriptions, apart from opted-in price alarm writes."""

import asyncio
import json
from decimal import Decimal
from unittest.mock import AsyncMock

import pytest

from pytr.alarms import Alarms
from pytr.api import PRICE_ALARM_WRITE_TYPES, READ_ONLY_SUBSCRIPTION_TYPES, TradeRepublicApi

WRITE_TYPES = [
    "simpleCreateOrder",
    "cancelOrder",
    "createSavingsPlan",
    "changeSavingsPlan",
    "cancelSavingsPlan",
    "addToWatchlist",
    "removeFromWatchlist",
    "subscribeNews",
    "unsubscribeNews",
]


class _Websocket:
    def __init__(self):
        self.sent: list[str] = []

    async def send(self, message: str) -> None:
        self.sent.append(message)


def _api():
    tr = TradeRepublicApi(phone_no="+490000000000", pin="0000", waf_token=None, save_cookies=False)
    ws = _Websocket()

    async def get_ws():
        return ws

    tr._get_ws = get_ws  # type: ignore[method-assign]
    # Class attributes; keep one test's subscriptions out of the next.
    tr.subscriptions = {}
    tr._previous_responses = {}
    return tr, ws


def _sent_types(ws):
    return [json.loads(m.split(" ", 2)[2])["type"] for m in ws.sent]


@pytest.mark.parametrize("subscription_type", [*WRITE_TYPES, *sorted(PRICE_ALARM_WRITE_TYPES), None, "unknown"])
def test_subscribe_refuses_types_off_the_allowlist(subscription_type):
    tr, ws = _api()

    with pytest.raises(PermissionError, match="read-only"):
        asyncio.run(tr.subscribe({"type": subscription_type}))

    assert ws.sent == []
    assert tr.subscriptions == {}


def test_subscribe_sends_read_only_types():
    tr, ws = _api()

    asyncio.run(tr.subscribe({"type": "portfolio"}))

    assert _sent_types(ws) == ["portfolio"]


def test_price_alarm_writes_need_the_opt_in():
    tr, ws = _api()
    tr.allow_price_alarm_writes = True

    async def run():
        await tr.create_price_alarm("DE0000000000", 1.0)
        await tr.cancel_price_alarm("alarm-id")

    asyncio.run(run())

    assert _sent_types(ws) == ["createPriceAlarm", "cancelPriceAlarm"]


def test_the_opt_in_does_not_open_other_writes():
    tr, _ = _api()
    tr.allow_price_alarm_writes = True

    with pytest.raises(PermissionError):
        asyncio.run(tr.subscribe({"type": "simpleCreateOrder"}))


@pytest.mark.parametrize("previous_opt_in", [False, True])
@pytest.mark.parametrize("fail_write", [False, True])
def test_set_alarms_restores_previous_opt_in(previous_opt_in, fail_write):
    tr, ws = _api()
    tr.allow_price_alarm_writes = previous_opt_in
    alarms = Alarms(tr)
    alarms.data = {"DE0000000000": [Decimal("1.0")]}
    alarms.alarms = [{"instrumentId": "DE0000000000", "targetPrice": "2.0", "id": "old-alarm"}]
    alarms.alarms_loop = AsyncMock()
    tr.recv = AsyncMock()
    tr.close = AsyncMock()
    original_create = tr.create_price_alarm

    async def create(isin, price):
        assert tr.allow_price_alarm_writes is True
        if fail_write:
            raise RuntimeError("write failed")
        return await original_create(isin, price)

    tr.create_price_alarm = create
    if fail_write:
        with pytest.raises(RuntimeError, match="write failed"):
            asyncio.run(alarms.set_alarms())
        assert ws.sent == []
    else:
        asyncio.run(alarms.set_alarms())
        assert _sent_types(ws) == ["createPriceAlarm", "cancelPriceAlarm"]

    assert tr.allow_price_alarm_writes is previous_opt_in


def test_allowlist_holds_no_write_types():
    assert not READ_ONLY_SUBSCRIPTION_TYPES & {*WRITE_TYPES, *PRICE_ALARM_WRITE_TYPES}


@pytest.mark.parametrize(
    "name",
    [
        "limit_order",
        "market_order",
        "stop_market_order",
        "cancel_order",
        "create_savings_plan",
        "change_savings_plan",
        "cancel_savings_plan",
        "savings_plan_parameters",
        "payout",
        "confirm_payout",
        "add_watchlist",
        "remove_watchlist",
        "subscribe_news",
        "unsubscribe_news",
    ],
)
def test_write_methods_are_gone(name):
    assert not hasattr(TradeRepublicApi, name)
