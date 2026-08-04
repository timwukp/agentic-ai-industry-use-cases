"""Trading + portfolio handlers against moto DynamoDB — real state mutations."""
import importlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _load(module_dir):
    sys.path.insert(0, str(REPO / "tools" / "finance" / module_dir))
    handler = importlib.import_module("handler")
    importlib.reload(handler)
    sys.path.pop(0)
    sys.modules.pop("handler", None)
    return handler


def test_market_buy_creates_position_and_order(ddb_tables):
    trading = _load("trading")
    res = trading.place_order("META", "BUY", 10, "MARKET", 0, "default")
    assert res["status"] == "FILLED"
    assert res["fill_price"] > 0
    status = trading.get_order_status(res["order_id"])
    assert status["status"] == "FILLED"

    portfolio = _load("portfolio")
    positions = portfolio.get_portfolio_positions("default")
    symbols = {p["symbol"] for p in positions["positions"]}
    assert "META" in symbols


def test_buy_averages_cost_basis(ddb_tables):
    trading = _load("trading")
    trading.place_order("AAPL", "BUY", 100, "MARKET", 0, "default")
    portfolio = _load("portfolio")
    aapl = next(p for p in portfolio.get_portfolio_positions("default")["positions"]
                if p["symbol"] == "AAPL")
    assert aapl["quantity"] == 200  # seeded 100 + bought 100
    assert aapl["avg_cost"] != 185.50  # weighted average moved


def test_sell_more_than_held_fails(ddb_tables):
    trading = _load("trading")
    res = trading.place_order("AAPL", "SELL", 500, "MARKET", 0, "default")
    assert "error" in res


def test_sell_all_removes_position(ddb_tables):
    trading = _load("trading")
    res = trading.place_order("JPM", "SELL", 80, "MARKET", 0, "default")
    assert res["status"] == "FILLED"
    portfolio = _load("portfolio")
    symbols = {p["symbol"] for p in portfolio.get_portfolio_positions("default")["positions"]}
    assert "JPM" not in symbols


def test_nonmarketable_limit_stays_open_and_cancels(ddb_tables):
    trading = _load("trading")
    res = trading.place_order("MSFT", "BUY", 5, "LIMIT", 0.01, "default")
    assert res["status"] == "OPEN"
    cancelled = trading.cancel_order(res["order_id"])
    assert cancelled["status"] == "CANCELLED"
    # cancelling again fails
    assert "error" in trading.cancel_order(res["order_id"])


def test_trade_history_summary(ddb_tables):
    trading = _load("trading")
    trading.place_order("AAPL", "BUY", 10, "MARKET", 0, "default")
    trading.place_order("MSFT", "SELL", 5, "MARKET", 0, "default")
    hist = trading.get_trade_history("default", 7)
    assert hist["total_orders"] == 2
    assert hist["summary"]["total_buy_value"] > 0
    assert hist["summary"]["total_sell_value"] > 0


def test_invalid_order_inputs(ddb_tables):
    trading = _load("trading")
    assert "error" in trading.place_order("AAPL", "HOLD", 10)
    assert "error" in trading.place_order("AAPL", "BUY", 0)
    assert "error" in trading.place_order("AAPL", "BUY", 10, "LIMIT", 0)


def test_portfolio_math(ddb_tables):
    portfolio = _load("portfolio")
    res = portfolio.get_portfolio_positions("default")
    s = res["summary"]
    assert s["num_positions"] == 4
    recomputed = round(sum(p["market_value"] for p in res["positions"]), 2)
    assert abs(s["total_market_value"] - recomputed) < 0.02
    assert "error" in portfolio.get_portfolio_positions("nonexistent")


def test_allocation_and_rebalance(ddb_tables):
    portfolio = _load("portfolio")
    alloc = portfolio.get_portfolio_allocation("default")
    assert abs(sum(alloc["by_sector"].values()) - 100) < 1.0
    reb = portfolio.suggest_rebalancing("default", '{"Technology": 30, "Energy": 20}')
    assert "suggested_trades" in reb
    assert "error" in portfolio.suggest_rebalancing("default", "not-json")


def test_pnl_periods(ddb_tables):
    portfolio = _load("portfolio")
    res = portfolio.calculate_pnl("default", "month")
    assert res["performance"]["value_end"] > 0
    assert "error" in portfolio.calculate_pnl("default", "decade")


def test_dispatch_routing(ddb_tables, gateway_context):
    trading = _load("trading")
    out = trading.lambda_handler({"symbol": "AAPL", "side": "BUY", "quantity": 1},
                                 gateway_context("place_order"))
    assert out["status"] == "FILLED"
    unknown = trading.lambda_handler({}, gateway_context("no_such_tool"))
    assert "error" in unknown
