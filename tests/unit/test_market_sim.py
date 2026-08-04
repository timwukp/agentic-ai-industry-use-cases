from datetime import date

from toolkit.market_sim import MarketSim


def test_quote_deterministic_same_day():
    sim1 = MarketSim(today=date(2026, 8, 4))
    sim2 = MarketSim(today=date(2026, 8, 4))
    q1, q2 = sim1.quote("AAPL"), sim2.quote("AAPL")
    q1.pop("timestamp"), q2.pop("timestamp")  # wall-clock, legitimately differs
    assert q1 == q2


def test_close_price_consistent_across_tools():
    sim = MarketSim(today=date(2026, 8, 4))
    quote_price = sim.quote("MSFT")["price"]
    assert quote_price == sim.close_price("MSFT")


def test_historical_last_close_matches_walk():
    sim = MarketSim(today=date(2026, 8, 4))
    hist = sim.historical("NVDA", 10)
    assert len(hist) == 10
    assert hist[-1]["date"] == "2026-08-03"
    assert hist[-1]["close"] == sim.close_price("NVDA", date(2026, 8, 3))


def test_historical_caps_at_252():
    assert len(MarketSim(today=date(2026, 8, 4)).historical("AAPL", 999)) == 252


def test_unknown_symbol_gets_stable_price():
    sim = MarketSim(today=date(2026, 8, 4))
    p1, p2 = sim.close_price("ZZZQ"), sim.close_price("ZZZQ")
    assert p1 == p2 > 0


def test_ohlc_bounds():
    for row in MarketSim(today=date(2026, 8, 4)).historical("JPM", 30):
        assert row["low"] <= row["close"] <= row["high"]


def test_overview_and_sectors_shape():
    sim = MarketSim(today=date(2026, 8, 4))
    ov = sim.market_overview()
    assert set(ov["indices"]) == {"SP500", "NASDAQ", "DOW", "RUSSELL2000"}
    assert len(sim.sector_performance()) == 11
