"""Deterministic market data simulator.

All values derive from a seeded RNG keyed on (symbol, date) so that:
- a quote is stable for a whole trading day and identical across tools,
- historical series are reproducible and internally consistent,
- no external API keys or network calls are needed.
"""
import hashlib
import math
import random
from datetime import date, datetime, timedelta, timezone

BASE_PRICES = {
    "AAPL": 245.50, "MSFT": 478.30, "GOOGL": 192.80, "AMZN": 228.15,
    "NVDA": 875.40, "META": 615.20, "TSLA": 248.90, "JPM": 242.70,
    "V": 315.60, "JNJ": 152.30, "WMT": 235.80, "PG": 178.40,
    "MA": 528.90, "HD": 412.50, "BAC": 45.20, "XOM": 108.70,
}

SECTORS = [
    "Technology", "Healthcare", "Financials", "Consumer Discretionary",
    "Communication Services", "Industrials", "Consumer Staples",
    "Energy", "Utilities", "Real Estate", "Materials",
]

INDICES = {"SP500": 6120.35, "NASDAQ": 19845.20, "DOW": 44250.80, "RUSSELL2000": 2285.40}


def _rng(*key_parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in key_parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


class MarketSim:
    """Stateless simulator; every method is deterministic for a given day."""

    def __init__(self, today: date | None = None):
        self.today = today or datetime.now(timezone.utc).date()

    def _base_price(self, symbol: str) -> float:
        symbol = symbol.upper()
        if symbol in BASE_PRICES:
            return BASE_PRICES[symbol]
        r = _rng("base", symbol)
        return round(20 + r.uniform(0, 400), 2)

    def close_price(self, symbol: str, on: date | None = None) -> float:
        """Daily close: random walk from the base price, keyed per (symbol, date)."""
        on = on or self.today
        base = self._base_price(symbol)
        # walk over the last 30 days for continuity without unbounded drift
        price = base
        for i in range(30, 0, -1):
            d = on - timedelta(days=i)
            step = _rng("walk", symbol.upper(), d.isoformat()).gauss(0.0005, 0.015)
            price *= (1 + step)
        return round(price, 2)

    def quote(self, symbol: str) -> dict:
        symbol = symbol.upper()
        r = _rng("quote", symbol, self.today.isoformat())
        prev = self.close_price(symbol, self.today - timedelta(days=1))
        price = self.close_price(symbol)
        change = round(price - prev, 2)
        volume = r.randint(5_000_000, 80_000_000)
        return {
            "symbol": symbol,
            "price": price,
            "change": change,
            "change_pct": round(change / prev * 100, 2) if prev else 0.0,
            "volume": volume,
            "avg_volume": int(volume * 1.1),
            "market_cap_billions": round(price * r.uniform(1, 3), 1),
            "pe_ratio": round(r.uniform(15, 45), 1),
            "52w_high": round(price * 1.25, 2),
            "52w_low": round(price * 0.75, 2),
            "dividend_yield": round(r.uniform(0, 3), 2),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def historical(self, symbol: str, days: int) -> list[dict]:
        days = min(days, 252)
        out = []
        for i in range(days, 0, -1):
            d = self.today - timedelta(days=i)
            close = self.close_price(symbol, d)
            r = _rng("ohlc", symbol.upper(), d.isoformat())
            high = round(close * (1 + abs(r.gauss(0, 0.01))), 2)
            low = round(close * (1 - abs(r.gauss(0, 0.01))), 2)
            out.append({
                "date": d.isoformat(),
                "open": round(close * (1 + r.gauss(0, 0.005)), 2),
                "high": high,
                "low": low,
                "close": close,
                "volume": r.randint(5_000_000, 60_000_000),
            })
        return out

    def market_overview(self) -> dict:
        r = _rng("overview", self.today.isoformat())
        vix = round(r.uniform(12, 25), 1)
        fear_greed = r.randint(20, 80)
        return {
            "indices": {
                name: {"value": base, "change_pct": round(r.uniform(-1.5, 1.5), 2)}
                for name, base in INDICES.items()
            },
            "volatility": {"VIX": vix, "VIX_status": "elevated" if vix > 20 else "normal"},
            "treasury": {
                "2Y": round(r.uniform(3.5, 5.0), 2),
                "10Y": round(r.uniform(3.8, 4.8), 2),
                "30Y": round(r.uniform(4.0, 5.0), 2),
            },
            "sentiment": {
                "fear_greed_index": fear_greed,
                "label": ("Fear" if fear_greed < 40 else "Neutral" if fear_greed < 60
                          else "Greed" if fear_greed < 75 else "Extreme Greed"),
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def sector_performance(self) -> list[dict]:
        return [
            {
                "name": s,
                "daily_change_pct": round(_rng("sector", s, self.today.isoformat()).uniform(-2, 2), 2),
                "ytd_change_pct": round(_rng("sector-ytd", s, self.today.year).uniform(-10, 25), 2),
                "market_cap_trillions": round(_rng("sector-cap", s).uniform(1, 15), 1),
            }
            for s in SECTORS
        ]

    def annual_volatility(self, symbol: str) -> float:
        """Deterministic per-symbol annualized volatility estimate."""
        return round(_rng("vol", symbol.upper()).uniform(0.12, 0.35), 4)

    def beta(self, symbol: str) -> float:
        return round(_rng("beta", symbol.upper()).uniform(0.5, 1.8), 2)


def daily_vol(annual: float) -> float:
    return annual / math.sqrt(252)
