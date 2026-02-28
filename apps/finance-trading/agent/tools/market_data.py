"""Market data tools for the Trading Assistant.

Provides real-time and historical market data, sector performance,
and market overview functionality.
"""
import json
import random
from datetime import datetime, timedelta
from strands import tool


@tool
def get_stock_quote(symbol: str) -> str:
    """Get real-time stock quote for a given ticker symbol.

    Retrieves current price, daily change, volume, market cap, and other
    key metrics for any publicly traded stock.

    Args:
        symbol: Stock ticker symbol (e.g., 'AAPL', 'MSFT', 'GOOGL', 'AMZN').

    Returns:
        JSON string with current stock data including price, change, volume, and market cap.
    """
    # Simulated market data - in production, this would call a real market data API
    # via AgentCore Identity-managed credentials
    base_prices = {
        "AAPL": 245.50, "MSFT": 478.30, "GOOGL": 192.80, "AMZN": 228.15,
        "NVDA": 875.40, "META": 615.20, "TSLA": 248.90, "JPM": 242.70,
        "V": 315.60, "JNJ": 152.30, "WMT": 235.80, "PG": 178.40,
        "MA": 528.90, "HD": 412.50, "BAC": 45.20, "XOM": 108.70,
    }

    base_price = base_prices.get(symbol.upper(), 100 + random.uniform(0, 200))
    change = random.uniform(-3, 3)
    change_pct = change / base_price * 100
    volume = random.randint(5_000_000, 80_000_000)

    return json.dumps({
        "symbol": symbol.upper(),
        "price": round(base_price + change, 2),
        "change": round(change, 2),
        "change_pct": round(change_pct, 2),
        "volume": volume,
        "avg_volume": int(volume * 1.1),
        "market_cap_billions": round(base_price * random.uniform(1, 3), 1),
        "pe_ratio": round(random.uniform(15, 45), 1),
        "52w_high": round(base_price * 1.25, 2),
        "52w_low": round(base_price * 0.75, 2),
        "dividend_yield": round(random.uniform(0, 3), 2),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_market_overview() -> str:
    """Get overview of major market indices and key market metrics.

    Returns current status of S&P 500, NASDAQ, DOW Jones, plus VIX,
    10-year Treasury yield, and overall market sentiment.

    Returns:
        JSON string with market indices, volatility index, and sentiment indicators.
    """
    return json.dumps({
        "indices": {
            "SP500": {"value": 6120.35, "change_pct": round(random.uniform(-1.5, 1.5), 2)},
            "NASDAQ": {"value": 19845.20, "change_pct": round(random.uniform(-2, 2), 2)},
            "DOW": {"value": 44250.80, "change_pct": round(random.uniform(-1, 1), 2)},
            "RUSSELL2000": {"value": 2285.40, "change_pct": round(random.uniform(-2, 2), 2)},
        },
        "volatility": {
            "VIX": round(random.uniform(12, 25), 1),
            "VIX_status": "elevated" if random.random() > 0.6 else "normal",
        },
        "treasury": {
            "2Y": round(random.uniform(3.5, 5.0), 2),
            "10Y": round(random.uniform(3.8, 4.8), 2),
            "30Y": round(random.uniform(4.0, 5.0), 2),
        },
        "sentiment": {
            "fear_greed_index": random.randint(20, 80),
            "label": random.choice(["Fear", "Neutral", "Greed", "Extreme Greed"]),
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_historical_prices(symbol: str, days: int) -> str:
    """Get historical daily closing prices for a stock.

    Retrieves daily OHLCV (Open, High, Low, Close, Volume) data for
    the specified number of trading days.

    Args:
        symbol: Stock ticker symbol (e.g., 'AAPL').
        days: Number of trading days of history to retrieve (max 252 for 1 year).

    Returns:
        JSON string with array of daily price records.
    """
    days = min(days, 252)
    base_price = 150 + random.uniform(0, 150)
    prices = []

    for i in range(days, 0, -1):
        date = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        daily_change = random.gauss(0.001, 0.02)
        base_price *= (1 + daily_change)

        high = base_price * (1 + abs(random.gauss(0, 0.01)))
        low = base_price * (1 - abs(random.gauss(0, 0.01)))
        open_price = base_price * (1 + random.gauss(0, 0.005))

        prices.append({
            "date": date,
            "open": round(open_price, 2),
            "high": round(high, 2),
            "low": round(low, 2),
            "close": round(base_price, 2),
            "volume": random.randint(5_000_000, 60_000_000),
        })

    return json.dumps({
        "symbol": symbol.upper(),
        "period_days": days,
        "data": prices,
    })


@tool
def get_sector_performance() -> str:
    """Get performance of major market sectors.

    Returns daily and year-to-date performance for all 11 GICS sectors.

    Returns:
        JSON string with sector names, daily change, and YTD performance.
    """
    sectors = [
        "Technology", "Healthcare", "Financials", "Consumer Discretionary",
        "Communication Services", "Industrials", "Consumer Staples",
        "Energy", "Utilities", "Real Estate", "Materials",
    ]

    return json.dumps({
        "sectors": [
            {
                "name": sector,
                "daily_change_pct": round(random.uniform(-2, 2), 2),
                "ytd_change_pct": round(random.uniform(-10, 25), 2),
                "market_cap_trillions": round(random.uniform(1, 15), 1),
            }
            for sector in sectors
        ],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })
