"""Tests for finance-trading market_data tools.

These tools use @tool decorator from strands which allows direct function calls.
The tools return simulated random data, so we test structure and types, not exact values.
"""
import json
import sys
from pathlib import Path

# Add the finance-trading agent directory to the path so we can import tools
sys.path.insert(0, str(Path(__file__).parent.parent / "apps" / "finance-trading"))

from agent.tools.market_data import (
    get_stock_quote,
    get_market_overview,
    get_historical_prices,
    get_sector_performance,
)


class TestGetStockQuote:
    """Tests for get_stock_quote tool."""

    def test_returns_valid_json(self):
        result = get_stock_quote(symbol="AAPL")
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_contains_expected_keys(self):
        result = get_stock_quote(symbol="AAPL")
        data = json.loads(result)
        expected_keys = [
            "symbol", "price", "change", "change_pct",
            "volume", "market_cap_billions", "pe_ratio",
            "52w_high", "52w_low", "timestamp",
        ]
        for key in expected_keys:
            assert key in data, f"Missing key: {key}"

    def test_symbol_is_uppercased(self):
        result = get_stock_quote(symbol="aapl")
        data = json.loads(result)
        assert data["symbol"] == "AAPL"

    def test_price_is_numeric(self):
        result = get_stock_quote(symbol="MSFT")
        data = json.loads(result)
        assert isinstance(data["price"], (int, float))
        assert data["price"] > 0

    def test_volume_is_positive_integer(self):
        result = get_stock_quote(symbol="GOOGL")
        data = json.loads(result)
        assert isinstance(data["volume"], int)
        assert data["volume"] > 0

    def test_unknown_symbol_still_returns_data(self):
        result = get_stock_quote(symbol="XYZZY")
        data = json.loads(result)
        assert data["symbol"] == "XYZZY"
        assert data["price"] > 0


class TestGetMarketOverview:
    """Tests for get_market_overview tool."""

    def test_returns_valid_json(self):
        result = get_market_overview()
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_contains_indices(self):
        result = get_market_overview()
        data = json.loads(result)
        assert "indices" in data
        indices = data["indices"]
        assert "SP500" in indices
        assert "NASDAQ" in indices
        assert "DOW" in indices
        assert "RUSSELL2000" in indices

    def test_indices_have_value_and_change(self):
        result = get_market_overview()
        data = json.loads(result)
        for name, index_data in data["indices"].items():
            assert "value" in index_data
            assert "change_pct" in index_data
            assert isinstance(index_data["value"], (int, float))

    def test_contains_volatility(self):
        result = get_market_overview()
        data = json.loads(result)
        assert "volatility" in data
        assert "VIX" in data["volatility"]
        assert isinstance(data["volatility"]["VIX"], (int, float))

    def test_contains_treasury(self):
        result = get_market_overview()
        data = json.loads(result)
        assert "treasury" in data
        treasury = data["treasury"]
        assert "2Y" in treasury
        assert "10Y" in treasury
        assert "30Y" in treasury

    def test_contains_sentiment(self):
        result = get_market_overview()
        data = json.loads(result)
        assert "sentiment" in data
        assert "fear_greed_index" in data["sentiment"]
        assert "label" in data["sentiment"]


class TestGetHistoricalPrices:
    """Tests for get_historical_prices tool."""

    def test_returns_valid_json(self):
        result = get_historical_prices(symbol="MSFT", days=30)
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_returns_correct_number_of_data_points(self):
        result = get_historical_prices(symbol="MSFT", days=30)
        data = json.loads(result)
        assert len(data["data"]) == 30

    def test_caps_at_252_days(self):
        result = get_historical_prices(symbol="MSFT", days=500)
        data = json.loads(result)
        assert len(data["data"]) == 252
        assert data["period_days"] == 252

    def test_data_points_have_ohlcv(self):
        result = get_historical_prices(symbol="AAPL", days=5)
        data = json.loads(result)
        for point in data["data"]:
            assert "date" in point
            assert "open" in point
            assert "high" in point
            assert "low" in point
            assert "close" in point
            assert "volume" in point

    def test_symbol_uppercased_in_response(self):
        result = get_historical_prices(symbol="aapl", days=5)
        data = json.loads(result)
        assert data["symbol"] == "AAPL"

    def test_prices_are_positive(self):
        result = get_historical_prices(symbol="MSFT", days=10)
        data = json.loads(result)
        for point in data["data"]:
            assert point["close"] > 0
            assert point["high"] > 0
            assert point["low"] > 0
            assert point["open"] > 0


class TestGetSectorPerformance:
    """Tests for get_sector_performance tool."""

    def test_returns_valid_json(self):
        result = get_sector_performance()
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_returns_11_sectors(self):
        result = get_sector_performance()
        data = json.loads(result)
        assert "sectors" in data
        assert len(data["sectors"]) == 11

    def test_sectors_have_expected_fields(self):
        result = get_sector_performance()
        data = json.loads(result)
        for sector in data["sectors"]:
            assert "name" in sector
            assert "daily_change_pct" in sector
            assert "ytd_change_pct" in sector
            assert "market_cap_trillions" in sector

    def test_sector_names_are_strings(self):
        result = get_sector_performance()
        data = json.loads(result)
        for sector in data["sectors"]:
            assert isinstance(sector["name"], str)
            assert len(sector["name"]) > 0

    def test_has_timestamp(self):
        result = get_sector_performance()
        data = json.loads(result)
        assert "timestamp" in data
