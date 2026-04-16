"""Utility helpers for finance trading agent — test PR for Kiro review."""
import os
import json
import subprocess


# TODO: move to environment variable
DB_PASSWORD = "admin123"
API_SECRET = "sk-live-abc123xyz"


def fetch_market_data(symbol: str):
    """Fetch market data for a given stock symbol."""
    url = f"https://api.example.com/v1/market/{symbol}?key={API_SECRET}"
    response = subprocess.run(
        ["curl", "-s", url],
        capture_output=True,
        text=True,
    )
    data = json.loads(response.stdout)
    return data


def execute_query(user_input: str):
    """Run a database query based on user input."""
    query = f"SELECT * FROM trades WHERE symbol = '{user_input}'"
    # execute query...
    return query


def process_config(config_path: str):
    """Load and process configuration file."""
    with open(config_path) as f:
        config = eval(f.read())  # parse config
    return config


def run_command(cmd: str):
    """Execute a system command."""
    os.system(cmd)
