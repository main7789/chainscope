"""
fetcher.py
────────────────────────────────────────
Purpose : Fetch raw data from Ethereum network
          via Etherscan API V2.
Depends : logger.py and cache.py
────────────────────────────────────────
"""

import requests
import os
import time
from dotenv import load_dotenv
from logger import get_logger
from cache import CacheManager

load_dotenv()
logger = get_logger("fetcher")

API_KEY       = os.getenv("ETHERSCAN_API_KEY")
BASE_URL      = "https://api.etherscan.io/v2/api"
WEI_TO_ETH    = 10 ** 18
REQUEST_DELAY = 0.25
CHAIN_ID      = 1


class EthereumFetcher:

    def __init__(self):
        if not API_KEY:
            raise ValueError("ETHERSCAN_API_KEY missing in .env file")
        self.api_key  = API_KEY
        self.base_url = BASE_URL
        self.cache    = CacheManager()
        logger.info("EthereumFetcher initialized")

    def _make_request(self, params: dict) -> dict:
        params["apikey"]  = self.api_key
        params["chainid"] = CHAIN_ID
        time.sleep(REQUEST_DELAY)
        try:
            response = requests.get(self.base_url, params=params, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            logger.error("Connection timeout")
            raise TimeoutError("Server did not respond within 15 seconds")
        except requests.exceptions.ConnectionError:
            logger.error("Internet connection failure")
            raise ConnectionError("Please check your internet connection")

    def get_balance(self, address: str) -> float:
        cache_key = f"balance_{address}"
        cached    = self.cache.get(cache_key)
        if cached is not None:
            logger.info("Balance from cache: %.6f ETH", cached)
            return cached
        params = {
            "module" : "account",
            "action" : "balance",
            "address": address,
            "tag"    : "latest",
        }
        data = self._make_request(params)
        if data.get("status") != "1":
            raise ValueError(f"API Error: {data.get('message')} — {data.get('result')}")
        balance = round(int(data["result"]) / WEI_TO_ETH, 6)
        self.cache.set(cache_key, balance)
        logger.info("Balance: %.6f ETH", balance)
        return balance

    def get_transactions(self, address: str, limit: int = 50) -> list[dict]:
        cache_key = f"txs_{address}_{limit}"
        cached    = self.cache.get(cache_key)
        if cached is not None:
            logger.info("Transactions from cache: %d transactions", len(cached))
            return cached
        params = {
            "module"    : "account",
            "action"    : "txlist",
            "address"   : address,
            "startblock": 0,
            "endblock"  : 99999999,
            "page"      : 1,
            "offset"    : limit,
            "sort"      : "desc",
        }
        data = self._make_request(params)
        if data.get("status") != "1":
            logger.warning("No transactions found: %s", data.get("message"))
            return []
        transactions = [
            {
                "hash"     : tx["hash"],
                "from"     : tx["from"],
                "to"       : tx["to"],
                "value_eth": round(int(tx["value"]) / WEI_TO_ETH, 6),
                "success"  : tx["isError"] == "0",
                "block"    : int(tx["blockNumber"]),
            }
            for tx in data["result"]
        ]
        self.cache.set(cache_key, transactions)
        logger.info("Fetched %d transactions", len(transactions))
        return transactions