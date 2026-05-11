"""
analyzer.py
────────────────────────────────────────
Purpose : Statistically analyze raw data
          and extract valuable insights.
Depends : fetcher.py
────────────────────────────────────────
"""

import pandas as pd
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional
from fetcher import EthereumFetcher
from logger import get_logger

logger = get_logger("analyzer")


@dataclass
class WalletReport:
    """Structure for a full single-wallet report"""

    address        : str
    balance_eth    : float
    total_tx       : int
    total_sent     : float
    total_received : float
    success_rate   : float
    avg_tx_value   : float
    largest_tx     : float
    top_addresses  : list  = field(default_factory=list)
    risk_level     : str   = "Undefined"
    warnings       : list  = field(default_factory=list)


class WalletAnalyzer:
    """
   Converts raw data into a comprehensive statistical report
    """

    def __init__(self):
        self.fetcher           = EthereumFetcher()
        self.MIN_TX_FOR_ANALYSIS = 3
        logger.info("WalletAnalyzer initialized")


    def _to_dataframe(self, transactions: list[dict]) -> pd.DataFrame:
        """ Converts transaction list to a pandas DataFrame"""

        if not transactions:
            return pd.DataFrame()

        df = pd.DataFrame(transactions)
        df["value_eth"] = pd.to_numeric(df["value_eth"], errors="coerce")
        df["success"]   = df["success"].astype(bool)
        return df


    def _success_rate(self, df: pd.DataFrame) -> float:
        """Calculates the percentage of successful transactions"""

        if df.empty:
            return 0.0
        return round((df["success"].sum() / len(df)) * 100, 2)


    def _top_addresses(self, df: pd.DataFrame, top_n: int = 3) -> list[str]:
        """Identifies the most interacted addresses"""

        if df.empty:
            return []

        all_addr   = list(df["from"]) + list(df["to"])
        counts     = Counter(all_addr)
        result     = []

        for address, count in counts.most_common(top_n + 1):
            if len(result) == top_n:
                break
            result.append(f"{address[:12]}...({count} txs)")

        return result


    def _assess_risk(self, data: dict) -> tuple[str, list[str]]:
        """Evaluates risk level and generates warnings"""

        warnings   = []
        risk_score = 0

        if data["success_rate"] < 80:
            warnings.append(
                f"⚠️ Low success rate: {data['success_rate']}%"
            )
            risk_score += 2

        if (data["largest_tx"] > data["avg_tx_value"] * 10
                and data["total_tx"] > self.MIN_TX_FOR_ANALYSIS):
            warnings.append(
                f"⚠️ Anomalous large transaction: {data['largest_tx']:.4f} ETH"
            )
            risk_score += 1

        if (data["total_tx"] < self.MIN_TX_FOR_ANALYSIS
                and data["balance_eth"] > 1.0):
            warnings.append("⚠️ Recent wallet with high balance")
            risk_score += 1

        if risk_score == 0:
            level = "🟢 Low"
        elif risk_score <= 2:
            level = "🟡 Medium"
        else:
            level = "🔴 High"

        return level, warnings


    def analyze(self, address: str, tx_limit: int = 50) -> WalletReport:
        """Main function — Produces the full report"""

        logger.info("Starting analysis for: %s", address[:16])

        balance      = self.fetcher.get_balance(address)
        transactions = self.fetcher.get_transactions(address, limit=tx_limit)
        df           = self._to_dataframe(transactions)

        if df.empty:
            return WalletReport(
                address        = address,
                balance_eth    = balance,
                total_tx       = 0,
                total_sent     = 0.0,
                total_received = 0.0,
                success_rate   = 0.0,
                avg_tx_value   = 0.0,
                largest_tx     = 0.0,
                risk_level     = "🔵 Not enough data",
                warnings       = ["No transactions found"],
            )

        sent_df     = df[df["from"].str.lower() == address.lower()]
        received_df = df[df["to"].str.lower()   == address.lower()]

        risk_data = {
            "success_rate" : self._success_rate(df),
            "largest_tx"   : df["value_eth"].max(),
            "avg_tx_value" : df["value_eth"].mean(),
            "total_tx"     : len(df),
            "balance_eth"  : balance,
        }
        risk_level, warnings = self._assess_risk(risk_data)

        logger.info(" Analysis complete — %d transactions processed", len(df))

        return WalletReport(
            address        = address,
            balance_eth    = balance,
            total_tx       = len(df),
            total_sent     = round(sent_df["value_eth"].sum(), 6),
            total_received = round(received_df["value_eth"].sum(), 6),
            success_rate   = risk_data["success_rate"],
            avg_tx_value   = round(risk_data["avg_tx_value"], 6),
            largest_tx     = round(risk_data["largest_tx"], 6),
            top_addresses  = self._top_addresses(df),
            risk_level     = risk_level,
            warnings       = warnings,
        )