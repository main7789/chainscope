"""
security.py
────────────────────────────────────────
Purpose : Deep security audit — Detects 5 fraud patterns.
Depends : fetcher.py and analyzer.py
────────────────────────────────────────
"""

import pandas as pd
from dataclasses import dataclass, field
from enum import Enum
from fetcher import EthereumFetcher
from analyzer import WalletAnalyzer, WalletReport
from logger import get_logger

logger = get_logger("security")


class ThreatLevel(Enum):
    CLEAN    = "🟢 Clean"
    LOW      = "🔵 Low"
    MEDIUM   = "🟡 Medium"
    HIGH     = "🟠 High"
    CRITICAL = "🔴 Critical"


@dataclass
class ThreatSignal:
    """Represents a single detected threat signal"""
    name        : str
    level       : ThreatLevel
    description : str
    evidence    : dict = field(default_factory=dict)


@dataclass
class SecurityReport:
    """Structure for the comprehensive security report"""
    address        : str
    overall_level  : ThreatLevel
    signals        : list = field(default_factory=list)
    total_signals  : int  = 0
    recommendation : str  = ""


class SecurityThresholds:
    """Detection threshold values"""
    DUST_MAX_ETH    = 0.001
    DUST_MIN_COUNT  = 3
    WASH_RATIO      = 0.3
    DUMP_RATIO      = 0.8
    DRAIN_WINDOW_TX = 5
    MIXER_ADDRESSES = {
        "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
        "0x722122df12d4e14e13ac3b6895a86e84145b6967",
        "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936",
    }


class SecurityAnalyzer:
    """Analyzes wallets for 5 suspicious behavioral patterns"""

    def __init__(self):
        self.fetcher   = EthereumFetcher()
        self.threshold = SecurityThresholds()
        logger.info("SecurityAnalyzer initialized")


    def _detect_wash_trading(self, df: pd.DataFrame, address: str):
        if df.empty or len(df) < 4:
            return None

        pairs = df.apply(
            lambda row: tuple(sorted([row["from"].lower(), row["to"].lower()])),
            axis=1,
        )
        pair_counts = pairs.value_counts()

        for pair, count in pair_counts.items():
            ratio = count / len(df)
            if ratio >= SecurityThresholds.WASH_RATIO:
                return ThreatSignal(
                    name        = "Wash Trading",
                    level       = ThreatLevel.HIGH,
                    description = f"Same pair repeated {count} times ({ratio*100:.1f}%)",
                    evidence    = {"pair": str(pair), "repetitions": int(count)},
                )
        return None


    def _detect_dumping(self, df: pd.DataFrame, balance: float):
        if df.empty or balance <= 0:
            return None

        sent_df = df[df["value_eth"] > 0]
        if sent_df.empty:
            return None

        largest       = sent_df["value_eth"].max()
        total_volume = sent_df["value_eth"].sum()

        if total_volume <= 0:
            return None

        ratio = largest / (balance + total_volume)
        if ratio >= SecurityThresholds.DUMP_RATIO:
            return ThreatSignal(
                name        = "Dumping Pattern",
                level       = ThreatLevel.CRITICAL,
                description = f"Single tx of {largest:.4f} ETH = {ratio*100:.1f}% of total value",
                evidence    = {"largest_tx": round(largest, 6), "dump_pct": round(ratio*100, 2)},
            )
        return None


    def _detect_dusting(self, df: pd.DataFrame, address: str):
        if df.empty:
            return None

        received_df = df[df["to"].str.lower() == address.lower()]
        dust_df     = received_df[received_df["value_eth"] < SecurityThresholds.DUST_MAX_ETH]

        if len(dust_df) < SecurityThresholds.DUST_MIN_COUNT:
            return None

        unique_senders = dust_df["from"].nunique()
        level = ThreatLevel.HIGH if unique_senders > 1 else ThreatLevel.MEDIUM

        return ThreatSignal(
            name        = "Dusting Attack",
            level       = level,
            description = f"{len(dust_df)} dust transactions from {unique_senders} senders",
            evidence    = {"dust_count": len(dust_df), "senders": int(unique_senders)},
        )


    def _detect_rapid_drain(self, df: pd.DataFrame, address: str):
        if df.empty or len(df) < SecurityThresholds.DRAIN_WINDOW_TX:
            return None

        sent_df = df[df["from"].str.lower() == address.lower()].copy()
        if sent_df.empty:
            return None

        total_sent    = sent_df["value_eth"].sum()
        if total_sent <= 0:
            return None

        window_volume = sent_df.head(SecurityThresholds.DRAIN_WINDOW_TX)["value_eth"].sum()
        ratio         = window_volume / total_sent

        if ratio >= 0.70:
            return ThreatSignal(
                name        = "Rapid Drain",
                level       = ThreatLevel.HIGH,
                description = f"Last {SecurityThresholds.DRAIN_WINDOW_TX} txs = {ratio*100:.1f}% of total sent volume",
                evidence    = {"window_volume": round(window_volume, 6), "drain_pct": round(ratio*100, 2)},
            )
        return None


    def _detect_mixer(self, df: pd.DataFrame):
        if df.empty:
            return None

        all_addresses = set(df["from"].str.lower()) | set(df["to"].str.lower())
        found         = all_addresses & SecurityThresholds.MIXER_ADDRESSES

        if not found:
            return None

        return ThreatSignal(
            name        = "Mixer Interaction",
            level       = ThreatLevel.CRITICAL,
            description = f"Interacted with {len(found)} known crypto mixers",
            evidence    = {"mixers_found": list(found)},
        )


    def _overall_level(self, signals: list) -> ThreatLevel:
        if not signals:
            return ThreatLevel.CLEAN

        priority = {
            ThreatLevel.CLEAN: 0, ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2, ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4,
        }
        return max(signals, key=lambda s: priority[s.level]).level


    def _recommendation(self, level: ThreatLevel, signals: list) -> str:
        texts = {
            ThreatLevel.CLEAN    : "✅ Wallet is clean — Safe to interact with.",
            ThreatLevel.LOW      : "🔵 Unusual activity — Proceed with caution.",
            ThreatLevel.MEDIUM   : "🟡 Suspicious patterns — Avoid sending large amounts.",
            ThreatLevel.HIGH     : "🟠 Risk detected — Avoid transacting with significant funds.",
            ThreatLevel.CRITICAL : "🔴 Critical Risk — Do NOT interact with this wallet.",
        }
        base = texts[level]
        if signals:
            base += "\n  Risks: " + ", ".join(s.name for s in signals)
        return base


    def audit(self, address: str, tx_limit: int = 50) -> SecurityReport:
        """Main function — Executes all detectors"""

        logger.info("Starting security audit for: %s", address[:16])

        transactions = self.fetcher.get_transactions(address, limit=tx_limit)
        balance      = self.fetcher.get_balance(address)
        df = pd.DataFrame(transactions) if transactions else pd.DataFrame()

        detectors = [
            self._detect_wash_trading(df, address),
            self._detect_dumping(df, balance),
            self._detect_dusting(df, address),
            self._detect_rapid_drain(df, address),
            self._detect_mixer(df),
        ]

        signals = [s for s in detectors if s is not None]

        for s in signals:
            logger.warning("Threat detected: %s — %s", s.name, s.level.value)

        overall = self._overall_level(signals)
        logger.info("Audit complete — Final Level: %s", overall.value)

        return SecurityReport(
            address        = address,
            overall_level  = overall,
            signals        = signals,
            total_signals  = len(signals),
            recommendation = self._recommendation(overall, signals),
        )