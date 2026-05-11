"""
security.py
────────────────────────────────────────
الغرض  : تدقيق أمني متعمق — كشف 5 أنماط احتيال
يعتمد  : على fetcher.py و analyzer.py
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
    CLEAN    = "🟢 نظيف"
    LOW      = "🔵 منخفض"
    MEDIUM   = "🟡 متوسط"
    HIGH     = "🟠 مرتفع"
    CRITICAL = "🔴 حرج"


@dataclass
class ThreatSignal:
    """إشارة تهديد واحدة مكتشفة"""
    name        : str
    level       : ThreatLevel
    description : str
    evidence    : dict = field(default_factory=dict)


@dataclass
class SecurityReport:
    """التقرير الأمني الشامل"""
    address        : str
    overall_level  : ThreatLevel
    signals        : list = field(default_factory=list)
    total_signals  : int  = 0
    recommendation : str  = ""


class SecurityThresholds:
    """قيم الحدود المستخدمة في الكشف"""
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
    """يفحص المحافظ بحثاً عن 5 أنماط مشبوهة"""

    def __init__(self):
        self.fetcher   = EthereumFetcher()
        self.threshold = SecurityThresholds()
        logger.info("تم تهيئة SecurityAnalyzer")


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
                    description = f"نفس الزوج يتكرر {count} مرة ({ratio*100:.1f}%)",
                    evidence    = {"pair": str(pair), "repetitions": int(count)},
                )
        return None


    def _detect_dumping(self, df: pd.DataFrame, balance: float):
        if df.empty or balance <= 0:
            return None

        sent_df = df[df["value_eth"] > 0]
        if sent_df.empty:
            return None

        largest      = sent_df["value_eth"].max()
        total_volume = sent_df["value_eth"].sum()

        if total_volume <= 0:
            return None

        ratio = largest / (balance + total_volume)
        if ratio >= SecurityThresholds.DUMP_RATIO:
            return ThreatSignal(
                name        = "Dumping Pattern",
                level       = ThreatLevel.CRITICAL,
                description = f"معاملة واحدة بقيمة {largest:.4f} ETH = {ratio*100:.1f}% من الرصيد",
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
            description = f"{len(dust_df)} معاملة غبار من {unique_senders} مرسل",
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
                description = f"آخر {SecurityThresholds.DRAIN_WINDOW_TX} معاملات = {ratio*100:.1f}% من الإرسال",
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
            description = f"تفاعل مع {len(found)} خلاط عملات معروف",
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
            ThreatLevel.CLEAN    : "✅ المحفظة نظيفة — يمكن التعامل بثقة",
            ThreatLevel.LOW      : "🔵 نشاط غير معتاد — تعامل بحذر",
            ThreatLevel.MEDIUM   : "🟡 نمط مشبوه — لا ترسل مبالغ كبيرة",
            ThreatLevel.HIGH     : "🟠 خطر — تجنب التعامل بمبالغ مهمة",
            ThreatLevel.CRITICAL : "🔴 خطر حرج — لا تتعامل مع هذه المحفظة",
        }
        base = texts[level]
        if signals:
            base += "\n  المخاطر: " + "، ".join(s.name for s in signals)
        return base


    def audit(self, address: str, tx_limit: int = 50) -> SecurityReport:
        """الدالة الرئيسية — تُشغّل كل الكاشفات"""

        logger.info("بدء التدقيق الأمني: %s", address[:16])

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
            logger.warning("تهديد مكتشف: %s — %s", s.name, s.level.value)

        overall = self._overall_level(signals)
        logger.info("اكتمل التدقيق — المستوى: %s", overall.value)

        return SecurityReport(
            address        = address,
            overall_level  = overall,
            signals        = signals,
            total_signals  = len(signals),
            recommendation = self._recommendation(overall, signals),
        )