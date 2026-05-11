"""
dashboard.py
────────────────────────────────────────
Purpose : Visualize results in the Terminal
Depends : analyzer.py and security.py
────────────────────────────────────────
"""

from rich.console import Console
from rich.table   import Table
from rich.panel   import Panel
from rich.columns import Columns
from rich.text    import Text
from rich.align   import Align
from rich.rule    import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
import time

from analyzer import WalletAnalyzer, WalletReport
from security import SecurityAnalyzer, SecurityReport, ThreatLevel
from logger   import get_logger

logger  = get_logger("dashboard")
console = Console()

THEME = {
    "primary"  : "cyan",
    "secondary": "blue",
    "success"  : "green",
    "warning"  : "yellow",
    "danger"   : "red",
    "muted"    : "dim white",
}


class ChainScopeDashboard:

    def __init__(self):
        self.console  = console
        self.analyzer = WalletAnalyzer()
        self.auditor  = SecurityAnalyzer()


    def _banner(self) -> None:
        self.console.print(Panel(
            Align.center(Text(
                "⛓  C H A I N S C O P E  ⛓",
                style=f"bold {THEME['primary']}"
            )),
            subtitle="[dim]Blockchain Intelligence Platform v1.0[/dim]",
            border_style=THEME["primary"],
        ))
        self.console.print(
            Align.center("[dim cyan]Ethereum Wallet Analyzer & Auditor[/dim cyan]")
        )
        self.console.print()


    def _loading(self) -> None:
        steps = [
            ("🌐", "Connecting to Ethereum Network"),
            ("📦", "Fetching Wallet Data"),
            ("🔍", "Analyzing Transactions"),
            ("🔐", "Running Security Audit"),
            ("📊", "Generating Report"),
        ]
        with Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[cyan]{task.description}[/cyan]"),
            BarColumn(bar_width=30),
            console=self.console,
        ) as progress:
            task = progress.add_task("Processing...", total=len(steps))
            for emoji, desc in steps:
                progress.update(task, description=f"{emoji}  {desc}")
                time.sleep(0.5)
                progress.advance(task)


    def _summary_cards(
        self,
        analysis: WalletReport,
        security: SecurityReport,
    ) -> Columns:

        def card(title, value, color):
            return Panel(
                Align.center(Text(value, style=f"bold {color}")),
                title=f"[dim]{title}[/dim]",
                border_style=color,
                padding=(1, 2),
            )

        bal_color = THEME["success"] if analysis.balance_eth > 0 else THEME["muted"]

        sr = analysis.success_rate
        sr_color = (
            THEME["success"] if sr >= 90 else
            THEME["warning"] if sr >= 70 else
            THEME["danger"]
        )

        threat_colors = {
            ThreatLevel.CLEAN   : THEME["success"],
            ThreatLevel.LOW     : "blue",
            ThreatLevel.MEDIUM  : THEME["warning"],
            ThreatLevel.HIGH    : "orange3",
            ThreatLevel.CRITICAL: THEME["danger"],
        }

        return Columns([
            card("💰 Balance",        f"{analysis.balance_eth:.4f} ETH",         bal_color),
            card("📊 Transactions",   str(analysis.total_tx),                    THEME["secondary"]),
            card("✅ Success Rate",   f"{analysis.success_rate:.1f}%",           sr_color),
            card("🔐 Security Level", security.overall_level.value,              threat_colors.get(security.overall_level, THEME["muted"])),
        ], equal=True)


    def _stats_table(self, analysis: WalletReport) -> Table:
        table = Table(
            title="📈 Statistical Analysis",
            title_style=f"bold {THEME['primary']}",
            border_style=THEME["secondary"],
            show_header=False,
            padding=(0, 2),
        )
        table.add_column("Metric", style=f"bold {THEME['primary']}", width=26)
        table.add_column("Value", style=THEME["muted"])

        rows = [
            ("💸 Total Sent"         , f"{analysis.total_sent:.6f} ETH"),
            ("📥 Total Received"     , f"{analysis.total_received:.6f} ETH"),
            ("📊 Avg. Tx Value"      , f"{analysis.avg_tx_value:.6f} ETH"),
            ("🏆 Largest Transaction" , f"{analysis.largest_tx:.6f} ETH"),
            ("⚡ Risk Level"         ,  analysis.risk_level),
        ]
        for indicator, value in rows:
            table.add_row(indicator, value)

        if analysis.top_addresses:
            table.add_row("", "")
            table.add_row(f"[bold {THEME['primary']}]🔗 Most Interacted Addresses[/]", "")
            for addr in analysis.top_addresses:
                table.add_row("  ↳", f"[dim]{addr}[/dim]")

        return table


    def _tx_table(self, transactions: list[dict]) -> Table:
        table = Table(
            title="📋 Latest Transactions",
            title_style=f"bold {THEME['primary']}",
            border_style=THEME["secondary"],
            header_style=f"bold {THEME['primary']}",
            show_lines=True,
        )
        for col, justify, width in [
            ("#", "center", 3), ("Hash", "center", 20),
            ("From", "center", 14), ("To", "center", 14),
            ("ETH", "right", 12), ("Status", "center", 8),
        ]:
            table.add_column(col, justify=justify, min_width=width)

        for i, tx in enumerate(transactions[:8], 1):
            v = tx.get("value_eth", 0)
            vc = THEME["success"] if v > 0.1 else THEME["warning"] if v > 0.01 else THEME["muted"]
            st = f"[{THEME['success']}]✅[/]" if tx.get("success") else f"[{THEME['danger']}]❌[/]"
            table.add_row(
                str(i),
                f"[dim]{tx.get('hash','')[:18]}...[/dim]",
                f"[dim]{tx.get('from','')[:12]}...[/dim]",
                f"[dim]{tx.get('to','')[:12]}...[/dim]",
                f"[{vc}]{v:.4f}[/]",
                st,
            )
        return table


    def _security_panel(self, security: SecurityReport) -> Panel:
        threat_colors = {
            ThreatLevel.CLEAN   : THEME["success"],
            ThreatLevel.LOW     : "blue",
            ThreatLevel.MEDIUM  : THEME["warning"],
            ThreatLevel.HIGH    : "orange3",
            ThreatLevel.CRITICAL: THEME["danger"],
        }
        color   = threat_colors.get(security.overall_level, THEME["muted"])
        content = Text()
        content.append(f"Level: {security.overall_level.value}\n\n", style=f"bold {color}")

        if not security.signals:
            content.append("✅ No suspicious patterns detected\n", style=THEME["success"])
        else:
            content.append(f"⚠️  {security.total_signals} Threat signals detected\n\n", style=THEME["warning"])
            for i, s in enumerate(security.signals, 1):
                sc = threat_colors.get(s.level, THEME["muted"])
                content.append(f"  [{i}] {s.name}\n",    style=f"bold {sc}")
                content.append(f"      {s.description}\n", style=THEME["muted"])

        content.append(f"\n{'─'*40}\n", style="dim")
        content.append("💡 Recommendation:\n", style=f"bold {THEME['primary']}")
        content.append(security.recommendation, style=THEME["muted"])

        return Panel(
            content,
            title=f"[bold {color}]🔐 Security Report[/]",
            border_style=color,
            padding=(1, 2),
        )


    def run(self, address: str) -> None:
        """Main entry point for the dashboard"""

        self.console.clear()
        self._banner()

        self.console.print(Panel(
            f"[{THEME['primary']}]Address: [bold]{address}[/bold][/]",
            border_style=THEME["primary"],
            padding=(0, 2),
        ))
        self.console.print()
        self._loading()
        self.console.print()

        try:
            analysis     = self.analyzer.analyze(address, tx_limit=50)
            security_rep = self.auditor.audit(address, tx_limit=50)
            transactions = self.analyzer.fetcher.get_transactions(address, limit=8)
        except Exception as e:
            self.console.print(Panel(
                f"[{THEME['danger']}]❌ Error: {e}[/]",
                border_style=THEME["danger"],
            ))
            return

        self.console.print(Rule(f"[bold {THEME['primary']}]📊 Summary[/]", style=THEME["secondary"]))
        self.console.print(self._summary_cards(analysis, security_rep))
        self.console.print()

        self.console.print(Rule(f"[bold {THEME['primary']}]🔍 Details[/]", style=THEME["secondary"]))
        self.console.print(Columns([
            self._stats_table(analysis),
            self._tx_table(transactions),
        ], equal=True))
        self.console.print()

        if analysis.warnings:
            for w in analysis.warnings:
                self.console.print(Panel(
                    f"[{THEME['warning']}]{w}[/]",
                    border_style=THEME["warning"],
                    padding=(0, 2),
                ))

        self.console.print(Rule(f"[bold {THEME['primary']}]🔐 Security[/]", style=THEME["secondary"]))
        self.console.print(self._security_panel(security_rep))
        self.console.print()
        self.console.print(Align.center("[dim]ChainScope v1.0 | Built with Python[/dim]"))