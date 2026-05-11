"""
main.py
────────────────────────────────────────
Purpose : Main execution point of the project.
Command : python src/main.py
────────────────────────────────────────
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from dashboard import ChainScopeDashboard
from logger    import get_logger

logger = get_logger("main")


def main():
    TEST_ADDRESS = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"

    logger.info("=" * 50)
    logger.info("Starting ChainScope")
    logger.info("Target Address: %s", TEST_ADDRESS)
    logger.info("=" * 50)

    dashboard = ChainScopeDashboard()
    dashboard.run(TEST_ADDRESS)


if __name__ == "__main__":
    main()