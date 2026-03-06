# =============================================================================
# SecureErase Pro — Desktop Application Entry Point
# =============================================================================
# Purpose  : Application bootstrap, argument parsing, and UIController launch
# Inputs   : CLI arguments (--nogui, --batch, --config)
# Outputs  : Launches GUI or runs headless batch wipe
# =============================================================================

import sys
import argparse


def main():
    parser = argparse.ArgumentParser(
        prog="secureerase-pro",
        description="SecureErase Pro — Enterprise Secure Data Destruction",
    )
    parser.add_argument("--nogui", action="store_true", help="Run in headless mode")
    parser.add_argument("--batch", type=str, help="Path to batch job JSON file")
    parser.add_argument("--config", type=str, help="Path to config file")
    args = parser.parse_args()

    # Modules imported here after scaffold implementation
    print("SecureErase Pro desktop application scaffold initialised.")


if __name__ == "__main__":
    main()
