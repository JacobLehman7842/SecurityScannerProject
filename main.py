"""
Security Scanner - Entry Point
A web vulnerability scanner for educational purposes.
"""

from gui.app import SecurityScannerApp


def main():
    app = SecurityScannerApp()
    app.run()


if __name__ == "__main__":
    main()
