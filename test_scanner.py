"""
Test script to verify scanning works.
"""

from scanner.core import Scanner


def test_scan(url: str):
    """Scan a URL and print findings."""
    print(f"\n{'='*60}")
    print(f"Scanning: {url}")
    print(f"{'='*60}\n")

    # Run scan
    scanner = Scanner(url)
    success, message, findings = scanner.run_scan()

    if not success:
        print(f"❌ Scan failed: {message}")
        return

    print(f"✓ {message}\n")

    # Display results
    if not findings:
        print("✓ All security headers are present!")
    else:
        print(f"⚠ Found {len(findings)} issue(s):\n")
        for i, finding in enumerate(findings, 1):
            print(f"{i}. [{finding.severity.value.upper()}] {finding.title}")
            print(f"   Description: {finding.description}")
            print(f"   Recommendation: {finding.recommendation}")
            print()


if __name__ == "__main__":
    # Test with a few sites
    test_urls = [
        "example.com",           # Simple site, probably missing headers
        "https://github.com",    # Well-secured site
    ]

    for url in test_urls:
        test_scan(url)
        input("\nPress Enter to continue to next test...")
