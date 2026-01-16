"""
Core scanner engine - orchestrates vulnerability checks.
"""

from utils.http_client import HTTPClient, validate_url
from scanner.header_checks import HeaderChecker
from scanner.file_checks import FileChecker
from utils.scoring import Finding


class Scanner:
    """Main scanner class that coordinates all vulnerability checks."""

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.findings = []
        self.http_client = HTTPClient()

    def run_scan(self) -> tuple[bool, str, list[Finding]]:
        
        is_valid, result = validate_url(self.target_url)
        if not is_valid:
            return False, result, []

        self.target_url = result  # Use the cleaned URL

        response = self.http_client.get(self.target_url)
        if response is None:
            return False, "Failed to fetch the target URL.", []

        # Run header checks
        header_checker = HeaderChecker(response.headers)
        header_findings = header_checker.check_all()

        # Run file checks
        file_checker = FileChecker(self.target_url, self.http_client)
        file_findings = file_checker.check_all()

        # Combine all findings
        self.findings = header_findings + file_findings

        return True, "Scan completed successfully.", self.findings

    def get_results(self) -> list[Finding]:
        return self.findings
