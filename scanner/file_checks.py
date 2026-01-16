"""
Sensitive file detection module.
Checks for commonly exposed sensitive files and directories.
"""

from utils.http_client import HTTPClient
from utils.scoring import Finding, Severity


class FileChecker:
    """Detects exposed sensitive files on the target."""

    # Sensitive files with their security implications
    # Format: (path, severity, description)
    SENSITIVE_PATHS = [
        ("/.git/config", Severity.CRITICAL,
         "Git configuration file exposed - may contain repository URL with credentials, reveals source code location."),

        ("/.git/HEAD", Severity.CRITICAL,
         "Git HEAD file exposed - confirms .git directory is accessible, entire source code can be downloaded."),

        ("/.env", Severity.CRITICAL,
         "Environment file exposed - commonly contains database passwords, API keys, and other secrets."),

        ("/config.php", Severity.HIGH,
         "Configuration file exposed - may contain database credentials and application secrets."),

        ("/wp-config.php", Severity.HIGH,
         "WordPress configuration exposed - contains database credentials and security keys."),

        ("/backup.sql", Severity.HIGH,
         "Database backup file exposed - contains all application data including user information."),

        ("/dump.sql", Severity.HIGH,
         "Database dump exposed - contains all application data including passwords and personal information."),

        ("/.htaccess", Severity.MEDIUM,
         "Apache configuration file exposed - may reveal server configuration and rewrite rules."),

        ("/robots.txt", Severity.LOW,
         "Robots.txt file found - not sensitive itself, but may reveal hidden paths attackers can explore."),
    ]

    def __init__(self, base_url: str, http_client: HTTPClient):
        """
        Initialize file checker.

        Args:
            base_url: The base URL to check (e.g., https://example.com)
            http_client: HTTPClient instance to use for requests
        """
        self.base_url = base_url.rstrip("/")
        self.http_client = http_client

    def check_all(self) -> list[Finding]:
        """
        Check for all sensitive files and return findings.

        Strategy:
        1. Loop through SENSITIVE_PATHS
        2. For each path, build full URL (base_url + path)
        3. Make HEAD request (faster - no body download)
        4. Check status code:
           - 200 = File exists (FINDING!)
           - 403 = Forbidden (file exists but can't access - still a finding)
           - 404 = Not found (good, no finding)
        5. If file exists, create Finding with appropriate severity

        Why HEAD request?
        - GET downloads the entire file (slow, wastes bandwidth)
        - HEAD only fetches headers (fast, tells us if file exists)

        Returns: List of Finding objects for exposed files

        TODO: Implement this logic
        Hint:
            findings = []
            for path, severity, description in self.SENSITIVE_PATHS:
                url = self.base_url + path
                response = self.http_client.head(url)
                if response and response.status_code in [200, 403]:
                    # File exists! Create finding
                    finding = Finding(
                        title=f"Exposed File: {path}",
                        severity=severity,
                        description=description,
                        recommendation=f"Remove or restrict access to {path}"
                    )
                    findings.append(finding)
            return findings
        """
        findings = []
        for path, severity, description in self.SENSITIVE_PATHS:
            url = self.base_url + path
            response = self.http_client.head(url)
            if response and response.status_code in [200, 403]:
                finding = Finding(
                    title=f"Exposed File: {path}",
                    severity=severity,
                    description=description,
                    recommendation=f"Remove or restrict access to {path}"
                )
                findings.append(finding)
        return findings
