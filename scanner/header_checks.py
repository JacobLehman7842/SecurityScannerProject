"""
Security header analysis module.
Checks for presence and configuration of security-related HTTP headers.
"""

from utils.scoring import Finding, Severity


class HeaderChecker:
    """Analyzes HTTP response headers for security issues."""

    def __init__(self, response_headers: dict):
        self.headers = response_headers

    def check_all(self) -> list[Finding]:
        findings = []
        check_x_frame_options = self.check_x_frame_options()
        if check_x_frame_options:
            findings.append(check_x_frame_options)
        check_x_content_type_options = self.check_x_content_type_options()
        if check_x_content_type_options:
            findings.append(check_x_content_type_options)
        check_strict_transport_security = self.check_strict_transport_security()
        if check_strict_transport_security:
            findings.append(check_strict_transport_security)
        check_content_security_policy = self.check_content_security_policy()
        if check_content_security_policy:
            findings.append(check_content_security_policy)
        check_referrer_policy = self.check_referrer_policy()
        if check_referrer_policy:
            findings.append(check_referrer_policy)
        return findings
        

    def check_x_frame_options(self) -> Finding | None:
        header_value = self.headers.get("X-Frame-Options")
        if not header_value:
            return Finding(
                title="Missing X-Frame-Options Header",
                severity=Severity.MEDIUM,
                description="The X-Frame-Options header is not set, which allows this site to be embedded in iframes on other domains. This enables clickjacking attacks where attackers can overlay invisible buttons to trick users into performing unintended actions.",
                recommendation="Add 'X-Frame-Options: DENY' to prevent all framing, or 'X-Frame-Options: SAMEORIGIN' to allow framing only by the same domain."
            )
       

    def check_x_content_type_options(self) -> Finding | None:
        header_value = self.headers.get("X-Content-Type-Options")
        if not header_value:
            return Finding(
                title="Missing X-Content-Type-Options Header",
                severity=Severity.MEDIUM,
                description="The X-Content-Type-Options header is not set, allowing browsers to MIME-sniff responses. Attackers could upload files that appear harmless but contain executable code, which browsers might execute instead of treating as the declared content type.",
                recommendation="Add 'X-Content-Type-Options: nosniff' to prevent browsers from MIME-sniffing and force them to respect the declared Content-Type."
            )

    def check_strict_transport_security(self) -> Finding | None:
        header_value = self.headers.get("Strict-Transport-Security")
        if not header_value:
            return Finding(
                title="Missing Strict-Transport-Security Header",
                severity=Severity.HIGH,
                description="The Strict-Transport-Security (HSTS) header is not set. Without HSTS, users can be vulnerable to SSL stripping attacks where an attacker downgrades the connection from HTTPS to HTTP, allowing them to intercept sensitive data.",
                recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to force browsers to always use HTTPS for at least one year."
            )

    def check_content_security_policy(self) -> Finding | None:
        header_value = self.headers.get("Content-Security-Policy")
        if not header_value:
            return Finding(
                title="Missing Content-Security-Policy Header",
                severity=Severity.HIGH,
                description="The Content-Security-Policy (CSP) header is not set, leaving the site vulnerable to Cross-Site Scripting (XSS) attacks. Without CSP, browsers will execute any JavaScript found in the page, including malicious scripts injected by attackers.",
                recommendation="Add a Content-Security-Policy header such as \"default-src 'self'; script-src 'self' https://trusted-cdn.com\" to whitelist trusted sources and block malicious scripts."
            )

    def check_referrer_policy(self) -> Finding | None:
        header_value = self.headers.get("Referrer-Policy")
        if not header_value:
            return Finding(
                title="Missing Referrer-Policy Header",
                severity=Severity.LOW,
                description="The Referrer-Policy header is not set, which means the full URL (including sensitive query parameters) may be sent to external sites when users click links. This can leak sensitive information like session tokens, user IDs, or private data in URLs.",
                recommendation="Add 'Referrer-Policy: strict-origin-when-cross-origin' to control referrer information, or 'no-referrer' for maximum privacy."
            )
