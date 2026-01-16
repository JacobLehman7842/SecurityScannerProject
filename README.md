# Security Scanner

A web vulnerability scanner built for educational purposes. Scans websites for common security misconfigurations and exposed sensitive files.

## Features

### Security Header Analysis
Checks for the presence of critical security headers:
- **X-Frame-Options** - Prevents clickjacking attacks
- **X-Content-Type-Options** - Prevents MIME-sniffing attacks
- **Strict-Transport-Security (HSTS)** - Enforces HTTPS connections
- **Content-Security-Policy (CSP)** - Mitigates XSS attacks
- **Referrer-Policy** - Controls referrer information leakage

### Sensitive File Detection
Scans for commonly exposed files that should be protected:
- `.git/config` and `.git/HEAD` - Git repository exposure
- `.env` - Environment variables with secrets
- `config.php`, `wp-config.php` - Configuration files
- `backup.sql`, `dump.sql` - Database backups
- `.htaccess` - Apache configuration
- `robots.txt` - Information disclosure

### User Interface
- Modern GUI built with CustomTkinter
- Real-time scan progress tracking
- Color-coded findings by severity (Critical, High, Medium, Low, Info)
- Detailed descriptions and remediation recommendations
- Ethical scanning authorization prompts

## Installation

### Prerequisites
- Python 3.10+
- pip

### Setup

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/SecurityScanner.git
cd SecurityScanner
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### GUI Application
Run the main application:
```bash
python main.py
```

1. Enter a target URL (e.g., `https://example.com`)
2. Confirm you have authorization to scan the target
3. Click "Start Scan"
4. View findings organized by severity

### Command Line Testing
Test scanner functionality:
```bash
python test_scanner.py
```

## Project Structure

```
SecurityScannerProject/
├── gui/
│   ├── app.py           # Main application window
│   └── components.py    # Reusable UI components
├── scanner/
│   ├── core.py          # Scan orchestration
│   ├── header_checks.py # Security header analysis
│   └── file_checks.py   # Sensitive file detection
├── utils/
│   ├── http_client.py   # HTTP request handling
│   └── scoring.py       # Finding severity classification
├── main.py              # Application entry point
└── requirements.txt     # Python dependencies
```

## Ethical Use

⚠️ **IMPORTANT: Only scan websites you own or have explicit written permission to test.**

- Unauthorized scanning is illegal and unethical
- This tool is for educational purposes and authorized security testing only
- Always obtain written permission before scanning any target
- Use on intentionally vulnerable training sites (DVWA, WebGoat, HackTheBox)

## Example Output

**Well-Secured Site (e.g., GitHub):**
- Few or no missing headers
- Properly configured security controls
- Only informational findings (robots.txt)

**Poorly-Secured Site (e.g., example.com):**
- Missing security headers (5+ findings)
- Potential for clickjacking, XSS, SSL stripping
- Missing HTTPS enforcement

## Technical Details

### Threading
Scans run in background threads to keep the GUI responsive during long-running operations.

### HTTP Requests
- Uses `requests` library with proper timeout handling
- HEAD requests for file existence checks (efficient, no body download)
- GET requests for header analysis
- Comprehensive error handling for network issues

### Finding Severity Levels
- **Critical** - Immediate risk (exposed secrets, source code)
- **High** - Significant vulnerability (missing CSP, HSTS)
- **Medium** - Important security control missing (X-Frame-Options)
- **Low** - Minor issue (referrer policy)
- **Info** - Informational (robots.txt present)

## Learning Outcomes

This project demonstrates:
- Python GUI development with CustomTkinter
- HTTP client programming with error handling
- Web security concepts and headers
- Threading for responsive applications
- Project structure and modular design
- Security scanning methodology

## Future Enhancements

Potential additions:
- XSS (Cross-Site Scripting) detection
- SQL injection testing
- SSL/TLS configuration analysis
- Port scanning
- Export scan results to JSON/PDF
- Scan scheduling and automation

## License

This project is for educational purposes only.

## Acknowledgments

Built as a learning project to understand web security vulnerabilities and ethical hacking practices.
