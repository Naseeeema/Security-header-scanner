import requests

class SecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()

    def check_security_headers(self):
        response = self.session.get(self.target_url)
        headers = response.headers

        missing_headers = []
        vulnerabilities = {}

        # Check for Content-Security-Policy header
        if 'Content-Security-Policy' not in headers:
            missing_headers.append('Content-Security-Policy')
            vulnerabilities['Content-Security-Policy'] = 'Cross-Site Scripting (XSS) attacks may be possible without a Content-Security-Policy.'

        # Check for X-Frame-Options header
        if 'X-Frame-Options' not in headers:
            missing_headers.append('X-Frame-Options')
            vulnerabilities['X-Frame-Options'] = 'Clickjacking attacks may be possible without X-Frame-Options protection.'

        # Check for X-Content-Type-Options header
        if 'X-Content-Type-Options' not in headers:
            missing_headers.append('X-Content-Type-Options')
            vulnerabilities['X-Content-Type-Options'] = 'MIME-sniffing attacks may be possible without X-Content-Type-Options protection.'

        # Check for Referrer-Policy header
        if 'Referrer-Policy' not in headers:
            missing_headers.append('Referrer-Policy')
            vulnerabilities['Referrer-Policy'] = 'Referrer information leakage may occur without Referrer-Policy protection.'

        # Check for Permissions-Policy header
        if 'Permissions-Policy' not in headers:
            missing_headers.append('Permissions-Policy')
            vulnerabilities['Permissions-Policy'] = 'Various security-related policies may not be enforced without Permissions-Policy protection.'

        return missing_headers, vulnerabilities

    def run_scan(self):
        missing_headers, vulnerabilities = self.check_security_headers()

        if missing_headers:
            print(f"Missing security headers for {self.target_url}: {', '.join(missing_headers)}")
            for header in missing_headers:
                print(f"Vulnerability if {header} is missing: {vulnerabilities[header]}")
        else:
            print(f"All security headers are present for {self.target_url}")
