from flask import Flask, render_template, request
from scanner import SecurityScanner

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')

    if not url:
        return render_template('error.html', message='Please provide a URL.')

    scanner = SecurityScanner(url)
    missing_headers, vulnerabilities = scanner.check_security_headers()

    if missing_headers:
        return render_template('scan_results.html', url=url, missing_headers=missing_headers, vulnerabilities=vulnerabilities)
    else:
        return render_template('scan_results.html', url=url, message='All security headers are present.')

if __name__ == '__main__':
    app.run(debug=True)
