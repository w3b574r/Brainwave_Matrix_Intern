import re
import tldextract
from urllib.parse import urlparse
from collections import defaultdict
from .utils import calculate_entropy, check_typosquatting, SUSPICIOUS_TLDS, SENSITIVE_PATHS

def analyze_url(url):
    findings = defaultdict(list)

    try:
        if not url.startswith(('http://', 'https://', 'www')):
            url = 'http://' + url

        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path.lower()
        ext = tldextract.extract(url)

        ts_result = check_typosquatting(domain)
        if ts_result:
            findings['critical'].append(ts_result)

        if any(tld in domain for tld in SUSPICIOUS_TLDS):
            findings['critical'].append(f"Suspicious TLD ({ext.suffix})")

        if re.match(r'^(\d{1,3}\.){3}\d{1,3}', domain):
            findings['critical'].append("Uses IP address instead of domain")

        if any(keyword in path for keyword in SENSITIVE_PATHS):
            findings['suspicious'].append(f"Sensitive path detected ({path})")

        if '-login.' in domain or '-secure.' in domain:
            findings['suspicious'].append("Suspicious subdomain structure")

        entropy = calculate_entropy(ext.domain)
        if entropy > 3.5:
            findings['suspicious'].append(f"High domain entropy ({entropy})")

        if parsed.scheme != 'https':
            findings['warnings'].append("No HTTPS encryption")

        if len(path) > 60:
            findings['warnings'].append("Unusually long URL path")

    except Exception as e:
        findings['errors'].append(f"Analysis error: {str(e)}")

    return findings

def classify_threat(findings):
    if findings.get('critical'):
        return "MALICIOUS"
    elif findings.get('suspicious'):
        return "SUSPICIOUS"
    elif findings.get('warnings'):
        return "LOW_RISK"
    else:
        return "CLEAN"
