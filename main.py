from Scanner.analyzer import analyze_url, classify_threat

def generate_report(url, findings, threat_level):
    print(f"\n{'='*50}\n🔗 Scanning: {url}")
    print(f"🛡️ Threat Level: {threat_level.replace('_', ' ').title()}")

    if threat_level == "CLEAN":
        print("\n✅ This link is clean and legitimate.")
        return

    if threat_level == "MALICIOUS":
        print("\n🚨 This link is MALICIOUS because:")
        for issue in findings['critical']:
            print(f"  ✖ {issue}")

    if threat_level == "SUSPICIOUS":
        print("\n⚠ This link is SUSPICIOUS because:")
        for issue in findings['suspicious']:
            print(f"  • {issue}")

    if findings.get('warnings'):
        print("\n⚠ Security Notes:")
        for note in findings['warnings']:
            print(f"  ! {note}")

def main():
    print("🔍 Advanced Phishing URL Scanner")
    print("Enter URLs to scan (one per line). Type 'done' to finish.\n")

    urls = []
    while True:
        try:
            url = input("URL: ").strip()
            if url.lower() == 'done':
                break
            if url:
                urls.append(url)
        except (KeyboardInterrupt, EOFError):
            print("\nScan cancelled by user.")
            return

    if not urls:
        print("No URLs provided.")
        return

    print("\n=== Scan Results ===")
    for url in set(urls):
        findings = analyze_url(url)
        threat_level = classify_threat(findings)
        generate_report(url, findings, threat_level)

if __name__ == "__main__":
    main()
