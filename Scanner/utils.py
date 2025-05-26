import math

COMMON_BRANDS = {
    'facebook': ['faceb00k', 'facebok', 'fac3book', 'fb-login'],
    'paypal': ['paypa1', 'paypai'],
    'amazon': ['amaz0n', 'amzon', 'amz0n'],
    'google': ['g00gle', 'go0gle', 'googlee'],
    'microsoft': ['micr0soft', 'mircosoft', 'ms-login'],
    'netflix': ['netfl1x', 'netflixx', 'n3tflix'],
    'bank': ['b4nk', 'bankk', 'online-bank'],
    'apple': ['app1e', 'aple', 'apple-id']
}

SUSPICIOUS_TLDS = ['.buzz','.tk','.gq','.ml','.ga','.cf','.xyz','.top']
SENSITIVE_PATHS = ['login','verify','secure','account','confirm','password','update', 'malware', 'phishing']

def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    for char in set(text):
        p_x = float(text.count(char)) / len(text)
        entropy += - p_x * math.log(p_x, 2)
    return round(entropy, 2)

def check_typosquatting(domain):
    domain = domain.lower()
    for brand, variants in COMMON_BRANDS.items():
        if domain == f"www.{brand}.com" or domain == f"{brand}.com":
            return None
        for variant in variants:
            if variant in domain:
                return f"Brand impersonation ({variant} vs {brand})"
    return None
