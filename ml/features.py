import re
import socket
from urllib.parse import urlparse


def extract_features(url: str) -> list:
    """
    Extract 30 features from a URL to match the UCI phishing dataset.
    Returns a list of 30 values, each -1, 0, or 1.
    """
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    
    features = []

    # 1. UsingIP — is IP address used instead of domain name?
    try:
        socket.inet_aton(domain)
        features.append(-1)  # phishing
    except:
        features.append(1)   # legitimate

    # 2. LongURL — URL length
    length = len(url)
    if length < 54:
        features.append(1)
    elif length <= 75:
        features.append(0)
    else:
        features.append(-1)

    # 3. ShortURL — is it a URL shortener?
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'short.link']
    if any(s in url.lower() for s in shorteners):
        features.append(-1)
    else:
        features.append(1)

    # 4. Symbol@ — @ symbol in URL
    features.append(-1 if '@' in url else 1)

    # 5. Redirecting// — double slash after protocol
    features.append(-1 if '//' in path else 1)

    # 6. PrefixSuffix- — hyphen in domain
    features.append(-1 if '-' in domain else 1)

    # 7. SubDomains — number of subdomains
    dots = domain.count('.')
    if dots == 1:
        features.append(1)
    elif dots == 2:
        features.append(0)
    else:
        features.append(-1)

    # 8. HTTPS — uses HTTPS?
    features.append(1 if parsed.scheme == 'https' else -1)

    # 9. DomainRegLen — domain registration length (can't check without whois, default)
    features.append(-1)

    # 10. Favicon — assume legitimate (can't check without fetching page)
    features.append(1)

    # 11. NonStdPort — non-standard port used?
    port = parsed.port
    if port is None or port in [80, 443]:
        features.append(1)
    else:
        features.append(-1)

    # 12. HTTPSDomainURL — "https" in domain name (fake https)
    features.append(-1 if 'https' in domain.lower() else 1)

    # 13. RequestURL — assume legitimate
    features.append(1)

    # 14. AnchorURL — assume legitimate
    features.append(1)

    # 15. LinksInScriptTags — assume legitimate
    features.append(1)

    # 16. ServerFormHandler — assume legitimate
    features.append(1)

    # 17. InfoEmail — email address in URL?
    features.append(-1 if 'mailto:' in url.lower() else 1)

    # 18. AbnormalURL — domain in URL matches parsed domain?
    features.append(1)

    # 19. WebsiteForwarding — assume legitimate
    features.append(1)

    # 20. StatusBarCust — assume legitimate
    features.append(1)

    # 21. DisableRightClick — assume legitimate
    features.append(1)

    # 22. UsingPopupWindow — assume legitimate
    features.append(1)

    # 23. IframeRedirection — assume legitimate
    features.append(1)

    # 24. AgeofDomain — assume old domain (legitimate)
    features.append(1)

    # 25. DNSRecording — check if domain resolves
    try:
        socket.gethostbyname(domain)
        features.append(1)
    except:
        features.append(-1)

    # 26. WebsiteTraffic — assume legitimate (needs API)
    features.append(1)

    # 27. PageRank — assume legitimate (needs API)
    features.append(1)

    # 28. GoogleIndex — assume indexed (legitimate)
    features.append(1)

    # 29. LinksPointingToPage — assume legitimate
    features.append(1)

    # 30. StatsReport — suspicious keywords in domain?
    suspicious = ['secure', 'account', 'update', 'login', 'verify', 'bank', 'paypal']
    if any(kw in domain.lower() for kw in suspicious):
        features.append(-1)
    else:
        features.append(1)

    return features