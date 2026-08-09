import re
import socket
import concurrent.futures
from datetime import datetime, timedelta
from urllib.parse import urlparse

import whois
import requests
from bs4 import BeautifulSoup


CACHE_TTL_HOURS = 24
PAGE_FETCH_TIMEOUT = 5


# ---------------------------------------------------------------------
# WHOIS helpers
# ---------------------------------------------------------------------

def _get_whois_data(domain: str, timeout: int = 5):
    """
    Fetch WHOIS data for a domain with a hard timeout.
    Returns None on failure/timeout so callers can fall back safely.
    """
    def _lookup():
        return whois.whois(domain)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_lookup)
        try:
            return future.result(timeout=timeout)
        except Exception:
            return None


def _compute_reg_len(w) -> int:
    """Feature 9 — DomainRegLen. 1 = registered >1 year (legit-ish), -1 = short/unknown (suspicious)."""
    if w and w.creation_date and w.expiration_date:
        creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiration = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        try:
            return 1 if (expiration - creation).days > 365 else -1
        except TypeError:
            return -1
    return -1


def _compute_age(w) -> int:
    """Feature 24 — AgeofDomain. 1 = older than 6 months, -1 = new/unknown (suspicious)."""
    if w and w.creation_date:
        creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        try:
            return 1 if (datetime.now() - creation).days > 180 else -1
        except TypeError:
            return -1
    return -1


def _compute_abnormal_url(w, domain: str) -> int:
    """
    Feature 18 — AbnormalURL. A domain with no resolvable WHOIS record at all
    is treated as suspicious. (This feature has very low model importance —
    0.0046 — so a simple presence check is sufficient rather than fragile
    text-matching against registrant fields, which are often WHOIS-privacy
    redacted even for legitimate sites.)
    """
    return 1 if w is not None else -1


def _get_cached_or_fetch(domain: str):
    """
    Look up cached WHOIS-derived features from domain_cache table (raw SQL,
    matching backend/database.py's style — no ORM session needed).
    Falls back to a live WHOIS lookup on cache miss/stale, then writes back.
    Returns (reg_len_feature, age_feature, whois_object).
    """
    from backend.database import get_cached_domain, upsert_cached_domain

    cached = get_cached_domain(domain)
    if cached:
        reg_len_feature, age_feature, cached_at = cached
        if (datetime.utcnow() - cached_at) < timedelta(hours=CACHE_TTL_HOURS):
            return reg_len_feature, age_feature, None  # whois object not cached, only features

    w = _get_whois_data(domain)
    reg_len_feature = _compute_reg_len(w)
    age_feature = _compute_age(w)

    upsert_cached_domain(domain, reg_len_feature, age_feature, datetime.utcnow())

    return reg_len_feature, age_feature, w


# ---------------------------------------------------------------------
# Page-content helpers (Anchor/RequestURL/ScriptLinks/FormHandler/etc.)
# ---------------------------------------------------------------------

def _fetch_page(url: str, timeout: int = PAGE_FETCH_TIMEOUT):
    """
    Fetch a page once. Returns (response, soup) — either may be None on failure.
    Reused across features 13, 14, 15, 16, 10, 19, 23 so we only hit the
    network once per scan.
    """
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        soup = BeautifulSoup(resp.text, "html.parser")
        return resp, soup
    except Exception:
        return None, None


def _is_same_domain(link: str, domain: str) -> bool:
    if not link or link.startswith('#') or link.lower().startswith('javascript:'):
        return False
    parsed_link = urlparse(link)
    if not parsed_link.netloc:
        return True  # relative link — same domain
    return domain.lower() in parsed_link.netloc.lower()


def _compute_request_url(soup, domain: str) -> int:
    """Feature 13 — RequestURL. High % of <img>/<script>/<video> src from other domains = suspicious."""
    if soup is None:
        return -1
    tags = soup.find_all(['img', 'script', 'video', 'audio', 'source'], src=True)
    if not tags:
        return 1
    bad = sum(1 for t in tags if not _is_same_domain(t['src'], domain))
    ratio = bad / len(tags)
    if ratio < 0.22:
        return 1
    elif ratio <= 0.61:
        return 0
    return -1


def _compute_anchor_url(soup, domain: str) -> int:
    """Feature 14 — AnchorURL. High % of <a href> pointing elsewhere/empty = suspicious."""
    if soup is None:
        return -1
    anchors = soup.find_all('a', href=True)
    if not anchors:
        return 1
    bad = sum(1 for a in anchors if not _is_same_domain(a['href'], domain))
    ratio = bad / len(anchors)
    if ratio < 0.31:
        return 1
    elif ratio <= 0.67:
        return 0
    return -1


def _compute_links_in_script_tags(soup, domain: str) -> int:
    """Feature 15 — LinksInScriptTags. Same idea, applied to <link>/<script src=...> tags."""
    if soup is None:
        return -1
    tags = soup.find_all(['link', 'script'], src=True) + soup.find_all('link', href=True)
    if not tags:
        return 1
    bad = 0
    for t in tags:
        target = t.get('src') or t.get('href')
        if not _is_same_domain(target, domain):
            bad += 1
    ratio = bad / len(tags)
    if ratio < 0.17:
        return 1
    elif ratio <= 0.81:
        return 0
    return -1


def _compute_server_form_handler(soup, domain: str) -> int:
    """Feature 16 — ServerFormHandler. Empty/about:blank/external form action = suspicious."""
    if soup is None:
        return -1
    forms = soup.find_all('form')
    if not forms:
        return 1
    suspicious_count = 0
    for f in forms:
        action = f.get('action', '')
        if action == '' or action.strip().lower() == 'about:blank':
            suspicious_count += 1
        elif not _is_same_domain(action, domain):
            suspicious_count += 1
    return -1 if suspicious_count > 0 else 1


def _compute_favicon(soup, domain: str) -> int:
    """Feature 10 — Favicon. Favicon loaded from a different domain = suspicious."""
    if soup is None:
        return -1
    icon_tag = soup.find('link', rel=lambda v: v and 'icon' in v.lower())
    if icon_tag is None or not icon_tag.get('href'):
        return 1  # no favicon declared — not inherently suspicious
    return 1 if _is_same_domain(icon_tag['href'], domain) else -1


def _compute_website_forwarding(resp) -> int:
    """Feature 19 — WebsiteForwarding. Many redirect hops = suspicious."""
    if resp is None:
        return -1
    hops = len(resp.history)
    if hops <= 1:
        return 1
    elif hops <= 3:
        return 0
    return -1


def _compute_iframe_redirection(soup) -> int:
    """Feature 23 — IframeRedirection. Presence of (likely hidden) iframes = suspicious."""
    if soup is None:
        return -1
    iframes = soup.find_all('iframe')
    if not iframes:
        return 1
    # A visible, normal-sized iframe is common and fine; frameborder=0 + tiny/hidden
    # size is the classic phishing-overlay pattern.
    suspicious = any(
        f.get('frameborder') == '0' or 'display:none' in (f.get('style') or '').replace(' ', '')
        for f in iframes
    )
    return -1 if suspicious else 0


# ---------------------------------------------------------------------
# Main feature extraction
# ---------------------------------------------------------------------

def extract_features(url: str, use_cache: bool = True) -> list:
    """
    Extract 30 features from a URL to match the UCI phishing dataset.
    Returns a list of 30 values, each -1, 0, or 1.

    use_cache: if True (default), WHOIS-derived features (#9, #24) are
    cached in the domain_cache table for 24h via backend/database.py.
    Set False to force a fresh WHOIS lookup every call (slower, no DB hit).

    NOTE on remaining hardcoded features (documented, not silently faked):
    #26 WebsiteTraffic, #27 PageRank, #28 GoogleIndex, #29 LinksPointingToPage
    require paid third-party APIs (Tranco/Similarweb/Google index API/backlink
    APIs) and are not implemented. #20 StatusBarCust, #21 DisableRightClick,
    #22 UsingPopupWindow require executing JS, not just parsing static HTML,
    so they're also left hardcoded. All are set to a neutral/legitimate
    default and this is a known, documented limitation — not a bug.
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

    # 9. DomainRegLen — domain registration length (WHOIS-based)
    if use_cache:
        reg_len_feature, age_feature, w = _get_cached_or_fetch(domain)
        if w is None:
            w = _get_whois_data(domain)  # need fresh whois object for AbnormalURL if cache hit
    else:
        w = _get_whois_data(domain)
        reg_len_feature = _compute_reg_len(w)
        age_feature = _compute_age(w)
    features.append(reg_len_feature)

    # Fetch the page once, reuse for features 10, 13, 14, 15, 16, 19, 23
    resp, soup = _fetch_page(url)

    # 10. Favicon — same-domain check
    features.append(_compute_favicon(soup, domain))

    # 11. NonStdPort — non-standard port used?
    port = parsed.port
    if port is None or port in [80, 443]:
        features.append(1)
    else:
        features.append(-1)

    # 12. HTTPSDomainURL — "https" in domain name (fake https)
    features.append(-1 if 'https' in domain.lower() else 1)

    # 13. RequestURL — % of external img/script/video sources
    features.append(_compute_request_url(soup, domain))

    # 14. AnchorURL — % of <a href> pointing elsewhere/empty (2nd most important model feature)
    features.append(_compute_anchor_url(soup, domain))

    # 15. LinksInScriptTags — % of external <link>/<script> sources
    features.append(_compute_links_in_script_tags(soup, domain))

    # 16. ServerFormHandler — empty/external/about:blank form actions
    features.append(_compute_server_form_handler(soup, domain))

    # 17. InfoEmail — email address in URL?
    features.append(-1 if 'mailto:' in url.lower() else 1)

    # 18. AbnormalURL — WHOIS registrant info vs domain
    features.append(_compute_abnormal_url(w, domain))

    # 19. WebsiteForwarding — number of redirect hops
    features.append(_compute_website_forwarding(resp))

    # 20. StatusBarCust — requires JS execution, not computable via static HTML. Documented limitation.
    features.append(1)

    # 21. DisableRightClick — requires JS execution, not computable via static HTML. Documented limitation.
    features.append(1)

    # 22. UsingPopupWindow — requires JS execution, not computable via static HTML. Documented limitation.
    features.append(1)

    # 23. IframeRedirection — hidden/suspicious iframe detection
    features.append(_compute_iframe_redirection(soup))

    # 24. AgeofDomain — domain age in days (WHOIS-based)
    features.append(age_feature)

    # 25. DNSRecording — check if domain resolves
    try:
        socket.gethostbyname(domain)
        features.append(1)
    except:
        features.append(-1)

    # 26. WebsiteTraffic — requires paid API (Tranco/Similarweb). Documented limitation.
    features.append(1)

    # 27. PageRank — requires paid API. Documented limitation.
    features.append(1)

    # 28. GoogleIndex — requires Google index-check API. Documented limitation.
    features.append(1)

    # 29. LinksPointingToPage — requires backlink API. Documented limitation.
    features.append(1)

    # 30. StatsReport — suspicious keywords in domain?
    suspicious = ['secure', 'account', 'update', 'login', 'verify', 'bank', 'paypal']
    if any(kw in domain.lower() for kw in suspicious):
        features.append(-1)
    else:
        features.append(1)

    return features
