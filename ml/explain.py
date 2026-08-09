import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# Human-readable names + a one-line meaning for each of the 30 features,
# in the same order extract_features() returns them.
FEATURE_INFO = [
    ("UsingIP", "URL uses a raw IP address instead of a domain name"),
    ("LongURL", "Overall URL length"),
    ("ShortURL", "URL was created with a link-shortening service"),
    ("Symbol@", "URL contains an '@' symbol"),
    ("Redirecting//", "URL has '//' redirection after the protocol"),
    ("PrefixSuffix-", "Domain contains a hyphen"),
    ("SubDomains", "Number of subdomains in the domain"),
    ("HTTPS", "URL uses HTTPS"),
    ("DomainRegLen", "Domain registration length (WHOIS)"),
    ("Favicon", "Favicon is loaded from the same domain"),
    ("NonStdPort", "URL uses a non-standard port"),
    ("HTTPSDomainURL", "The word 'https' appears inside the domain name itself (fake-https trick)"),
    ("RequestURL", "% of images/scripts/videos loaded from a different domain"),
    ("AnchorURL", "% of links on the page pointing elsewhere or nowhere"),
    ("LinksInScriptTags", "% of script/link tags pointing to a different domain"),
    ("ServerFormHandler", "Where login/contact forms on the page submit their data"),
    ("InfoEmail", "URL contains a mailto: link"),
    ("AbnormalURL", "Whether a WHOIS record exists for this domain at all"),
    ("WebsiteForwarding", "Number of redirects before reaching the final page"),
    ("StatusBarCust", "(not computed — requires JS execution)"),
    ("DisableRightClick", "(not computed — requires JS execution)"),
    ("UsingPopupWindow", "(not computed — requires JS execution)"),
    ("IframeRedirection", "Presence of hidden/suspicious iframes"),
    ("AgeofDomain", "Domain age (WHOIS)"),
    ("DNSRecording", "Domain resolves via DNS"),
    ("WebsiteTraffic", "(not computed — requires a paid traffic API)"),
    ("PageRank", "(not computed — requires a paid API)"),
    ("GoogleIndex", "(not computed — requires a search-index API)"),
    ("LinksPointingToPage", "(not computed — requires a backlink API)"),
    ("StatsReport", "Domain contains suspicious keywords like 'secure', 'login', 'verify'"),
]


def _summarize_features(url: str, features: list) -> str:
    """
    Turn the raw feature vector into a short readable list, skipping
    features that are neutral (0) or not actually computed, so Claude's
    prompt stays focused on real signals only.
    """
    lines = [f"URL: {url}"]
    for (name, meaning), value in zip(FEATURE_INFO, features):
        if "(not computed" in meaning:
            continue
        if value == 1:
            verdict = "OK"
        elif value == -1:
            verdict = "SUSPICIOUS"
        else:
            continue  # skip neutral/0 values, not informative enough
        lines.append(f"- {name} [{verdict}]: {meaning}")
    return "\n".join(lines)


def explain_prediction(url: str, features: list, prediction: str, confidence: float) -> str:
    """
    Calls Groq (free tier, LLaMA 3.1) to produce a short, plain-English
    explanation of why the model made this prediction, grounded in the
    actual computed features. Returns a fallback string if the API call
    fails for any reason.
    """
    feature_summary = _summarize_features(url, features)

    prompt = f"""A phishing-detection model analyzed this URL and made a prediction.

{feature_summary}

Model prediction: {prediction} (confidence: {confidence:.1f}%)

Each line above is already labeled [OK] or [SUSPICIOUS] — do not relabel or reinterpret them. In 2-3 short sentences, explain to a non-technical user why this URL was flagged as {prediction}. Only mention items actually marked [SUSPICIOUS] as red flags, and only mention items marked [OK] as reassuring signs. Do not invent details not present in the list. Be direct and concrete."""

    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            max_tokens=200,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"(Explanation unavailable: {str(e)})"
