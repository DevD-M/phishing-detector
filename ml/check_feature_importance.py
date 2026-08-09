import joblib
import numpy as np

model = joblib.load("ml/phishing_model.pkl")

feature_names = [
    "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//",
    "PrefixSuffix-", "SubDomains", "HTTPS", "DomainRegLen", "Favicon",
    "NonStdPort", "HTTPSDomainURL", "RequestURL", "AnchorURL",
    "LinksInScriptTags", "ServerFormHandler", "InfoEmail", "AbnormalURL",
    "WebsiteForwarding", "StatusBarCust", "DisableRightClick",
    "UsingPopupWindow", "IframeRedirection", "AgeofDomain", "DNSRecording",
    "WebsiteTraffic", "PageRank", "GoogleIndex", "LinksPointingToPage",
    "StatsReport"
]

importances = model.feature_importances_
ranked = sorted(zip(feature_names, importances), key=lambda x: -x[1])

print(f"{'Feature':<20} {'Importance':<10} {'Currently Hardcoded?'}")
print("-" * 55)
hardcoded = {"Favicon", "RequestURL", "AnchorURL", "LinksInScriptTags",
             "ServerFormHandler", "AbnormalURL", "WebsiteForwarding",
             "StatusBarCust", "DisableRightClick", "UsingPopupWindow",
             "IframeRedirection", "WebsiteTraffic", "PageRank",
             "GoogleIndex", "LinksPointingToPage"}

for name, imp in ranked:
    flag = "HARDCODED" if name in hardcoded else ""
    print(f"{name:<20} {imp:.4f}     {flag}")
