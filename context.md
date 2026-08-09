# Project Context — Phishing URL Detector

## Stack
- ML: Python, scikit-learn, pandas
- Backend: FastAPI, PostgreSQL, SQLAlchemy
- Frontend: React
- Explainability: Groq API (LLaMA 3.1 8B, free tier)

## Current Status — COMPLETE ✅ (all 4 next-tasks from last cycle done)

## Completed (this cycle)
- [x] **Fixed false negatives / hardcoded features** — used `model.feature_importances_` to find that
      `AnchorURL` (25% importance, #2 overall) and 17 other features were hardcoded to a fixed
      "legitimate" value. Implemented real WHOIS-based features (`DomainRegLen`, `AgeofDomain`,
      `AbnormalURL`) with a timeout-wrapped, thread-pooled WHOIS lookup + 24h caching via a
      `domain_cache` Postgres table (raw SQL, matching existing `database.py` style — no ORM).
      Implemented real page-content features (`AnchorURL`, `RequestURL`, `LinksInScriptTags`,
      `ServerFormHandler`, `Favicon`, `WebsiteForwarding`, `IframeRedirection`) via a single reused
      BeautifulSoup page fetch per scan. Remaining hardcoded features (`WebsiteTraffic`, `PageRank`,
      `GoogleIndex`, `LinksPointingToPage`, `StatusBarCust`, `DisableRightClick`, `UsingPopupWindow`)
      are documented in-code as genuine limitations (need paid APIs or JS execution) — not silently faked.
      Verified fix: `paypal-secure-login.tk` flipped from 81-83% "legitimate" (wrong) to 91% "phishing" (correct).
- [x] **LLM explainability layer** — `ml/explain.py` calls Groq (not Anthropic — switched for cost reasons,
      staying free-tier while unemployed) to generate a 2-3 sentence plain-English explanation per prediction,
      grounded strictly in the actual computed feature values (prompt explicitly pins [OK]/[SUSPICIOUS] labels
      to prevent the 8B model from relabeling signals). Wired into `POST /scan` response as an `explanation`
      field. Displayed in the React result card. NOT currently persisted to DB (only live scan responses have it,
      scan history table does not show past explanations) — known gap, not yet prioritized.
- [x] **Delete endpoint** — `DELETE /scans/{id}` added to `backend/main.py`, wired to a Delete button per row
      in the React scan history table. CRUD is now complete (Create via `/scan`, Read via `/scans`, Delete via
      `/scans/{id}`; no Update — not a meaningful operation for scan records).
- [x] **README.md** — full rewrite covering architecture, tech stack, model performance, an "engineering
      decisions" section (feature-importance-driven debugging story, WHOIS timeout/caching design, cost-conscious
      LLM choice), and documented known limitations. Pushed to GitHub along with `requirements.txt`
      (generated via `pip freeze`, was previously missing).

## Files (updated)
- `ml/features.py` — 30-feature extractor, now ~15 features computed live (WHOIS + page-fetch) vs. mostly-hardcoded before
- `ml/explain.py` — Groq-based explanation layer (new)
- `backend/main.py` — `/scan`, `/scans`, `/scans/{id}` DELETE
- `backend/database.py` — raw-SQL `domain_cache` table helpers (`init_domain_cache_table`, `get_cached_domain`, `upsert_cached_domain`)
- `frontend/src/App.js` — explanation display in result card, Delete button in history table
- `README.md`, `requirements.txt` — new, pushed to GitHub

## To Start
Terminal 1: `cd D:\Projects\phishing-detector` → `venv\Scripts\activate` → `uvicorn backend.main:app --reload`
Terminal 2: `cd D:\Projects\phishing-detector\frontend` → `npm start`

## Known Issues / Gaps
- `explanation` field is not persisted to DB — scan history only shows past predictions, not past explanations
- 7 features remain intentionally hardcoded (documented in `features.py` docstring) — need paid APIs or headless
  browser (JS execution) to compute properly; not a near-term priority
- `anthropic` package still in `requirements.txt`/venv from the abandoned Anthropic-API attempt — harmless but
  could be `pip uninstall`ed for cleanliness
- venv folder was accidentally pushed to GitHub early on (harmless, noted previously)

## Next Tasks (not yet started — pick one when resuming)
1. **Resume update** — rewrite the phishing-detector bullet points with quantified outcomes from this cycle
   (e.g. "diagnosed and fixed a feature-engineering bug using model feature-importance analysis, flipping
   false-negative classification on test phishing URLs"; "built an LLM-grounded explainability layer using
   Groq API"). This was flagged as the top overall priority before this cycle started.

2. **Internship applications** — Internshala, LinkedIn, Wellfound, Twitter/X outreach — was top priority
   before this side-quest into feature.py started.


## Broader background (unchanged from before this cycle)
College resumes next week; transitioning from hostel to a flat. DSA (Stacks/Queues → Linked List next),
OS/CN prep (~45% complete), and CNN mini-project remain paused/backlogged during this internship-application
push. See prior conversation history / Claude's memory for full detail on those threads.