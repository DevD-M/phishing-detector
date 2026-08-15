## Groq Model Migration (llama-3.1-8b-instant → gpt-oss-20b)

**Problem:** Same Groq deprecation (Aug 16, 2026) affected the LLM-based explainability layer (`ml/explain.py`) that generates plain-English reasons for phishing predictions.

**Why this solution:** Same reasoning as CollegeBot — drop-in replacement model on the same API, minimal migration risk under deadline pressure.

**Alternatives considered:** Removing the explainability feature entirely to sidestep migration work — rejected, since it's a differentiating feature of the project (turns a black-box prediction into a user-facing explanation).

**Implementation:**
- Located the single hardcoded reference in `ml/explain.py` line 84
- Swapped `model="llama-3.1-8b-instant"` → `model="openai/gpt-oss-20b"`
- Tested via `/scan` endpoint (FastAPI Swagger UI) — API returned 200 but `explanation` field was empty (`""`)

**Bug encountered & fix:** Empty explanation despite a successful API call (no exception raised). Added debug logging (`finish_reason`, raw content) and found `finish_reason: "length"` — the reasoning model was consuming the entire `max_tokens` budget on internal reasoning tokens, leaving nothing for the actual output. Fixed by setting `reasoning_effort="low"` in the API call, which reduces internal reasoning overhead for this simple 2-3 sentence summarization task, and kept `max_tokens=500`.

**Trade-offs:** Reasoning models add a new failure mode (silent empty output on `finish_reason: length`) that simpler instruct models don't have — worth monitoring token usage/finish_reason in production logging going forward.

**Interview questions:**
- What's the difference between a reasoning model and a standard instruct model in an API integration context?
- Describe a bug where the API call succeeded (200, no exception) but the output was still wrong — how did you debug it?