# Project Context — Phishing URL Detector

## Stack
- ML: Python, scikit-learn, pandas
- Backend: FastAPI, PostgreSQL, SQLAlchemy
- Frontend: React

## Current Phase
COMPLETE ✅

## Completed
- [x] Git + GitHub setup
- [x] Python virtual environment
- [x] Dataset loaded and explored (11,054 URLs, 32 features)
- [x] Random Forest model trained — 96.9% accuracy, 97.6% recall
- [x] Model saved to ml/phishing_model.pkl
- [x] Feature extraction from raw URLs (ml/features.py — 30 features)
- [x] FastAPI backend (POST /scan, GET /scans)
- [x] PostgreSQL connected — scans table storing all results
- [x] React frontend — input box, result card, scan history table

## Files That Matter
- ml/exploration.ipynb — EDA and model training
- ml/phishing_model.pkl — saved trained model
- ml/features.py — 30-feature URL extraction function
- data/phishing.csv — dataset
- backend/main.py — FastAPI routes
- backend/database.py — PostgreSQL connection
- frontend/src/App.js — React UI

## Key Decisions Made
- Random Forest with 100 trees, random_state=42
- Prioritized Recall over Accuracy (security use case)
- Top features: HTTPS (32%), AnchorURL (25%)
- Class distribution: 6157 legitimate, 4897 phishing (mild imbalance, no special handling needed)
- CORS enabled for localhost:3000
- Features default to 1 (legitimate) for whois/traffic checks (not implemented)

## Known Limitations
- whois, PageRank, WebsiteTraffic features hardcoded — reduces accuracy on some URLs
- No authentication on API endpoints
- Model running locally only, not deployed

## Resume Line
Built end-to-end ML web app — Random Forest classifier (96.9% accuracy, 97.6% recall) with 30-feature URL extraction pipeline, FastAPI REST API, PostgreSQL CRUD, and React frontend.

## To Start Next Session
cd D:\Projects\phishing-detector
venv\Scripts\activate
uvicorn backend.main:app --reload  (terminal 1)
cd frontend && npm start           (terminal 2)