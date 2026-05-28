# Project Context — Phishing URL Detector

## Stack
- ML: Python, scikit-learn, pandas
- Backend: FastAPI, PostgreSQL, SQLAlchemy
- Frontend: React

## Current Phase
Phase 2 — FastAPI Backend

## Completed
- [x] Git + GitHub setup
- [x] Python virtual environment
- [x] Dataset loaded and explored (11,054 URLs, 32 features)
- [x] Random Forest model trained — 96.9% accuracy, 97.6% recall
- [x] Model saved to ml/phishing_model.pkl
- [ ] Feature extraction from raw URLs
- [ ] FastAPI backend
- [ ] PostgreSQL connected
- [ ] React frontend

## Files That Matter
- ml/exploration.ipynb — EDA and model training
- ml/phishing_model.pkl — saved trained model
- data/phishing.csv — dataset

## Key Decisions Made
- Random Forest with 100 trees, random_state=42
- Prioritized Recall over Accuracy (security use case)
- Top features: HTTPS (32%), AnchorURL (25%)
- Class distribution: 6157 legitimate, 4897 phishing (mild imbalance, no special handling needed)

## Where I Left Off
Phase 1 complete. Starting Phase 2 — FastAPI backend.
Next: Install FastAPI, create main.py, build POST /scan endpoint that loads the model and returns predictions.

## To Start Next Session
cd D:\Projects\phishing-detector
venv\Scripts\activate