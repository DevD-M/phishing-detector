from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy import text
import joblib
import numpy as np
from backend.database import get_connection
from fastapi.middleware.cors import CORSMiddleware
from ml.features import extract_features
from backend.database import init_domain_cache_table
from ml.explain import explain_prediction

init_domain_cache_table()
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)
model = joblib.load("ml/phishing_model.pkl")


class URLRequest(BaseModel):
    url: str


@app.get("/")
def read_root():
    return {"status": "Phishing Detector API is running"}


@app.post("/scan")
def scan_url(request: URLRequest):
    features = extract_features(request.url)
    dummy_features = [features]
    prediction_raw = model.predict(dummy_features)[0]
    confidence = model.predict_proba(dummy_features)[0].max()
    prediction_label = "legitimate" if prediction_raw == 1 else "phishing"

    # Ask Claude to explain the prediction in plain English, grounded in
    # the actual computed feature values (not invented).
    explanation = explain_prediction(
        url=request.url,
        features=features,
        prediction=prediction_label,
        confidence=float(confidence) * 100
    )

    # Save to database
    with get_connection() as conn:
        conn.execute(text("""
            INSERT INTO scans (url, prediction, confidence)
            VALUES (:url, :prediction, :confidence)
        """), {
            "url": request.url,
            "prediction": prediction_label,
            "confidence": float(confidence)
        })
        conn.commit()

    return {
        "url": request.url,
        "prediction": prediction_label,
        "confidence": round(float(confidence), 4),
        "explanation": explanation
    }


@app.get("/scans")
def get_scans():
    with get_connection() as conn:
        result = conn.execute(text("SELECT * FROM scans ORDER BY scanned_at DESC"))
        rows = result.fetchall()

    return [
        {
            "id": row[0],
            "url": row[1],
            "prediction": row[2],
            "confidence": row[3],
            "scanned_at": str(row[4])
        }
        for row in rows
    ]


@app.delete("/scans/{scan_id}")
def delete_scan(scan_id: int):
    with get_connection() as conn:
        result = conn.execute(
            text("DELETE FROM scans WHERE id = :scan_id"),
            {"scan_id": scan_id}
        )
        conn.commit()

        if result.rowcount == 0:
            return {"error": f"No scan found with id {scan_id}"}

    return {"status": "deleted", "id": scan_id}

