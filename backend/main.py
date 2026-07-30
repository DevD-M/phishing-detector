from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy import text
import joblib
import numpy as np
from backend.database import get_connection
from fastapi.middleware.cors import CORSMiddleware

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
    # Dummy features for now
    dummy_features = np.zeros((1, 30))
    
    prediction_raw = model.predict(dummy_features)[0]
    confidence = model.predict_proba(dummy_features)[0].max()
    prediction_label = "legitimate" if prediction_raw == 1 else "phishing"
    
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
        "confidence": round(float(confidence), 4)
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