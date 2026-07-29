from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import numpy as np

app = FastAPI()

model = joblib.load("ml/phishing_model.pkl")

class URLRequest(BaseModel):
    url: str

@app.get("/")
def read_root():
    return {"status": "Phishing Detector API is running"}

@app.post("/scan")
def scan_url(request: URLRequest):
    
    dummy_features = np.zeros((1, 30))
    
    prediction_raw = model.predict(dummy_features)[0]
    
    confidence = model.predict_proba(dummy_features)[0].max()
    
    prediction_label = "legitimate" if prediction_raw == 1 else "phishing"
    
    return {
        "url": request.url,
        "prediction": prediction_label,
        "confidence": round(float(confidence), 4)
    }