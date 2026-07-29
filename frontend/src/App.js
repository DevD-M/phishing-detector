import { useState, useEffect } from "react";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(false);

  // Fetch scan history on page load
  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    const res = await fetch("http://localhost:8000/scans");
    const data = await res.json();
    setScans(data);
  };

  const handleScan = async () => {
    if (!url) return;
    setLoading(true);
    const res = await fetch("http://localhost:8000/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
    });
    const data = await res.json();
    setResult(data);
    setLoading(false);
    fetchScans(); // refresh history
  };

  return (
    <div style={{ maxWidth: "800px", margin: "40px auto", fontFamily: "Arial", padding: "0 20px" }}>
      
      <h1 style={{ textAlign: "center" }}>🛡️ Phishing URL Detector</h1>

      {/* Input Section */}
      <div style={{ display: "flex", gap: "10px", marginBottom: "20px" }}>
        <input
          type="text"
          placeholder="Enter URL to scan..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          style={{ flex: 1, padding: "10px", fontSize: "16px", borderRadius: "5px", border: "1px solid #ccc" }}
        />
        <button
          onClick={handleScan}
          disabled={loading}
          style={{ padding: "10px 20px", fontSize: "16px", backgroundColor: "#007bff", color: "white", border: "none", borderRadius: "5px", cursor: "pointer" }}
        >
          {loading ? "Scanning..." : "Scan"}
        </button>
      </div>

      {/* Result Card */}
      {result && (
        <div style={{
          padding: "20px",
          borderRadius: "8px",
          marginBottom: "30px",
          backgroundColor: result.prediction === "phishing" ? "#ffe0e0" : "#e0ffe0",
          border: `2px solid ${result.prediction === "phishing" ? "#ff4444" : "#44bb44"}`
        }}>
          <h2>{result.prediction === "phishing" ? "⚠️ Phishing Detected!" : "✅ Legitimate"}</h2>
          <p><strong>URL:</strong> {result.url}</p>
          <p><strong>Confidence:</strong> {(result.confidence * 100).toFixed(1)}%</p>
        </div>
      )}

      {/* Scan History */}
      <h2>Scan History</h2>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ backgroundColor: "#f0f0f0" }}>
            <th style={th}>ID</th>
            <th style={th}>URL</th>
            <th style={th}>Prediction</th>
            <th style={th}>Confidence</th>
            <th style={th}>Time</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id}>
              <td style={td}>{scan.id}</td>
              <td style={td}>{scan.url.length > 40 ? scan.url.substring(0, 40) + "..." : scan.url}</td>
              <td style={{ ...td, color: scan.prediction === "phishing" ? "red" : "green", fontWeight: "bold" }}>
                {scan.prediction}
              </td>
              <td style={td}>{(scan.confidence * 100).toFixed(1)}%</td>
              <td style={td}>{scan.scanned_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const th = { padding: "10px", border: "1px solid #ddd", textAlign: "left" };
const td = { padding: "8px", border: "1px solid #ddd" };

export default App;