import { useState } from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid
} from "recharts";

function App() {
  const [output, setOutput] = useState("");
  const [files, setFiles] = useState([]);
  const [alerts, setAlerts] = useState({});
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [expanded, setExpanded] = useState({});
  const [showHelp, setShowHelp] = useState(false);

  const toggleSection = (file, section) => {
    setExpanded((prev) => ({
      ...prev,
      [file]: {
        ...(prev[file] || {}),
        [section]: !prev[file]?.[section]
      }
    }));
  };

  const getEffectiveSeverity = (baseSeverity, count) => {
    if (count > 50) return "high";
    if (count > 10) return "medium";
    return baseSeverity;
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "high": return "#ff4d4d";
      case "medium": return "#ffa500";
      case "low": return "#4caf50";
      default: return "#ccc";
    }
  };

  const explanationMap = {
    rare_destinations: { title: "Rare Destination", severity: "low", explanation: "Device contacted an uncommon destination.", details: ["Unusual routing", "Misconfiguration", "Recon activity"], actions: ["Verify destination", "Check host", "Review logs"] },
    unusual_ports: { title: "Unusual Ports", severity: "medium", explanation: "Traffic using uncommon ports.", details: ["Hidden services", "Misconfiguration", "Firewall bypass"], actions: ["Identify service", "Validate usage", "Restrict ports"] },
    port_scans: { title: "Port Scan", severity: "high", explanation: "Multiple ports scanned rapidly.", details: ["Recon", "Attack prep", "Vulnerability discovery"], actions: ["Block source", "Rate limit", "Investigate origin"] },
    traffic_spikes: { title: "Traffic Spikes", severity: "medium", explanation: "Sudden increase in traffic.", details: ["Exfiltration", "Malware", "Brute force"], actions: ["Inspect host", "Analyze traffic", "Limit activity"] },
    plaintext_credentials: { title: "Plaintext Credentials", severity: "high", explanation: "Credentials sent unencrypted.", details: ["HTTP login", "Basic auth"], actions: ["Use HTTPS", "Rotate credentials"] },
    tokens_in_url: { title: "Tokens in URL", severity: "medium", explanation: "Sensitive tokens in URLs.", details: ["Session leaks", "API exposure"], actions: ["Move tokens", "Invalidate tokens"] },
    weak_tls: { title: "Weak TLS", severity: "medium", explanation: "Outdated TLS detected.", details: ["TLS 1.0/1.1", "Weak ciphers"], actions: ["Upgrade TLS", "Disable weak ciphers"] },
    tracker_domains: { title: "Tracker Domains", severity: "low", explanation: "Tracking domains detected.", details: ["User tracking", "Analytics"], actions: ["Block trackers"] }
  };

  const buildChartData = () => {
    const totals = {};
    Object.values(alerts).forEach((fileData) => {
      const all = { ...(fileData?.intrusion || {}), ...(fileData?.privacy || {}) };
      Object.entries(all).forEach(([cat, data]) => {
        if (!data || data.count === 0) return;
        totals[cat] = (totals[cat] || 0) + data.count;
      });
    });
    return Object.entries(totals).map(([cat, count]) => ({
      name: explanationMap[cat]?.title || cat,
      value: count
    }));
  };

  const buildPerFileChartData = () => {
    return files.map((file) => {
      const fileData = alerts[file] || {};
      const all = { ...(fileData.intrusion || {}), ...(fileData.privacy || {}) };
      let total = 0;
      Object.values(all).forEach((d) => {
        if (d && d.count) total += d.count;
      });
      return { name: file, alerts: total };
    });
  };

  const chartColors = ["#4caf50", "#ffa500", "#ff4d4d", "#8884d8", "#82ca9d", "#ffc658"];

  const runScript = async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/run");
      const data = await res.json();
      setOutput(data.message || "");
      setFiles(data.files_processed || []);
      setAlerts(data.alerts || {});
      setSelectedAlert(null);
    } catch (err) {
      setOutput(err.toString());
    }
  };

  const uploadFiles = async () => {
    const formData = new FormData();
    for (let i = 0; i < selectedFiles.length; i++) {
      formData.append("files", selectedFiles[i]);
    }
    try {
      const res = await fetch("http://127.0.0.1:8000/upload", { method: "POST", body: formData });
      const data = await res.json();
      setOutput("Uploaded:\n- " + data.uploaded_files.join("\n- "));
    } catch {
      setOutput("Upload failed");
    }
  };

  const buttonStyle = {
    background: "#2a2a2a",
    color: "#fff",
    borderRadius: "8px",
    border: "1px solid #444",
    padding: "8px 12px",
    cursor: "pointer"
  };

  return (
    <div style={{ background: "#1e1e1e", minHeight: "100vh", color: "#f5f5f5" }}>

      <div style={{ background: "#0f3d2e", padding: "15px", textAlign: "center", fontSize: "28px", fontWeight: "bold", position: "relative" }}>
        <button
          onClick={() => setShowHelp(true)}
          style={{
            position: "absolute",
            left: "15px",
            top: "50%",
            transform: "translateY(-50%)",
            background: "#145c44",
            color: "#fff",
            borderRadius: "50%",
            width: "30px",
            height: "30px",
            border: "none",
            cursor: "pointer"
          }}
        >
          ?
        </button>
        BubbleSec
      </div>

      {showHelp && (
        <div
          onClick={() => setShowHelp(false)}
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            width: "100%",
            height: "100%",
            background: "rgba(0,0,0,0.7)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center"
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              background: "#2a2a2a",
              padding: "20px",
              borderRadius: "10px",
              maxWidth: "500px"
            }}
          >
            <h2>Instructions</h2>
            <p>
              First, you must use software like Wireshark to create captures of your network. 
              Example PCAP files are provided in na_dashboard/zeek-monitor/pcaps.
            </p>
            <p>
              Upload your files using: "Choose Files" → "Upload" → "Run Analysis".
              You may upload multiple files at once.
            </p>
            <p>
              After running analysis, use the middle section to explore alerts for each file.
            </p>
            <p>
              On the right, graphs summarize the data and explanations appear below when alerts are clicked.
            </p>
            <button style={buttonStyle} onClick={() => setShowHelp(false)}>Close</button>
          </div>
        </div>
      )}

      <div style={{ display: "flex", padding: "20px", gap: "20px" }}>

        <div style={{ width: "300px" }}>
          <h2>Upload PCAPs</h2>

          <label style={buttonStyle}>
            Choose Files
            <input
              type="file"
              multiple
              onChange={(e) => setSelectedFiles(e.target.files)}
              style={{ display: "none" }}
            />
          </label>

          <br /><br />

          <button style={buttonStyle} onClick={uploadFiles}>Upload</button>
          <br /><br />
          <button style={buttonStyle} onClick={runScript}>Run Analysis</button>

          <h3>Output:</h3>
          <pre>{output}</pre>
        </div>

        <div style={{ flex: 1.5 }}>
          <h2>Processed Files</h2>
          {files.map((file) => {
            const fileAlerts = alerts[file] || {};
            return (
              <div key={file} style={{ border: "1px solid #444", borderRadius: "10px", padding: "10px", marginBottom: "15px", background: "#2a2a2a" }}>
                <strong>{file}</strong>

                <div onClick={() => toggleSection(file, "intrusion")} style={{ cursor: "pointer", display: "flex", gap: "5px" }}>
                  <span style={{ transform: expanded[file]?.intrusion ? "rotate(90deg)" : "rotate(0deg)", transition: "0.2s" }}>▶</span>
                  Intrusion
                </div>

                {expanded[file]?.intrusion && (
                  <div style={{ marginLeft: "15px" }}>
                    {Object.entries(fileAlerts.intrusion || {}).map(([cat, d]) => {
                      if (!d || d.count === 0) return null;
                      const info = explanationMap[cat];
                      const severity = getEffectiveSeverity(info.severity, d.count);
                      return (
                        <div key={cat} style={{ color: getSeverityColor(severity), cursor: "pointer" }} onClick={() => setSelectedAlert(cat)}>
                          {info.title} ({d.count})
                        </div>
                      );
                    })}
                  </div>
                )}

                <div onClick={() => toggleSection(file, "privacy")} style={{ cursor: "pointer", display: "flex", gap: "5px" }}>
                  <span style={{ transform: expanded[file]?.privacy ? "rotate(90deg)" : "rotate(0deg)", transition: "0.2s" }}>▶</span>
                  Privacy
                </div>

                {expanded[file]?.privacy && (
                  <div style={{ marginLeft: "15px" }}>
                    {Object.entries(fileAlerts.privacy || {}).map(([cat, d]) => {
                      if (!d || d.count === 0) return null;
                      const info = explanationMap[cat];
                      const severity = getEffectiveSeverity(info.severity, d.count);
                      return (
                        <div key={cat} style={{ color: getSeverityColor(severity), cursor: "pointer" }} onClick={() => setSelectedAlert(cat)}>
                          {info.title} ({d.count})
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        <div style={{ flex: 1.5 }}>
          <h2>Insights</h2>

          <PieChart width={300} height={300}>
            <Pie data={buildChartData()} dataKey="value" nameKey="name" outerRadius={100}>
              {buildChartData().map((_, i) => <Cell key={i} fill={chartColors[i % chartColors.length]} />)}
            </Pie>
            <Tooltip />
            <Legend />
          </PieChart>

          <BarChart width={400} height={300} data={buildPerFileChartData()}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" stroke="#fff" />
            <YAxis stroke="#fff" />
            <Tooltip />
            <Bar dataKey="alerts" fill="#8884d8" />
          </BarChart>

          <div style={{ marginTop: "20px", padding: "10px", background: "#2a2a2a" }}>
            <h3>Explanation</h3>
            {!selectedAlert ? (
              <p>Select an alert to view details.</p>
            ) : (
              (() => {
                const info = explanationMap[selectedAlert];
                return (
                  <div>
                    <h3>{info.title}</h3>
                    <p>{info.explanation}</p>
                    <ul>{info.details.map((d, i) => <li key={i}>{d}</li>)}</ul>
                    <ul>{info.actions.map((a, i) => <li key={i}>{a}</li>)}</ul>
                  </div>
                );
              })()
            )}
          </div>
        </div>

      </div>
    </div>
  );
}

export default App;