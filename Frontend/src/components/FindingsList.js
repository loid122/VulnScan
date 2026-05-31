import React, { useEffect, useState } from 'react';
import axios from 'axios';

function FindingsList({ scanId }) {
  const [findings, setFindings] = useState([]);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const res = await axios.get(`http://localhost:5000/api/findings?scanId=${scanId}`);
        setFindings(res.data);
      } catch (err) {
        console.error(err);
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [scanId]);

  return (
    <div className="findings-container">
      <h2>Findings ({findings.length})</h2>
      <div className="findings-list">
        {findings.map(f => (
          <div key={f._id} onClick={() => setSelected(f)} className="finding-item">
            <strong>{f.type}</strong> - {f.param} on {f.url}
          </div>
        ))}
      </div>
      {selected && (
        <div className="finding-detail">
          <h3>Detail</h3>
          <p><b>Type:</b> {selected.type}</p>
          <p><b>Payload:</b> {selected.payload}</p>
          <p><b>Confidence:</b> {selected.confidence}</p>
          <p><b>Request:</b> <pre>{selected.request}</pre></p>
          <p><b>Response Snippet:</b> <pre>{selected.responseSnippet}</pre></p>
          {selected.screenshot && (
            <img src={`data:image/png;base64,${selected.screenshot}`} alt="Screenshot" style={{maxWidth: '100%'}} />
          )}
        </div>
      )}
    </div>
  );
}

export default FindingsList;
