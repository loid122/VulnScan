import React, { useState } from 'react';
import axios from 'axios';

function ScanForm({ onScanStarted }) {
  const [url, setUrl] = useState('');
  const [cookie, setCookie] = useState('');
  const [loading, setLoading] = useState(false);

  const startScan = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const res = await axios.post('http://localhost:5000/api/scan', {
        url,
        cookie: cookie.trim(),
      });
      onScanStarted(res.data.scanId);
    } catch (err) {
      alert('Error starting scan');
    }

    setLoading(false);
  };

  return (
    <form onSubmit={startScan}>
      <input
        type="text"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="Target URL (e.g., http://localhost/dvwa/vulnerabilities/sqli/?id=1)"
        required
      />

      <textarea
        value={cookie}
        onChange={(e) => setCookie(e.target.value)}
        placeholder="Paste cookies like: PHPSESSID=abc123; security=low"
        rows={3}
      />

      <button type="submit" disabled={loading}>
        {loading ? 'Scanning...' : 'Start Scan'}
      </button>
    </form>
  );
}

export default ScanForm;