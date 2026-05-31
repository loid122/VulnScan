const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { runScan } = require('./services/scanner');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Just a json file to store findings
const DATA_DIR = path.join(__dirname, 'data');
const FINDINGS_FILE = path.join(DATA_DIR, 'findings.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(FINDINGS_FILE)) fs.writeFileSync(FINDINGS_FILE, '[]');

function getFindings() {
  return JSON.parse(fs.readFileSync(FINDINGS_FILE));
}

function saveFinding(finding) {
  const findings = getFindings();
  finding._id = Date.now().toString(36) + Math.random().toString(36).substr(2);
  finding.createdAt = new Date().toISOString();
  findings.push(finding);
  fs.writeFileSync(FINDINGS_FILE, JSON.stringify(findings, null, 2));
}

// Internal backend endpoints of the tool to communicate
app.post('/api/scan', async (req, res) => {
  const { url, cookie } = req.body;         
  if (!url) return res.status(400).json({ error: 'Target URL required' });
  const scanId = Date.now().toString();
  runScan(scanId, url, saveFinding, cookie || '')
    .catch(err => console.error('Scan error:', err));
  res.json({ scanId, message: 'Scan started' });
});

app.get('/api/findings', (req, res) => {
  const { scanId } = req.query;
  const findings = getFindings().filter(f => !scanId || f.scanId === scanId);
  res.json(findings);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));