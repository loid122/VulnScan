import React, { useState } from 'react';
import ScanForm from './components/ScanForm';
import FindingsList from './components/FindingsList';
import './App.css';

function App() {
  const [scanId, setScanId] = useState(null);
  return (
    <div className="App">
      <h1>Vulnerability Scanner</h1>
      <ScanForm onScanStarted={setScanId} />
      {scanId && <FindingsList scanId={scanId} />}
    </div>
  );
}

export default App;
