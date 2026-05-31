## VulnScan
An automated web vulnerability scanner built on the MERN stack (Node.js + React), designed to identify and verify common OWASP Top 10 vulnerabilities in both traditional and single‑page applications.


## Overview
VulnScanner is a fully automated security testing tool that crawls a web application, discovers injection points, and tests them for SQL Injection, Cross‑Site Scripting (reflected & stored), and Command Injection.
It provides detailed evidence – raw HTTP requests/responses, and screenshots with visual proof of exploitation – and uses an AI‑powered verification layer to reduce false positives.

The tool is built for educational purposes and works out‑of‑the‑box against deliberately vulnerable applications like DVWA, bWAPP, and OWASP Juice Shop.

## Key Features
Intelligent Crawling
Uses headless Chrome (Puppeteer) to render JavaScript‑heavy SPAs, extract forms, input fields, and query parameters (including hash‑fragment routes). Automatically discovers API endpoints by intercepting form submissions.

Multi‑Vector Testing
Supports SQL Injection (error‑based, boolean‑based, time‑based, login bypass), Reflected & Stored XSS (with unique per‑test markers), and Command Injection (echo‑based + time‑based).
Payloads are context‑aware, and detection relies on differential analysis (baseline vs. injection).

Visual Proof & Evidence
Every finding includes a screenshot captured at the moment of exploitation.
For XSS, the native alert() is overridden to display a distinct red banner – ensuring the screenshot always contains undeniable proof.

AI‑Powered Verification
Findings can be automatically verified using a multimodal LLM (via OpenRouter). The AI inspects the screenshot and response evidence to decide whether the vulnerability is genuine, adjusting confidence levels and adding explanatory comments.

Smart Test Orchestration
Once a vulnerability is discovered on a given page, subsequent test types for that page are skipped – saving time and reducing noise.

Simple Storage
All findings are stored in a local JSON file (no database required), making the tool lightweight and easy to set up.

## Technology Stack
Layer	Technology
Backend	Node.js, Express, Puppeteer, Cheerio, Axios, sharp
Frontend	React (Create React App), Axios
AI	OpenRouter (Gemini Flash, GPT‑4o‑mini, etc.)
Storage	Local JSON file
## How It Works
User Input – via the React UI, you provide a target URL and an optional session cookie.

Crawling Phase – Puppeteer renders the page; Cheerio extracts forms, input fields, and links. Hash‑based SPAs are fully supported.

Injection Point Discovery – each parameter is treated as a potential injection point, with other fields filled with realistic defaults (including submit buttons).

Vulnerability Testing – the scanner sequentially tests SQLi, stored XSS, reflected XSS, and command injection. Unique markers guarantee no cross‑contamination.

Evidence Collection – successful exploits trigger a screenshot (with a visible alert banner for XSS) and capture the raw HTTP request/response.

AI Verification (optional) – after the scan, an LLM reviews each finding and updates its confidence.

Results – findings are displayed in real‑time on the dashboard, with expandable evidence and AI verdicts.

## Ideal Use Cases
CTF practice & security training – scan DVWA, bWAPP, or Juice Shop to understand how vulnerabilities are detected and exploited.

Demo / portfolio project – showcase full‑stack development, browser automation, and AI integration skills.

Basis for a custom scanner – easily extendable with new OWASP categories (e.g., file inclusion, IDOR) by adding a new test module.

## Setup & Run
bash
```
# Backend
cd backend && npm install
node server.js

# Frontend (in another terminal)
cd frontend && npm install && npm start

# Optionally start a vulnerable target
docker run -d -p 80:80 vulnerables/web-dvwa
```
Then open http://localhost:3000, enter the target URL (e.g., http://localhost/vulnerabilities/sqli/), provide a session cookie, and start scanning.

VulnScanner demonstrates that modern web vulnerability scanning – often seen as complex enterprise software – can be built from scratch with a few open‑source libraries, a clear architecture, and an optional AI safety net.
