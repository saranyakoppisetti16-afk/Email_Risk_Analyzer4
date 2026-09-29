# Email Risk Analyzer

## Overview
A Python-based email security tool that scans email headers and body text for common phishing and spoofing indicators.

## Objective
Identify:
- Phishing vectors
- Suspicious SPF/DKIM authentication results
- From/Return-Path spoofing mismatches
- Suspicious external links
- Urgent or threatening action language
- An overall phishing risk score

## Project Files
- `email_risk_analyzer.py` — Python source code.
- `phishing_analysis_report.pdf` — Sample phishing analysis report.

## How It Works
1. Parses raw email headers such as From, Return-Path, and Authentication-Results.
2. Extracts the email body.
3. Checks SPF and DKIM results.
4. Looks for external URLs.
5. Detects common urgency/action keywords.
6. Calculates a risk score from 0–100.
7. Classifies the result as Low, Medium, or High risk.

## Run
```bash
python email_risk_analyzer.py
```

## Sample Output
```text
=== EMAIL RISK ANALYZER ===
Risk Score: 95/100
Risk Level: HIGH

Indicators:
- From and Return-Path domains do not match.
- SPF authentication failed.
- DKIM authentication failed.
- External link detected: secure-login.example.org
- Urgency/action language: immediately, password, suspended, verify
```

## Report
The included `phishing_analysis_report.pdf` documents the sample email, detected indicators, risk contribution, findings, and recommended safe handling.

## Safety Note
This project is intended for defensive security education and analysis. The sample uses reserved example domains and does not access real accounts or live links.

## Submission
This README accompanies the Email Risk Analyzer Python script and Phishing Analysis Report PDF.
