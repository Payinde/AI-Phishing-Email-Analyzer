# Portfolio Evidence

📄 **[Open or download the AI Phishing Email Analyzer Portfolio Report](https://raw.githubusercontent.com/Payinde/AI-Phishing-Email-Analyzer/main/evidence/AI_Phishing_Email_Analyzer_Portfolio_Report.pdf)**

This directory contains sanitized evidence demonstrating the development,
testing, and validation of the AI Phishing Email Analyzer.

## Recommended Evidence

- Streamlit interface overview
- Legitimate sample classified as Low risk
- Suspicious sample classified as Medium risk
- HMRC impersonation classified as High risk
- Microsoft password-expiration impersonation classified as High risk
- Outlook account-reactivation impersonation classified as High risk
- Local-AI explanation and fallback behavior
- Automated test suite showing all tests passed
- Sanitized downloadable JSON analysis report

## Validation Summary

Detection Engine v2 corrected three false-negative results:

| Test scenario | Initial result | Final result |
|---|---:|---:|
| HMRC refund impersonation | Low — 8 | High — 68 |
| Microsoft password expiration | Low — 13 | High — 88 |
| Outlook account reactivation | Low — 0 | High — 70 |

The final automated regression and AI-guardrail suite passed:

```text
Ran 13 tests in 0.005s

OK
```
