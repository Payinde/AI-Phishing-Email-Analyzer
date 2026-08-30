import json
from datetime import datetime, timezone

import streamlit as st

from analyzer import analyze_email
from ai_explainer import explain_analysis


st.set_page_config(
    page_title="AI Phishing Email Analyzer",
    page_icon="🛡️",
    layout="wide",
)


SAMPLE_EMAILS = {
    "Legitimate — Low risk": """
From: HR Department <hr@example.test>
Subject: Updated holiday schedule

Hello team,

The updated holiday schedule is available on the internal
employee portal.

Please contact Human Resources if you have any questions.

Regards,
HR Department

This is a safe, synthetic training sample.
""",

    "Suspicious — Medium risk": """
From: Account Support <support@example.test>
Subject: Unusual activity detected

We detected unusual activity on your account.

Confirm your identity to review the activity. Click here:
https://account-review.example.test/login

This is a safe, synthetic training sample.
""",

    "Phishing simulation — High risk": """
From: Security Team <security@example.test>
Subject: Urgent account verification required

URGENT: Verify your account immediately to prevent suspension.

Click here:
http://192.0.2.10/update.exe

This is a safe, synthetic training sample.
""",
}


st.title("🛡️ AI Phishing Email Analyzer")

st.caption(
    "Rule-based phishing detection with an optional "
    "guardrailed local-AI explanation."
)

st.info(
    "Training tool only. Use sanitized email content and "
    "validate all automated findings manually."
)


input_mode = st.radio(
    "Choose an email input method",
    options=[
        "Built-in test sample",
        "Paste custom email",
        "Upload sanitized file",
    ],
    horizontal=True,
)


if input_mode == "Built-in test sample":
    selected_sample = st.selectbox(
        "Select a test scenario",
        options=list(SAMPLE_EMAILS.keys()),
        index=2,
    )

    initial_email = SAMPLE_EMAILS[selected_sample]
    input_key = f"sample_{selected_sample}"

elif input_mode == "Upload sanitized file":
    uploaded_file = st.file_uploader(
        "Upload a sanitized email",
        type=["txt", "eml"],
        help="Supported formats: .txt and .eml",
    )

    if uploaded_file is not None:
        initial_email = uploaded_file.getvalue().decode(
            "utf-8",
            errors="replace",
        )

        input_key = f"upload_{uploaded_file.name}"

    else:
        initial_email = ""
        input_key = "upload_empty"

else:
    initial_email = ""
    input_key = "custom_email"


email_text = st.text_area(
    "Email content",
    value=initial_email,
    height=300,
    key=input_key,
    help=(
        "Use sanitized headers and body text. "
        "Do not submit confidential information."
    ),
)


use_local_ai = st.toggle(
    "Generate a guardrailed local-AI explanation with Ollama",
    value=True,
)


if st.button(
    "Analyze Email",
    type="primary",
    use_container_width=True,
):
    if not email_text.strip():
        st.warning(
            "Enter, select, or upload email content "
            "before analysis."
        )

        st.stop()

    result = analyze_email(
        email_text
    )

    st.subheader(
        "Risk assessment"
    )

    risk_column, score_column, sender_column = st.columns(3)

    risk_column.metric(
        "Risk level",
        result["risk_level"],
    )

    score_column.metric(
        "Risk score",
        f'{result["score"]}/100',
    )

    sender_column.metric(
        "Sender domain",
        result["sender_domain"] or "Not detected",
    )

    st.progress(
        result["score"] / 100
    )

    if result["risk_level"] == "High":
        st.error(
            "High-risk indicators detected. "
            "Escalate for analyst review."
        )

    elif result["risk_level"] == "Medium":
        st.warning(
            "Suspicious indicators detected. "
            "Further review is required."
        )

    elif result["score"] == 0:
        st.success(
            "No configured suspicious indicators were detected."
        )

    else:
        st.success(
            "Low-scoring indicators were detected. "
            "Manual validation is still recommended."
        )

    st.subheader(
        "Detected indicators"
    )

    if result["indicators"]:
        display_indicators = [
            {
                "Category": item["category"],
                "Evidence": item["detail"],
                "Points": item["points"],
            }
            for item in result["indicators"]
        ]

        st.dataframe(
            display_indicators,
            use_container_width=True,
            hide_index=True,
        )

    else:
        st.write(
            "No configured indicators were detected."
        )

    st.subheader(
        "Extracted URLs"
    )

    if result["urls"]:
        for url in result["urls"]:
            st.code(
                url,
                language=None,
            )

    else:
        st.write(
            "No HTTP or HTTPS URLs were extracted."
        )

    ai_explanation = (
        "Local-AI explanation was not requested."
    )

    if use_local_ai:
        st.subheader(
            "Guardrailed local-AI explanation"
        )

        with st.spinner(
            "Generating a constrained explanation "
            "with qwen2.5:1.5b..."
        ):
            ai_explanation = explain_analysis(
                result
            )

        st.text(
            ai_explanation
        )

    report = {
        "report_title": "AI Phishing Email Analysis",
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "risk_level": result["risk_level"],
        "risk_score": result["score"],
        "sender_domain": (
            result["sender_domain"] or None
        ),
        "indicators": result["indicators"],
        "extracted_urls": result["urls"],
        "local_ai_enabled": use_local_ai,
        "explanation": ai_explanation,
        "disclaimer": (
            "Automated findings require human analyst validation."
        ),
    }

    report_json = json.dumps(
        report,
        indent=2,
    )

    st.subheader(
        "Export analysis"
    )

    st.download_button(
        label="Download JSON report",
        data=report_json,
        file_name="phishing_email_analysis_report.json",
        mime="application/json",
        use_container_width=True,
    )

    st.caption(
        "The exported report excludes the raw email body "
        "to reduce unnecessary exposure of sensitive content."
    )

    st.caption(
        "The risk score is produced by transparent detection "
        "rules. AI may explain potential impact but cannot "
        "change the score."
    )
