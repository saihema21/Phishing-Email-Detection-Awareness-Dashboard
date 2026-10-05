import os
import json
import pandas as pd
import streamlit as st
import plotly.express as px

from utils.analyzer import (
    calculate_phishing_score,
    extract_urls
)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Phishing Email Detection & Awareness Dashboard",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>
    .main-title {
        font-size: 36px;
        font-weight: 700;
        margin-bottom: 5px;
    }

    .subtitle {
        font-size: 17px;
        color: #666;
        margin-bottom: 25px;
    }

    .risk-high {
        padding: 18px;
        border-radius: 10px;
        background-color: #ffe5e5;
        border-left: 6px solid #d32f2f;
    }

    .risk-medium {
        padding: 18px;
        border-radius: 10px;
        background-color: #fff4cc;
        border-left: 6px solid #f9a825;
    }

    .risk-low {
        padding: 18px;
        border-radius: 10px;
        background-color: #e8f5e9;
        border-left: 6px solid #388e3c;
    }

    .section-title {
        font-size: 25px;
        font-weight: 650;
        margin-top: 25px;
        margin-bottom: 15px;
    }
    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# LOAD DATASET
# ============================================================

DATA_PATH = "data/phishing_email_dataset.csv"

if not os.path.exists(DATA_PATH):
    st.error(
        "Dataset not found. Please run generate_dataset.py first."
    )
    st.stop()

df = pd.read_csv(DATA_PATH)


# ============================================================
# SESSION STATE
# ============================================================

if "analysis_history" not in st.session_state:
    st.session_state.analysis_history = []


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ Phishing Email Detection & Awareness Dashboard</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Defensive cybersecurity dashboard for explainable email phishing risk assessment'
    '</div>',
    unsafe_allow_html=True
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("Navigation")

page = st.sidebar.radio(
    "Select Section",
    [
        "Dashboard",
        "Email Analyzer",
        "Analysis History",
        "Awareness Center",
        "Dataset Explorer"
    ]
)

st.sidebar.markdown("---")

st.sidebar.info(
    """
    **Security Notice**

    This application is designed for defensive and educational
    cybersecurity analysis.

    • Uses synthetic/sample email data  
    • Does not visit URLs  
    • Does not execute attachments  
    • Does not collect credentials
    """
)


# ============================================================
# DASHBOARD PAGE
# ============================================================

if page == "Dashboard":

    st.markdown(
        '<div class="section-title">📊 Security Overview</div>',
        unsafe_allow_html=True
    )

    total_emails = len(df)
    phishing_count = int(
        (df["label"] == "PHISHING").sum()
    )
    legitimate_count = int(
        (df["label"] == "LEGITIMATE").sum()
    )

    phishing_percentage = (
        phishing_count / total_emails * 100
        if total_emails > 0
        else 0
    )

    # --------------------------------------------------------
    # TOP CARDS
    # --------------------------------------------------------

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric(
        "Total Emails",
        total_emails
    )

    col2.metric(
        "Phishing Emails",
        phishing_count
    )

    col3.metric(
        "Legitimate Emails",
        legitimate_count
    )

    col4.metric(
        "Phishing Rate",
        f"{phishing_percentage:.1f}%"
    )

    col5.metric(
        "Dataset Balance",
        "50 / 50"
    )

    st.markdown("---")

    # --------------------------------------------------------
    # CLASSIFICATION DISTRIBUTION
    # --------------------------------------------------------

    col1, col2 = st.columns(2)

    with col1:

        st.subheader("Email Classification Distribution")

        class_data = (
            df["label"]
            .value_counts()
            .reset_index()
        )

        class_data.columns = [
            "Classification",
            "Count"
        ]

        fig = px.pie(
            class_data,
            names="Classification",
            values="Count",
            hole=0.45
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    with col2:

        st.subheader("Phishing vs Legitimate")

        bar_data = pd.DataFrame({
            "Category": [
                "Legitimate",
                "Phishing"
            ],
            "Count": [
                legitimate_count,
                phishing_count
            ]
        })

        fig = px.bar(
            bar_data,
            x="Category",
            y="Count",
            text="Count"
        )

        fig.update_traces(
            textposition="outside"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    # --------------------------------------------------------
    # CATEGORY ANALYSIS
    # --------------------------------------------------------

    st.subheader("Email Categories")

    category_data = (
        df["category"]
        .value_counts()
        .reset_index()
    )

    category_data.columns = [
        "Category",
        "Count"
    ]

    fig = px.bar(
        category_data,
        x="Category",
        y="Count",
        text="Count"
    )

    fig.update_layout(
        xaxis_tickangle=-35
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    # --------------------------------------------------------
    # DATASET PREVIEW
    # --------------------------------------------------------

    st.subheader("Dataset Preview")

    st.dataframe(
        df.head(20),
        use_container_width=True
    )


# ============================================================
# EMAIL ANALYZER
# ============================================================

elif page == "Email Analyzer":

    st.markdown(
        '<div class="section-title">🔍 Email Risk Analyzer</div>',
        unsafe_allow_html=True
    )

    st.write(
        "Enter a synthetic or sample email below to perform "
        "static phishing-risk analysis."
    )

    sender = st.text_input(
        "Sender Email",
        placeholder="security-alert@example.invalid.test"
    )

    subject = st.text_input(
        "Email Subject",
        placeholder="URGENT: Verify Your Account"
    )

    body = st.text_area(
        "Email Body",
        height=220,
        placeholder=(
            "Paste the email body here..."
        )
    )

    urls_text = st.text_area(
        "URLs",
        height=100,
        placeholder=(
            "Enter one URL per line. "
            "The application performs static analysis only."
        )
    )

    attachment = st.text_input(
        "Attachment Name",
        placeholder="document.pdf.exe"
    )

    analyze_button = st.button(
        "🔎 Analyze Email",
        type="primary"
    )

    if analyze_button:

        if not sender or not subject or not body:
            st.warning(
                "Please enter sender, subject, and email body."
            )
            st.stop()

        # Extract URLs from body
        extracted_urls = extract_urls(body)

        # Add URLs entered manually
        manual_urls = [
            url.strip()
            for url in urls_text.splitlines()
            if url.strip()
        ]

        all_urls = list(
            dict.fromkeys(
                extracted_urls + manual_urls
            )
        )

        result = calculate_phishing_score(
            sender=sender,
            subject=subject,
            body=body,
            urls=all_urls,
            attachment_name=attachment
        )

        risk_score = result["risk_score"]
        classification = result["classification"]

        # Save history
        history_record = {
            "analysis_id": f"ANALYSIS-{len(st.session_state.analysis_history) + 1:04d}",
            "sender_domain": (
                sender.split("@")[1]
                if "@" in sender
                else "Unknown"
            ),
            "subject": subject,
            "risk_score": risk_score,
            "classification": classification,
            "indicators": "; ".join(
                result["indicators"]
            ),
            "analyzed_at": pd.Timestamp.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        }

        st.session_state.analysis_history.append(
            history_record
        )

        st.markdown("---")

        st.subheader("Risk Assessment")

        # Risk display
        if risk_score >= 70:

            st.error(
                f"🚨 {classification}"
            )

        elif risk_score >= 50:

            st.warning(
                f"⚠️ {classification}"
            )

        elif risk_score >= 25:

            st.info(
                f"ℹ️ {classification}"
            )

        else:

            st.success(
                f"✅ {classification}"
            )

        # Score
        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Risk Score",
            f"{risk_score}/100"
        )

        col2.metric(
            "Classification",
            classification
        )

        col3.metric(
            "Suspicious URLs",
            result["suspicious_url_count"]
        )

        st.progress(
            risk_score / 100
        )

        # Indicators
        st.subheader("🚩 Detected Indicators")

        if result["indicators"]:

            for indicator in result["indicators"]:
                st.write(
                    f"• {indicator}"
                )

        else:

            st.success(
                "No major phishing indicators detected."
            )

        # Recommendations
        st.subheader("🛡️ Security Recommendations")

        for recommendation in result["recommendations"]:

            st.write(
                f"• {recommendation}"
            )

        # URL analysis
        st.subheader("🔗 URLs Analyzed")

        if all_urls:

            for url in all_urls:
                st.code(url)

            st.caption(
                "URLs are analyzed statically. "
                "The application does not visit or execute them."
            )

        else:

            st.info(
                "No URLs were detected."
            )

        # Download result
        result_json = json.dumps(
            result,
            indent=4
        )

        st.download_button(
            "⬇️ Download Analysis Result",
            data=result_json,
            file_name="phishing_analysis_result.json",
            mime="application/json"
        )


# ============================================================
# ANALYSIS HISTORY
# ============================================================

elif page == "Analysis History":

    st.markdown(
        '<div class="section-title">🕒 Analysis History</div>',
        unsafe_allow_html=True
    )

    if not st.session_state.analysis_history:

        st.info(
            "No emails have been analyzed during this session."
        )

    else:

        history_df = pd.DataFrame(
            st.session_state.analysis_history
        )

        st.dataframe(
            history_df,
            use_container_width=True
        )

        st.subheader("Risk Score Distribution")

        fig = px.histogram(
            history_df,
            x="risk_score",
            nbins=10,
            title="Analyzed Email Risk Scores"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )


# ============================================================
# AWARENESS CENTER
# ============================================================

elif page == "Awareness Center":

    st.markdown(
        '<div class="section-title">🎓 Phishing Awareness Center</div>',
        unsafe_allow_html=True
    )

    st.write(
        "Use these defensive checks before clicking links, "
        "opening attachments, or responding to unexpected emails."
    )

    awareness_items = [
        (
            "👤 Check the Sender",
            "Look carefully at the sender address and domain. "
            "Attackers may use misleading or unfamiliar domains."
        ),
        (
            "🌐 Inspect the Domain",
            "Check spelling, unusual subdomains, raw IP addresses, "
            "and unexpected domain structures."
        ),
        (
            "⏰ Be Careful With Urgency",
            "Messages demanding immediate action can use pressure "
            "to prevent careful verification."
        ),
        (
            "🔗 Inspect Suspicious Links",
            "Do not click suspicious links. Check the URL structure "
            "before taking action."
        ),
        (
            "🔐 Never Share Credentials",
            "Do not provide passwords, OTPs, authentication codes, "
            "or sensitive information through unexpected requests."
        ),
        (
            "📎 Check Attachments",
            "Be especially cautious with executable or double-extension "
            "attachments."
        ),
        (
            "💳 Verify Payment Requests",
            "Unexpected payment, invoice, refund, or banking requests "
            "should be independently verified."
        ),
        (
            "⚠️ Watch Threats and Pressure",
            "Threats such as account suspension or legal consequences "
            "can be used as social-engineering techniques."
        ),
    ]

    for title, description in awareness_items:

        with st.expander(title):

            st.write(description)

    st.markdown("---")

    st.subheader("✅ Before You Click Checklist")

    checklist = [
        "Do I recognize the sender?",
        "Does the sender domain look legitimate?",
        "Was I expecting this message?",
        "Is the email creating unnecessary urgency?",
        "Is a password or OTP being requested?",
        "Is sensitive personal information requested?",
        "Does the URL look suspicious?",
        "Is there an unexpected attachment?",
        "Is a payment or financial action requested?",
        "Can I verify the request through another trusted channel?",
    ]

    for item in checklist:

        st.checkbox(
            item,
            key=f"check_{item}"
        )

    st.markdown("---")

    st.warning(
        "If an email appears suspicious, do not click links, "
        "open attachments, or provide sensitive information. "
        "Verify the request through a trusted independent channel."
    )


# ============================================================
# DATASET EXPLORER
# ============================================================

elif page == "Dataset Explorer":

    st.markdown(
        '<div class="section-title">🗂️ Dataset Explorer</div>',
        unsafe_allow_html=True
    )

    st.write(
        "Explore the synthetic phishing email dataset used "
        "by this defensive cybersecurity project."
    )

    label_filter = st.multiselect(
        "Filter by Classification",
        options=df["label"].unique(),
        default=list(df["label"].unique())
    )

    category_filter = st.multiselect(
        "Filter by Category",
        options=df["category"].unique(),
        default=list(df["category"].unique())
    )

    filtered_df = df[
        df["label"].isin(label_filter)
        & df["category"].isin(category_filter)
    ]

    st.metric(
        "Filtered Records",
        len(filtered_df)
    )

    st.dataframe(
        filtered_df,
        use_container_width=True
    )

    csv_data = filtered_df.to_csv(
        index=False
    )

    st.download_button(
        "⬇️ Download Filtered Dataset",
        data=csv_data,
        file_name="filtered_phishing_dataset.csv",
        mime="text/csv"
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")

st.caption(
    "Phishing Email Detection & Awareness Dashboard | "
    "Defensive cybersecurity and educational project | "
    "Synthetic data only"
)