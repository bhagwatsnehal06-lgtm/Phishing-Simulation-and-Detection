
import streamlit as st
import pandas as pd
import plotly.express as px

# ---------------------------------------------------------
# Cybersecurity Risk Assessment Framework for Small Businesses
# Starter version: business profile + risk assessment dashboard
# ---------------------------------------------------------

st.set_page_config(
    page_title="Cyber Risk Assessment",
    page_icon="🛡️",
    layout="wide"
)

# ---------- Simple dashboard styling ----------
st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(135deg, #08111f 0%, #101d32 55%, #0b1424 100%);
        color: #eef4ff;
    }
    [data-testid="stSidebar"] {
        background: #0d192b;
    }
    .block-container {
        padding-top: 2rem;
        max-width: 1400px;
    }
    div[data-testid="stMetric"] {
        background: #14243b;
        border: 1px solid #294363;
        padding: 16px;
        border-radius: 14px;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# ---------- Risk data and scoring ----------
DEFAULT_RISKS = [
    {
        "Threat": "Phishing",
        "Description": "Employees may be tricked into revealing passwords or sensitive information.",
        "Likelihood": 4,
        "Impact": 4,
        "Asset": "Email accounts",
    },
    {
        "Threat": "Ransomware",
        "Description": "Malware may encrypt business files and interrupt operations.",
        "Likelihood": 3,
        "Impact": 5,
        "Asset": "Business data",
    },
    {
        "Threat": "Weak passwords",
        "Description": "Easy-to-guess or reused passwords may allow unauthorized access.",
        "Likelihood": 4,
        "Impact": 3,
        "Asset": "User accounts",
    },
    {
        "Threat": "Insider threat",
        "Description": "An employee or contractor may misuse authorized access.",
        "Likelihood": 2,
        "Impact": 4,
        "Asset": "Company systems",
    },
    {
        "Threat": "Data breach",
        "Description": "Confidential customer or business information may be exposed.",
        "Likelihood": 3,
        "Impact": 5,
        "Asset": "Customer records",
    },
]


def risk_level(score):
    """Convert a likelihood-impact score into a risk category."""
    if score >= 20:
        return "Critical"
    if score >= 15:
        return "High"
    if score >= 8:
        return "Medium"
    return "Low"


def recommendation(threat):
    """Return a practical first-line mitigation suggestion."""
    suggestions = {
        "Phishing": "Provide phishing-awareness training, enable email filtering, and use MFA.",
    }