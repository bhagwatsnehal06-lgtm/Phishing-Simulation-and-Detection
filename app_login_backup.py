
import streamlit as st
import pandas as pd
import plotly.express as px
from auth_db import initialize_database, register_user, authenticate_user, save_assessment, load_assessments

st.set_page_config(page_title="Cyber Risk Assessment", page_icon="🛡️", layout="wide")
initialize_database()

st.markdown("""
<style>
.stApp {background:linear-gradient(135deg,#08111f,#101d32 55%,#0b1424);color:#eef4ff;}
[data-testid="stSidebar"] {background:#0d192b;}
.block-container {padding-top:2rem;max-width:1400px;}
div[data-testid="stMetric"] {background:#14243b;border:1px solid #294363;padding:16px;border-radius:14px;}
</style>
""", unsafe_allow_html=True)


def risk_level(score):
    if score >= 20:
        return "Critical"
    if score >= 15:
        return "High"
    if score >= 8:
        return "Medium"
    return "Low"


def recommendation(threat):
    suggestions = {
        "Phishing": "Train employees, filter suspicious email, and enable multi-factor authentication.",
        "Ransomware": "Keep offline backups, update software, and use endpoint protection.",
        "Weak passwords": "Use unique passwords, a password manager, and multi-factor authentication.",
        "Insider threat": "Apply least-privilege access and review account activity.",
        "Data breach": "Encrypt sensitive data, restrict access, and maintain security logs.",
        "Malware": "Use updated endpoint protection and install software updates.",
        "Unpatched software": "Maintain an asset list and apply security updates promptly.",
        "Lost device": "Enable disk encryption, screen locks, and remote wipe.",
        "Wi-Fi attack": "Use WPA2/WPA3, change router defaults, and separate guest Wi-Fi."
    }
    return suggestions.get(threat, "Review access, update systems, and monitor for suspicious activity.")


# Login and registration
if "user" not in st.session_state:
    st.session_state.user = None

if st.session_state.user is None:
    st.title("🛡️ CyberRisk Assessment")
    st.write("Sign in or create an account to manage your business risk assessments.")
    login_tab, register_tab = st.tabs(["Login", "Create Account"])

    with login_tab:
        with st.form("login_form"):
            email = st.text_input("Email address")
            password = st.text_input("Password", type="password")
            login_clicked = st.form_submit_button("Login", type="primary")
        if login_clicked:
            account = authenticate_user(email, password)
            if account:
                st.session_state.user = account
                st.rerun()
            else:
                st.error("Incorrect email or password.")

    with register_tab:
        with st.form("register_form"):
            name = st.text_input("Full name")
            new_email = st.text_input("Email address")
            new_password = st.text_input("Password (minimum 8 characters)", type="password")
            confirm_password = st.text_input("Confirm password", type="password")
            create_clicked = st.form_submit_button("Create Account", type="primary")
        if create_clicked:
            if new_password != confirm_password:
                st.error("Passwords do not match.")
            else:
                ok, message = register_user(name, new_email, new_password)
                if ok:
                    st.success(message)
                else:
                    st.error(message)

    st.info("Passwords are stored as bcrypt hashes, not as plain text.")
    st.stop()


# Authenticated application
user = st.session_state.user
st.sidebar.title("🛡️ CyberRisk")
st.sidebar.write(f"Signed in as **{user['name']}**")
page = st.sidebar.radio("Navigation", ["Dashboard", "New Risk Assessment", "Risk Register", "About"])
if st.sidebar.button("Logout"):
    st.session_state.user = None
    st.rerun()

st.title("🛡️ Cybersecurity Risk Assessment")
