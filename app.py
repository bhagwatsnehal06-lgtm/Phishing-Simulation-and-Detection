from io import BytesIO
import streamlit as st
import pandas as pd
import plotly.express as px
from auth_db import initialize_database, register_user, authenticate_user, save_assessment, load_assessments, load_admin_data, update_user_role
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

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


def create_pdf_report(assessments, user_name):
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph(
        "Cybersecurity Risk Assessment Report",
        styles["Title"]
    ))

    content.append(Spacer(1, 15))

    content.append(Paragraph(
        f"Prepared for: {escape(str(user_name))}",
        styles["Normal"]
    ))

    content.append(Spacer(1, 20))

    for index, item in enumerate(assessments, 1):

        score = int(item["Likelihood"]) * int(item["Impact"])
        level = risk_level(score)

        content.append(Paragraph(
            f"Assessment {index}: {escape(str(item['Threat']))}",
            styles["Heading2"]
        ))

        data = [
            ["Field", "Details"],
            ["Threat", str(item["Threat"])],
            ["Description", str(item["Description"])],
            ["Asset", str(item["Asset"])],
            ["Likelihood", str(item["Likelihood"])],
            ["Impact", str(item["Impact"])],
            ["Risk Score", str(score)],
            ["Risk Level", level],
            ["Recommendation", recommendation(item["Threat"])]
        ]

        safe_data = [
            [
                Paragraph(escape(str(cell)), styles["Normal"])
                for cell in row
            ]
            for row in data
        ]

        table = Table(safe_data, colWidths=[120, 390])

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP")
        ]))

        content.append(table)
        content.append(Spacer(1, 20))

    doc.build(content)

    buffer.seek(0)
    return buffer.getvalue()





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

pages = ["Dashboard", "New Risk Assessment", "Risk Register", "About"]

if user.get("role") == "admin":
    pages.append("Admin Dashboard")

page = st.sidebar.radio("Navigation", pages)

if st.sidebar.button("Logout"):
    st.session_state.user = None
    st.rerun()

st.title("🛡️ Cybersecurity Risk Assessment")

# Load user's risk assessments
assessments = load_assessments(user["id"])


if page == "Dashboard":
    st.subheader("📊 Security Overview")
    st.write("Monitor your organization's cybersecurity risks.")

    df = pd.DataFrame(assessments)

    if not df.empty:
        df["Risk Score"] = df["Likelihood"] * df["Impact"]
        df["Risk Level"] = df["Risk Score"].apply(risk_level)

        total = len(df)
        critical = (df["Risk Level"] == "Critical").sum()
        high = (df["Risk Level"] == "High").sum()
        medium = (df["Risk Level"] == "Medium").sum()
        low = (df["Risk Level"] == "Low").sum()
    else:
        total = critical = high = medium = low = 0

    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric("Total Assessments", total)
    c2.metric("Critical Risks", critical)
    c3.metric("High Risks", high)
    c4.metric("Medium Risks", medium)
    c5.metric("Low Risks", low)

    st.divider()
    st.subheader("Risk Distribution")

    chart_data = pd.DataFrame({
        "Risk Level": ["Critical", "High", "Medium", "Low"],
        "Count": [critical, high, medium, low]
    })

    fig = px.pie(
        chart_data,
        names="Risk Level",
        values="Count",
        hole=0.45
    )

    st.plotly_chart(fig, use_container_width=True)
    
    if not df.empty:
        heatmap_data = pd.crosstab(
            df["Likelihood"],
            df["Impact"]
        ).reindex(
            index=range(1, 6),
            columns=range(1, 6),
            fill_value=0
        )

        st.subheader("🔥 Risk Heatmap")

        heatmap = px.imshow(
            heatmap_data,
            x=[1, 2, 3, 4, 5],
            y=[1, 2, 3, 4, 5],
            text_auto=True,
            color_continuous_scale="Reds",
            labels={
                "x": "Impact",
                "y": "Likelihood",
                "color": "Risk Count"
            }
        )

        st.plotly_chart(heatmap, use_container_width=True)

    st.subheader("Recent Risk Assessments")

    if not df.empty:
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No assessments found. Create your first assessment.")


elif page == "New Risk Assessment":
    st.subheader("📝 New Cybersecurity Risk Assessment")

    with st.form("risk_form"):
        business = st.text_input("Business / Organization Name")
        industry = st.selectbox(
            "Industry",
            ["IT", "Healthcare", "Education", "Finance", "Manufacturing", "Other"]
        )
        size = st.selectbox(
            "Business Size",
            ["Small", "Medium", "Large"]
        )

        st.write("### Security Controls")
        q1 = st.select_slider("How strong are your passwords?", options=[1, 2, 3, 4, 5])
        q2 = st.select_slider("How frequently do you update software?", options=[1, 2, 3, 4, 5])
        q3 = st.select_slider("How secure are your backups?", options=[1, 2, 3, 4, 5])
        q4 = st.select_slider("How strong is your email security?", options=[1, 2, 3, 4, 5])
        q5 = st.select_slider("How well is sensitive data protected?", options=[1, 2, 3, 4, 5])

        submitted = st.form_submit_button("Calculate Risk", type="primary")

    if submitted:
        if not business.strip():
            st.error("Please enter the business name.")
        else:
             
            control_score = (6-q1) + (6-q2) + (6-q3) + (6-q4) + (6-q5)

            likelihood = max(1, min(5, round(control_score / 5)))

            impact_values = {
                "Small": 3,
                "Medium": 4,
                "Large": 5
            }

            impact = impact_values[size]
            score = likelihood * impact
            level = risk_level(score)

            risk_data = {
                "Threat": "Weak Security Controls",
                "Description": f"Cybersecurity assessment for {business} in {industry}.",
                "Asset": business,
                "Likelihood": likelihood,
                "Impact": impact
            }
            save_assessment(
                user["id"],
                business,
                industry,
                size,
                risk_data
            )


            st.success("Assessment saved successfully!")
            st.metric("Risk Score", f"{score}/25")
            st.metric("Risk Level", level)

            if level == "Critical":
                st.error("Critical Risk")
            elif level == "High":
                st.warning("High Risk")
            elif level == "Medium":
                st.info("Medium Risk")
            else:
                st.success("Low Risk")

            st.subheader("Security Recommendations")
            st.write(recommendation("Weak passwords"))
            st.write(recommendation("Ransomware"))
            st.write(recommendation("Data breach"))

            st.rerun()


    st.subheader("📋 Risk Register")

    df = pd.DataFrame(assessments)

    if not df.empty:
        df["Risk Score"] = df["Likelihood"] * df["Impact"]
        df["Risk Level"] = df["Risk Score"].apply(risk_level)
        df["Recommendation"] = df["Threat"].apply(recommendation)
        st.dataframe(df, use_container_width=True)
        st.divider()


         
        st.download_button(
            "Download Risk Register CSV",
            df.to_csv(index=False),
            file_name="cyberrisk_register.csv",
            mime="text/csv",
            key="risk_register_csv"
        )

        pdf_file = create_pdf_report(
            assessments,
            user["name"]
        )

        st.download_button(
            "📄 Download PDF Report",
            data=pdf_file,
            file_name="CyberRisk_Assessment_Report.pdf",
            mime="application/pdf",
            key="risk_register_pdf"
        )

    else:
        st.info("No risk assessments found.")


elif page == "Admin Dashboard":
    if user.get("role") != "admin":
        st.error("Access denied. Admin only.")
        st.stop()

    st.subheader("🛡️ Admin Dashboard")

    users_data, assessment_data = load_admin_data()

    users_df = pd.DataFrame(
        users_data,
        columns=["ID", "Name", "Email", "Role"]
    )

    assessments_df = pd.DataFrame(
        assessment_data,
        columns=[
            "User", "Business", "Industry",
            "Threat", "Likelihood", "Impact"
        ]
    )

    total_users = len(users_df)
    total_assessments = len(assessments_df)

    if not assessments_df.empty:
        scores = (
            assessments_df["Likelihood"] *
            assessments_df["Impact"]
        )

        levels = scores.apply(risk_level)

        critical = (levels == "Critical").sum()
        high = (levels == "High").sum()
    else:
        critical = high = 0

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Users", total_users)
    c2.metric("Total Assessments", total_assessments)
    c3.metric("Critical Risks", critical)
    c4.metric("High Risks", high)

    st.divider()

    st.subheader("👥 Registered Users")
    st.dataframe(users_df, use_container_width=True)
    st.divider()
    st.subheader("🔐 Change User Role")

    if not users_df.empty:
        selected_user = st.selectbox(
    "Select User",
    users_df["Email"].tolist(),
    key="admin_select_user"
)

    new_role = st.selectbox(
        "Select New Role",
        ["user", "admin"],
    key="admin_new_role"
)

    if st.button("Update Role"):
            if selected_user == user["email"]:
                st.warning("You cannot change your own role.")
            else:
                update_user_role(selected_user, new_role)
                st.success("Role updated successfully!")
                st.rerun()
    st.divider()
    st.subheader("🔐 Change User Role")

    if not users_df.empty:
        selected_user = st.selectbox(
        "Select User",
        users_df["Email"].tolist(),
        key="admin_select_user_2"
    )

    new_role = st.selectbox(
        "Select New Role",
        ["user", "admin"],
        key="admin_new_role_2"
    )

    if st.button("Update Role", key="admin_update_role_2"):
        if selected_user == user["email"]:
            st.warning("You cannot change your own role.")
        else:
            update_user_role(selected_user, new_role)
            st.success("User role updated successfully!")
            st.rerun()
    st.divider()
    st.subheader("🔐 Change User Role")

    if not users_df.empty:
        selected_user = st.selectbox(
            "Select User",
            users_df["Email"].tolist()
        )

        new_role = st.selectbox(
            "Select New Role",
            ["user", "admin"]
        )

        if st.button("Update Role"):
            if selected_user == user["email"]:
                st.warning("You cannot change your own role here.")
            else:
                update_user_role(selected_user, new_role)
                st.success("User role updated successfully!")
                st.rerun()

    st.subheader("📋 All System Assessments")
    st.dataframe(assessments_df, use_container_width=True)
