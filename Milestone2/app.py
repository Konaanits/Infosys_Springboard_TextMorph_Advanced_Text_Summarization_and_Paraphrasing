%%writefile app.py
import streamlit as st
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import bcrypt
import jwt
import datetime
import time
import os
import re
import hmac
import hashlib
import struct
import db
from streamlit_option_menu import option_menu
import plotly.graph_objects as go
import PyPDF2

# --- Configuration ---
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
SECRET_KEY = os.getenv("JWT_SECRET", "super-secret-key-change-this")
EMAIL_ADDRESS = "konaofficialpurpose28@gmail.com"
OTP_EXPIRY_MINUTES = 10
SECURITY_QUESTIONS = [
    "What is your mother's maiden name?",
    "What was your first school?",
    "What is your favorite food?",
    "What is your childhood nickname?"
]

# --- Database Initialization ---
if 'db_initialized' not in st.session_state:
    db.init_db()
    st.session_state['db_initialized'] = True

# --- UI Theme (Neon Style) ---
st.set_page_config(page_title="Smart Readability & Text Analysis System", page_icon="🧠", layout="wide")

def apply_neon_theme():
    st.markdown("""
    <style>
        /* =========================
   FULL PAGE MOUNTAIN BACKGROUND
   ========================= */

.stApp{
    background-image:url("https://images.unsplash.com/photo-1504386106331-3e4e71712b38");
    background-size:cover;
    background-position:center;
    background-attachment:fixed;
}


/* =========================
   CENTER GLASS CONTAINER
   ========================= */

.main .block-container{

    max-width:520px;
    margin-top:90px;
    padding:45px;

    background:rgba(255,255,255,0.18);
    backdrop-filter:blur(14px);

    border-radius:20px;
    box-shadow:0 12px 40px rgba(0,0,0,0.35);
}


/* =========================
   HEADERS
   ========================= */

h1,h2,h3{
    text-align:center;
    color:white !important;
    font-weight:700;
}


/* =========================
   INPUTS + TEXTAREA
   ========================= */

.stTextInput input,
.stTextArea textarea{

    background:rgba(255,255,255,0.92);
    border-radius:10px;
    padding:12px;
    border:none;
}


/* =========================
   BUTTONS
   ========================= */

.stButton button{

    width:100%;
    border-radius:10px;

    background:#0d1b2a;
    color:white;
    font-weight:600;
    padding:12px;
    border:none;

}

.stButton button:hover{
    background:#1b263b;
}


/* =========================
   PASSWORD STRENGTH COLORS
   ========================= */

.strength-weak{color:#ff4b4b;font-weight:600;}
.strength-medium{color:#ffb020;font-weight:600;}
.strength-strong{color:#1dd1a1;font-weight:600;}


/* =========================
   SIDEBAR GLASS
   ========================= */

section[data-testid="stSidebar"]{

    background:rgba(0,0,0,0.40);
    backdrop-filter:blur(10px);
}


/* =========================
   TABS STYLE
   ========================= */

.stTabs [data-baseweb="tab"]{

    background:rgba(255,255,255,0.35);
    border-radius:8px;
    padding:8px 18px;
}

.stTabs [aria-selected="true"]{

    background:white !important;
    color:black !important;
}


/* =========================
   EXPANDER
   ========================= */

.streamlit-expanderHeader{
    background:rgba(255,255,255,0.35);
    border-radius:8px;
}


/* =========================
   METRICS
   ========================= */

[data-testid="stMetricValue"]{
    color:white;
    font-weight:700;
}


/* =========================
   CHAT MESSAGES
   ========================= */

.stChatMessage{

    background:rgba(255,255,255,0.88);
    border-radius:12px;
    padding:10px;
}


/* =========================
   FORM TRANSPARENCY FIX
   ========================= */

div[data-testid="stForm"]{
    background:transparent;
}
/* INPUT CENTER + WIDTH */

.stTextInput,
.stTextInput > div,
.stTextInput input{
    max-width:320px;
    margin-left:auto;
    margin-right:auto;
}

/* TEXT VISIBILITY */

.stTextInput input,
.stTextArea textarea{
    color:black !important;
    font-weight:500;
}

/* PLACEHOLDER */

input::placeholder{
    color:#666 !important;
}

/* CURSOR COLOR FIX */

.stTextInput input,
.stTextArea textarea{

    caret-color:black !important;
}
label{
    color:white !important;
    font-weight:600;
}
/* =========================
   MAKE WARNING MESSAGE STRONGER
   ========================= */

div[data-baseweb="notification"]{

    background: rgba(180,0,0,0.85) !important;   /* darker red */
    color: white !important;
    font-weight:600 !important;
    border-radius:10px !important;
}


/* text inside warning */
div[data-baseweb="notification"] p{
    color:white !important;
    font-size:16px !important;
}
/* =====================================================
   AFTER LOGIN — MAKE DASHBOARD MATCH LOGIN STYLE
   ===================================================== */


/* --------- SIDEBAR → SAME GLASS STYLE AS LOGIN --------- */

section[data-testid="stSidebar"]{

    background:rgba(0,0,0,0.45) !important;
    backdrop-filter:blur(14px);
}


/* sidebar text clean white */

section[data-testid="stSidebar"] *{
    color:white !important;
}


/* --------- HEADER TEXT BRIGHT WHITE --------- */

h1{
    color:white !important;
    text-align:center;
    font-weight:700;
}


/* --------- CHAT INPUT → MATCH LOGIN INPUT STYLE --------- */

[data-testid="stChatInput"] textarea{

    background:rgba(255,255,255,0.92) !important;
    border-radius:10px !important;
    padding:12px !important;
    color:black !important;
}


/* --------- CHAT INPUT BOX CONTAINER --------- */

[data-testid="stChatInput"]{

    background:transparent !important;
}


/* --------- CHAT MESSAGES → SAME GLASS CARD --------- */

.stChatMessage{

    background:rgba(255,255,255,0.88);
    border-radius:12px;
    padding:12px;
}


/* --------- REMOVE DARK TOP BAR --------- */

header{
    background:transparent !important;
}
/* =========================
   CHANGE INFOSYS LOGO COLOR
   ========================= */

/* big Infosys text */

section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] strong{

    color:#ffe8c2 !important;
}


/* email link color */

section[data-testid="stSidebar"] a{

    color:#ffe8c2 !important;
    text-decoration:none !important;
}


/* sidebar icons */

section[data-testid="stSidebar"] svg{

    fill:#ffe8c2 !important;
    color:#ffe8c2 !important;
}
/* =========================
   DIM BACKGROUND AFTER LOGIN ONLY
   ========================= */

/* when sidebar exists → user logged in → add dark overlay */

body:has(section[data-testid="stSidebar"]) .stApp::after{
    content:"";
    position:fixed;
    inset:0;

    background:rgba(0,0,0,0.45);   /* increase/decrease here */

    pointer-events:none;
    z-index:0;
}

/* keep app content above overlay */

.stApp > *{
    position:relative;
    z-index:1;
}
/* TARGET ONLY THE NAV CARD */

section[data-testid="stSidebar"]
div[data-testid="stVerticalBlock"] > div:nth-of-type(3){

    background:rgba(255,255,255,0.10) !important;
    backdrop-filter:blur(14px);
    border-radius:14px;
    padding:14px;
}
/* ===== REMOVE ALL BLUE ACTIVE HIGHLIGHTS IN SIDEBAR ===== */

/* remove blue background from anything clickable in sidebar */
section[data-testid="stSidebar"] *:focus,
section[data-testid="stSidebar"] *:active,
section[data-testid="stSidebar"] *[aria-selected="true"],
section[data-testid="stSidebar"] *[aria-current="true"],
section[data-testid="stSidebar"] *[aria-current="page"],
section[data-testid="stSidebar"] button:focus,
section[data-testid="stSidebar"] a:focus {

    background: rgba(255,255,255,0.15) !important;   /* your soft glass highlight */
    box-shadow: none !important;
    outline: none !important;
    border: none !important;
}


/* remove default blue outline */
section[data-testid="stSidebar"] *{
    outline: none !important;
    box-shadow: none !important;
}
/* SECURITY QUESTION WIDTH FIX */

div[data-baseweb="select"]{
    max-width:320px !important;
    margin-left:auto !important;
    margin-right:auto !important;
}
/* SECURITY QUESTION WHITE STYLE */

div[data-baseweb="select"] > div{

    background:rgba(255,255,255,0.92) !important;
    color:black !important;
    border-radius:10px !important;
}


    </style>
    """, unsafe_allow_html=True)

apply_neon_theme()

# --- Helpers ---
def get_relative_time(date_str):
    if not date_str: return "some time ago"
    try:
        past = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        diff = datetime.datetime.utcnow() - past
        days = diff.days
        seconds = diff.seconds
        if days > 365: return f"{days // 365} years ago"
        elif days > 30: return f"{days // 30} months ago"
        elif days > 0: return f"{days} days ago"
        elif seconds > 3600: return f"{seconds // 3600} hours ago"
        elif seconds > 60: return f"{seconds // 60} minutes ago"
        else: return "just now"
    except: return date_str

def is_valid_email(email):
    return re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email) is not None

def check_password_strength(password):
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    has_space = bool(re.search(r"\s", password))

    if has_space: return "Weak", ["No spaces allowed"]
    is_alphanum = (has_upper or has_lower) and has_digit

    if len(password) >= 8 and is_alphanum: return "Strong", []
    if len(password) >= 6 and is_alphanum and has_special: return "Medium", ["Add 2 more chars for Strong"]
    if len(password) >= 1: return "Weak", ["Too short (aim for 8+)"]
    return "Weak", ["Enter password"]

# --- Security Logic ---
def generate_otp():
    """Generates a 6-digit OTP using HMAC-SHA1 (RFC 4226)."""
    secret = secrets.token_bytes(20)
    counter = int(time.time())
    msg = struct.pack(">Q", counter)
    hmac_hash = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = hmac_hash[19] & 0xf
    code = ((hmac_hash[offset] & 0x7f) << 24 |
            (hmac_hash[offset + 1] & 0xff) << 16 |
            (hmac_hash[offset + 2] & 0xff) << 8 |
            (hmac_hash[offset + 3] & 0xff))
    otp = code % 1000000
    return f"{otp:06d}"

def create_otp_token(otp, email):
    """Creates a JWT containing the hashed OTP, bound to the user's email."""
    otp_hash = bcrypt.hashpw(otp.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    payload = {
        'otp_hash': otp_hash, 'sub': email, 'type': 'password_reset',
        'iat': datetime.datetime.utcnow(),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=OTP_EXPIRY_MINUTES)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_otp_token(token, input_otp, email):
    """Verifies the token signature, expiration, email binding, and OTP hash."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if payload.get('type') != 'password_reset': return False, "Invalid token type"
        if payload.get('sub') != email: return False, "Token does not belong to this user"
        if bcrypt.checkpw(input_otp.encode('utf-8'), payload['otp_hash'].encode('utf-8')):
            return True, "Valid OTP"
        return False, "Invalid OTP"
    except jwt.ExpiredSignatureError: return False, "OTP Expired"
    except jwt.InvalidTokenError: return False, "Invalid Token"

# --- Email Logic ---
def send_email(to_email, otp, app_pass=None):
    msg = MIMEMultipart()
    msg['From'] = f"Read Wise AI <{EMAIL_ADDRESS}>"
    msg['To'] = to_email
    msg['Subject'] = "🔐 Read Wise AI - Password Reset OTP"
    body = f"""
    <!DOCTYPE html><html><head><style>
    .container {{ font-family: Arial, Helvetica, sans-serif; background-color: #111827; padding: 40px; text-align: center; color: #ffffff; }}
    .card {{ background-color: #1f2937; border-radius: 16px; box-shadow: 0 12px 40px rgba(0, 0, 0, 0.45); padding: 40px; max-width: 500px; margin: 0 auto; border: 1px solid #374151; }}
    .header {{ color: #ffe8c2; font-size: 26px; font-weight: 700; margin-bottom: 22px; text-shadow: 0 0 5px #ffe8c2; }}
    .otp-box {{ background-color: #111827; color: #ffe8c2; font-size: 38px; font-weight: 700; letter-spacing: 10px; padding: 22px; border-radius: 12px; margin: 30px 0; display: inline-block; border: 2px solid #ffe8c2; box-shadow: 0 0 10px rgba(0, 255, 204, 0.3); }}
    .text {{ color: #d1d5db; font-size: 16px; line-height: 1.6; margin-bottom: 22px; }}
    .footer {{ color: #6b7280; font-size: 12px; margin-top: 30px; }}
    </style></head><body><div class="container"><div class="card">
    <div class="header">🧠 Read Wise AI Security</div>
    <div class="text">Use this OTP to reset your password for <span style="color:#ffe8c2;">{to_email}</span>.</div>
    <div class="otp-box">{otp}</div>
    <div class="text">Valid for <strong>{OTP_EXPIRY_MINUTES} minutes</strong>.</div>
    <div class="footer">&copy; 2026 Read Wise AI Secure Auth</div>
    </div></div></body></html>
    """
    msg.attach(MIMEText(body, 'html'))
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        password_to_use = app_pass if app_pass else EMAIL_PASSWORD
        if not password_to_use: return False, "No App Password found. Check Secrets."
        server.login(EMAIL_ADDRESS, password_to_use)
        server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
        server.quit()
        return True, "Email sent successfully!"
    except Exception as e: return False, str(e)

# --- Visualization Helper ---
def create_gauge(value, title, min_val=0, max_val=100, color="#00ffcc"):
    fig = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = value,
        title = {'text': title, 'font': {'color': color, 'size': 14}},
        number = {'font': {'color': color, 'size': 20}},
        gauge = {
            'axis': {'range': [min_val, max_val], 'tickwidth': 1, 'tickcolor': color},
            'bar': {'color': color},
            'bgcolor': "#1f2937",
            'borderwidth': 2,
            'bordercolor': "#374151",
            'steps': [
                {'range': [min_val, max_val], 'color': "#0e1117"}
            ],
        }
    ))
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",font={'color': '#ffffff', 'family': 'Courier New'},height=250,margin=dict(l=10, r=10, t=40, b=10))
    return fig

# --- Navigation & Routing ---
if 'user' not in st.session_state: st.session_state['user'] = None
if 'page' not in st.session_state: st.session_state['page'] = 'login'

def switch_page(page):
    st.session_state['page'] = page
    st.rerun()

def logout():
    st.session_state['user'] = None
    st.session_state['page'] = 'login'
    st.rerun()

# ========================================
# --- PAGES ---
# ========================================

def login_page():
    st.title("🧠 Read Wise AI")
    st.markdown("### Secure Login")

    with st.form("login_form"):
        email = st.text_input("Email *")
        password = st.text_input("Password *", type='password')
        submit = st.form_submit_button("Login")

        if submit:
            is_locked, wait_time = db.is_rate_limited(email)
            if is_locked:
                st.error(f"⛔ Account Locked! Too many failed attempts. Try again in {int(wait_time)}s.")
            elif not email or not password:
                st.error("Please fill in all mandatory fields (*).")
            elif db.authenticate_user(email, password):
                st.session_state['user'] = email
                with st.spinner("Logging in..."):time.sleep(1)
                st.toast(f"Welcome to Read Wise AI, {email}", icon="✅")
                st.rerun()
            else:
                st.error("Invalid email or password.")
                old_dt = db.check_is_old_password(email, password)
                if old_dt:
                    st.warning(f"⚠️ You entered an old password from {get_relative_time(old_dt)}. Please use your latest password.")

    st.markdown("---")
    if st.button("Create Account"):switch_page("register")
    if st.button("Forgot Password?"):switch_page("forgot")

def register_page():
    st.title("🧠 Read Wise AI")
    st.markdown("### Create New Account")

    email = st.text_input("Email Address *")
    password = st.text_input("Password *", type='password')
    question = st.selectbox("Security Question *", SECURITY_QUESTIONS)
    answer = st.text_input("Security Answer *")

    if password:
        s, f = check_password_strength(password)
        if s == "Weak": st.markdown("Strength: <span class='strength-weak'>Weak</span>", unsafe_allow_html=True)
        elif s == "Medium": st.markdown("Strength: <span class='strength-medium'>Medium</span>", unsafe_allow_html=True)
        else: st.markdown("Strength: <span class='strength-strong'>Strong ✓</span>", unsafe_allow_html=True)
        if f: st.caption(f"Issues: {', '.join(f)}")

    if st.button("Register"):
        if not question or not answer.strip():st.error("Please fill the security answer. It cannot be empty.")
        elif not email or not password:
            st.error("Please fill in all mandatory fields (*).")
        elif not is_valid_email(email):
            st.error("Invalid email format.")
        else:
            strength, feedback = check_password_strength(password)
            if strength == "Weak":
                st.error(f"Password is too weak: {', '.join(feedback)}")
            elif db.register_user(email, password):
                st.success("Registration Successful! Redirecting to login...")
                time.sleep(2)
                switch_page("login")
            else:
                st.error("User with this email already exists.")

    st.markdown("---")
    if st.button("Return to Login"): switch_page("login")

def forgot_page():
    st.title("🧠 Read Wise AI")
    st.markdown("### Password Recovery")

    if 'stage' not in st.session_state: st.session_state['stage'] = 'email'

    if st.session_state['stage'] == 'email':
        email = st.text_input("Enter your registered Email *")
        if st.button("Next"):
            if not email: st.error("Email is mandatory (*).")
            elif not is_valid_email(email): st.error("Invalid email format.")
            elif db.check_user_exists(email):
                st.session_state['reset_email'] = email
                st.session_state['stage'] = 'otp'
                st.rerun()
            else: st.error("Email not found in our database.")
        st.markdown("---")
        if st.button("Return to Login"): switch_page("login")

    elif st.session_state['stage'] == 'otp':
        st.info(f"Account found: {st.session_state['reset_email']}")
        if EMAIL_PASSWORD:
            st.success("✅ Application Password loaded from secrets.")
            app_pass = EMAIL_PASSWORD
        else:
            st.warning("⚠️ No Env Var found.")
            app_pass = st.text_input("Enter Google App Password manually *", type="password")

        if st.button("Send Verification Code"):
            if app_pass:
                otp = generate_otp()
                with st.spinner("Sending OTP..."):
                    success, msg = send_email(st.session_state['reset_email'], otp, app_pass)
                if success:
                    st.session_state['token'] = create_otp_token(otp, st.session_state['reset_email'])
                    st.session_state['stage'] = 'verify'
                    st.success("OTP Sent!")
                    time.sleep(1)
                    st.rerun()
                else: st.error(f"Failed to send email: {msg}")
            else: st.error("App Password is required (*).")
        st.markdown("---")
        if st.button("Cancel"):
            st.session_state['stage'] = 'email'
            st.rerun()

    elif st.session_state['stage'] == 'verify':
        st.info("Check your email for the code.")
        otp_input = st.text_input("Enter 6-digit OTP *", max_chars=6)
        if st.button("Verify OTP"):
            if not otp_input: st.error("OTP is required (*)")
            else:
                valid, msg = verify_otp_token(st.session_state['token'], otp_input, st.session_state['reset_email'])
                if valid:
                    st.session_state['stage'] = 'reset'
                    st.success("Verified!")
                    time.sleep(1)
                    st.rerun()
                else: st.error(msg)
        if st.button("Resend Code"):
            st.session_state['stage'] = 'otp'
            st.rerun()

    elif st.session_state['stage'] == 'reset':
        p1 = st.text_input("New Password *", type='password')
        p2 = st.text_input("Confirm New Password *", type='password')
        if p1:
            s, f = check_password_strength(p1)
            if s == "Weak": st.markdown("Strength: <span class='strength-weak'>Weak</span>", unsafe_allow_html=True)
            elif s == "Medium": st.markdown("Strength: <span class='strength-medium'>Medium</span>", unsafe_allow_html=True)
            else: st.markdown("Strength: <span class='strength-strong'>Strong ✓</span>", unsafe_allow_html=True)
            if f: st.caption(f"Issues: {', '.join(f)}")

        if st.button("Update Password"):
            if not p1 or not p2: st.error("All password fields are mandatory (*).")
            elif p1 != p2: st.error("Passwords do not match.")
            elif db.check_password_reused(st.session_state['reset_email'], p1): st.error("⚠️ Old password reuse is not permitted.")
            else:
                strength, _ = check_password_strength(p1)
                if strength == "Weak": st.error("Password is too weak.")
                else:
                    db.update_password(st.session_state['reset_email'], p1)
                    st.balloons()
                    st.success("Password Updated! Please Login.")
                    for key in ['stage', 'reset_email', 'token']:
                        if key in st.session_state: del st.session_state[key]
                    time.sleep(2)
                    switch_page("login")
    if st.button("Cancel Recovery"): switch_page("login")

def chat_page():
    if not st.session_state['user']: switch_page('login'); return
    st.title("🤖 Read Wise AI Chat")
    if "messages" not in st.session_state: st.session_state.messages = []
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]): st.markdown(msg["content"])
    if prompt := st.chat_input("Ask me anything..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"): st.markdown(prompt)
        with st.chat_message("assistant"):
            response = f"Simulated Response: {prompt} (Secure Mock)"
            st.markdown(response)
            st.session_state.messages.append({"role": "assistant", "content": response})

def readability_page():
    if not st.session_state['user']: switch_page('login'); return

    st.title(" TEXT READABILITY ANALYZER 📖")

    # Input Method: Text or File
    tab1, tab2 = st.tabs(["✍️ Input Text", "📂 Upload File (TXT/PDF)"])
    text_input = ""

    with tab1:
        raw_text = st.text_area("Enter text to analyze (min 50 chars):", height=200)
        if raw_text: text_input = raw_text

    with tab2:
        uploaded_file = st.file_uploader("Upload a file", type=["txt", "pdf"])
        if uploaded_file:
            try:
                if uploaded_file.type == "application/pdf":
                    reader = PyPDF2.PdfReader(uploaded_file)
                    text = ""
                    for page in reader.pages:
                        text += page.extract_text() + "\n"
                    text_input = text
                    st.info(f"✅ Loaded {len(reader.pages)} pages from PDF.")
                else:
                    text_input = uploaded_file.read().decode("utf-8")
                    st.info(f"✅ Loaded TXT file: {uploaded_file.name}")
            except Exception as e:
                st.error(f"Error reading file: {e}")

    if st.button("Analyze Readability", type="primary"):
        if len(text_input) < 50:
            st.error("Text is too short (min 50 chars). Please enter more text or upload a valid file.")
        else:
            import readability
            with st.spinner("Calculating advanced metrics..."):
                analyzer = readability.ReadabilityAnalyzer(text_input)
                score = analyzer.get_all_metrics()

            # --- Results Dashboard ---
            st.markdown("---")
            st.subheader("📊 Analysis Results")

            # 1. Overall Grade (Average)
            avg_grade = (score['Flesch-Kincaid Grade'] + score['Gunning Fog'] + score['SMOG Index'] + score['Coleman-Liau']) / 4

            # Determine Level
            if avg_grade <= 6: level, color = "Beginner (Elementary)", "#28a745"
            elif avg_grade <= 10: level, color = "Intermediate (Middle School)", "#17a2b8"
            elif avg_grade <= 14: level, color = "Advanced (High School/College)", "#ffc107"
            else: level, color = "Expert (Professional/Academic)", "#dc3545"

            st.markdown(f"""
            <div style="background-color: #1f2937; padding: 20px; border-radius: 10px; border-left: 5px solid {color}; text-align: center;">
                <h2 style="margin:0; color: {color} !important;">Overall Level: {level}</h2>
                <p style="margin:5px 0 0 0; color: #9ca3af;">Approximate Grade Level: {int(avg_grade)}</p>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("### 📈 Detailed Metrics")

            # 2. Visual Gauges
            c1, c2, c3 = st.columns(3)
            with c1:
                st.plotly_chart(create_gauge(score["Flesch Reading Ease"], "Flesch Reading Ease", 0, 100, "#00ffcc"), use_container_width=True)
                with st.expander("ℹ️ About Flesch Ease"):
                    st.caption("0-100 Scale. Higher is easier. 60-70 is standard.")

            with c2:
                st.plotly_chart(create_gauge(score["Flesch-Kincaid Grade"], "Flesch-Kincaid Grade", 0, 20, "#ff00ff"), use_container_width=True)
                with st.expander("ℹ️ About Kincaid Grade"):
                    st.caption("US Grade Level. 8.0 means 8th grader can understand.")

            with c3:
                st.plotly_chart(create_gauge(score["SMOG Index"], "SMOG Index", 0, 20, "#ffff00"), use_container_width=True)
                with st.expander("ℹ️ About SMOG"):
                    st.caption("Commonly used for medical writing. Based on polysyllables.")

            c4, c5 = st.columns(2)
            with c4:
                st.plotly_chart(create_gauge(score["Gunning Fog"], "Gunning Fog", 0, 20, "#00ccff"), use_container_width=True)
                with st.expander("ℹ️ About Gunning Fog"):
                    st.caption("Based on sentence length and complex words.")

            with c5:
                st.plotly_chart(create_gauge(score["Coleman-Liau"], "Coleman-Liau", 0, 20, "#ff9900"), use_container_width=True)
                with st.expander("ℹ️ About Coleman-Liau"):
                    st.caption("Based on characters instead of syllables. Good for automated analysis.")

            # 3. Text Stats
            st.markdown("### 📝 Text Statistics")
            s1, s2, s3, s4, s5 = st.columns(5)
            s1.metric("Sentences", analyzer.num_sentences)
            s2.metric("Words", analyzer.num_words)
            s3.metric("Syllables", analyzer.num_syllables)
            s4.metric("Complex Words", analyzer.complex_words)
            s5.metric("Characters", analyzer.char_count)

def admin_page():
    if st.session_state['user'] != "admin@llm.com": st.error("Access Denied"); return
    st.title("🛡️ Admin Panel")
    users = db.get_all_users()

    st.metric("Total Users", len(users))
    st.markdown("---")

    c1, c2, c3 = st.columns([3, 2, 1])
    c1.markdown("**Email**"); c2.markdown("**Joined**"); c3.markdown("**Action**")
    st.markdown("---")
    for u_email, u_created in users:
        c1, c2, c3 = st.columns([3, 2, 1])
        c1.write(f"{u_email}"); c2.write(u_created)
        if u_email != "admin@llm.com":
            if c3.button("Delete", key=u_email, type="primary"):
                db.delete_user(u_email)
                st.warning(f"Deleted {u_email}"); time.sleep(0.5); st.rerun()

# ========================================
# --- MAIN ROUTING WITH SIDEBAR ---
# ========================================

if st.session_state['user']:
    with st.sidebar:
        st.image("https://cdn-icons-png.flaticon.com/512/4712/4712109.png", width=100)
        st.markdown(f"**👤 {st.session_state['user']}**")
        st.markdown("---")

        opts = ["Chat", "Readability"]
        icons = ["chat-dots", "book"]
        if st.session_state['user'] == "admin@llm.com":
            opts.append("Admin"); icons.append("shield-lock")

        selected = option_menu("Read Wise AI", opts, icons=icons, menu_icon="cast", default_index=0,
            styles={
    "container": {"background-color": "transparent"},
    "icon": {"color": "#ffe8c2"},
    "nav-link": {
    "color": "#f5f5f5",
    "font-family": "Courier New",
    "border-radius": "10px",
    "margin": "4px",
    "padding": "10px",
},
    "nav-link-selected": {
    "background-color": "rgba(255,255,255,0.15)",
    "color": "white",
    "border-radius": "10px",
    "margin": "4px",
    "padding": "10px",
},
})

        st.markdown("---")
        if st.button("🔓 Log Out"): logout()

    if selected == "Chat": chat_page()
    elif selected == "Readability": readability_page()
    elif selected == "Admin": admin_page()
else:
    if st.session_state['page'] == 'login': login_page()
    elif st.session_state['page'] == 'register': register_page()
    elif st.session_state['page'] == 'forgot': forgot_page()
