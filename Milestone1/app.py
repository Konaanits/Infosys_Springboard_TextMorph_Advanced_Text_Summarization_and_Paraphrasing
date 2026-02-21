import streamlit as st
import jwt
import datetime
import time
import re
# --- Configuration ---
SECRET_KEY = "super_secret_key_for_demo"  # In production, use environment variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
# --- JWT Utils ---
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
# --- Validation Utils ---
def is_valid_email(email):
    # Regex for standard email format
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'
    try:
        if re.match(pattern, email):
            return True
    except:
        return False
    return False
def is_valid_password(password):
    # Alphanumeric check and min length 8
    if len(password) < 8:
        return False
    if not password.isalnum():
        return False
    return True
# --- Session State Management ---
if 'jwt_token' not in st.session_state:
    st.session_state['jwt_token'] = None
if 'page' not in st.session_state:
    st.session_state['page'] = 'login'
# Mock Database (In-memory for demo)
# Structure: {email: {'password': password, 'username': username, ...}}
# Also store usernames separately for quick check: {username: email}
if 'users' not in st.session_state:
    st.session_state['users'] = {}
if 'usernames' not in st.session_state:
    st.session_state['usernames'] = set()
# --- Styling ---
st.set_page_config(page_title="Infosys SpringBoard Intern", page_icon="🤖", layout="wide")

st.markdown("""
<style>

/* Full background image */
.stApp {
    background: url("https://images.unsplash.com/photo-1504386106331-3e4e71712b38") no-repeat center center fixed;
    background-size: cover;
}
/* Main Heading */
.main-title {
    font-size: 46px;
    font-weight: 800;
    color: white;
    letter-spacing: 2px;
    text-align: center;
    margin-top: 10px;     /* 🔥 smaller = moves heading UP */
    margin-bottom: -30px; /* 🔥 pulls white box closer */
    text-shadow: 0px 4px 20px rgba(0,0,0,0.8);
}

/* Dark overlay */
.stApp::before {
    content: "";
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.4);
    z-index: -1;
}



/* Title */
.login-title {
    font-size: 38px;
    font-weight: 800;
    margin-top: 10px;
    margin-bottom: 15px;
    color: black;
    text-align:center;
}
/* Label Styling */
label {
    color: white !important;
    font-size: 29px !important;
    font-weight: 900 !important;
    letter-spacing: 1px;
}

/* White Input Box Container */
div[data-baseweb="input"] > div {
    background-color: white !important;
    border-radius: 6px !important;
    border: 2px solid #ccc !important;
    transition: 0.3s ease-in-out;
}

/* Input Text Color */
input {
    color: black !important;
    font-weight: 600;
}

/* Focus Highlight */
div[data-baseweb="input"]:focus-within > div {
    border: 2px solid #d8921f !important;
    box-shadow: 0px 0px 8px rgba(216,146,31,0.6);
}


/* Input Text */
input {
    color: black !important;
    font-weight: 600;
}

/* Focus Effect */
div[data-baseweb="input"]:focus-within > div {
    border: 2px solid #d8921f !important;
    box-shadow: 0px 0px 12px rgba(216,146,31,0.8);
}


/* Button */
.stButton>button {
    background-color: #d8921f;
    color: blue;
    border-radius: 0px;
    height: 55px;
    width: 100%;
    border: none;
    font-weight: 700;
}

.stButton>button:hover {
    background-color: #b87412;
}
/* Improve Error Message Visibility */
div[data-testid="stAlert"] {
    background-color: #ff1a1a !important;
    border-radius: 8px !important;
    padding: 18px !important;
    box-shadow: 0px 0px 20px rgba(255, 0, 0, 0.8);
}

/* Target inner text container */
div[data-testid="stAlert"] p {
    color: white !important;
    font-size: 20px !important;
    font-weight: 800 !important;
}

/* Remove default borders */
div[data-testid="stAlert"] > div {
    border: none !important;
}
/* CENTER LOGIN CARD */
.login-card {
    background: rgba(255,255,255,0.92);
    padding: 45px;
    border-radius: 18px;
    box-shadow: 0px 20px 60px rgba(0,0,0,0.45);
    max-width: 520px;
    margin: auto;
}



/* FIX INPUT SIZE */
div[data-baseweb="input"] {
    margin-bottom: 18px;
}

/* LOGIN BUTTON MODERN */
.stButton>button {
    background: linear-gradient(90deg,#ff9800,#ff6a00);
    color: white;
    border-radius: 10px;
    height: 52px;
    font-size: 18px;
    font-weight: 700;
    transition: 0.3s;
}

.stButton>button:hover {
    transform: translateY(-2px);
    box-shadow: 0px 10px 20px rgba(0,0,0,0.4);
}
/* CRITICAL FIX FOR STREAMLIT WIDTH */
.block-container {
    max-width: 1000px;
    padding-top: 0rem;   /* remove extra top gap */
}

/* LOGIN CARD */
.login-card {
    background: rgba(255,255,255,0.95);
    padding: 40px;
    border-radius: 18px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    margin-top: -20px;
}
/* FORCE LOGIN PAGE TO CENTER VERTICALLY */
section.main > div {
    display: flex;
    flex-direction: column;
    justify-content: center;
    min-height: 80vh;
}
svg {
    fill: #555 !important;
}

</style>
""", unsafe_allow_html=True)



# --- Views ---
def login_page():

    # Main Title
    st.markdown(
    "<h1 class='main-title'>Infosys SpringBoard Intern</h1>",unsafe_allow_html=True)
    
    
    col1, col2, col3 = st.columns([1,2,1])
    with col2:
      
      st.markdown("<div class='login-card'>", unsafe_allow_html=True)
      st.markdown("<div class='login-title'>Sign In</div>", unsafe_allow_html=True)
      with st.form("login_form"):

        email = st.text_input("EMAIL ID")
        password = st.text_input("PASSWORD", type="password")

        submitted = st.form_submit_button("Login")

        if submitted:
            if email in st.session_state['users'] and st.session_state['users'][email]['password'] == password:
                username = st.session_state['users'][email]['username']
                token = create_access_token({"sub": email, "username": username})
                st.session_state['jwt_token'] = token
                st.rerun()
            else:
                st.error("Invalid email or password")
      st.markdown("</div>", unsafe_allow_html=True)

    

    st.markdown("<a href='#' style='color:#007cc3;'>Forgot Password?</a>", unsafe_allow_html=True)

   
    st.markdown("---")
    c1, c2 = st.columns(2)
    with c1:
      if st.button("Forgot Password?"):
        st.session_state['page'] = 'forgot'
        st.rerun()
    with c2:
      if st.button("Create an Account"):
        st.session_state['page'] = 'signup'
        st.rerun()
def signup_page():
    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.title("Create Account")

        with st.form("signup_form"):
            username = st.text_input("Username (Required)")
            email = st.text_input("Email Address (@domain.com required)")
            password = st.text_input("Password (min 8 chars, alphanumeric)")
            confirm_password = st.text_input("Confirm Password", type="password")
            security_question = st.selectbox("Select Security Question",["SELECT QUESTION","What is your pet's name?","What is your favorite teacher's name?","What is your birthplace?","What is your favorite sport?"])
            security_answer = st.text_input("Security Answer")
            submitted = st.form_submit_button("Sign Up")

            if submitted:
                errors = []

                # Username Validation
                if not username:
                    errors.append("Username is mandatory.")
                elif username in st.session_state['usernames']:
                    errors.append(f"Username '{username}' is already taken.")

                # Email Validation
                if not email:
                    errors.append("Email is mandatory.")
                elif not is_valid_email(email):
                    errors.append("Invalid Email format (e.g. user@domain.com).")
                elif email in st.session_state['users']:
                    errors.append(f"Email '{email}' is already registered.")

                # Password Validation
                if not password:
                    errors.append("Password is mandatory.")
                elif not is_valid_password(password):
                    errors.append("Password must be at least 8 characters long and contain only alphanumeric characters.")

                # Confirm Password
                if password != confirm_password:
                    errors.append("Passwords do not match.")
                    # Security Question Validation
                if security_question == "SELECT QUESTION":
                  errors.append("Please select a security question.")
                    # Security Answer Validation
                if not security_answer:
                  errors.append("Security answer is mandatory.")

                if errors:
                    for error in errors:
                        st.error(error)
                else:
                    # Success
                    st.session_state['users'][email] = {'password': password,'username': username,'security_question': security_question,'security_answer': security_answer.lower().strip()}

                    st.session_state['usernames'].add(username)

                    # Auto-login after signup
                    token = create_access_token({"sub": email, "username": username})
                    st.session_state['jwt_token'] = token
                    st.success("Account created successfully!")
                    time.sleep(1)
                    st.rerun()

        st.markdown("---")
        if st.button("Back to Login"):
            st.session_state['page'] = 'login'
            st.rerun()
def forgot_password_page():
    st.title("Reset Password")

    if "reset_email" not in st.session_state:
        st.session_state["reset_email"] = None

    if "allow_password_reset" not in st.session_state:
        st.session_state["allow_password_reset"] = False

    # STEP 1: Enter Email
    if not st.session_state["reset_email"]:
        email = st.text_input("Enter your registered Email")

        if st.button("Verify Email"):
            if email in st.session_state["users"]:
                st.session_state["reset_email"] = email
                st.rerun()
            else:
                st.error("Email not found")

    # STEP 2: Show Security Question
    else:
        email = st.session_state["reset_email"]
        user_data = st.session_state["users"][email]

        st.write("Security Question:")
        st.info(user_data["security_question"])

        answer = st.text_input("Enter your Answer")

        if st.button("Submit Answer"):
            if answer.lower().strip() == user_data["security_answer"]:
                st.session_state["allow_password_reset"] = True
                st.success("Answer verified!")
            else:
                st.error("Incorrect answer")

        # STEP 3: Reset Password
        if st.session_state["allow_password_reset"]:
            new_password = st.text_input("New Password", type="password")

            if st.button("Update Password"):
                if is_valid_password(new_password):
                    st.session_state["users"][email]["password"] = new_password

                    # Issue new JWT
                    token = create_access_token({
                        "sub": email,
                        "username": user_data["username"]
                    })
                    st.session_state["jwt_token"] = token

                    st.success("Password updated successfully!")
                    st.session_state["reset_email"] = None
                    st.session_state["allow_password_reset"] = False
                    st.session_state["page"] = "login"
                    st.rerun()
                else:
                    st.error("Password must be minimum 8 characters and alphanumeric")

def dashboard_page():
    token = st.session_state.get('jwt_token')
    payload = verify_token(token)

    if not payload:
        st.session_state['jwt_token'] = None
        st.warning("Session expired or invalid. Please login again.")
        time.sleep(1)
        st.rerun()
        return
    username = payload.get("username", "User")

    with st.sidebar:
        st.title("🤖 LLM")
        st.markdown("---")
        if st.button("➕ New Chat", use_container_width=True):
             st.info("Started new chat!")

        st.markdown("### History")
        st.markdown("- Project analysis")
        st.markdown("- NLP")
        st.markdown("---")
        st.markdown("### Settings")
        if st.button("Logout", use_container_width=True):
            st.session_state['jwt_token'] = None
            st.rerun()
    # Main Content - Chat Interface
    st.title(f"Welcome, {username}!")
    st.markdown("### How can I help you today?")

    # Chat container (Simple simulation)
    chat_placeholder = st.empty()

    with chat_placeholder.container():
        st.markdown('<div class="bot-msg">Hello! I am LLM. Ask me anything about LLM!</div>', unsafe_allow_html=True)
        # Assuming we might store chat history in session state later

    # User input area at bottom
    with st.form(key='chat_form', clear_on_submit=True):
        col1, col2 = st.columns([6, 1])
        with col1:
            user_input = st.text_input("Message LLM...", placeholder="Ask me anything about LLM...", label_visibility="collapsed")
        with col2:
            submit_button = st.form_submit_button("Send")

        if submit_button and user_input:
             # Just append messages visually for demo
             st.markdown(f'<div class="user-msg">{user_input}</div>', unsafe_allow_html=True)
             st.markdown('<div class="bot-msg">I am a demo bot. I received your message!</div>', unsafe_allow_html=True)
# --- Main App Logic ---
token = st.session_state.get('jwt_token')
if token:
    if verify_token(token):
        dashboard_page()
    else:
        st.session_state['jwt_token'] = None
        st.session_state['page'] = 'login'
        st.rerun()
else:
    if st.session_state['page'] == 'signup':
        signup_page()
    elif st.session_state['page'] == 'forgot':
        forgot_password_page()
    else:
        login_page()

with open("app.py", "w") as f:
    f.write(app_code)
print("Streamlit app code written to 'app.py'")
