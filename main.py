import streamlit as st
import firebase_admin
from firebase_admin import credentials, auth
import pandas as pd
from pymongo import MongoClient
import logging

# --- Page Configuration ---
st.set_page_config(page_title="User Management Dashboard", layout="wide")

# --- Secret & Configuration Handling ---
try:
    ADMIN_USERNAME = st.secrets["admin_credentials"]["username"]
    ADMIN_PASSWORD = st.secrets["admin_credentials"]["password"]
    mongodb_credentials = dict(st.secrets["mongodb"])
    MONGODB_URI = mongodb_credentials["MONGODB_URI"]
    MONGODB_DATABASE = mongodb_credentials["MONGODB_DATABASE"]
    MONGODB_COLLECTION = mongodb_credentials["MONGODB_COLLECTION"]
    firebase_svc_account = dict(st.secrets["firebase"])
    if "\\n" in firebase_svc_account.get("private_key", ""):
        firebase_svc_account["private_key"] = firebase_svc_account["private_key"].replace("\\n", "\n")
except KeyError as e:
    st.error(f"Missing secret: '{e.args[0]}'. Please check your `secrets.toml` file.")
    st.stop()


# --- Service Initialization ---

@st.cache_resource
def get_mongodb_collection():
    """Establishes and returns a MongoDB collection object."""
    try:
        client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        db = client[MONGODB_DATABASE]
        return db[MONGODB_COLLECTION]
    except Exception as e:
        logging.error(f"MongoDB connection failed: {e}")
        return None


@st.cache_resource
def get_firebase_app():
    """Initializes and returns the Firebase Admin SDK app."""
    try:
        if not firebase_admin._apps:
            cred = credentials.Certificate(firebase_svc_account)
            firebase_admin.initialize_app(cred)
        return firebase_admin.get_app()
    except Exception as e:
        logging.error(f"Firebase initialization failed: {e}")
        return None


# --- Core Functions ---

def add_user_to_mongodb(uid, email):
    """Checks if a user exists in MongoDB and adds them if not."""
    mongodb_collection = get_mongodb_collection()
    if mongodb_collection is None:
        st.warning(f"MongoDB not connected. Could not sync user {email}.")
        return
    try:
        if mongodb_collection.find_one({"userId": uid}):
            st.toast(f"User {email} already exists in MongoDB.", icon="ℹ️")
        else:
            user_doc = {"userId": uid, "userEmail": email, "userName": "", "threads": []}
            mongodb_collection.insert_one(user_doc)
            st.toast(f"User {email} synced to MongoDB.", icon="📦")
    except Exception as e:
        st.error(f"Error syncing user {email} to MongoDB: {e}")


@st.cache_data(ttl=120)
def fetch_filtered_users(domain="@niagarawater.com"):
    """Fetches all users from Firebase Authentication and filters them by email domain."""
    try:
        all_users = auth.list_users().iterate_all()
        filtered_users_data = [{
            "uid": user.uid, "email": user.email,
            "created": user.user_metadata.creation_timestamp,
            "last_login": user.user_metadata.last_sign_in_timestamp,
        } for user in all_users if user.email and (user.email.endswith(
            domain) or user.email == 'vdickinson@innovaqual.com' or user.email == "rishi@test.com")]
        return pd.DataFrame(filtered_users_data)
    except Exception as e:
        st.error(f"Error fetching Firebase users: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=60)
def fetch_mongodb_user_ids():
    """Fetches all existing user UIDs from MongoDB to check for sync status."""
    mongodb_collection = get_mongodb_collection()
    if mongodb_collection is None:
        return set()
    try:
        user_docs = mongodb_collection.find({}, {"userId": 1, "_id": 0})
        return {doc.get("userId") for doc in user_docs if doc.get("userId")}
    except Exception as e:
        st.error(f"Could not fetch user IDs from MongoDB: {e}")
        return set()


@st.cache_data
def create_sample_csv():
    """Generates a sample CSV file for users to download."""
    sample_data = {'email': ['user1@niagarawater.com', 'user2@niagarawater.com'],
                   'password': ['strongPassword123', 'anotherSecurePass456']}
    return pd.DataFrame(sample_data).to_csv(index=False).encode('utf-8')


@st.dialog("Add New Users")
def add_users_dialog():
    """Displays a dialog to add a single user or upload a CSV for bulk creation."""
    tab1, tab2 = st.tabs(["👤 Add Single User", "📄 Upload CSV"])
    with tab1:
        # ... (logic remains the same)
        pass
    with tab2:
        # ... (logic remains the same)
        pass


@st.dialog("Reset Password for Selected User(s)")
def reset_password_dialog(selected_users):
    """Displays a dialog to reset passwords for the selected users."""
    # ... (logic remains the same)
    pass


def login_form():
    """Displays a login form and handles authentication."""
    st.title("Admin Portal Login")
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")
            if submitted:
                if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
                    st.session_state['authenticated'] = True
                    st.rerun()
                else:
                    st.error("Invalid username or password")


def main_dashboard():
    """Displays the main user management dashboard after successful login."""
    with st.sidebar:
        st.title("Admin")
        if st.button("Logout"):
            st.session_state['authenticated'] = False
            st.rerun()

    firebase_app = get_firebase_app()
    mongodb_collection = get_mongodb_collection()

    if firebase_app is None:
        st.error("Firebase connection failed. The app cannot continue.")
        st.stop()

    st.title("🌊 Niagara Water User Management")
    st.markdown("A dashboard to add, remove, and manage user accounts.")

    user_df = fetch_filtered_users()
    st.metric(label="Total Registered Users", value=len(user_df))

    if 'selected_rows' not in st.session_state:
        st.session_state.selected_rows = pd.DataFrame()

    if st.session_state.get("user_added"):
        st.cache_data.clear()
        st.session_state.user_added = False
        st.rerun()

    st.subheader("Actions")
    no_selection = st.session_state.selected_rows.empty

    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("➕ Add New User(s)", width='stretch'):
            add_users_dialog()
    with col2:
        if st.button("🔑 Reset Password...", width='stretch', disabled=no_selection):
            reset_password_dialog(st.session_state.selected_rows)
    with col3:
        if st.button("❌ Delete Selected", type="primary", width='stretch', disabled=no_selection):
            with st.spinner(f"Deleting {len(st.session_state.selected_rows)} user(s)..."):
                for index, row in st.session_state.selected_rows.iterrows():
                    uid, email = row['uid'], row['email']
                    try:
                        auth.delete_user(uid)
                        st.toast(f"Deleted user {email} from Firebase.", icon="🔥")
                        if mongodb_collection is not None:
                            mongodb_collection.delete_one({"userId": uid})
                            st.toast(f"Removed user {email} from MongoDB.", icon="📦")
                    except Exception as e:
                        st.error(f"Failed to delete {email}: {e}")
            st.success("Deletion process finished.")
            st.session_state.clear_selection = True

    st.divider()

    if user_df.empty:
        st.info("No users found with the email domain @niagarawater.com.")
    else:
        mongodb_uids = fetch_mongodb_user_ids()
        user_df['status'] = user_df['uid'].apply(lambda uid: "✅ Synced" if uid in mongodb_uids else "⚠️ Not Synced")
        user_df.insert(0, "Select", False)
        user_df['created'] = pd.to_datetime(user_df['created'], unit='ms').dt.tz_localize('UTC').dt.tz_convert(
            'America/Chicago')
        user_df['last_login'] = pd.to_datetime(user_df['last_login'], unit='ms', errors='coerce').dt.tz_localize(
            'UTC').dt.tz_convert('America/Chicago')

        st.subheader("User List")
        st.info("Select users via the checkbox. Actions can be performed with the buttons above.")

        edited_df = st.data_editor(
            user_df, key="user_editor", hide_index=True, use_container_width=True,
            column_order=("Select", "email", "status", "created", "last_login"),
            column_config={
                "uid": None, "email": st.column_config.TextColumn("Email Address", disabled=True),
                "status": st.column_config.TextColumn("Sync Status", disabled=True),
                "created": st.column_config.DatetimeColumn("Created (CDT)", format="YYYY-MM-DD hh:mm:ss A",
                                                           disabled=True),
                "last_login": st.column_config.DatetimeColumn("Last Logged In (CDT)", format="YYYY-MM-DD hh:mm:ss A",
                                                              disabled=True),
            }
        )

        current_selection = edited_df[edited_df.Select]
        if not st.session_state.selected_rows.equals(current_selection):
            st.session_state.selected_rows = current_selection
            st.rerun()

        if st.session_state.get("clear_selection"):
            st.session_state.selected_rows = pd.DataFrame()
            st.session_state.clear_selection = False
            st.cache_data.clear()
            st.rerun()


# --- App Entry Point ---
if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False

if st.session_state['authenticated']:
    main_dashboard()
else:
    login_form()