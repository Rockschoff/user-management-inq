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
            domain))]
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


# --- FIX: Removed the 'mongodb_collection' parameter from the function signature ---
@st.dialog("Add New Users")
def add_users_dialog():
    """Displays a dialog to add a single user or upload a CSV for bulk creation."""
    tab1, tab2 = st.tabs(["👤 Add Single User", "📄 Upload CSV"])

    with tab1:
        st.write("Enter the new user's email and an initial password.")
        with st.form("new_user_form"):
            email = st.text_input("User Email")
            password = st.text_input("Initial Password", type="password")
            submitted = st.form_submit_button("Create User")
            if submitted:
                if not email or not password:
                    st.warning("Email and password cannot be empty.")
                    return
                if not email.endswith("@niagarawater.com"):
                    st.warning("Email must end with @niagarawater.com")
                    return
                try:
                    user = auth.create_user(email=email, password=password)
                    st.success(f"Successfully created user: {user.email}")
                    # --- FIX: Corrected the function call to pass only required arguments ---
                    add_user_to_mongodb(user.uid, user.email)
                    st.session_state.user_added = True
                except Exception as e:
                    st.error(f"Failed to create user: {e}")

    with tab2:
        st.info(
            """
            **Instructions for CSV Upload:**
            1.  Your CSV file **must** contain two columns: `email` and `password`.
            2.  The column headers must be in lowercase.
            3.  All emails should end with `@niagarawater.com`.
            """
        )
        st.download_button(
            label="Download Sample CSV",
            data=create_sample_csv(),
            file_name='sample_users.csv',
            mime='text/csv',
        )
        uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
        if uploaded_file is not None:
            if st.button("Create Users from CSV", type="primary", width='stretch'):
                try:
                    df = pd.read_csv(uploaded_file)
                    if not {'email', 'password'}.issubset(df.columns):
                        st.error("CSV must contain 'email' and 'password' columns.")
                        return

                    users_to_create = df.to_dict('records')
                    success_count = 0
                    errors = []
                    progress_text = "Starting user creation..."
                    bar = st.progress(0, text=progress_text)

                    for i, user_data in enumerate(users_to_create):
                        email = user_data.get('email')
                        password = user_data.get('password')
                        progress_text = f"Creating user ({i + 1}/{len(users_to_create)}): {email}"
                        bar.progress((i + 1) / len(users_to_create), text=progress_text)

                        if not email or not password or not isinstance(email, str):
                            errors.append((email or "N/A", "Row is missing email or password."))
                            continue
                        if not email.endswith("@niagarawater.com"):
                            errors.append((email, "Email does not have the required @niagarawater.com domain."))
                            continue

                        try:
                            auth.create_user(email=email, password=str(password))
                            success_count += 1
                            new_user = auth.get_user_by_email(email)
                            # --- FIX: Corrected the function call here as well ---
                            add_user_to_mongodb(new_user.uid, new_user.email)
                        except Exception as e:
                            errors.append((email, str(e)))

                    bar.empty()
                    st.success(f"Process complete. Successfully created {success_count} user(s).")
                    if errors:
                        st.warning(f"Failed to create {len(errors)} user(s). See details below.")
                        with st.expander("View Error Details"):
                            error_df = pd.DataFrame(errors, columns=['Email', 'Error'])
                            st.dataframe(error_df, use_container_width=True)
                    st.session_state.user_added = True
                except Exception as e:
                    st.error(f"An error occurred while processing the file: {e}")


@st.dialog("Reset Password for Selected User(s)")
def reset_password_dialog(selected_users):
    """Displays a dialog to reset passwords for the selected users."""
    user_count = len(selected_users)
    st.write(f"You are resetting passwords for **{user_count}** user(s):")
    for email in selected_users["email"]:
        st.markdown(f"- `{email}`")

    action = st.radio(
        "Choose a reset method:",
        ["Send a password reset link", "Set a new temporary password"],
        key="reset_action", horizontal=True
    )
    new_password = None
    if "Set a new temporary password" in action:
        new_password = st.text_input("Enter new temporary password", type="password")
    if st.button("Confirm and Proceed", type="primary"):
        if "Set a new temporary password" in action and not new_password:
            st.warning("Please enter a new password.")
            return
        with st.spinner("Processing password resets..."):
            for index, user in selected_users.iterrows():
                uid, email = user["uid"], user["email"]
                try:
                    if "Set a new temporary password" in action:
                        auth.update_user(uid, password=new_password)
                        st.toast(f"Password updated for {email}.", icon="✅")
                    else:
                        auth.generate_password_reset_link(email)
                        st.toast(f"Reset link sent to {email}.", icon="📧")
                except Exception as e:
                    st.error(f"Failed for {email}: {e}")
        st.success("Password reset process complete.")
        st.session_state.clear_selection = True


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
        user_df['created'] = pd.to_datetime(user_df['created'], unit='ms').dt.tz_localize('UTC').dt.tz_convert('America/Chicago')
        user_df['last_login'] = pd.to_datetime(user_df['last_login'], unit='ms', errors='coerce').dt.tz_localize('UTC').dt.tz_convert('America/Chicago')

        st.subheader("User List")
        st.info("Select users via the checkbox. Actions can be performed with the buttons above.")

        edited_df = st.data_editor(
            user_df, key="user_editor", hide_index=True, use_container_width=True,
            column_order=("Select", "email", "status", "created", "last_login"),
            column_config={
                "uid": None, "email": st.column_config.TextColumn("Email Address", disabled=True),
                "status": st.column_config.TextColumn("Sync Status", disabled=True),
                "created": st.column_config.DatetimeColumn("Created (CDT)", format="YYYY-MM-DD hh:mm:ss A", disabled=True),
                "last_login": st.column_config.DatetimeColumn("Last Logged In (CDT)", format="YYYY-MM-DD hh:mm:ss A", disabled=True),
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