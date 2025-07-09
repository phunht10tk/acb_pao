from flask import Flask, request, jsonify
import os
import logging
from msal import ConfidentialClientApplication
from ldap3 import Server, Connection, ALL, NTLM
from dotenv import load_dotenv

# Load .env variables
load_dotenv()

# Flask setup
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# === Azure AD Certificate Auth ===
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
AZURE_CERT_PATH = os.getenv("AZURE_CERT_PATH", "cert.pem")
AZURE_CERT_THUMBPRINT = os.getenv("AZURE_CERT_THUMBPRINT")
AZURE_SCOPE = ["https://graph.microsoft.com/.default"]

# === AD LDAP Settings ===
AD_DOMAIN = os.getenv("AD_DOMAIN", "acb.com.vn")
AD_SERVER = os.getenv("AD_SERVER", "ldap://ad.acb.com.vn")

def load_certificate(path):
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception as e:
        logging.error(f"Failed to read certificate: {e}")
        return None

def authenticate_azure_cert():
    private_key = load_certificate(AZURE_CERT_PATH)
    if not private_key:
        return None

    authority = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}"
    try:
        app_msal = ConfidentialClientApplication(
            client_id=AZURE_CLIENT_ID,
            authority=authority,
            client_credential={
                "private_key": private_key,
                "thumbprint": AZURE_CERT_THUMBPRINT
            }
        )

        result = app_msal.acquire_token_for_client(scopes=AZURE_SCOPE)

        if "access_token" in result:
            logging.info("Azure certificate login successful")
            return result["access_token"]
        else:
            logging.error(f"Azure auth failed: {result.get('error_description')}")
            return None
    except Exception as e:
        logging.exception("Exception during Azure auth")
        return None

def authenticate_ad_ldap(username, password):
    if not username or not password:
        return False

    try:
        server = Server(AD_SERVER, get_info=ALL)
        user_dn = f"{AD_DOMAIN}\\{username}"
        conn = Connection(server, user=user_dn, password=password, authentication=NTLM)
        if conn.bind():
            logging.info(f"LDAP auth successful for {username}")
            conn.unbind()
            return True
        else:
            logging.warning(f"LDAP auth failed for {username}")
            return False
    except Exception as e:
        logging.exception("LDAP authentication error")
        return False

@app.route('/login', methods=['POST'])
def login():
    data = request.json or {}

    username = data.get("username")
    password = data.get("password")

    if username and password:
        # LDAP login path
        if authenticate_ad_ldap(username, password):
            return jsonify({
                "message": "Authenticated via Active Directory LDAP",
                "user": username
            })
        else:
            return jsonify({"error": "Invalid AD credentials"}), 401
    else:
        # Azure certificate login path
        token = authenticate_azure_cert()
        if token:
            return jsonify({
                "message": "Authenticated via Azure Certificate",
                "access_token": token
            })
        else:
            return jsonify({"error": "Azure certificate authentication failed"}), 401

@app.route('/')
def index():
    return "ACB PAO Login Service — Azure AD & LDAP Authentication"

if __name__ == '__main__':
    app.run(debug=True)
