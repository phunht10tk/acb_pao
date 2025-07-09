from flask import Flask, request, jsonify
from dotenv import load_dotenv
from ldap3 import Server, Connection, ALL, NTLM
import boto3
import os

load_dotenv()

app = Flask(__name__)

# Load AD credentials
AD_USERNAME = os.getenv("AD_USERNAME")
AD_PASSWORD = os.getenv("AD_PASSWORD")
AD_DOMAIN = os.getenv("AD_DOMAIN")
AD_SERVER = os.getenv("AD_SERVER")

def authenticate_ad(username, password):
    try:
        server = Server(AD_SERVER, get_info=ALL)
        user_dn = f"{AD_DOMAIN}\\{username}"
        conn = Connection(server, user=user_dn, password=password, authentication=NTLM)
        if conn.bind():
            conn.unbind()
            return True
        else:
            return False
    except Exception as e:
        print("AD auth error:", e)
        return False

def get_aws_identity(profile_name="acb-pao"):
    session = boto3.Session(profile_name=profile_name)
    sts = session.client('sts')
    return sts.get_caller_identity()

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    if authenticate_ad(username, password):
        try:
            identity = get_aws_identity()
            return jsonify({
                "message": "Login successful",
                "aws_user": identity
            })
        except Exception as e:
            return jsonify({
                "message": "AD login OK, but AWS failed",
                "error": str(e)
            }), 500
    else:
        return jsonify({"error": "Invalid AD credentials"}), 401

@app.route('/')
def index():
    return '''
        <h2>ACB PAO Login</h2>
        <form method="post" action="/login" enctype="application/json">
            Use curl or Postman to test login: POST /login with JSON {"username": "yourname", "password": "yourpass"}
        </form>
    '''

if __name__ == '__main__':
    app.run(debug=True)
