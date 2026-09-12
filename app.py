import os
import re
import requests
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-in-production")
database_url = os.environ.get("DATABASE_URL", "sqlite:///zkb.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=os.environ.get("GOOGLE_CLIENT_ID", ""),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET", ""),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)
    provider = db.Column(db.String(20), default="email")

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

with app.app_context():
    db.create_all()

LANGUAGE_IDS = {71: "python", 63: "javascript", 54: "cpp"}
MAX_CODE_SIZE = 100 * 1024

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/run-code", methods=["POST"])
def run_code():
    data = request.get_json(silent=True) or {}
    code = data.get("source_code", "")
    language_id = data.get("language_id")
    if not isinstance(code, str) or not code.strip():
        return jsonify({"error": "Source code is empty."}), 400
    if len(code.encode("utf-8")) > MAX_CODE_SIZE:
        return jsonify({"error": "Code is too large. Maximum size is 100 KB."}), 413
    try:
        language_id = int(language_id)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid language."}), 400
    if language_id not in LANGUAGE_IDS:
        return jsonify({"error": "Unsupported language."}), 400

    try:
        response = requests.post(
            "https://ce.judge0.com/submissions?wait=true",
            json={"language_id": language_id, "source_code": code},
            headers={"Content-Type": "application/json"},
            timeout=35,
        )
        response.raise_for_status()
        return jsonify(response.json())
    except requests.Timeout:
        return jsonify({"error": "Code runner timed out. Please try again."}), 504
    except requests.RequestException as exc:
        return jsonify({"error": f"Code runner unavailable: {exc}"}), 502

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        email = str(data.get("email", "")).strip().lower()
        password = data.get("password", "")
        if not email or not password:
            return jsonify({"success": False, "message": "Email and password are required."}), 400
        user = User.query.filter_by(email=email).first()
        if user and user.password and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return jsonify({"success": True, "message": "Logged in successfully!", "username": user.username})
        return jsonify({"success": False, "message": "Invalid email or password."}), 401
    return render_template("login.html") if os.path.exists(os.path.join(app.root_path, "templates", "login.html")) else redirect(url_for("home"))

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")
    if not username or not email or not password:
        return jsonify({"success": False, "message": "All fields are required."}), 400
    if len(username) < 3 or len(username) > 50:
        return jsonify({"success": False, "message": "Username must be 3–50 characters."}), 400
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({"success": False, "message": "Enter a valid email address."}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters."}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"success": False, "message": "Username already exists."}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"success": False, "message": "Email already registered."}), 409
    try:
        user = User(username=username, email=email, password=bcrypt.generate_password_hash(password).decode("utf-8"), provider="email")
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return jsonify({"success": True, "message": "Account created successfully!", "username": username})
    except Exception:
        db.session.rollback()
        return jsonify({"success": False, "message": "Registration error."}), 500

@app.route("/login/google")
def google_login():
    if not os.environ.get("GOOGLE_CLIENT_ID") or not os.environ.get("GOOGLE_CLIENT_SECRET"):
        return redirect(url_for("home"))
    redirect_uri = url_for("google_authorize", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/authorize/google")
def google_authorize():
    try:
        token = google.authorize_access_token()
        user_info = token.get("userinfo") or {}
        email = str(user_info.get("email", "")).strip().lower()
        if not email:
            return redirect(url_for("home"))
        username = str(user_info.get("name") or email.split("@")[0]).strip()[:50]
        user = User.query.filter_by(email=email).first()
        if not user:
            base = username or "zkbuser"
            username = base
            n = 1
            while User.query.filter_by(username=username).first():
                n += 1
                username = f"{base[:45]}{n}"
            user = User(username=username, email=email, password=None, provider="google")
            db.session.add(user)
            db.session.commit()
        login_user(user)
    except Exception:
        pass
    return redirect(url_for("home"))

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return jsonify({"success": True, "message": "Logged out successfully!"})

@app.route("/user-status")
def user_status():
    if current_user.is_authenticated:
        return jsonify({"authenticated": True, "username": current_user.username, "provider": current_user.provider})
    return jsonify({"authenticated": False})

if __name__ == "__main__":
    app.run(debug=True)
