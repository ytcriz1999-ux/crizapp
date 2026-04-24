import os
from flask import Flask, render_template, request, redirect, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = "super_secret_key_change_this"

# ================= SECURITY SESSION =================
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# ================= DATABASE (SQLite) =================
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///videoweb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ================= UPLOAD =================
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ================= MODELS =================
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")

class Video(db.Model):
    __tablename__ = "video"
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# ================= INIT DB =================
with app.app_context():
    db.create_all()

# ================= LOGIN REQUIRED =================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect("/")
        return f(*args, **kwargs)
    return wrapper

# ================= ADMIN ONLY =================
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = User.query.get(session.get("user"))
        if not user or user.role != "admin":
            return "Access denied"
        return f(*args, **kwargs)
    return wrapper

# ================= REGISTER =================
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":

        username = request.form["username"].strip().lower()
        password = request.form["password"]

        if User.query.filter_by(username=username).first():
            return "User already exists"

        hashed = generate_password_hash(password, method="pbkdf2:sha256")

        user = User(username=username, password=hashed)
        db.session.add(user)
        db.session.commit()

        return redirect("/")

    return render_template("register.html")

# ================= LOGIN =================
@app.route("/", methods=["GET","POST"])
def login():
    if request.method == "POST":

        username = request.form["username"].strip().lower()
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session["user"] = user.id
            session["role"] = user.role
            return redirect("/dashboard")

        return "Invalid login"

    return render_template("login.html")

# ================= DASHBOARD =================
@app.route("/dashboard")
@login_required
def dashboard():

    user_id = session["user"]
    videos = Video.query.filter_by(user_id=user_id).all()

    return render_template("dashboard.html", videos=videos)

# ================= ADMIN =================
@app.route("/admin")
@login_required
@admin_required
def admin():

    users = User.query.all()
    videos = Video.query.all()

    return render_template("admin.html", users=users, videos=videos)

# ================= UPLOAD =================
@app.route("/upload", methods=["GET","POST"])
@login_required
def upload():

    if request.method == "POST":

        file = request.files["video"]

        if file and file.filename:
            filename = secure_filename(file.filename)

            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

            video = Video(filename=filename, user_id=session["user"])
            db.session.add(video)
            db.session.commit()

        return redirect("/dashboard")

    return render_template("upload.html")

# ================= STREAM VIDEO =================
@app.route("/uploads/<filename>")
@login_required
def stream(filename):

    video = Video.query.filter_by(
        filename=filename,
        user_id=session["user"]
    ).first()

    if not video:
        return "Access denied"

    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# ================= DELETE =================
@app.route("/delete/<int:id>")
@login_required
def delete(id):

    video = Video.query.get(id)

    if video and video.user_id == session["user"]:

        path = os.path.join(app.config["UPLOAD_FOLDER"], video.filename)
        if os.path.exists(path):
            os.remove(path)

        db.session.delete(video)
        db.session.commit()

    return redirect("/dashboard")

# ================= LOGOUT =================
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True)