import os
import sqlite3
import uuid
from datetime import datetime, timezone
from functools import wraps
from dotenv import load_dotenv
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_from_directory,
    abort
)
from flask_wtf import FlaskForm, CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is missing from .env")

if not ADMIN_USERNAME:
    raise RuntimeError("ADMIN_USERNAME is missing from .env")

if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD is missing from .env")


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = SECRET_KEY

# Maximum upload size: 50 MB
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

# Secure session configuration
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# For local HTTP development this is False.
# Set SESSION_COOKIE_SECURE=True when running behind HTTPS.
app.config["SESSION_COOKIE_SECURE"] = os.getenv(
    "SESSION_COOKIE_SECURE", "False"
).lower() == "true"


# ============================================================
# CSRF PROTECTION
# ============================================================

csrf = CSRFProtect(app)


# ============================================================
# FILE CONFIGURATION
# ============================================================

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Uploaded files are stored OUTSIDE static/
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# Change this list whenever you want to allow different extensions.
ALLOWED_EXTENSIONS = {
    "pdf",
    "txt",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "jpg",
    "jpeg",
    "png",
    "zip",
    "json",
    "py",
    "csv",
}


# ============================================================
# DATABASE
# ============================================================

DATABASE = os.path.join(BASE_DIR, "database.db")


def get_db():
    """Create and return a SQLite database connection."""

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    return connection


def init_database():
    """Create the files table if it does not already exist."""

    connection = get_db()

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL UNIQUE,
            file_size INTEGER NOT NULL,
            upload_time TEXT NOT NULL
        )
        """
    )

    connection.commit()
    connection.close()


# ============================================================
# FORMS
# ============================================================

class LoginForm(FlaskForm):
    username = StringField(
        "Admin ID",
        validators=[DataRequired()]
    )

    password = PasswordField(
        "Password",
        validators=[DataRequired()]
    )

    submit = SubmitField("Login")


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def allowed_file(filename):
    """Check whether the uploaded file has an allowed extension."""

    if not filename:
        return False

    if "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()

    return extension in ALLOWED_EXTENSIONS


def admin_required(function):
    """
    Protect an admin route.

    If the user is not authenticated, send them to the
    admin login page.
    """

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if not session.get("admin_authenticated"):
            return redirect(url_for("admin_login"))

        return function(*args, **kwargs)

    return decorated_function


# ============================================================
# SECURITY HEADERS
# ============================================================

@app.after_request
def add_security_headers(response):

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Prevent browsers from caching admin pages.
    if request.path.startswith("/admin"):
        response.headers["Cache-Control"] = "no-store"

    return response


# ============================================================
# PUBLIC USER PAGE
# ============================================================

@app.route("/")
def upload_page():

    return render_template("upload.html")


# ============================================================
# FILE UPLOAD
# ============================================================

@app.route("/upload", methods=["POST"])
def upload_file():

    if "file" not in request.files:
        flash("Please select a file.", "error")
        return redirect(url_for("upload_page"))

    uploaded_file = request.files["file"]

    if uploaded_file.filename == "":
        flash("Please select a file.", "error")
        return redirect(url_for("upload_page"))

    # Check extension
    if not allowed_file(uploaded_file.filename):
        flash(
            "This file type is not allowed.",
            "error"
        )
        return redirect(url_for("upload_page"))

    # Sanitize original filename
    original_filename = secure_filename(uploaded_file.filename)

    if not original_filename:
        flash("Invalid filename.", "error")
        return redirect(url_for("upload_page"))

    # Generate a random server-side filename.
    # The original filename is NEVER used as the physical filename.
    extension = original_filename.rsplit(".", 1)[1].lower()

    stored_filename = f"{uuid.uuid4().hex}.{extension}"

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        stored_filename
    )

    try:

        uploaded_file.save(file_path)

        # Determine actual stored file size
        file_size = os.path.getsize(file_path)

        upload_time = datetime.now(
            timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")

        connection = get_db()

        connection.execute(
            """
            INSERT INTO files (
                original_filename,
                stored_filename,
                file_size,
                upload_time
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                original_filename,
                stored_filename,
                file_size,
                upload_time,
            ),
        )

        connection.commit()
        connection.close()

    except Exception:

        # If database insertion fails after saving the file,
        # remove the file so we don't leave an orphaned upload.
        if os.path.exists(file_path):
            os.remove(file_path)

        app.logger.exception("File upload failed.")

        flash(
            "The file could not be uploaded.",
            "error"
        )

        return redirect(url_for("upload_page"))

    flash(
        "File uploaded successfully.",
        "success"
    )

    return redirect(url_for("upload_page"))


# ============================================================
# ADMIN LOGIN
# ============================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    # Already logged in
    if session.get("admin_authenticated"):
        return redirect(url_for("admin_dashboard"))

    form = LoginForm()

    if form.validate_on_submit():

        username = form.username.data
        password = form.password.data

        # Hash the environment password for comparison.
        # The password itself is never stored in the database.
        password_hash = generate_password_hash(
            ADMIN_PASSWORD
        )

        username_correct = username == ADMIN_USERNAME

        password_correct = check_password_hash(
            password_hash,
            password
        )

        if username_correct and password_correct:

            # Clear old session data before creating authenticated session
            session.clear()

            session["admin_authenticated"] = True

            return redirect(
                url_for("admin_dashboard")
            )

        flash(
            "Invalid admin ID or password.",
            "error"
        )

    return render_template(
        "admin_login.html",
        form=form
    )


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():

    connection = get_db()

    files = connection.execute(
        """
        SELECT
            id,
            original_filename,
            file_size,
            upload_time
        FROM files
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return render_template(
        "admin_dashboard.html",
        files=files
    )


# ============================================================
# ADMIN FILE DOWNLOAD
# ============================================================

@app.route("/admin/download/<int:file_id>")
@admin_required
def download_file(file_id):

    connection = get_db()

    file_record = connection.execute(
        """
        SELECT stored_filename, original_filename
        FROM files
        WHERE id = ?
        """,
        (file_id,)
    ).fetchone()

    connection.close()

    if file_record is None:
        abort(404)

    stored_filename = file_record["stored_filename"]
    original_filename = file_record["original_filename"]

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        stored_filename,
        as_attachment=True,
        download_name=original_filename
    )


# ============================================================
# ADMIN DELETE
# ============================================================

@app.route("/admin/delete/<int:file_id>", methods=["POST"])
@admin_required
def delete_file(file_id):

    connection = get_db()

    file_record = connection.execute(
        """
        SELECT stored_filename
        FROM files
        WHERE id = ?
        """,
        (file_id,)
    ).fetchone()

    if file_record is None:

        connection.close()

        flash(
            "File not found.",
            "error"
        )

        return redirect(
            url_for("admin_dashboard")
        )

    stored_filename = file_record["stored_filename"]

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        stored_filename
    )

    try:

        # Delete physical file
        if os.path.exists(file_path):
            os.remove(file_path)

        # Delete database record
        connection.execute(
            """
            DELETE FROM files
            WHERE id = ?
            """,
            (file_id,)
        )

        connection.commit()

        flash(
            "File deleted successfully.",
            "success"
        )

    except Exception:

        connection.rollback()

        app.logger.exception(
            "File deletion failed."
        )

        flash(
            "The file could not be deleted.",
            "error"
        )

    finally:
        connection.close()

    return redirect(
        url_for("admin_dashboard")
    )


# ============================================================
# ADMIN LOGOUT
# ============================================================

@app.route("/admin/logout")
def admin_logout():

    session.clear()

    return redirect(
        url_for("admin_login")
    )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(413)
def file_too_large(error):

    flash(
        "File is too large. Maximum allowed size is 50 MB.",
        "error"
    )

    return redirect(
        url_for("upload_page")
    )


@app.errorhandler(404)
def page_not_found(error):

    return "Page not found.", 404


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    init_database()

    app.run(
        debug=False,
        host="0.0.0.0",
        port=5000
    )