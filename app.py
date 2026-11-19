import os
import re
import time
import uuid
import sqlite3
from functools import wraps
from flask import Flask, request, jsonify, render_template, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))

is_production = bool(os.environ.get("RENDER") or os.environ.get("HTTPS_ONLY"))

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=is_production,
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
)

ADMIN_PASSWORD_HASH = generate_password_hash(
    os.environ.get("ADMIN_PASS", "12345678")
)

DB_PATH = "planner.db"
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
ALLOWED_PLANS = {"3m_350da", "1y_700da"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

FAILED_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                plan TEXT DEFAULT '3m_350da',
                receipt_file TEXT,
                active INTEGER DEFAULT 0,
                session_token TEXT,
                last_ip TEXT,
                user_agent TEXT,
                last_login TEXT,
                login_count INTEGER DEFAULT 0,
                study_data TEXT DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        existing_cols = [
            r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()
        ]
        migrations = [
            ("plan", "TEXT DEFAULT '3m_350da'"),
            ("last_ip", "TEXT"),
            ("user_agent", "TEXT"),
            ("last_login", "TEXT"),
            ("login_count", "INTEGER DEFAULT 0"),
            ("study_data", "TEXT DEFAULT '{}'"),
        ]
        for col, col_type in migrations:
            if col not in existing_cols:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {col_type}")


def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def is_valid_dz_phone(phone):
    return bool(re.match(r"^(05|06|07)\d{8}$", phone))


def check_rate_limit(key):
    record = FAILED_ATTEMPTS.get(key)
    if not record:
        return False, 0
    count, first_time = record
    if count >= MAX_ATTEMPTS:
        elapsed = time.time() - first_time
        if elapsed < LOCKOUT_SECONDS:
            return True, int(LOCKOUT_SECONDS - elapsed)
        del FAILED_ATTEMPTS[key]
    return False, 0


def record_failed_attempt(key):
    now = time.time()
    if key in FAILED_ATTEMPTS:
        count, first_time = FAILED_ATTEMPTS[key]
        if now - first_time > LOCKOUT_SECONDS:
            FAILED_ATTEMPTS[key] = (1, now)
        else:
            FAILED_ATTEMPTS[key] = (count + 1, first_time)
    else:
        FAILED_ATTEMPTS[key] = (1, now)


def clear_failed_attempts(key):
    FAILED_ATTEMPTS.pop(key, None)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get("user_id")
        token = session.get("session_token")
        if not user_id or not token:
            return jsonify({"ok": False, "error": "يرجى تسجيل الدخول أولاً."}), 401

        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

        if not user or not user["active"]:
            session.clear()
            return jsonify({"ok": False, "error": "الحساب غير مفعل."}), 403

        if user["session_token"] != token:
            session.clear()
            return jsonify({"ok": False, "error": "تم تسجيل الدخول من جهاز آخر! تم إنهاء جلستك هنا."}), 401

        return f(user, *args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"ok": False, "error": "صلاحيات المدير مطلوبة."}), 403
        return f(*args, **kwargs)
    return decorated


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/session", methods=["GET"])
def get_session():
    user_id = session.get("user_id")
    token = session.get("session_token")
    if not user_id or not token:
        return jsonify({"authenticated": False})

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user or not user["active"] or user["session_token"] != token:
        session.clear()
        return jsonify({"authenticated": False})

    return jsonify({
        "authenticated": True,
        "user": {
            "name": user["name"],
            "phone": user["phone"],
            "plan": user["plan"] or "3m_350da",
            "active": True,
            "studyData": user["study_data"],
        }
    })


@app.route("/api/register", methods=["POST"])
def register():
    name = (request.form.get("name") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    password = request.form.get("password") or ""
    plan = (request.form.get("plan") or "3m_350da").strip()
    accept_terms = request.form.get("acceptTerms") == "true"
    not_robot = request.form.get("notRobot") == "true"

    if len(name) < 3 or len(name) > 60:
        return jsonify({"ok": False, "error": "يرجى إدخال اسم صحيح (3 أحرف على الأقل)."}), 400

    if not is_valid_dz_phone(phone):
        return jsonify({"ok": False, "error": "رقم الهاتف غير صحيح (05 / 06 / 07 متبوعاً بـ 8 أرقام)."}), 400

    if len(password) < 8 or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return jsonify({"ok": False, "error": "كلمة المرور يجب أن تكون 8 أحرف على الأقل وتضم حروفاً وأرقاماً."}), 400

    if plan not in ALLOWED_PLANS:
        return jsonify({"ok": False, "error": "الباقة المختارة غير صالحة."}), 400

    if not accept_terms or not not_robot:
        return jsonify({"ok": False, "error": "يرجى الموافقة على الشروط وتأكيد أنك لست روبوت."}), 400

    receipt_filename = None
    if "receipt" in request.files and request.files["receipt"].filename != "":
        file = request.files["receipt"]
        if not allowed_file(file.filename):
            return jsonify({"ok": False, "error": "صيغة الصورة غير مدعومة (PNG, JPG, WEBP)."}), 400
        ext = file.filename.rsplit(".", 1)[1].lower()
        receipt_filename = f"{uuid.uuid4().hex}.{ext}"
        file.save(os.path.join(UPLOAD_FOLDER, secure_filename(receipt_filename)))

    try:
        with get_db() as conn:
            conn.execute(
                """INSERT INTO users (name, phone, password_hash, plan, receipt_file, active, last_ip, user_agent)
                   VALUES (?, ?, ?, ?, ?, 0, ?, ?)""",
                (
                    name,
                    phone,
                    generate_password_hash(password),
                    plan,
                    receipt_filename,
                    get_client_ip(),
                    (request.headers.get("User-Agent") or "")[:180],
                )
            )
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "رقم الهاتف مسجل مسبقاً."}), 409
    except Exception as e:
        print("REGISTER ERROR:", repr(e))
        return jsonify({"ok": False, "error": f"خطأ في قاعدة البيانات: {e}"}), 500

    return jsonify({"ok": True, "message": "تم إرسال طلب اشتراكك بنجاح! بانتظار تأكيد الفليكسي."})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip()
    password = data.get("password") or ""
    client_key = f"login:{get_client_ip()}:{phone}"

    blocked, remaining = check_rate_limit(client_key)
    if blocked:
        return jsonify({"ok": False, "error": f"محاولات كثيرة. أعد المحاولة بعد {remaining} ثانية."}), 429

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE phone = ?", (phone,)).fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        record_failed_attempt(client_key)
        return jsonify({"ok": False, "error": "بيانات الدخول غير صحيحة."}), 401

    if not user["active"]:
        return jsonify({"ok": False, "error": "حسابك قيد المراجعة بانتظار تأكيد الفليكسي."}), 403

    clear_failed_attempts(client_key)

    new_token = uuid.uuid4().hex
    client_ip = get_client_ip()
    ua = (request.headers.get("User-Agent") or "")[:180]
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

    with get_db() as conn:
        conn.execute(
            """UPDATE users
               SET session_token = ?, last_ip = ?, user_agent = ?, last_login = ?, login_count = COALESCE(login_count, 0) + 1
               WHERE id = ?""",
            (new_token, client_ip, ua, now_str, user["id"])
        )

    session.clear()
    session["user_id"] = user["id"]
    session["session_token"] = new_token

    return jsonify({
        "ok": True,
        "user": {
            "name": user["name"],
            "phone": user["phone"],
            "plan": user["plan"] or "3m_350da",
            "active": True,
            "studyData": user["study_data"],
        }
    })


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/study-data", methods=["POST"])
@login_required
def save_study_data(user):
    data = request.get_json(silent=True)
    if not data or "studyData" not in data:
        return jsonify({"ok": False, "error": "بيانات غير صالحة."}), 400

    with get_db() as conn:
        conn.execute("UPDATE users SET study_data = ? WHERE id = ?", (data["studyData"], user["id"]))

    return jsonify({"ok": True})


@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""
    client_key = f"admin:{get_client_ip()}"

    blocked, remaining = check_rate_limit(client_key)
    if blocked:
        return jsonify({"ok": False, "error": f"محاولات كثيرة. انتظر {remaining} ثانية."}), 429

    if not check_password_hash(ADMIN_PASSWORD_HASH, password):
        record_failed_attempt(client_key)
        return jsonify({"ok": False, "error": "كلمة مرور المدير غير صحيحة."}), 401

    clear_failed_attempts(client_key)
    session["is_admin"] = True
    return jsonify({"ok": True})


@app.route("/api/admin/users", methods=["GET"])
@admin_required
def admin_users():
    with get_db() as conn:
        rows = conn.execute(
            """SELECT id, name, phone, plan, receipt_file, active, last_ip, user_agent, last_login, login_count, created_at
               FROM users ORDER BY id DESC"""
        ).fetchall()

    users_list = [dict(r) for r in rows]
    stats = {
        "total": len(users_list),
        "active": sum(1 for u in users_list if u["active"]),
        "pending": sum(1 for u in users_list if not u["active"]),
        "with_receipt": sum(1 for u in users_list if u["receipt_file"]),
        "total_logins": sum(u["login_count"] or 0 for u in users_list),
    }
    return jsonify({"ok": True, "users": users_list, "stats": stats})


@app.route("/api/admin/toggle/<int:user_id>", methods=["POST"])
@admin_required
def admin_toggle_user(user_id):
    with get_db() as conn:
        user = conn.execute("SELECT active FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return jsonify({"ok": False, "error": "المستخدم غير موجود."}), 404
        new_status = 0 if user["active"] else 1
        conn.execute("UPDATE users SET active = ? WHERE id = ?", (new_status, user_id))
    return jsonify({"ok": True, "active": bool(new_status)})


@app.route("/api/admin/delete/<int:user_id>", methods=["DELETE"])
@admin_required
def admin_delete_user(user_id):
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return jsonify({"ok": True})


@app.route("/uploads/<filename>")
@admin_required
def uploaded_receipt(filename):
    return send_from_directory(UPLOAD_FOLDER, secure_filename(filename))


init_db()

if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)