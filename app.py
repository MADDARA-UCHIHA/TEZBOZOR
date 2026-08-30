import sqlite3
import os
import re
import time
import uuid
import logging
from datetime import datetime
from functools import wraps
from flask import Flask, g, request, session, jsonify, render_template, redirect, url_for, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from PIL import Image

# Load variables from a local .env file if python-dotenv is installed and the file
# exists (typical for local development). In real deployments (systemd, Docker,
# Gunicorn behind a process manager, etc.) real environment variables are usually
# set directly and this is a harmless no-op — it never overrides a variable that's
# already set in the actual environment.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("bozor_app")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "bozor.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_EXT = {"png", "jpg", "jpeg", "webp", "gif"}
MAX_IMAGE_BYTES = 4 * 1024 * 1024  # 4MB per image
MAX_IMAGE_DIMENSION = 4000  # px, guards against decompression-bomb style images

app = Flask(__name__)

# ---------- SECRET_KEY: fail fast in production instead of silently rotating ----------
# A silently-generated random key invalidates every session on each restart/worker
# respawn, which is confusing in production. Set REQUIRE_SECRET_KEY=1 (recommended for
# any real deployment) to make a missing SECRET_KEY a hard startup error instead.
_secret_key = os.environ.get("SECRET_KEY")
if not _secret_key:
    if os.environ.get("REQUIRE_SECRET_KEY") == "1":
        raise RuntimeError(
            "SECRET_KEY environment variable is not set and REQUIRE_SECRET_KEY=1. "
            "Set SECRET_KEY before starting the app in production."
        )
    _secret_key = os.urandom(32).hex()
    logger.warning(
        "SECRET_KEY is not set — using a random ephemeral key for this process only. "
        "All sessions will be invalidated on restart, and with multiple worker "
        "processes each worker will have a DIFFERENT key. Set the SECRET_KEY "
        "environment variable before deploying to production."
    )
app.config["SECRET_KEY"] = _secret_key
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Set SECURE_COOKIES=1 in the environment once the site is served over HTTPS in production
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SECURE_COOKIES") == "1"
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024  # 6MB max request body (form + image)

csrf = CSRFProtect(app)

# ---------- optional Redis backend for rate limiting ----------
# The original in-memory dicts (LOGIN_ATTEMPTS / ACTION_LOG) only work correctly with a
# single worker process. Under Gunicorn/uWSGI with >1 worker, each worker keeps its own
# counters, so an attacker's effective attempt budget multiplies by the worker count.
# If REDIS_URL is set, rate-limit state is shared across all workers via Redis; otherwise
# it falls back to the original in-memory behaviour (fine for single-process/dev use only).
redis_client = None
_redis_url = os.environ.get("REDIS_URL")
if _redis_url:
    try:
        import redis as _redis_lib
        redis_client = _redis_lib.from_url(_redis_url, socket_connect_timeout=2)
        redis_client.ping()
        logger.info("Rate limiting backed by Redis at %s", _redis_url)
    except Exception as exc:
        redis_client = None
        logger.warning(
            "REDIS_URL was set but Redis is unreachable (%s) — falling back to "
            "in-memory rate limiting, which is NOT safe across multiple worker "
            "processes.", exc,
        )
else:
    logger.warning(
        "REDIS_URL is not set — rate limiting uses in-memory state. This is fine for "
        "local development but unsafe for a multi-worker production deployment. Set "
        "REDIS_URL to share rate-limit state across workers."
    )


from flask_wtf.csrf import CSRFError


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify({"error": "Xavfsizlik tokeni eskirgan. Sahifani yangilab qayta urinib ko'ring.",
                     "code": "csrf_expired"}), 400


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def verify_and_resave_image(file_storage, dest_path):
    """Verify the upload is actually a valid image (not a renamed script/executable),
    strip any embedded metadata, and re-encode it before saving to disk."""
    try:
        img = Image.open(file_storage.stream)
        img.verify()  # raises if not a real image
        file_storage.stream.seek(0)
        img = Image.open(file_storage.stream)
        if img.width > MAX_IMAGE_DIMENSION or img.height > MAX_IMAGE_DIMENSION:
            return False, "Rasm o'lchami juda katta"
        if img.mode not in ("RGB", "RGBA"):
            img = img.convert("RGBA" if "A" in img.mode else "RGB")
        img.save(dest_path)
        return True, None
    except Exception:
        return False, "Fayl haqiqiy rasm emas yoki buzilgan"


PHONE_RE = re.compile(r"^\+?[0-9]{7,15}$")


def valid_phone(p):
    if not p:
        return True  # optional field
    return bool(PHONE_RE.match(p.strip()))


# ---------- rate limiting (simple in-memory, per-IP / per-user) ----------
LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60

ACTION_LOG = {}  # key -> list of timestamps, for generic rate limiting


def is_locked_out(ip):
    if redis_client:
        try:
            val = redis_client.get(f"loginfail:{ip}")
            return bool(val) and int(val) >= MAX_ATTEMPTS
        except Exception:
            logger.exception("Redis error in is_locked_out; failing open to in-memory check")
    rec = LOGIN_ATTEMPTS.get(ip)
    if not rec:
        return False
    count, last_time = rec
    if count >= MAX_ATTEMPTS and time.time() - last_time < LOCKOUT_SECONDS:
        return True
    if time.time() - last_time >= LOCKOUT_SECONDS:
        LOGIN_ATTEMPTS.pop(ip, None)
        return False
    return False


def register_failed_attempt(ip):
    if redis_client:
        try:
            key = f"loginfail:{ip}"
            pipe = redis_client.pipeline()
            pipe.incr(key)
            pipe.expire(key, LOCKOUT_SECONDS)
            pipe.execute()
            return
        except Exception:
            logger.exception("Redis error in register_failed_attempt; falling back to in-memory")
    count, _ = LOGIN_ATTEMPTS.get(ip, (0, time.time()))
    LOGIN_ATTEMPTS[ip] = (count + 1, time.time())


def clear_attempts(ip):
    if redis_client:
        try:
            redis_client.delete(f"loginfail:{ip}")
            return
        except Exception:
            logger.exception("Redis error in clear_attempts; falling back to in-memory")
    LOGIN_ATTEMPTS.pop(ip, None)


def rate_limited(key, max_calls, window_seconds):
    """Generic sliding-window rate limiter. Returns True if the caller should be blocked.
    Uses a Redis sorted set (shared across worker processes) when available, otherwise
    falls back to the original per-process in-memory window."""
    now = time.time()
    if redis_client:
        try:
            rkey = f"ratelimit:{key}"
            redis_client.zremrangebyscore(rkey, 0, now - window_seconds)
            count = redis_client.zcard(rkey)
            if count >= max_calls:
                return True
            redis_client.zadd(rkey, {f"{now}:{uuid.uuid4().hex}": now})
            redis_client.expire(rkey, int(window_seconds) + 1)
            return False
        except Exception:
            logger.exception("Redis error in rate_limited; falling back to in-memory")
    history = [t for t in ACTION_LOG.get(key, []) if now - t < window_seconds]
    if len(history) >= max_calls:
        ACTION_LOG[key] = history
        return True
    history.append(now)
    ACTION_LOG[key] = history
    return False


def rate_limit(max_calls, window_seconds, key_fn):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = f"{fn.__name__}:{key_fn()}"
            if rate_limited(key, max_calls, window_seconds):
                return jsonify({"error": "Juda ko'p urinish. Birozdan keyin qayta urinib ko'ring."}), 429
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def client_ip():
    return request.remote_addr or "unknown"


def current_user_key():
    return session.get("user_id") or client_ip()


# ---------- database ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            price TEXT NOT NULL,
            description TEXT,
            phone TEXT,
            image_filename TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ad_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(ad_id) REFERENCES ads(id) ON DELETE CASCADE,
            FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS call_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ad_id INTEGER NOT NULL,
            caller_id INTEGER NOT NULL,
            callee_id INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    db.commit()
    db.close()


# ---------- validation ----------
USERNAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{2,19}$")


def valid_username(u):
    return bool(USERNAME_RE.match(u or ""))


def valid_password(p):
    if not isinstance(p, str) or not (8 <= len(p) <= 128):
        return False
    has_letter = re.search(r"[A-Za-z]", p)
    has_digit = re.search(r"[0-9]", p)
    return bool(has_letter and has_digit)


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    return db.execute("SELECT id, username FROM users WHERE id = ?", (uid,)).fetchone()


def login_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "Avval tizimga kiring"}), 401
        return fn(*args, **kwargs)

    return wrapper


# ---------- pages ----------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/csrf")
def api_csrf():
    return jsonify({"csrf_token": generate_csrf()})


# ---------- auth endpoints ----------
@app.route("/api/register", methods=["POST"])
@rate_limit(max_calls=5, window_seconds=300, key_fn=client_ip)
def api_register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not valid_username(username):
        return jsonify({"error": "Foydalanuvchi nomi harf bilan boshlanib, 3-20 belgidan iborat bo'lishi kerak (harf, raqam, _)"}), 400
    if not valid_password(password):
        return jsonify({"error": "Parol kamida 8 belgidan iborat bo'lib, harf va raqamni o'z ichiga olishi kerak"}), 400

    db = get_db()
    exists = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if exists:
        return jsonify({"error": "Bu foydalanuvchi nomi allaqachon band"}), 409

    pw_hash = generate_password_hash(password)
    db.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, pw_hash, datetime.utcnow().isoformat()),
    )
    db.commit()
    user = db.execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchone()

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return jsonify({"ok": True, "username": user["username"]})


@app.route("/api/login", methods=["POST"])
def api_login():
    ip = request.remote_addr or "unknown"
    if is_locked_out(ip):
        return jsonify({"error": "Juda ko'p urinish. Keyinroq qayta urinib ko'ring."}), 429

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    db = get_db()
    user = db.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,)).fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        register_failed_attempt(ip)
        return jsonify({"error": "Login yoki parol noto'g'ri"}), 401

    clear_attempts(ip)
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return jsonify({"ok": True, "username": user["username"]})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
def api_me():
    user = current_user()
    if not user:
        return jsonify({"user": None})
    return jsonify({"user": {"id": user["id"], "username": user["username"]}})


# ---------- ads endpoints ----------
@app.route("/api/channel/<username>", methods=["GET"])
def api_channel(username):
    db = get_db()
    seller = db.execute("SELECT id, username, created_at FROM users WHERE username = ?", (username,)).fetchone()
    if not seller:
        return jsonify({"error": "Bunday sotuvchi topilmadi"}), 404
    rows = db.execute(
        """SELECT id, title, price, description, phone, image_filename, created_at
           FROM ads WHERE user_id = ? ORDER BY id DESC""",
        (seller["id"],),
    ).fetchall()
    return jsonify({
        "seller": {"id": seller["id"], "username": seller["username"], "joined": seller["created_at"]},
        "ads": [dict(r) for r in rows],
        "ads_count": len(rows),
    })


@app.route("/api/ads", methods=["GET"])
def api_list_ads():
    q = (request.args.get("q") or "").strip()
    limit = request.args.get("limit", 30, type=int) or 30
    limit = max(1, min(limit, 100))  # bounded, so a client can't force a huge scan
    offset = request.args.get("offset", 0, type=int) or 0
    offset = max(0, offset)
    db = get_db()
    if q:
        rows = db.execute(
            """SELECT ads.id, ads.title, ads.price, ads.description, ads.phone,
                      ads.image_filename, ads.created_at,
                      users.username AS author, users.id AS author_id
               FROM ads JOIN users ON ads.user_id = users.id
               WHERE ads.title LIKE ? ORDER BY ads.id DESC LIMIT ? OFFSET ?""",
            (f"%{q}%", limit, offset),
        ).fetchall()
    else:
        rows = db.execute(
            """SELECT ads.id, ads.title, ads.price, ads.description, ads.phone,
                      ads.image_filename, ads.created_at,
                      users.username AS author, users.id AS author_id
               FROM ads JOIN users ON ads.user_id = users.id
               ORDER BY ads.id DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
    return jsonify({"ads": [dict(r) for r in rows], "limit": limit, "offset": offset})


@app.route("/api/ads", methods=["POST"])
@login_required
@rate_limit(max_calls=10, window_seconds=600, key_fn=current_user_key)
def api_create_ad():
    # multipart/form-data: title, price, description, phone, image(optional file)
    title = (request.form.get("title") or "").strip()
    price = (request.form.get("price") or "").strip()
    description = (request.form.get("description") or "").strip()
    phone = (request.form.get("phone") or "").strip()

    if not title or len(title) > 100:
        return jsonify({"error": "Sarlavha noto'g'ri (1-100 belgi)"}), 400
    if not price or len(price) > 30:
        return jsonify({"error": "Narx noto'g'ri"}), 400
    if len(description) > 1000:
        return jsonify({"error": "Tavsif juda uzun"}), 400
    if not valid_phone(phone):
        return jsonify({"error": "Telefon raqami noto'g'ri (masalan: +998901234567)"}), 400

    image_filename = None
    file = request.files.get("image")
    if file and file.filename:
        if not allowed_file(file.filename):
            return jsonify({"error": "Faqat rasm fayllari ruxsat etilgan (png, jpg, jpeg, webp, gif)"}), 400
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        if size > MAX_IMAGE_BYTES:
            return jsonify({"error": "Rasm hajmi 4MB dan oshmasligi kerak"}), 400
        # Save with a fresh, always-safe extension (.jpg or .png) chosen after
        # Pillow re-encodes the file — this neutralises polyglot files (e.g. a
        # script hidden inside a ".jpg") since only real pixel data survives.
        image_filename = f"{uuid.uuid4().hex}.jpg"
        dest_path = os.path.join(UPLOAD_DIR, image_filename)
        ok, err = verify_and_resave_image(file, dest_path)
        if not ok:
            return jsonify({"error": err}), 400

    db = get_db()
    db.execute(
        """INSERT INTO ads (user_id, title, price, description, phone, image_filename, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (session["user_id"], title, price, description, phone or None, image_filename,
         datetime.utcnow().isoformat()),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/ads/<int:ad_id>", methods=["DELETE"])
@login_required
def api_delete_ad(ad_id):
    db = get_db()
    ad = db.execute("SELECT user_id, image_filename FROM ads WHERE id = ?", (ad_id,)).fetchone()
    if not ad:
        return jsonify({"error": "Topilmadi"}), 404
    if ad["user_id"] != session["user_id"]:
        return jsonify({"error": "Ruxsat yo'q"}), 403
    db.execute("DELETE FROM ads WHERE id = ?", (ad_id,))
    db.commit()
    if ad["image_filename"]:
        try:
            os.remove(os.path.join(UPLOAD_DIR, ad["image_filename"]))
        except OSError:
            pass
    return jsonify({"ok": True})


@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    safe_name = secure_filename(filename)
    if safe_name != filename:
        return "", 404
    return send_from_directory(UPLOAD_DIR, safe_name)


# ---------- chat endpoints ----------
# Chat is scoped per (ad, buyer) pair so a seller with several interested
# buyers on the same ad sees separate conversations instead of one mixed thread.

@app.route("/api/conversations/<int:ad_id>", methods=["GET"])
@login_required
def api_list_conversations(ad_id):
    """For the ad owner: list distinct buyers who have messaged about this ad."""
    db = get_db()
    ad = db.execute("SELECT user_id FROM ads WHERE id = ?", (ad_id,)).fetchone()
    if not ad:
        return jsonify({"error": "E'lon topilmadi"}), 404
    if ad["user_id"] != session["user_id"]:
        return jsonify({"error": "Ruxsat yo'q"}), 403

    rows = db.execute(
        """SELECT DISTINCT u.id AS buyer_id, u.username AS buyer_name
           FROM messages m
           JOIN users u ON u.id = CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END
           WHERE m.ad_id = ? AND (m.sender_id = ? OR m.receiver_id = ?)""",
        (ad["user_id"], ad_id, ad["user_id"], ad["user_id"]),
    ).fetchall()
    return jsonify({"conversations": [dict(r) for r in rows]})


@app.route("/api/messages/<int:ad_id>", methods=["GET"])
@login_required
def api_get_messages(ad_id):
    db = get_db()
    ad = db.execute("SELECT user_id FROM ads WHERE id = ?", (ad_id,)).fetchone()
    if not ad:
        return jsonify({"error": "E'lon topilmadi"}), 404

    uid = session["user_id"]
    owner_id = ad["user_id"]

    if uid == owner_id:
        # Seller must specify which buyer's conversation to view.
        other_id = request.args.get("with", type=int)
        if not other_id:
            return jsonify({"error": "Suhbatdoshni tanlang"}), 400
    else:
        other_id = owner_id

    rows = db.execute(
        """SELECT messages.id, messages.body, messages.created_at, messages.sender_id,
                  users.username AS sender_name
           FROM messages JOIN users ON messages.sender_id = users.id
           WHERE ad_id = ?
             AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
           ORDER BY messages.id ASC LIMIT 200""",
        (ad_id, uid, other_id, other_id, uid),
    ).fetchall()
    return jsonify({"messages": [dict(r) for r in rows], "owner_id": owner_id, "other_id": other_id})


@app.route("/api/messages/<int:ad_id>", methods=["POST"])
@login_required
@rate_limit(max_calls=20, window_seconds=60, key_fn=current_user_key)
def api_send_message(ad_id):
    data = request.get_json(silent=True) or {}
    body = (data.get("body") or "").strip()
    if not body or len(body) > 500:
        return jsonify({"error": "Xabar bo'sh yoki juda uzun"}), 400

    db = get_db()
    ad = db.execute("SELECT user_id FROM ads WHERE id = ?", (ad_id,)).fetchone()
    if not ad:
        return jsonify({"error": "E'lon topilmadi"}), 404

    sender_id = session["user_id"]
    owner_id = ad["user_id"]

    if sender_id != owner_id:
        # Buyer messaging the seller.
        receiver_id = owner_id
    else:
        # Seller replying — must specify which buyer.
        receiver_id = data.get("to")
        if not receiver_id:
            return jsonify({"error": "Suhbatdoshni tanlang"}), 400
        receiver_id = int(receiver_id)
        buyer_exists = db.execute("SELECT id FROM users WHERE id = ?", (receiver_id,)).fetchone()
        if not buyer_exists:
            return jsonify({"error": "Foydalanuvchi topilmadi"}), 404

    db.execute(
        "INSERT INTO messages (ad_id, sender_id, receiver_id, body, created_at) VALUES (?, ?, ?, ?, ?)",
        (ad_id, sender_id, receiver_id, body, datetime.utcnow().isoformat()),
    )
    db.commit()
    return jsonify({"ok": True})


# ---------- call log (signal only, no real audio/video transport) ----------
@app.route("/api/call/<int:ad_id>", methods=["POST"])
@login_required
@rate_limit(max_calls=6, window_seconds=300, key_fn=current_user_key)
def api_start_call(ad_id):
    db = get_db()
    ad = db.execute("SELECT user_id, phone FROM ads WHERE id = ?", (ad_id,)).fetchone()
    if not ad:
        return jsonify({"error": "E'lon topilmadi"}), 404
    if not ad["phone"]:
        return jsonify({"error": "Bu e'londa telefon raqami ko'rsatilmagan"}), 400
    caller_id = session["user_id"]
    callee_id = ad["user_id"]
    if caller_id == callee_id:
        return jsonify({"error": "O'zingizga qo'ng'iroq qila olmaysiz"}), 400
    db.execute(
        "INSERT INTO call_logs (ad_id, caller_id, callee_id, created_at) VALUES (?, ?, ?, ?)",
        (ad_id, caller_id, callee_id, datetime.utcnow().isoformat()),
    )
    db.commit()
    return jsonify({"ok": True, "phone": ad["phone"]})


# ---------- security headers ----------
@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    )
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Only sent when the app is configured for HTTPS (SECURE_COOKIES=1), since HSTS on a
    # plain-HTTP dev server would just be misleading and can't be un-sent once cached.
    if app.config["SESSION_COOKIE_SECURE"]:
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return resp


# Runs on import (not just under `python app.py`) so the schema also gets created when
# the app is started via a production WSGI server such as Gunicorn/uWSGI (see wsgi.py).
init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
