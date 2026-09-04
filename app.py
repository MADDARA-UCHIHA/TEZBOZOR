import sqlite3
import os
import re
import time
import uuid
import json
import hmac
import hashlib
import logging
from contextlib import suppress
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, g, request, session, jsonify, render_template, redirect, url_for, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from PIL import Image

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load variables from a local .env file if python-dotenv is installed and the file
# exists (typical for local development). In real deployments (systemd, Docker,
# Gunicorn behind a process manager, etc.) real environment variables are usually
# set directly and this is a harmless no-op — it never overrides a variable that's
# already set in the actual environment.
try:
    from dotenv import load_dotenv
    # Resolve configuration beside the application, not from the process cwd.
    load_dotenv(os.path.join(BASE_DIR, ".env"))
except ImportError:
    pass

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("bozor_app")

DB_PATH = os.path.join(BASE_DIR, "bozor.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_EXT = {"png", "jpg", "jpeg", "webp", "gif"}
MAX_IMAGE_BYTES = 4 * 1024 * 1024  # 4MB per image
MAX_IMAGE_DIMENSION = 4000  # px, guards against decompression-bomb style images

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

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
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
app.config["SESSION_COOKIE_NAME"] = "tezbozor_session"
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "").strip()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
ADMIN_SESSION_SECONDS = 30 * 60


def admin_client_fingerprint():
    user_agent = request.headers.get("User-Agent", "")
    return hashlib.sha256(user_agent.encode("utf-8")).hexdigest()
# Set SECURE_COOKIES=1 in the environment once the site is served over HTTPS in production.
# Keep it disabled by default so the documented local HTTP server can persist sessions.
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SECURE_COOKIES", "0") == "1"
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


@app.errorhandler(RequestEntityTooLarge)
def handle_request_too_large(e):
    return jsonify({"error": "Yuklangan ma'lumot hajmi 6MB dan oshmasligi kerak"}), 413


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


PHONE_RE = re.compile(r"^998[0-9]{9}$")
MAX_AD_IMAGES = 4


def valid_phone(p):
    digits = re.sub(r"\D", "", p or "")
    return bool(PHONE_RE.match(digits))


def ad_image_names(ad_id, legacy_filename=None):
    rows = get_db().execute(
        "SELECT filename FROM ad_images WHERE ad_id = ? ORDER BY id", (ad_id,)
    ).fetchall()
    names = [row["filename"] for row in rows]
    if not names and legacy_filename:
        names.append(legacy_filename)
    return names


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


def rate_limited_redis(key, max_calls, window_seconds, now):
    rkey = f"ratelimit:{key}"
    redis_client.zremrangebyscore(rkey, 0, now - window_seconds)
    count = redis_client.zcard(rkey)
    if count >= max_calls:
        return True
    redis_client.zadd(rkey, {f"{now}:{uuid.uuid4().hex}": now})
    redis_client.expire(rkey, int(window_seconds) + 1)
    return False


def rate_limited(key, max_calls, window_seconds):
    """Generic sliding-window rate limiter. Returns True if the caller should be blocked.
    Uses a Redis sorted set (shared across worker processes) when available, otherwise
    falls back to the original per-process in-memory window."""
    now = time.time()
    if redis_client:
        try:
            return rate_limited_redis(key, max_calls, window_seconds, now)
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

        CREATE TABLE IF NOT EXISTS user_profiles (
            user_id INTEGER PRIMARY KEY,
            avatar_filename TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
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

        CREATE TABLE IF NOT EXISTS ad_images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ad_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            FOREIGN KEY(ad_id) REFERENCES ads(id) ON DELETE CASCADE
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

        CREATE TABLE IF NOT EXISTS webrtc_calls (
            call_id TEXT PRIMARY KEY,
            ad_id INTEGER NOT NULL,
            caller_id INTEGER NOT NULL,
            callee_id INTEGER NOT NULL,
            offer TEXT,
            answer TEXT,
            status TEXT NOT NULL DEFAULT 'ringing',
            created_at TEXT NOT NULL,
            FOREIGN KEY(ad_id) REFERENCES ads(id) ON DELETE CASCADE,
            FOREIGN KEY(caller_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(callee_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS webrtc_candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            call_id TEXT NOT NULL,
            sender_id INTEGER NOT NULL,
            candidate TEXT NOT NULL,
            FOREIGN KEY(call_id) REFERENCES webrtc_calls(call_id) ON DELETE CASCADE,
            FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE
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


def current_avatar_filename(user_id):
    row = get_db().execute(
        "SELECT avatar_filename FROM user_profiles WHERE user_id = ?", (user_id,)
    ).fetchone()
    return row["avatar_filename"] if row else None


def login_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "Avval tizimga kiring"}), 401
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        authenticated_at = session.get("admin_authenticated_at", 0)
        session_is_fresh = isinstance(authenticated_at, (int, float)) and (
            time.time() - authenticated_at < ADMIN_SESSION_SECONDS
        )
        expected_fingerprint = admin_client_fingerprint()
        session_fingerprint = session.get("admin_client_fingerprint", "")
        if (
            not session.get("admin_authenticated")
            or not ADMIN_USERNAME
            or session.get("admin_username") != ADMIN_USERNAME
            or not session_is_fresh
            or not isinstance(session_fingerprint, str)
            or not hmac.compare_digest(session_fingerprint, expected_fingerprint)
        ):
            session.pop("admin_authenticated", None)
            session.pop("admin_username", None)
            session.pop("admin_authenticated_at", None)
            return jsonify({
                "error": "Admin sessiyasi tugagan. Qayta kiring.",
                "code": "admin_session_required",
            }), 403
        return fn(*args, **kwargs)

    return wrapper


# ---------- pages ----------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/csrf")
def api_csrf():
    return jsonify({"csrf_token": generate_csrf()})


@app.route("/admin")
def admin_page():
    return render_template("admin.html")


@app.route("/api/admin/login", methods=["POST"])
@rate_limit(max_calls=5, window_seconds=300, key_fn=client_ip)
def api_admin_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not ADMIN_USERNAME or not ADMIN_PASSWORD:
        logger.error("Admin login attempted without ADMIN_USERNAME/ADMIN_PASSWORD configured")
        return jsonify({"error": "Admin kirishi serverda sozlanmagan"}), 503
    if not hmac.compare_digest(username, ADMIN_USERNAME) or not hmac.compare_digest(password, ADMIN_PASSWORD):
        logger.warning("Failed admin login for username %r from %s", username, client_ip())
        return jsonify({"error": "Admin login yoki parol noto'g'ri"}), 401
    session.clear()
    session.permanent = True
    session["admin_authenticated"] = True
    session["admin_username"] = ADMIN_USERNAME
    session["admin_authenticated_at"] = time.time()
    session["admin_client_fingerprint"] = admin_client_fingerprint()
    logger.info("Admin session started for %s from %s", ADMIN_USERNAME, client_ip())
    return jsonify({"ok": True})


@app.route("/api/admin/logout", methods=["POST"])
def api_admin_logout():
    if session.get("admin_authenticated"):
        logger.info("Admin session ended for %s from %s", session.get("admin_username"), client_ip())
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/admin/overview")
@admin_required
def api_admin_overview():
    db = get_db()
    stats = {
        "users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "ads": db.execute("SELECT COUNT(*) FROM ads").fetchone()[0],
        "messages": db.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
    }
    users = db.execute(
        "SELECT id, username, created_at FROM users ORDER BY id DESC LIMIT 100"
    ).fetchall()
    ads = db.execute(
        """SELECT ads.id, ads.title, ads.price, ads.created_at, users.username AS author
           FROM ads JOIN users ON users.id = ads.user_id
           ORDER BY ads.id DESC LIMIT 100"""
    ).fetchall()
    return jsonify({
        "stats": stats,
        "users": [dict(row) for row in users],
        "ads": [dict(row) for row in ads],
    })


@app.route("/api/admin/ads/<int:ad_id>", methods=["DELETE"])
@admin_required
@rate_limit(max_calls=30, window_seconds=600, key_fn=current_user_key)
def api_admin_delete_ad(ad_id):
    db = get_db()
    ad = db.execute("SELECT image_filename FROM ads WHERE id = ?", (ad_id,)).fetchone()
    if not ad:
        return jsonify({"error": "E'lon topilmadi"}), 404
    image_filenames = ad_image_names(ad_id, ad["image_filename"])
    db.execute("DELETE FROM ads WHERE id = ?", (ad_id,))
    db.commit()
    for filename in image_filenames:
        with suppress(OSError):
            os.remove(os.path.join(UPLOAD_DIR, filename))
    return jsonify({"ok": True})


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@admin_required
@rate_limit(max_calls=30, window_seconds=600, key_fn=current_user_key)
def api_admin_delete_user(user_id):
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({"error": "Foydalanuvchi topilmadi"}), 404
    image_rows = db.execute(
        """SELECT user_profiles.avatar_filename FROM user_profiles
           WHERE user_profiles.user_id = ?""", (user_id,)
    ).fetchall()
    ad_rows = db.execute(
        "SELECT id, image_filename FROM ads WHERE user_id = ?", (user_id,)
    ).fetchall()
    filenames = [row["avatar_filename"] for row in image_rows if row["avatar_filename"]]
    for ad in ad_rows:
        filenames.extend(ad_image_names(ad["id"], ad["image_filename"]))
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    for filename in set(filenames):
        with suppress(OSError):
            os.remove(os.path.join(UPLOAD_DIR, filename))
    return jsonify({"ok": True})


# ---------- auth endpoints ----------
@app.route("/api/register", methods=["POST"])
@rate_limit(max_calls=5, window_seconds=300, key_fn=client_ip)
def api_register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if data.get("terms_accepted") is not True:
        return jsonify({"error": "Ro'yxatdan o'tish uchun Foydalanish shartlarini qabul qiling"}), 400

    if not valid_username(username):
        return jsonify({"error": "Foydalanuvchi nomi harf bilan boshlanib, 3-20 belgidan iborat bo'lishi kerak (harf, raqam, _)"}), 400
    if ADMIN_USERNAME and username.casefold() == ADMIN_USERNAME.casefold():
        return jsonify({"error": "Bu foydalanuvchi nomi allaqachon band"}), 409
    if not (password_is_valid := valid_password(password)):
        return jsonify({"error": "Parol kamida 8 belgidan iborat bo'lib, harf va raqamni o'z ichiga olishi kerak"}), 400

    db = get_db()
    if db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
        return jsonify({"error": "Bu foydalanuvchi nomi allaqachon band"}), 409

    pw_hash = generate_password_hash(password)
    db.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, pw_hash, datetime.utcnow().isoformat()),
    )
    db.commit()
    user = db.execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchone()

    session.clear()
    session.permanent = True
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

    if ADMIN_USERNAME and ADMIN_PASSWORD and hmac.compare_digest(username, ADMIN_USERNAME) and hmac.compare_digest(password, ADMIN_PASSWORD):
        ip = request.remote_addr or "unknown"
        clear_attempts(ip)
        session.clear()
        session.permanent = True
        session["admin_authenticated"] = True
        session["admin_username"] = ADMIN_USERNAME
        session["admin_authenticated_at"] = time.time()
        session["admin_client_fingerprint"] = admin_client_fingerprint()
        return jsonify({"ok": True, "username": ADMIN_USERNAME, "is_admin": True})

    db = get_db()
    user = db.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,)).fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        register_failed_attempt(ip)
        return jsonify({"error": "Login yoki parol noto'g'ri"}), 401

    clear_attempts(ip)
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return jsonify({"ok": True, "username": user["username"]})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
def api_me():
    if user := current_user():
        return jsonify({"user": {"id": user["id"], "username": user["username"],
                                 "avatar_filename": current_avatar_filename(user["id"])}})
    return jsonify({"user": None})


@app.route("/api/profile/avatar", methods=["POST"])
@login_required
def api_profile_avatar():
    file = request.files.get("avatar")
    if not file or not file.filename:
        return jsonify({"error": "Profil rasmi tanlanmagan"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "Faqat rasm fayllari ruxsat etilgan"}), 400
    file.seek(0, os.SEEK_END)
    if file.tell() > MAX_IMAGE_BYTES:
        return jsonify({"error": "Rasm hajmi 4MB dan oshmasligi kerak"}), 400
    file.seek(0)
    filename = f"avatar-{uuid.uuid4().hex}.jpg"
    path = os.path.join(UPLOAD_DIR, filename)
    ok, err = verify_and_resave_image(file, path)
    if not ok:
        return jsonify({"error": err}), 400
    db = get_db()
    old = current_avatar_filename(session["user_id"])
    db.execute(
        """INSERT INTO user_profiles (user_id, avatar_filename) VALUES (?, ?)
           ON CONFLICT(user_id) DO UPDATE SET avatar_filename = excluded.avatar_filename""",
        (session["user_id"], filename),
    )
    db.commit()
    if old:
        with suppress(OSError):
            os.remove(os.path.join(UPLOAD_DIR, old))
    return jsonify({"ok": True, "avatar_filename": filename})


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
    ads = []
    for row in rows:
        item = dict(row)
        item["image_filenames"] = ad_image_names(row["id"], row["image_filename"])
        ads.append(item)
    return jsonify({
        "seller": {"id": seller["id"], "username": seller["username"], "joined": seller["created_at"]},
        "ads": ads,
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
    ads = []
    for row in rows:
        item = dict(row)
        item["image_filenames"] = ad_image_names(row["id"], row["image_filename"])
        ads.append(item)
    return jsonify({"ads": ads, "limit": limit, "offset": offset})


@app.route("/api/ads/<int:ad_id>/related", methods=["GET"])
def api_related_ads(ad_id):
    db = get_db()
    ad = db.execute("SELECT id, title FROM ads WHERE id = ?", (ad_id,)).fetchone()
    if not ad:
        return jsonify({"error": "E'lon topilmadi"}), 404
    keyword = (ad["title"] or "").split()[0].strip()
    rows = db.execute(
        """SELECT ads.id, ads.title, ads.price, ads.description, ads.phone,
                  ads.image_filename, users.username AS author
           FROM ads JOIN users ON ads.user_id = users.id
           WHERE ads.id != ? AND ads.title LIKE ?
           ORDER BY ads.id DESC LIMIT 6""",
        (ad_id, f"%{keyword}%"),
    ).fetchall()
    return jsonify({"ads": [dict(row) for row in rows]})


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
        return jsonify({"error": "Telefon raqami majburiy va noto'g'ri (masalan: +998 (90) 902-04-06)"}), 400

    files = [file for file in request.files.getlist("images") if file and file.filename]
    files += [file for file in request.files.getlist("image") if file and file.filename]
    if not files:
        return jsonify({"error": "Kamida 1 ta rasm yuklash majburiy"}), 400
    if len(files) > MAX_AD_IMAGES:
        return jsonify({"error": "Ko'pi bilan 4 ta rasm yuklash mumkin"}), 400

    image_filenames = []
    for file in files:
        if not allowed_file(file.filename):
           return jsonify({"error": "Faqat rasm fayllari ruxsat etilgan (png, jpg, jpeg, webp, gif)"}), 400
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        if size > MAX_IMAGE_BYTES:
           return jsonify({"error": "Har bir rasm hajmi 4MB dan oshmasligi kerak"}), 400
        image_filename = f"{uuid.uuid4().hex}.jpg"
        dest_path = os.path.join(UPLOAD_DIR, image_filename)
        ok, err = verify_and_resave_image(file, dest_path)
        if not ok:
           for saved in image_filenames:
               try:
                   os.remove(os.path.join(UPLOAD_DIR, saved))
               except OSError:
                   pass
           return jsonify({"error": err}), 400
        image_filenames.append(image_filename)

    db = get_db()
    db.execute(
        """INSERT INTO ads (user_id, title, price, description, phone, image_filename, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (session["user_id"], title, price, description, phone, image_filenames[0],
         datetime.utcnow().isoformat()),
    )
    ad_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.executemany(
        "INSERT INTO ad_images (ad_id, filename) VALUES (?, ?)",
        [(ad_id, filename) for filename in image_filenames],
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
    image_filenames = ad_image_names(ad_id, ad["image_filename"])
    db.execute("DELETE FROM ads WHERE id = ?", (ad_id,))
    db.commit()
    for filename in image_filenames:
        with suppress(OSError):
            os.remove(os.path.join(UPLOAD_DIR, filename))
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
        try:
            receiver_id = int(receiver_id)
        except (TypeError, ValueError):
            return jsonify({"error": "Suhbatdosh noto'g'ri"}), 400
        buyer_exists = db.execute(
            """SELECT 1 FROM users u JOIN messages m ON u.id = m.sender_id
               WHERE u.id = ? AND m.ad_id = ? AND m.sender_id != ?
                 AND m.receiver_id = ? LIMIT 1""",
            (receiver_id, ad_id, owner_id, owner_id),
        ).fetchone()
        if not buyer_exists:
            return jsonify({"error": "Bu e'lon bo'yicha suhbat topilmadi"}), 404

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
    call_id = uuid.uuid4().hex
    db.execute(
        """INSERT INTO webrtc_calls
           (call_id, ad_id, caller_id, callee_id, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (call_id, ad_id, caller_id, callee_id, datetime.utcnow().isoformat()),
    )
    db.commit()
    return jsonify({"ok": True, "phone": ad["phone"], "call_id": call_id})


def get_webrtc_call(call_id):
    call = get_db().execute(
        "SELECT * FROM webrtc_calls WHERE call_id = ?", (call_id,)
    ).fetchone()
    if not call:
        return None, (jsonify({"error": "Qo'ng'iroq topilmadi"}), 404)
    if session["user_id"] not in (call["caller_id"], call["callee_id"]):
        return None, (jsonify({"error": "Ruxsat yo'q"}), 403)
    return call, None


@app.route("/api/webrtc/incoming", methods=["GET"])
@login_required
def api_webrtc_incoming():
    rows = get_db().execute(
        """SELECT w.call_id, w.ad_id, w.caller_id, u.username AS caller_name,
                  a.title
           FROM webrtc_calls w
           JOIN users u ON u.id = w.caller_id
           JOIN ads a ON a.id = w.ad_id
           WHERE w.callee_id = ? AND w.status = 'ringing'
           ORDER BY w.created_at DESC LIMIT 10""",
        (session["user_id"],),
    ).fetchall()
    return jsonify({"calls": [dict(row) for row in rows]})


@app.route("/api/webrtc/<call_id>", methods=["GET"])
@login_required
def api_webrtc_state(call_id):
    call, error = get_webrtc_call(call_id)
    if error:
        return error
    db = get_db()
    candidates = db.execute(
        "SELECT id, sender_id, candidate FROM webrtc_candidates WHERE call_id = ? ORDER BY id",
        (call_id,),
    ).fetchall()
    return jsonify({
        "call_id": call["call_id"],
        "offer": json.loads(call["offer"]) if call["offer"] else None,
        "answer": json.loads(call["answer"]) if call["answer"] else None,
        "status": call["status"],
        "candidates": [
            {"id": row["id"], "sender_id": row["sender_id"], "candidate": json.loads(row["candidate"])}
            for row in candidates
        ],
    })


@app.route("/api/webrtc/<call_id>/offer", methods=["POST"])
@login_required
def api_webrtc_offer(call_id):
    call, error = get_webrtc_call(call_id)
    if error:
        return error
    if call["caller_id"] != session["user_id"]:
        return jsonify({"error": "Faqat qo'ng'iroq qiluvchi offer yuborishi mumkin"}), 403
    offer = (request.get_json(silent=True) or {}).get("offer")
    if not isinstance(offer, dict):
        return jsonify({"error": "WebRTC offer noto'g'ri"}), 400
    db = get_db()
    db.execute("UPDATE webrtc_calls SET offer = ? WHERE call_id = ?", (json.dumps(offer), call_id))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/webrtc/<call_id>/answer", methods=["POST"])
@login_required
def api_webrtc_answer(call_id):
    call, error = get_webrtc_call(call_id)
    if error:
        return error
    if call["callee_id"] != session["user_id"]:
        return jsonify({"error": "Faqat qabul qiluvchi answer yuborishi mumkin"}), 403
    answer = (request.get_json(silent=True) or {}).get("answer")
    if not isinstance(answer, dict):
        return jsonify({"error": "WebRTC answer noto'g'ri"}), 400
    db = get_db()
    db.execute(
        "UPDATE webrtc_calls SET answer = ?, status = 'connected' WHERE call_id = ?",
        (json.dumps(answer), call_id),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/webrtc/<call_id>/candidate", methods=["POST"])
@login_required
def api_webrtc_candidate(call_id):
    call, error = get_webrtc_call(call_id)
    if error:
        return error
    candidate = (request.get_json(silent=True) or {}).get("candidate")
    if not isinstance(candidate, dict):
        return jsonify({"error": "ICE candidate noto'g'ri"}), 400
    db = get_db()
    db.execute(
        "INSERT INTO webrtc_candidates (call_id, sender_id, candidate) VALUES (?, ?, ?)",
        (call_id, session["user_id"], json.dumps(candidate)),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/webrtc/<call_id>/end", methods=["POST"])
@login_required
def api_webrtc_end(call_id):
    call, error = get_webrtc_call(call_id)
    if error:
        return error
    db = get_db()
    db.execute("UPDATE webrtc_calls SET status = 'ended' WHERE call_id = ?", (call_id,))
    db.commit()
    return jsonify({"ok": True})


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
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(self), camera=(self)"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    if request.path.startswith("/api/") or request.path == "/admin":
        resp.headers["Cache-Control"] = "no-store"
    # Only sent when the app is configured for HTTPS (SECURE_COOKIES=1), since HSTS on a
    # plain-HTTP dev server would just be misleading and can't be un-sent once cached.
    if app.config["SESSION_COOKIE_SECURE"] and request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return resp


# Runs on import (not just under `python app.py`) so the schema also gets created when
# the app is started via a production WSGI server such as Gunicorn/uWSGI (see wsgi.py).
init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)