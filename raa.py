"""
HM Chat - Real-time messaging server
Author: Med Rayen Bouazizi

Single-file backend for an Android-style real-time chat application.
Features: single-use email registration, session tokens, direct messages,
groups with shareable invite links and optional admin password, profile
pictures, media messages (image/video/voice), message deletion, emoji
reactions, typing indicators, block/unblock, and full chat history so
nothing is lost on a page refresh.

Run:
    pip install flask flask-socketio --break-system-packages
    python3 hm.py
Then open http://<server-ip>:5000 in the browser.

Note: this uses Flask-SocketIO's "threading" async mode, which needs no
extra async library (eventlet/gevent). It's reliable on Termux and fine
for a personal/small-group server. If you later run this behind a real
production setup with many concurrent users, you can switch async_mode
to "eventlet" or "gevent" once those packages install cleanly for your
Python version.
"""

import os
import sqlite3
import uuid
import time
import hashlib
import secrets
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory, g
from flask_socketio import SocketIO, join_room, emit

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "hm.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
AVATAR_DIR = os.path.join(UPLOAD_DIR, "avatars")
MEDIA_DIR = os.path.join(UPLOAD_DIR, "media")
os.makedirs(AVATAR_DIR, exist_ok=True)
os.makedirs(MEDIA_DIR, exist_ok=True)

ALLOWED_MEDIA = {"png", "jpg", "jpeg", "gif", "webp", "mp4", "mov", "webm",
                  "mp3", "wav", "ogg", "m4a", "3gp", "aac"}
MAX_CONTENT_LENGTH = 60 * 1024 * 1024  # 60 MB

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.secret_key = secrets.token_hex(32)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading",
                     max_http_buffer_size=MAX_CONTENT_LENGTH)

# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------

def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(_exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


def db_conn():
    """Standalone connection for use inside Socket.IO handlers (no app context)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            avatar TEXT DEFAULT '',
            token TEXT UNIQUE,
            status TEXT DEFAULT 'offline',
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS groups(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            creator_id INTEGER NOT NULL,
            invite_token TEXT UNIQUE NOT NULL,
            password_hash TEXT DEFAULT '',
            avatar TEXT DEFAULT '',
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS group_members(
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT DEFAULT 'member',
            joined_at REAL NOT NULL,
            PRIMARY KEY(group_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_type TEXT NOT NULL,        -- 'dm' or 'group'
            chat_id TEXT NOT NULL,          -- 'uidA_uidB' for dm, group id (as text) for group
            sender_id INTEGER NOT NULL,
            msg_type TEXT NOT NULL,         -- text, image, video, voice
            content TEXT DEFAULT '',
            media_path TEXT DEFAULT '',
            timestamp REAL NOT NULL,
            deleted INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS reactions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            emoji TEXT NOT NULL,
            UNIQUE(message_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS blocks(
            blocker_id INTEGER NOT NULL,
            blocked_id INTEGER NOT NULL,
            PRIMARY KEY(blocker_id, blocked_id)
        );
        """
    )
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def dm_chat_id(uid1, uid2):
    a, b = sorted([int(uid1), int(uid2)])
    return f"{a}_{b}"


def hash_pw(pw):
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + pw).encode()).hexdigest()
    return f"{salt}${h}"


def verify_pw(pw, stored):
    if not stored:
        return False
    try:
        salt, h = stored.split("$")
    except ValueError:
        return False
    return hashlib.sha256((salt + pw).encode()).hexdigest() == h


def new_token():
    return secrets.token_urlsafe(32)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_MEDIA


def user_public(u):
    return {
        "id": u["id"], "username": u["username"], "email": u["email"],
        "avatar": u["avatar"], "status": u["status"],
    }


def serialize_message(conn, r):
    reactions = conn.execute(
        "SELECT user_id, emoji FROM reactions WHERE message_id=?", (r["id"],)
    ).fetchall()
    sender = conn.execute(
        "SELECT username, avatar FROM users WHERE id=?", (r["sender_id"],)
    ).fetchone()
    return {
        "id": r["id"], "chat_type": r["chat_type"], "chat_id": r["chat_id"],
        "sender_id": r["sender_id"],
        "sender_name": sender["username"] if sender else "Unknown",
        "sender_avatar": sender["avatar"] if sender else "",
        "msg_type": r["msg_type"],
        "content": "" if r["deleted"] else r["content"],
        "media_path": "" if r["deleted"] else r["media_path"],
        "timestamp": r["timestamp"],
        "deleted": bool(r["deleted"]),
        "reactions": [{"user_id": x["user_id"], "emoji": x["emoji"]} for x in reactions],
    }


def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
        if not token:
            return jsonify({"error": "Missing session token"}), 401
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()
        if not user:
            return jsonify({"error": "Invalid or expired session"}), 401
        g.user = user
        return f(*args, **kwargs)
    return wrapper


# --------------------------------------------------------------------------
# Auth routes
# --------------------------------------------------------------------------

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not email or "@" not in email:
        return jsonify({"error": "Please provide a valid email address"}), 400
    if not username:
        return jsonify({"error": "Username is required"}), 400
    if len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if existing:
        return jsonify({"error": "This email has already been used to create an account"}), 409

    token = new_token()
    db.execute(
        "INSERT INTO users(email, username, password_hash, token, status, created_at) "
        "VALUES (?,?,?,?,?,?)",
        (email, username, hash_pw(password), token, "online", time.time()),
    )
    db.commit()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    return jsonify({"token": token, "user": user_public(user)})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user or not verify_pw(password, user["password_hash"]):
        return jsonify({"error": "Invalid email or password"}), 401
    token = new_token()
    db.execute("UPDATE users SET token=?, status='online' WHERE id=?", (token, user["id"]))
    db.commit()
    user = db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
    return jsonify({"token": token, "user": user_public(user)})


@app.route("/api/logout", methods=["POST"])
@auth_required
def logout():
    db = get_db()
    db.execute("UPDATE users SET token=NULL, status='offline' WHERE id=?", (g.user["id"],))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/me", methods=["GET"])
@auth_required
def me():
    return jsonify({"user": user_public(g.user)})


@app.route("/api/profile", methods=["POST"])
@auth_required
def update_profile():
    username = request.form.get("username")
    avatar_file = request.files.get("avatar")
    db = get_db()
    if username:
        db.execute("UPDATE users SET username=? WHERE id=?", (username.strip(), g.user["id"]))
    if avatar_file and avatar_file.filename and allowed_file(avatar_file.filename):
        ext = avatar_file.filename.rsplit(".", 1)[1].lower()
        fname = f"{g.user['id']}_{uuid.uuid4().hex}.{ext}"
        avatar_file.save(os.path.join(AVATAR_DIR, fname))
        db.execute("UPDATE users SET avatar=? WHERE id=?",
                   (f"/uploads/avatars/{fname}", g.user["id"]))
    db.commit()
    user = db.execute("SELECT * FROM users WHERE id=?", (g.user["id"],)).fetchone()
    return jsonify({"user": user_public(user)})


# --------------------------------------------------------------------------
# Users / search / block
# --------------------------------------------------------------------------

@app.route("/api/users/search", methods=["GET"])
@auth_required
def search_users():
    q = (request.args.get("q") or "").strip()
    db = get_db()
    if q:
        rows = db.execute(
            "SELECT * FROM users WHERE (username LIKE ? OR email LIKE ?) AND id != ? "
            "ORDER BY username LIMIT 30",
            (f"%{q}%", f"%{q}%", g.user["id"]),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM users WHERE id != ? ORDER BY username LIMIT 50", (g.user["id"],)
        ).fetchall()
    blocked = {
        r["blocked_id"]
        for r in db.execute("SELECT blocked_id FROM blocks WHERE blocker_id=?", (g.user["id"],))
    }
    return jsonify({"users": [user_public(u) for u in rows if u["id"] not in blocked]})


@app.route("/api/block", methods=["POST"])
@auth_required
def block_user():
    target_id = (request.get_json(force=True) or {}).get("user_id")
    db = get_db()
    db.execute("INSERT OR IGNORE INTO blocks(blocker_id, blocked_id) VALUES (?,?)",
               (g.user["id"], target_id))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/unblock", methods=["POST"])
@auth_required
def unblock_user():
    target_id = (request.get_json(force=True) or {}).get("user_id")
    db = get_db()
    db.execute("DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?", (g.user["id"], target_id))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/block/status/<int:other_id>", methods=["GET"])
@auth_required
def block_status(other_id):
    db = get_db()
    i_blocked = db.execute(
        "SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=?", (g.user["id"], other_id)
    ).fetchone() is not None
    they_blocked = db.execute(
        "SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=?", (other_id, g.user["id"])
    ).fetchone() is not None
    return jsonify({"i_blocked": i_blocked, "they_blocked": they_blocked})


@app.route("/api/blocked", methods=["GET"])
@auth_required
def list_blocked():
    db = get_db()
    rows = db.execute(
        "SELECT u.* FROM users u JOIN blocks b ON b.blocked_id=u.id WHERE b.blocker_id=?",
        (g.user["id"],),
    ).fetchall()
    return jsonify({"users": [user_public(u) for u in rows]})


# --------------------------------------------------------------------------
# Groups
# --------------------------------------------------------------------------

@app.route("/api/groups", methods=["POST"])
@auth_required
def create_group():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    password = data.get("password") or ""
    if not name:
        return jsonify({"error": "Group name is required"}), 400
    db = get_db()
    token = secrets.token_urlsafe(12)
    pw_hash = hash_pw(password) if password else ""
    cur = db.execute(
        "INSERT INTO groups(name, creator_id, invite_token, password_hash, created_at) "
        "VALUES (?,?,?,?,?)",
        (name, g.user["id"], token, pw_hash, time.time()),
    )
    gid = cur.lastrowid
    db.execute(
        "INSERT INTO group_members(group_id, user_id, role, joined_at) VALUES (?,?,?,?)",
        (gid, g.user["id"], "admin", time.time()),
    )
    db.commit()
    return jsonify({
        "group": {
            "id": gid, "name": name, "invite_token": token,
            "has_password": bool(password), "role": "admin",
        }
    })


@app.route("/api/groups/mine", methods=["GET"])
@auth_required
def my_groups():
    db = get_db()
    rows = db.execute(
        """SELECT g.*, m.role FROM groups g
           JOIN group_members m ON m.group_id = g.id
           WHERE m.user_id=?""",
        (g.user["id"],),
    ).fetchall()
    return jsonify({
        "groups": [
            {"id": r["id"], "name": r["name"], "avatar": r["avatar"],
             "invite_token": r["invite_token"], "role": r["role"],
             "has_password": bool(r["password_hash"])}
            for r in rows
        ]
    })


@app.route("/api/groups/join/<token>", methods=["POST"])
@auth_required
def join_group(token):
    password = (request.get_json(force=True) or {}).get("password", "")
    db = get_db()
    grp = db.execute("SELECT * FROM groups WHERE invite_token=?", (token,)).fetchone()
    if not grp:
        return jsonify({"error": "Invalid invite link"}), 404
    if grp["password_hash"] and not verify_pw(password, grp["password_hash"]):
        return jsonify({"error": "Incorrect group password"}), 403
    db.execute(
        "INSERT OR IGNORE INTO group_members(group_id, user_id, role, joined_at) VALUES (?,?,?,?)",
        (grp["id"], g.user["id"], "member", time.time()),
    )
    db.commit()
    return jsonify({"group": {"id": grp["id"], "name": grp["name"], "role": "member"}})


@app.route("/api/groups/<int:gid>/members", methods=["GET"])
@auth_required
def group_members(gid):
    db = get_db()
    member = db.execute(
        "SELECT * FROM group_members WHERE group_id=? AND user_id=?", (gid, g.user["id"])
    ).fetchone()
    if not member:
        return jsonify({"error": "You are not a member of this group"}), 403
    rows = db.execute(
        """SELECT u.*, m.role FROM users u
           JOIN group_members m ON m.user_id = u.id
           WHERE m.group_id=?""",
        (gid,),
    ).fetchall()
    return jsonify({"members": [{**user_public(r), "role": r["role"]} for r in rows]})


@app.route("/api/groups/<int:gid>/avatar", methods=["POST"])
@auth_required
def group_avatar(gid):
    db = get_db()
    member = db.execute(
        "SELECT role FROM group_members WHERE group_id=? AND user_id=?", (gid, g.user["id"])
    ).fetchone()
    if not member or member["role"] != "admin":
        return jsonify({"error": "Only the group admin can change this"}), 403
    avatar_file = request.files.get("avatar")
    if not avatar_file or not allowed_file(avatar_file.filename):
        return jsonify({"error": "Invalid image"}), 400
    ext = avatar_file.filename.rsplit(".", 1)[1].lower()
    fname = f"g{gid}_{uuid.uuid4().hex}.{ext}"
    avatar_file.save(os.path.join(AVATAR_DIR, fname))
    db.execute("UPDATE groups SET avatar=? WHERE id=?", (f"/uploads/avatars/{fname}", gid))
    db.commit()
    return jsonify({"avatar": f"/uploads/avatars/{fname}"})


# --------------------------------------------------------------------------
# Media upload
# --------------------------------------------------------------------------

@app.route("/api/upload", methods=["POST"])
@auth_required
def upload_media():
    f = request.files.get("file")
    if not f or not f.filename or not allowed_file(f.filename):
        return jsonify({"error": "Invalid or missing file"}), 400
    ext = f.filename.rsplit(".", 1)[1].lower()
    fname = f"{uuid.uuid4().hex}.{ext}"
    f.save(os.path.join(MEDIA_DIR, fname))
    return jsonify({"path": f"/uploads/media/{fname}"})


@app.route("/uploads/<path:subpath>")
def serve_upload(subpath):
    return send_from_directory(UPLOAD_DIR, subpath)


# --------------------------------------------------------------------------
# Message history (so a page refresh never loses data)
# --------------------------------------------------------------------------

@app.route("/api/messages/dm/<int:other_id>", methods=["GET"])
@auth_required
def dm_history(other_id):
    db = get_db()
    chat_id = dm_chat_id(g.user["id"], other_id)
    rows = db.execute(
        "SELECT * FROM messages WHERE chat_type='dm' AND chat_id=? ORDER BY id ASC LIMIT 300",
        (chat_id,),
    ).fetchall()
    return jsonify({"messages": [serialize_message(db, r) for r in rows]})


@app.route("/api/messages/group/<int:gid>", methods=["GET"])
@auth_required
def group_history(gid):
    db = get_db()
    member = db.execute(
        "SELECT 1 FROM group_members WHERE group_id=? AND user_id=?", (gid, g.user["id"])
    ).fetchone()
    if not member:
        return jsonify({"error": "You are not a member of this group"}), 403
    rows = db.execute(
        "SELECT * FROM messages WHERE chat_type='group' AND chat_id=? ORDER BY id ASC LIMIT 300",
        (str(gid),),
    ).fetchall()
    return jsonify({"messages": [serialize_message(db, r) for r in rows]})


# --------------------------------------------------------------------------
# Socket.IO realtime layer
# --------------------------------------------------------------------------

sid_to_user = {}


@socketio.on("auth")
def sio_auth(data):
    token = (data or {}).get("token")
    conn = db_conn()
    user = conn.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()
    if not user:
        emit("auth_error", {"error": "Invalid session"})
        conn.close()
        return
    sid_to_user[request.sid] = user["id"]
    join_room(f"user:{user['id']}")
    for grow in conn.execute("SELECT group_id FROM group_members WHERE user_id=?", (user["id"],)):
        join_room(f"group:{grow['group_id']}")
    conn.execute("UPDATE users SET status='online' WHERE id=?", (user["id"],))
    conn.commit()
    conn.close()
    emit("auth_ok", {"user_id": user["id"]})


@socketio.on("disconnect")
def sio_disconnect():
    uid = sid_to_user.pop(request.sid, None)
    if uid:
        conn = db_conn()
        conn.execute("UPDATE users SET status='offline' WHERE id=?", (uid,))
        conn.commit()
        conn.close()


def rooms_for(chat_type, chat_id):
    """Return the exact list of rooms a chat's events should be delivered to.
    Each user's personal room ('user:<id>') is joined exactly once per
    connection, so this guarantees exactly one delivery per connected
    client -- no duplicates."""
    if chat_type == "dm":
        a, b = chat_id.split("_")
        return [f"user:{a}", f"user:{b}"]
    return [f"group:{chat_id}"]


@socketio.on("send_message")
def sio_send_message(data):
    uid = sid_to_user.get(request.sid)
    if not uid:
        emit("error_msg", {"error": "Not authenticated"})
        return

    chat_type = (data or {}).get("chat_type")     # 'dm' or 'group'
    target = (data or {}).get("target")           # other_id for dm, group_id for group
    msg_type = (data or {}).get("msg_type", "text")
    content = (data or {}).get("content", "")
    media_path = (data or {}).get("media_path", "")

    if chat_type not in ("dm", "group") or target is None:
        emit("error_msg", {"error": "Malformed message"})
        return
    if msg_type == "text" and not content.strip():
        emit("error_msg", {"error": "Empty message"})
        return

    conn = db_conn()
    if chat_type == "dm":
        # Check BOTH directions: either side having blocked the other stops the message.
        blocked = conn.execute(
            "SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) "
            "OR (blocker_id=? AND blocked_id=?)",
            (target, uid, uid, target),
        ).fetchone()
        if blocked:
            emit("error_msg", {"error": "You cannot message this user"})
            conn.close()
            return
        chat_id = dm_chat_id(uid, target)
    else:
        member = conn.execute(
            "SELECT 1 FROM group_members WHERE group_id=? AND user_id=?", (target, uid)
        ).fetchone()
        if not member:
            emit("error_msg", {"error": "Not a group member"})
            conn.close()
            return
        chat_id = str(target)

    cur = conn.execute(
        "INSERT INTO messages(chat_type, chat_id, sender_id, msg_type, content, media_path, timestamp) "
        "VALUES (?,?,?,?,?,?,?)",
        (chat_type, chat_id, uid, msg_type, content, media_path, time.time()),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM messages WHERE id=?", (cur.lastrowid,)).fetchone()
    payload = serialize_message(conn, row)
    conn.close()

    # Echo back the client-generated id so the sender's UI can replace its
    # optimistic bubble instantly instead of waiting for a full reload.
    payload["client_id"] = (data or {}).get("client_id")

    for room in rooms_for(chat_type, chat_id):
        emit("new_message", payload, room=room)


@socketio.on("delete_message")
def sio_delete_message(data):
    uid = sid_to_user.get(request.sid)
    msg_id = (data or {}).get("message_id")
    conn = db_conn()
    row = conn.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
    if not row or row["sender_id"] != uid:
        emit("error_msg", {"error": "You can only delete your own messages"})
        conn.close()
        return
    conn.execute("UPDATE messages SET deleted=1, content='', media_path='' WHERE id=?", (msg_id,))
    conn.commit()
    chat_type, chat_id = row["chat_type"], row["chat_id"]
    conn.close()
    for room in rooms_for(chat_type, chat_id):
        emit("message_deleted", {"message_id": msg_id}, room=room)


@socketio.on("react_message")
def sio_react(data):
    uid = sid_to_user.get(request.sid)
    if not uid:
        return
    msg_id = (data or {}).get("message_id")
    emoji = (data or {}).get("emoji")
    if not msg_id or not emoji:
        return
    conn = db_conn()
    row = conn.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
    if not row:
        conn.close()
        return
    conn.execute(
        "INSERT INTO reactions(message_id, user_id, emoji) VALUES (?,?,?) "
        "ON CONFLICT(message_id, user_id) DO UPDATE SET emoji=excluded.emoji",
        (msg_id, uid, emoji),
    )
    conn.commit()
    chat_type, chat_id = row["chat_type"], row["chat_id"]
    conn.close()
    for room in rooms_for(chat_type, chat_id):
        emit("message_reacted", {"message_id": msg_id, "user_id": uid, "emoji": emoji}, room=room)


@socketio.on("typing")
def sio_typing(data):
    uid = sid_to_user.get(request.sid)
    if not uid:
        return
    chat_type = (data or {}).get("chat_type")
    target = (data or {}).get("target")
    if chat_type not in ("dm", "group") or target is None:
        return
    if chat_type == "dm":
        emit("typing", {"user_id": uid}, room=f"user:{target}")
    else:
        emit("typing", {"user_id": uid}, room=f"group:{target}", include_self=False)


# --------------------------------------------------------------------------
# Frontend
# --------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "hm.html")


if __name__ == "__main__":
    init_db()
    print("HM Chat Server starting on http://0.0.0.0:5000")
    socketio.run(app, host="0.0.0.0", port=5000)
