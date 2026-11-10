import base64
import hashlib
import hmac
import os
import secrets
import time
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from typing import Literal
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor
from pathlib import Path
import re
from uuid import uuid4

UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"
MAX_ATTACHMENT_SIZE = 20 * 1024 * 1024
MAX_ATTACHMENTS_PER_ARTICLE = 5
ALLOWED_ATTACHMENT_EXTENSIONS = {".doc", ".docx", ".odt", ".pdf", ".rtf", ".txt"}
SESSION_COOKIE = "manuscript_session"
SESSION_MAX_AGE = 60 * 60 * 12
SESSION_SECRET = os.environ.get("SESSION_SECRET") or secrets.token_urlsafe(32)
EDITOR_REGISTRATION_CODE = os.environ.get("EDITOR_REGISTRATION_CODE")
PASSWORD_HASH_N = 2 ** 14


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    create_app_tables()
    yield


app = FastAPI(title="投稿審查系統", lifespan=lifespan)

# 資料庫連線配置
DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "database": "postgres",
    "user": "postgres",
    "password": "010030"
}

def get_connection():
    return psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)

# Request 模型
class ArticleCreate(BaseModel):
    category: str
    title: str
    content: str

class ArticleUpdate(BaseModel):
    category: str
    title: str
    content: str


class RegisterRequest(BaseModel):
    username: str
    password: str
    role: Literal["author", "editor"]
    editor_code: str = ""


class LoginRequest(BaseModel):
    username: str
    password: str


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    password_hash = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=PASSWORD_HASH_N,
        r=8,
        p=1,
        dklen=64
    )
    return f"{salt.hex()}:{password_hash.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, expected_hash = stored_hash.split(":", 1)
        actual_hash = hash_password(password, bytes.fromhex(salt_hex)).split(":", 1)[1]
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual_hash, expected_hash)


def create_session_token(user_id: int) -> str:
    expires_at = int(time.time()) + SESSION_MAX_AGE
    payload = base64.urlsafe_b64encode(f"{user_id}:{expires_at}".encode()).decode().rstrip("=")
    signature = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def read_session_user_id(token: str | None) -> int | None:
    if not token or "." not in token:
        return None
    payload, signature = token.rsplit(".", 1)
    expected_signature = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        return None
    try:
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
        user_id_text, expires_at_text = decoded.split(":", 1)
        user_id = int(user_id_text)
        if int(expires_at_text) < int(time.time()):
            return None
        return user_id
    except (ValueError, UnicodeDecodeError):
        return None


def set_session_cookie(response: Response, user_id: int, request: Request) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=create_session_token(user_id),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax"
    )


def get_current_user(request: Request) -> dict:
    user_id = read_session_user_id(request.cookies.get(SESSION_COOKIE))
    if user_id is None:
        raise HTTPException(status_code=401, detail="請先登入。")
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, display_name, role FROM users WHERE id = %s;",
                (user_id,)
            )
            user = cur.fetchone()
    finally:
        conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="登入狀態已失效，請重新登入。")
    return dict(user)


def require_author(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "author":
        raise HTTPException(status_code=403, detail="此功能僅限作者帳號使用。")
    return user


def require_editor(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "editor":
        raise HTTPException(status_code=403, detail="此功能僅限編輯帳號使用。")
    return user


def get_attachment_path(article_id: int, stored_name: str) -> Path:
    return UPLOAD_DIR / str(article_id) / stored_name


def create_app_tables():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    display_name VARCHAR(100) NOT NULL,
                    password_hash TEXT NOT NULL,
                    role VARCHAR(10) NOT NULL CHECK (role IN ('author', 'editor')),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS articles (
                    id SERIAL PRIMARY KEY,
                    author_name VARCHAR(100) NOT NULL,
                    category VARCHAR(50) NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    content TEXT NOT NULL,
                    status VARCHAR(20) DEFAULT '編輯中',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            cur.execute(
                """
                ALTER TABLE articles
                ADD COLUMN IF NOT EXISTS author_user_id INTEGER REFERENCES users(id);
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_articles_author_user_id ON articles(author_user_id);"
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS article_attachments (
                    id SERIAL PRIMARY KEY,
                    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
                    original_name VARCHAR(255) NOT NULL,
                    stored_name VARCHAR(64) NOT NULL,
                    content_type VARCHAR(255),
                    file_size BIGINT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
        conn.commit()
    finally:
        conn.close()


@app.get("/")
def read_root():
    return FileResponse("index.html")


@app.post("/api/auth/register")
def register(data: RegisterRequest, request: Request, response: Response):
    username = data.username.strip().lower()
    display_name = username
    if not re.fullmatch(r"[a-z0-9_.-]{3,50}", username):
        raise HTTPException(status_code=400, detail="帳號需為 3 至 50 個英數字、底線、句點或連字號。")
    if len(data.password) < 8 or len(data.password) > 128:
        raise HTTPException(status_code=400, detail="密碼長度需為 8 至 128 個字元。")
    if data.role == "editor" and (
        not EDITOR_REGISTRATION_CODE
        or not hmac.compare_digest(data.editor_code, EDITOR_REGISTRATION_CODE)
    ):
        raise HTTPException(status_code=403, detail="編輯註冊碼無效或尚未設定。")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (username, display_name, password_hash, role)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (username) DO NOTHING
                RETURNING id, username, display_name, role;
                """,
                (username, display_name, hash_password(data.password), data.role)
            )
            user = cur.fetchone()
            if not user:
                raise HTTPException(status_code=409, detail="此帳號已被註冊。")
        conn.commit()
    finally:
        conn.close()

    user = dict(user)
    set_session_cookie(response, user["id"], request)
    return {"user": user}


@app.post("/api/auth/login")
def login(data: LoginRequest, request: Request, response: Response):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, username, display_name, role, password_hash
                FROM users
                WHERE username = %s;
                """,
                (data.username.strip().lower(),)
            )
            user = cur.fetchone()
    finally:
        conn.close()
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤。")

    set_session_cookie(response, user["id"], request)
    return {
        "user": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"],
            "role": user["role"]
        }
    }


@app.get("/api/auth/me")
def get_session_user(user: dict = Depends(get_current_user)):
    return {"user": user}


@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie(key=SESSION_COOKIE, httponly=True, samesite="lax")
    return {"message": "已安全登出。"}

# ==================== 作者功能 ====================

# 1. 查看作者自己的投稿稿件清單 (編輯中、審查中、已通過)
@app.get("/api/articles/mine")
def get_author_articles(user: dict = Depends(require_author)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, category, title, content, status, created_at
                FROM articles
                WHERE author_user_id = %s
                ORDER BY id DESC;
                """,
                (user["id"],)
            )
            return cur.fetchall()
    finally:
        conn.close()

# 2. 新增投稿 (狀態預設: 編輯中)
@app.post("/api/articles")
def create_article(data: ArticleCreate, user: dict = Depends(require_author)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO articles
                    (author_user_id, author_name, category, title, content, status)
                VALUES (%s, %s, %s, %s, %s, '編輯中')
                RETURNING id;
                """,
                (user["id"], user["display_name"], data.category, data.title, data.content)
            )
            art_id = cur.fetchone()["id"]
            conn.commit()
            return {"message": "稿件草稿建立成功！", "id": art_id}
    finally:
        conn.close()

# 3. 編輯投稿 (僅限「編輯中」狀態)
@app.put("/api/articles/{art_id}")
def update_article(art_id: int, data: ArticleUpdate, user: dict = Depends(require_author)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM articles WHERE id = %s AND author_user_id = %s;",
                (art_id, user["id"])
            )
            art = cur.fetchone()
            if not art:
                raise HTTPException(status_code=404, detail="找不到該稿件！")
            if art["status"] != "編輯中":
                raise HTTPException(status_code=400, detail="非「編輯中」狀態之稿件不可修改！")

            cur.execute(
                "UPDATE articles SET category = %s, title = %s, content = %s WHERE id = %s;",
                (data.category, data.title, data.content, art_id)
            )
            conn.commit()
            return {"message": "稿件更新成功！"}
    finally:
        conn.close()

# 4. 刪除編輯中稿件 (僅限「編輯中」狀態)
@app.delete("/api/articles/{art_id}")
def delete_article(art_id: int, user: dict = Depends(require_author)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM articles WHERE id = %s AND author_user_id = %s;",
                (art_id, user["id"])
            )
            art = cur.fetchone()
            if not art:
                raise HTTPException(status_code=404, detail="找不到該稿件！")
            if art["status"] != "編輯中":
                raise HTTPException(status_code=400, detail="僅能刪除「編輯中」之草稿！")

            cur.execute(
                "SELECT stored_name FROM article_attachments WHERE article_id = %s;",
                (art_id,)
            )
            stored_names = [row["stored_name"] for row in cur.fetchall()]
            cur.execute("DELETE FROM articles WHERE id = %s;", (art_id,))
            conn.commit()
            for stored_name in stored_names:
                get_attachment_path(art_id, stored_name).unlink(missing_ok=True)
            return {"message": "稿件已成功刪除！"}
    finally:
        conn.close()


@app.post("/api/articles/{art_id}/attachments")
async def upload_attachment(
    art_id: int,
    request: Request,
    filename: str,
    user: dict = Depends(require_author)
):
    original_name = Path(filename.replace("\\", "/")).name
    extension = Path(original_name).suffix.lower()
    if not original_name or len(original_name) > 255:
        raise HTTPException(status_code=400, detail="檔名無效或超過 255 個字元。")
    if extension not in ALLOWED_ATTACHMENT_EXTENSIONS:
        raise HTTPException(status_code=400, detail="僅接受 PDF、Word、ODT、RTF 或 TXT 文件。")

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_ATTACHMENT_SIZE:
                raise HTTPException(status_code=413, detail="單一檔案大小不可超過 20 MB。")
        except ValueError as error:
            raise HTTPException(status_code=400, detail="檔案大小標頭無效。") from error

    content = bytearray()
    async for chunk in request.stream():
        content.extend(chunk)
        if len(content) > MAX_ATTACHMENT_SIZE:
            raise HTTPException(status_code=413, detail="單一檔案大小不可超過 20 MB。")
    if not content:
        raise HTTPException(status_code=400, detail="無法上傳空白檔案。")

    conn = get_connection()
    stored_path = None
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM articles WHERE id = %s AND author_user_id = %s;",
                (art_id, user["id"])
            )
            article = cur.fetchone()
            if not article:
                raise HTTPException(status_code=404, detail="找不到該稿件！")
            if article["status"] != "編輯中":
                raise HTTPException(status_code=400, detail="僅能為編輯中的草稿上傳附件。")

            cur.execute(
                "SELECT COUNT(*) AS count FROM article_attachments WHERE article_id = %s;",
                (art_id,)
            )
            if cur.fetchone()["count"] >= MAX_ATTACHMENTS_PER_ARTICLE:
                raise HTTPException(status_code=400, detail="每篇稿件最多可上傳 5 個附件。")

            stored_name = f"{uuid4().hex}{extension}"
            stored_path = get_attachment_path(art_id, stored_name)
            stored_path.parent.mkdir(parents=True, exist_ok=True)
            stored_path.write_bytes(content)
            cur.execute(
                """
                INSERT INTO article_attachments
                    (article_id, original_name, stored_name, content_type, file_size)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id, original_name, file_size;
                """,
                (
                    art_id,
                    original_name,
                    stored_name,
                    request.headers.get("content-type"),
                    len(content)
                )
            )
            attachment = cur.fetchone()
        conn.commit()
        return dict(attachment)
    except Exception:
        if stored_path:
            stored_path.unlink(missing_ok=True)
        raise
    finally:
        conn.close()


@app.get("/api/articles/{art_id}/attachments")
def get_article_attachments(art_id: int, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT author_user_id, status FROM articles WHERE id = %s;",
                (art_id,)
            )
            article = cur.fetchone()
            if not article:
                raise HTTPException(status_code=404, detail="找不到該稿件！")
            if user["role"] == "author" and article["author_user_id"] != user["id"]:
                raise HTTPException(status_code=404, detail="找不到該稿件！")
            if user["role"] == "editor" and article["status"] == "編輯中":
                raise HTTPException(status_code=404, detail="找不到該稿件！")
            cur.execute(
                """
                SELECT id, original_name, file_size, content_type
                FROM article_attachments
                WHERE article_id = %s
                ORDER BY id ASC;
                """,
                (art_id,)
            )
            return cur.fetchall()
    finally:
        conn.close()


@app.get("/api/attachments/{attachment_id}")
def download_attachment(attachment_id: int, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT a.article_id, a.original_name, a.stored_name,
                    articles.author_user_id, articles.status
                FROM article_attachments AS a
                JOIN articles ON articles.id = a.article_id
                WHERE a.id = %s;
                """,
                (attachment_id,)
            )
            attachment = cur.fetchone()
    finally:
        conn.close()

    if not attachment:
        raise HTTPException(status_code=404, detail="找不到該附件！")
    if user["role"] == "author" and attachment["author_user_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="找不到該附件！")
    if user["role"] == "editor" and attachment["status"] == "編輯中":
        raise HTTPException(status_code=404, detail="找不到該附件！")
    path = get_attachment_path(attachment["article_id"], attachment["stored_name"])
    if not path.is_file():
        raise HTTPException(status_code=404, detail="附件檔案不存在。")
    return FileResponse(path, filename=attachment["original_name"])


@app.delete("/api/attachments/{attachment_id}")
def delete_attachment(attachment_id: int, user: dict = Depends(require_author)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT a.article_id, a.stored_name, articles.status
                FROM article_attachments AS a
                JOIN articles ON articles.id = a.article_id
                WHERE a.id = %s AND articles.author_user_id = %s;
                """,
                (attachment_id, user["id"])
            )
            attachment = cur.fetchone()
            if not attachment:
                raise HTTPException(status_code=404, detail="找不到該附件！")
            if attachment["status"] != "編輯中":
                raise HTTPException(status_code=400, detail="僅能移除編輯中草稿的附件。")

            cur.execute("DELETE FROM article_attachments WHERE id = %s;", (attachment_id,))
            conn.commit()
        get_attachment_path(attachment["article_id"], attachment["stored_name"]).unlink(missing_ok=True)
        return {"message": "附件已移除。"}
    finally:
        conn.close()


# 5. 送出投稿 : 編輯中 => 審查中
@app.post("/api/articles/{art_id}/submit")
def submit_article(art_id: int, user: dict = Depends(require_author)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM articles WHERE id = %s AND author_user_id = %s;",
                (art_id, user["id"])
            )
            art = cur.fetchone()
            if not art:
                raise HTTPException(status_code=404, detail="找不到該稿件！")
            if art["status"] != "編輯中":
                raise HTTPException(status_code=400, detail="稿件已送出或審查完成，無法重複送出！")

            cur.execute("UPDATE articles SET status = '審查中' WHERE id = %s;", (art_id,))
            conn.commit()
            return {"message": "已成功送出投稿進入審查！"}
    finally:
        conn.close()


# ==================== 編輯功能 ====================

# 6. 查看待審查清單 (作者、類別、標題)
@app.get("/api/articles/editor/pending", dependencies=[Depends(require_editor)])
def get_pending_articles():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, author_name, category, title, content, status FROM articles WHERE status = '審查中' ORDER BY id ASC;"
            )
            return cur.fetchall()
    finally:
        conn.close()

# 6. 查看已通過稿件
@app.get("/api/articles/editor/approved", dependencies=[Depends(require_editor)])
def get_approved_articles():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, author_name, category, title, content, status FROM articles WHERE status = '已通過' ORDER BY id ASC;"
            )
            return cur.fetchall()
    finally:
        conn.close()

# 7. 選擇通過 : 審查中 => 已通過
@app.post("/api/articles/{art_id}/approve", dependencies=[Depends(require_editor)])
def approve_article(art_id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE articles SET status = '已通過' WHERE id = %s AND status = '審查中';", (art_id,))
            conn.commit()
            return {"message": "稿件審核通過！"}
    finally:
        conn.close()

# 8. 退回稿件 : 審查中 => 編輯中
@app.post("/api/articles/{art_id}/reject", dependencies=[Depends(require_editor)])
def reject_article(art_id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE articles SET status = '編輯中' WHERE id = %s AND status = '審查中';", (art_id,))
            conn.commit()
            return {"message": "稿件已退回給作者修改。"}
    finally:
        conn.close()