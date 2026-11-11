import base64
import hashlib
import hmac
import os
import secrets
import time
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from typing import Literal
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor
from pathlib import Path
from uuid import uuid4

UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"
MAX_ATTACHMENT_SIZE = 20 * 1024 * 1024
MAX_ATTACHMENTS_PER_ARTICLE = 5
ALLOWED_ATTACHMENT_EXTENSIONS = {".doc", ".docx", ".odt", ".pdf", ".rtf", ".txt"}
SESSION_MAX_AGE = 60 * 60 * 12
SESSION_SECRET = os.environ.get("SESSION_SECRET") or secrets.token_urlsafe(32)
EDITOR_REGISTRATION_CODE = os.environ.get("EDITOR_REGISTRATION_CODE")
PASSWORD_HASH_N = 2 ** 14

# FastAPI 啟動時建立資料表；yield 後開始處理請求。
@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    create_app_tables()
    yield

# 將生命週期函式交給 FastAPI 管理應用程式啟動流程。
app = FastAPI(title="投稿審查系統", lifespan=lifespan)


@app.middleware("http")
async def disable_api_response_caching(request: Request, call_next):
    # 先讓 FastAPI 處理請求，再檢查回應。
    response = await call_next(request)
    # API 回應不允許瀏覽器或代理伺服器快取。
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# 資料庫連線配置
DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "database": "postgres",
    "user": "postgres",
    "password": "010030"
}

def get_connection():
    # 使用字典格式回傳查詢結果，方便用欄位名稱取值。
    return psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)

# 以下模型定義 API 接收的資料欄位與型別。
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


# 使用隨機鹽值與 scrypt 雜湊密碼，避免以明文儲存。
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


# 驗證輸入密碼是否與資料庫中的雜湊值相符。
def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, expected_hash = stored_hash.split(":", 1)
        actual_hash = hash_password(password, bytes.fromhex(salt_hex)).split(":", 1)[1]
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual_hash, expected_hash)


# 建立含使用者編號、到期時間及簽章的登入權杖。
def create_session_token(user_id: int) -> str:
    payload = base64.urlsafe_b64encode(
        f"{user_id}:{int(time.time()) + SESSION_MAX_AGE}".encode()
    ).decode().rstrip("=")
    signature = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


# 驗證權杖簽章與有效期限，成功時回傳使用者編號。
def read_session_user_id(token: str | None) -> int | None:
    try:
        payload, signature = token.rsplit(".", 1)
        expected_signature = hmac.new(
            SESSION_SECRET.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            return None
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
        user_id, expires_at = decoded.split(":", 1)
        user_id = int(user_id)
        if int(expires_at) < int(time.time()):
            return None
        return user_id
    except (AttributeError, ValueError, UnicodeDecodeError):
        return None


# 從 Bearer 權杖取得登入使用者，並確認帳號仍存在。
def get_current_user(request: Request) -> dict:
    authorization = request.headers.get("authorization", "")
    scheme, separator, token = authorization.partition(" ")
    user_id = read_session_user_id(token.strip()) if separator and scheme.lower() == "bearer" else None
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


# FastAPI 權限依賴：限制端點只供作者使用。
def require_author(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "author":
        raise HTTPException(status_code=403, detail="此功能僅限作者帳號使用。")
    return user


# FastAPI 權限依賴：限制端點只供編輯使用。
def require_editor(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "editor":
        raise HTTPException(status_code=403, detail="此功能僅限編輯帳號使用。")
    return user


# 附件依稿件編號分資料夾儲存。
def get_attachment_path(article_id: int, stored_name: str) -> Path:
    return UPLOAD_DIR / str(article_id) / stored_name


# 建立使用者、稿件及附件資料表，並補上必要欄位與索引。
def create_app_tables():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role VARCHAR(10) NOT NULL CHECK (role IN ('author', 'editor')),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            cur.execute(
                """
                ALTER TABLE users
                ALTER COLUMN username TYPE TEXT,
                ALTER COLUMN display_name TYPE TEXT;
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
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_article_attachments_article_id ON article_attachments(article_id);"
            )
        conn.commit()
    finally:
        conn.close()


# 網站首頁回傳前端 HTML。
@app.get("/")
def read_root():
    return FileResponse("index.html")


# 註冊時拒絕空帳密，並驗證編輯註冊碼；成功後回傳登入權杖。
@app.post("/api/auth/register")
def register(data: RegisterRequest):
    username = data.username
    display_name = username
    if not username or not data.password:
        raise HTTPException(status_code=400, detail="帳號和密碼不可空白。")
    if data.role == "editor" and (
        not EDITOR_REGISTRATION_CODE
        or not hmac.compare_digest(data.editor_code, EDITOR_REGISTRATION_CODE)
    ):
        raise HTTPException(status_code=403, detail="編輯註冊碼無效或尚未設定。")
#建立資料庫連線，並將新使用者資料寫入 users 資料表；若帳號已存在則回傳衝突錯誤。
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
    return {"user": user, "access_token": create_session_token(user["id"])}


# 驗證帳號密碼，成功後回傳使用者資料及登入權杖。
@app.post("/api/auth/login")
def login(data: LoginRequest):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, username, display_name, role, password_hash
                FROM users
                WHERE username = %s;
                """,
                (data.username,)
            )
            user = cur.fetchone()
    finally:
        conn.close()
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤。")

    return {
        "user": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"],
            "role": user["role"]
        },
        "access_token": create_session_token(user["id"])
    }


#重新整理網頁時維持登入狀態
@app.get("/api/auth/me")
def get_session_user(user: dict = Depends(get_current_user)):
    return {"user": user}


# 登出端點；前端需清除本機保存的權杖。
@app.post("/api/auth/logout")
def logout():
    return {"message": "已安全登出。"}

# ==================== 作者功能 ====================

# 取得目前作者的投稿及每篇稿件的附件摘要。
@app.get("/api/articles/mine")
def get_author_articles(user: dict = Depends(require_author)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT articles.id, category, title, content, status, created_at,
                    COALESCE(attachment_data.attachments, '[]'::json) AS attachments
                FROM articles
                LEFT JOIN LATERAL (
                    SELECT json_agg(json_build_object(
                        'id', article_attachments.id,
                        'original_name', original_name,
                        'file_size', file_size
                    ) ORDER BY article_attachments.id) AS attachments
                    FROM article_attachments
                    WHERE article_attachments.article_id = articles.id
                ) AS attachment_data ON TRUE
                WHERE author_user_id = %s
                ORDER BY articles.id DESC;
                """,
                (user["id"],)
            )
            return cur.fetchall()
    finally:
        conn.close()

# 建立新稿件，初始狀態為「編輯中」。
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

# 作者只能修改自己的「編輯中」稿件。
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

# 作者只能刪除自己的「編輯中」稿件，並一併移除附件檔案。
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


# 上傳附件：檢查檔名、格式、大小、稿件狀態與數量後儲存檔案及資料。
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


# 列出稿件附件；作者只能看自己的，編輯不能看尚未送出的草稿。
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


# 下載附件前確認使用者有權查看所屬稿件。
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


# 作者只能移除自己「編輯中」稿件的附件。
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


# 將作者的「編輯中」稿件送入審查，狀態改為「審查中」。
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

# 依指定狀態查詢稿件，並附上附件摘要供編輯者查看。
def query_editor_articles(statuses: list[str]):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT articles.id, author_name, category, title, content, status,
                    COALESCE(attachment_data.attachments, '[]'::json) AS attachments
                FROM articles
                LEFT JOIN LATERAL (
                    SELECT json_agg(json_build_object(
                        'id', article_attachments.id,
                        'original_name', original_name,
                        'file_size', file_size
                    ) ORDER BY article_attachments.id) AS attachments
                    FROM article_attachments
                    WHERE article_attachments.article_id = articles.id
                ) AS attachment_data ON TRUE
                WHERE articles.status = ANY(%s)
                ORDER BY articles.id ASC;
                """,
                (statuses,)
            )
            return cur.fetchall()
    finally:
        conn.close()


# 編輯者查看審查中的稿件。
@app.get("/api/articles/editor/pending", dependencies=[Depends(require_editor)])
def get_pending_articles():
    return query_editor_articles(["審查中"])

# 編輯者查看已通過的稿件。
@app.get("/api/articles/editor/approved", dependencies=[Depends(require_editor)])
def get_approved_articles():
    return query_editor_articles(["已通過"])

# 編輯者一次查看審查中及已通過的稿件。
@app.get("/api/articles/editor", dependencies=[Depends(require_editor)])
def get_editor_articles():
    return query_editor_articles(["審查中", "已通過"])

# 將審查中的稿件標記為「已通過」。
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

# 將審查中的稿件退回作者，狀態改回「編輯中」。
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