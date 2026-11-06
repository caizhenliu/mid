from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor

app = FastAPI(title="投稿審查系統")

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
    author_name: str
    category: str
    title: str
    content: str

class ArticleUpdate(BaseModel):
    category: str
    title: str
    content: str

@app.get("/")
def read_root():
    return FileResponse("index.html")

# ==================== 作者功能 ====================

# 1. 查看作者自己的投稿稿件清單 (編輯中、審查中、已通過)
@app.get("/api/articles/author/{author_name}")
def get_author_articles(author_name: str):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, category, title, content, status, created_at FROM articles WHERE author_name = %s ORDER BY id DESC;",
                (author_name,)
            )
            return cur.fetchall()
    finally:
        conn.close()

# 2. 新增投稿 (狀態預設: 編輯中)
@app.post("/api/articles")
def create_article(data: ArticleCreate):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO articles (author_name, category, title, content, status)
                VALUES (%s, %s, %s, %s, '編輯中') RETURNING id;
                """,
                (data.author_name, data.category, data.title, data.content)
            )
            art_id = cur.fetchone()["id"]
            conn.commit()
            return {"message": "稿件草稿建立成功！", "id": art_id}
    finally:
        conn.close()

# 3. 編輯投稿 (僅限「編輯中」狀態)
@app.put("/api/articles/{art_id}")
def update_article(art_id: int, data: ArticleUpdate):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM articles WHERE id = %s;", (art_id,))
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
def delete_article(art_id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM articles WHERE id = %s;", (art_id,))
            art = cur.fetchone()
            if not art:
                raise HTTPException(status_code=404, detail="找不到該稿件！")
            if art["status"] != "編輯中":
                raise HTTPException(status_code=400, detail="僅能刪除「編輯中」之草稿！")

            cur.execute("DELETE FROM articles WHERE id = %s;", (art_id,))
            conn.commit()
            return {"message": "稿件已成功刪除！"}
    finally:
        conn.close()

# 5. 送出投稿 : 編輯中 => 審查中
@app.post("/api/articles/{art_id}/submit")
def submit_article(art_id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM articles WHERE id = %s;", (art_id,))
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
@app.get("/api/articles/editor/pending")
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

# 7. 選擇通過 : 審查中 => 已通過
@app.post("/api/articles/{art_id}/approve")
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
@app.post("/api/articles/{art_id}/reject")
def reject_article(art_id: int):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE articles SET status = '編輯中' WHERE id = %s AND status = '審查中';", (art_id,))
            conn.commit()
            return {"message": "稿件已退回給作者修改。"}
    finally:
        conn.close()