from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Header

from fastapi.middleware.cors import CORSMiddleware

from fastapi.responses import FileResponse

from pydantic import BaseModel

from typing import Optional

from pathlib import Path

from datetime import datetime, timezone

import hashlib

import secrets

import hmac

import os

import io

import json

import re

import sqlite3

import pandas as pd



# ============================================================

# APP

# ============================================================



app = FastAPI(title="DataMarket API", version="4.0.0")

app.add_middleware(

    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],

)



# ============================================================

# DIRECTORIES / DATABASE

# ============================================================



BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"

ORIGINAL_DIR = DATA_DIR / "original"

CLEANED_DIR = DATA_DIR / "cleaned"

DB_PATH = DATA_DIR / "datamarket.db"



ORIGINAL_DIR.mkdir(parents=True, exist_ok=True)

CLEANED_DIR.mkdir(parents=True, exist_ok=True)





def db():

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys = ON")

    return conn





def init_db():

    conn = db()

    conn.executescript(

        """

        CREATE TABLE IF NOT EXISTS users (

            id TEXT PRIMARY KEY,

            name TEXT NOT NULL,

            email TEXT NOT NULL UNIQUE,

            role TEXT NOT NULL CHECK(role IN ('buyer','seller')),

            password_hash TEXT NOT NULL,

            wallet_address TEXT,

            created_at TEXT NOT NULL

        );



        CREATE TABLE IF NOT EXISTS sessions (

            token TEXT PRIMARY KEY,

            user_id TEXT NOT NULL,

            created_at TEXT NOT NULL,

            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE

        );



        CREATE TABLE IF NOT EXISTS datasets (

            id TEXT PRIMARY KEY,

            seller_id TEXT NOT NULL,

            seller_name TEXT NOT NULL,

            seller_email TEXT NOT NULL,

            name TEXT NOT NULL,

            category TEXT NOT NULL,

            rows_count INTEGER NOT NULL,

            columns_count INTEGER NOT NULL,

            quality_score REAL NOT NULL,

            predicted_price REAL NOT NULL,
            seller_price REAL,

            analysis TEXT NOT NULL,

            cleaning_stats TEXT NOT NULL,

            file_hash TEXT NOT NULL,

            dataset_hash TEXT NOT NULL,

            original_path TEXT NOT NULL,

            cleaned_path TEXT NOT NULL,

            cleaned_filename TEXT NOT NULL,

            status TEXT NOT NULL,

            created_at TEXT NOT NULL,

            published_at TEXT,

            FOREIGN KEY(seller_id) REFERENCES users(id) ON DELETE CASCADE

        );



        CREATE INDEX IF NOT EXISTS idx_datasets_seller ON datasets(seller_id);

        CREATE INDEX IF NOT EXISTS idx_datasets_status ON datasets(status);

        CREATE INDEX IF NOT EXISTS idx_datasets_hashes ON datasets(file_hash, dataset_hash);



        CREATE TABLE IF NOT EXISTS purchases (

            id TEXT PRIMARY KEY,

            dataset_id TEXT,

            dataset_name TEXT NOT NULL,

            buyer_id TEXT NOT NULL,

            buyer_name TEXT NOT NULL,

            buyer_email TEXT NOT NULL,

            seller_id TEXT NOT NULL,

            seller_name TEXT NOT NULL,

            price REAL NOT NULL,

            currency TEXT NOT NULL,

            wallet_address TEXT,

            transaction_hash TEXT,

            status TEXT NOT NULL,

            purchased_at TEXT NOT NULL,

            dataset_deleted INTEGER NOT NULL DEFAULT 0,

            FOREIGN KEY(buyer_id) REFERENCES users(id) ON DELETE CASCADE

        );



        CREATE INDEX IF NOT EXISTS idx_purchases_buyer ON purchases(buyer_id);

        CREATE INDEX IF NOT EXISTS idx_purchases_seller ON purchases(seller_id);

        CREATE INDEX IF NOT EXISTS idx_purchases_dataset ON purchases(dataset_id);

        """

    )

    conn.commit()

    conn.close()





init_db()



# ============================================================

# MODELS

# ============================================================



class RegisterRequest(BaseModel):

    name: str

    email: str

    password: str

    role: str





class LoginRequest(BaseModel):

    email: str

    password: str

    role: str





class WalletRequest(BaseModel):

    wallet_address: str





class PurchaseRequest(BaseModel):

    dataset_id: str

    transaction_hash: Optional[str] = None

    wallet_address: Optional[str] = None
class PublishRequest(BaseModel):
    seller_price: float


# ============================================================

# HELPERS

# ============================================================



def now():

    return datetime.now(timezone.utc).isoformat()





def normalize_email(email):

    return str(email).strip().lower()





def normalize_role(role):

    role = str(role).strip().lower()

    if role not in {"buyer", "seller"}:

        raise HTTPException(status_code=400, detail="Role must be buyer or seller.")

    return role





def new_id(prefix):

    return prefix + "_" + secrets.token_hex(8)





def safe_filename(filename):

    filename = Path(filename or "dataset").name

    filename = re.sub(r"[^a-zA-Z0-9._-]", "_", filename)

    return filename or "dataset"





def hash_password(password):

    salt = os.urandom(16)

    iterations = 310000

    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)

    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"





def verify_password(password, stored):

    try:

        algorithm, iterations, salt, expected = stored.split("$")

        if algorithm != "pbkdf2_sha256":

            return False

        actual = hashlib.pbkdf2_hmac(

            "sha256", password.encode(), bytes.fromhex(salt), int(iterations)

        )

        return hmac.compare_digest(actual.hex(), expected)

    except Exception:

        return False





def row_to_user(row):

    return dict(row) if row else None





def public_user(user):

    return {

        "id": user["id"],

        "name": user["name"],

        "email": user["email"],

        "role": user["role"],

        "wallet_address": user.get("wallet_address"),

        "created_at": user["created_at"],

    }





def create_session(user_id):

    token = secrets.token_urlsafe(48)

    conn = db()

    conn.execute(

        "INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)",

        (token, user_id, now()),

    )

    conn.commit()

    conn.close()

    return token





def current_user(authorization: Optional[str] = Header(None)):

    if not authorization:

        raise HTTPException(status_code=401, detail="Authorization token required.")

    if not authorization.lower().startswith("bearer "):

        raise HTTPException(status_code=401, detail="Invalid authorization format.")

    token = authorization.split(" ", 1)[1].strip()

    conn = db()

    row = conn.execute(

        "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?",

        (token,),

    ).fetchone()

    conn.close()

    if not row:

        raise HTTPException(status_code=401, detail="Invalid or expired session.")

    return dict(row)





def require_role(user, role):

    if user["role"] != role:

        raise HTTPException(status_code=403, detail=f"{role.capitalize()} account required.")

    return user





def dataset_from_row(row):

    item = dict(row)

    item["rows"] = item.pop("rows_count")

    item["columns"] = item.pop("columns_count")

    item["cleaning_stats"] = json.loads(item["cleaning_stats"])

    return item





def public_dataset(item):

    if isinstance(item, sqlite3.Row):

        item = dataset_from_row(item)

    elif "rows_count" in item:

        item = dict(item)

        item["rows"] = item.pop("rows_count")

        item["columns"] = item.pop("columns_count")

        if isinstance(item.get("cleaning_stats"), str):

            item["cleaning_stats"] = json.loads(item["cleaning_stats"])

    return {

        "id": item["id"],

        "name": item["name"],

        "category": item["category"],

        "rows": item["rows"],

        "columns": item["columns"],

        "quality_score": item["quality_score"],

        "predicted_price": item["predicted_price"],
        "seller_price": item.get("seller_price"),
        "price": (
            item["seller_price"]
            if item.get("seller_price") is not None
            else item["predicted_price"]
        ),

        "analysis": item["analysis"],

        "cleaning_stats": item["cleaning_stats"],

        "status": item["status"],

        "seller": item["seller_name"],

        "seller_id": item["seller_id"],

        "created_at": item["created_at"],

        "published_at": item.get("published_at"),

    }



# ============================================================

# AUTH

# ============================================================



@app.post("/register")

def register(request: RegisterRequest):

    name = request.name.strip()

    email = normalize_email(request.email)

    role = normalize_role(request.role)

    password = request.password



    if not re.fullmatch(r"[^@\s]+@[^@\s]+", email):

        raise HTTPException(status_code=400, detail="Enter an email/username in name@domain format without spaces.")

    if len(name) < 2:

        raise HTTPException(status_code=400, detail="Name must contain at least 2 characters.")

    if len(password) < 6:

        raise HTTPException(status_code=400, detail="Password must contain at least 6 characters.")



    conn = db()

    existing = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()

    if existing:

        conn.close()

        raise HTTPException(

            status_code=409,

            detail="This email is already registered. Please use the same role to log in or use a different email.",

        )



    user_id = new_id("user")

    user = {

        "id": user_id,

        "name": name,

        "email": email,

        "role": role,

        "password_hash": hash_password(password),

        "wallet_address": None,

        "created_at": now(),

    }

    conn.execute(

        "INSERT INTO users(id,name,email,role,password_hash,wallet_address,created_at) VALUES(?,?,?,?,?,?,?)",

        (user_id, name, email, role, user["password_hash"], None, user["created_at"]),

    )

    conn.commit()

    conn.close()

    return {"message": "Account created successfully.", "user": public_user(user)}





@app.post("/login")

def login(request: LoginRequest):

    email = normalize_email(request.email)

    role = normalize_role(request.role)

    conn = db()

    row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

    conn.close()

    if not row:

        raise HTTPException(status_code=401, detail="No account found with this email.")

    user = dict(row)

    if user["role"] != role:

        raise HTTPException(

            status_code=401,

            detail=f"This email belongs to a {user['role']} account. Please select {user['role']}.",

        )

    if not verify_password(request.password, user["password_hash"]):

        raise HTTPException(status_code=401, detail="Incorrect password.")

    token = create_session(user["id"])

    return {

        "message": "Login successful.",

        "token": token,

        "access_token": token,

        "user": public_user(user),

    }





@app.post("/logout")

def logout(authorization: Optional[str] = Header(None)):

    if authorization and authorization.lower().startswith("bearer "):

        token = authorization.split(" ", 1)[1].strip()

        conn = db()

        conn.execute("DELETE FROM sessions WHERE token=?", (token,))

        conn.commit()

        conn.close()

    return {"message": "Logged out successfully."}





@app.get("/me")

def me(user=Depends(current_user)):

    return {"user": public_user(user)}





@app.post("/wallet")

def wallet(request: WalletRequest, user=Depends(current_user)):

    address = request.wallet_address.strip()

    if len(address) < 10:

        raise HTTPException(status_code=400, detail="Invalid wallet address.")

    conn = db()

    conn.execute("UPDATE users SET wallet_address=? WHERE id=?", (address, user["id"]))

    conn.commit()

    conn.close()

    return {"message": "Wallet connected successfully.", "wallet_address": address}



# ============================================================

# DATAFRAME / AI-LIKE ANALYSIS

# ============================================================



def read_dataframe(filename, content):

    extension = Path(filename).suffix.lower()

    try:

        if extension == ".csv":

            return pd.read_csv(io.BytesIO(content))

        if extension in {".xlsx", ".xls"}:

            return pd.read_excel(io.BytesIO(content))

        if extension == ".json":

            return pd.DataFrame(json.loads(content.decode()))

    except Exception as error:

        raise HTTPException(status_code=400, detail="Could not read dataset: " + str(error))

    raise HTTPException(status_code=400, detail="Supported formats: CSV, XLSX, XLS, JSON.")





def normalized_dataframe(df):

    work = df.copy()

    work.columns = [str(c).strip().lower().replace(" ", "_") for c in work.columns]

    for column in work.columns:

        work[column] = (

            work[column].fillna("").astype(str).str.strip().str.lower().str.replace(r"\s+", " ", regex=True)

        )

    work = work.dropna(how="all")

    work = work.reindex(sorted(work.columns), axis=1)

    try:

        work = work.sort_values(by=list(work.columns))

    except Exception:

        pass

    return work.reset_index(drop=True)





def dataset_hash(df):

    text = normalized_dataframe(df).to_csv(index=False)

    return hashlib.sha256(text.encode()).hexdigest()





def file_hash(content):

    return hashlib.sha256(content).hexdigest()





def clean_dataset(df):
    cleaned = df.copy()
    original_rows = len(cleaned)
    original_columns = len(cleaned.columns)

    names = []
    used = {}
    for index, column in enumerate(cleaned.columns):
        name = str(column).strip()
        name = re.sub(r"\s+", "_", name)
        name = re.sub(r"[^a-zA-Z0-9_]", "_", name).strip("_")
        if not name:
            name = f"column_{index + 1}"
        count = used.get(name, 0)
        if count:
            name = f"{name}_{count + 1}"
        used[name] = count + 1
        names.append(name)
    cleaned.columns = names

    rows_before = len(cleaned)
    cols_before = len(cleaned.columns)
    cleaned = cleaned.dropna(how="all")
    empty_rows_removed = rows_before - len(cleaned)
    cleaned = cleaned.dropna(axis=1, how="all")
    empty_columns_removed = cols_before - len(cleaned.columns)

    for column in cleaned.columns:
        if cleaned[column].dtype == "object":
            cleaned[column] = cleaned[column].apply(
                lambda value: value.strip() if isinstance(value, str) else value
            )

    # Convert numeric-looking text to numbers while preserving decimal values.
    for column in cleaned.columns:
        if cleaned[column].dtype == "object":
            non_empty = cleaned[column].dropna().astype(str).str.strip()
            if len(non_empty) > 0:
                numeric_values = pd.to_numeric(non_empty, errors="coerce")
                if numeric_values.notna().mean() >= 0.90:
                    cleaned[column] = pd.to_numeric(cleaned[column], errors="coerce")

    duplicates = int(cleaned.duplicated().sum())
    cleaned = cleaned.drop_duplicates()
    missing_before = int(cleaned.isna().sum().sum())

    for column in cleaned.columns:
        if cleaned[column].isna().sum() == 0:
            continue
        if pd.api.types.is_numeric_dtype(cleaned[column]):
            value = cleaned[column].median()
            if pd.isna(value):
                value = 0
        else:
            mode = cleaned[column].mode()
            value = mode.iloc[0] if len(mode) else "Unknown"
        cleaned[column] = cleaned[column].fillna(value)

    missing_after = int(cleaned.isna().sum().sum())
    cleaned = cleaned.reset_index(drop=True)

    return cleaned, {
        "original_rows": original_rows,
        "cleaned_rows": len(cleaned),
        "original_columns": original_columns,
        "cleaned_columns": len(cleaned.columns),
        "empty_rows_removed": empty_rows_removed,
        "empty_columns_removed": empty_columns_removed,
        "duplicates_removed": duplicates,
        "missing_values_before": missing_before,
        "missing_values_filled": missing_before - missing_after,
        "missing_values_after": missing_after,
    }

def category(filename, columns):

    text = filename.lower() + " " + " ".join(str(c).lower() for c in columns)

    mapping = {

        "Finance": ["finance", "income", "revenue", "loan", "credit", "bank", "transaction"],

        "Marketing": ["marketing", "campaign", "lead", "click", "conversion", "advertising"],

        "Healthcare": ["health", "medical", "patient", "hospital", "diagnosis"],

        "E-commerce": ["order", "product", "purchase", "customer", "sales", "cart"],

        "Education": ["student", "school", "college", "university", "course", "grade"],

        "Technology": ["software", "server", "device", "computer", "api", "developer"],

    }

    best, score = "General", 0

    for name, words in mapping.items():

        current = sum(1 for word in words if word in text)

        if current > score:

            score, best = current, name

    return best





def quality_score(df, stats):

    score = 100

    total_cells = max(len(df) * max(len(df.columns), 1), 1)

    missing_ratio = stats["missing_values_filled"] / total_cells

    duplicate_ratio = stats["duplicates_removed"] / max(stats["original_rows"], 1)

    score -= min(30, missing_ratio * 100)

    score -= min(25, duplicate_ratio * 100)

    if len(df) >= 100:

        score += 5

    elif len(df) >= 50:

        score += 3

    if len(df.columns) >= 5:

        score += 3

    return max(0, min(100, round(score)))





def predicted_price(df, quality, category_name):
    rows = len(df)
    columns = len(df.columns)

    if rows <= 100:
        price = 4.0
    elif rows <= 500:
        price = 7.0
    elif rows <= 1000:
        price = 12.0
    elif rows <= 5000:
        price = 30.0
    elif rows <= 10000:
        price = 50.0
    elif rows <= 50000:
        price = 125.0
    else:
        price = 200.0

    quality_factor = 0.80 + (quality / 100) * 0.40
    price *= quality_factor

    if columns >= 20:
        price *= 1.10
    elif columns >= 10:
        price *= 1.05

    price = max(3.0, min(price, 500.0))

    return round(price, 2)



def analysis_text(filename, df, stats, quality, price, category_name):

    missing = stats["missing_values_filled"]

    duplicates = stats["duplicates_removed"]

    missing_text = f"{missing} missing values were handled." if missing else "No missing values required filling."

    duplicate_text = f"{duplicates} duplicate rows were removed." if duplicates else "No duplicate rows were found."

    return (

        f"The dataset '{filename}' was analyzed successfully. After cleaning, it contains "

        f"{len(df)} rows and {len(df.columns)} columns. {missing_text} {duplicate_text} "

        f"The estimated quality score is {quality}/100. The dataset is classified under "

        f"{category_name}. The AI recommended marketplace price is ${price:.2f}, based on "

        f"dataset size, structure and estimated quality."

    )



# ============================================================

# DUPLICATE CHECK

# ============================================================



def find_duplicate(f_hash, d_hash):

    conn = db()

    row = conn.execute(

        "SELECT * FROM datasets WHERE file_hash=? OR dataset_hash=? LIMIT 1",

        (f_hash, d_hash),

    ).fetchone()

    conn.close()

    return row



# ============================================================

# ANALYZE DATASET

# ============================================================



@app.post("/analyze-dataset")

async def analyze_dataset(file: UploadFile = File(...), user=Depends(current_user)):

    require_role(user, "seller")

    filename = safe_filename(file.filename)

    content = await file.read()

    if not content:

        raise HTTPException(status_code=400, detail="File is empty.")



    f_hash = file_hash(content)

    df = read_dataframe(filename, content)

    d_hash = dataset_hash(df)

    duplicate = find_duplicate(f_hash, d_hash)



    if duplicate:

        # Allow the same seller to re-analyze its own pending dataset, replacing the old pending record.

        if duplicate["seller_id"] == user["id"] and duplicate["status"] == "pending":

            old = dict(duplicate)

            for p in (old.get("original_path"), old.get("cleaned_path")):

                if p and Path(p).exists():

                    try:

                        Path(p).unlink()

                    except Exception:

                        pass

            conn = db()

            conn.execute("DELETE FROM datasets WHERE id=?", (old["id"],))

            conn.commit()

            conn.close()

        else:

            status_text = "already published in the marketplace" if duplicate["status"] == "published" else "already been submitted"

            raise HTTPException(

                status_code=409,

                detail=f"This dataset or an equivalent normalized dataset has {status_text}."

            )



    cleaned, stats = clean_dataset(df)

    q = quality_score(
        cleaned,
        stats
    )

    cat = category(
        filename,
        cleaned.columns
    )

    price = predicted_price(
        cleaned,
        q,
        cat
    )

    analysis = analysis_text(
        filename,
        cleaned,
        stats,
        q,
        price,
        cat
    )



    dataset_id = new_id("dataset")

    original_path = ORIGINAL_DIR / f"{dataset_id}_{filename}"

    original_path.write_bytes(content)

    cleaned_filename = f"{Path(filename).stem}_cleaned_{dataset_id}.csv"

    cleaned_path = CLEANED_DIR / cleaned_filename

    cleaned.to_csv(cleaned_path, index=False)



    created_at = now()

    conn = db()

    conn.execute(

        """

        INSERT INTO datasets(

            id,seller_id,seller_name,seller_email,name,category,rows_count,columns_count,

            quality_score,predicted_price,seller_price,analysis,cleaning_stats,file_hash,dataset_hash,

            original_path,cleaned_path,cleaned_filename,status,created_at,published_at

        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)

        """,

        (

            dataset_id, user["id"], user["name"], user["email"], filename, cat,

            len(cleaned), len(cleaned.columns), q, price, None, analysis, json.dumps(stats),

            f_hash, d_hash, str(original_path), str(cleaned_path), cleaned_filename,

            "pending", created_at, None,

        ),

    )

    conn.commit()

    conn.close()



    preview = json.loads(cleaned.head(10).to_json(orient="records", date_format="iso"))

    return {

        "success": True,

        "message": "Dataset analyzed successfully.",

        "dataset": {

            "id": dataset_id,

            "name": filename,

            "category": cat,

            "rows": len(cleaned),

            "columns": len(cleaned.columns),

            "quality_score": q,

            "predicted_price": price,

            "price": price,

            "analysis": analysis,

            "cleaning_stats": stats,

            "preview": preview,

            "status": "pending",

            "seller": user["name"],

        },

    }



# ============================================================

# PENDING DATASET

# ============================================================



@app.get("/pending-dataset/{dataset_id}")

def pending_dataset(dataset_id: str, user=Depends(current_user)):

    require_role(user, "seller")

    conn = db()

    row = conn.execute("SELECT * FROM datasets WHERE id=? AND status='pending'", (dataset_id,)).fetchone()

    conn.close()

    if not row:

        raise HTTPException(status_code=404, detail="Pending dataset not found.")

    if row["seller_id"] != user["id"]:

        raise HTTPException(status_code=403, detail="You do not own this dataset.")

    item = dataset_from_row(row)

    path = Path(item["cleaned_path"])

    if not path.exists():

        raise HTTPException(status_code=404, detail="Cleaned file not found.")

    df = pd.read_csv(path)

    public = public_dataset(item)

    public["preview"] = json.loads(df.head(10).to_json(orient="records"))

    return {"dataset": public}



# ============================================================

# PUBLISH

# ============================================================



@app.post("/publish-dataset/{dataset_id}")
def publish(
    dataset_id: str,
    payload: PublishRequest,
    user=Depends(current_user)
):
    seller_price = payload.seller_price
    require_role(user, "seller")

    conn = db()

    row = conn.execute(
        "SELECT * FROM datasets WHERE id=?",
        (dataset_id,)
    ).fetchone()

    if not row:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Pending dataset not found."
        )

    if row["seller_id"] != user["id"]:
        conn.close()
        raise HTTPException(
            status_code=403,
            detail="You do not own this dataset."
        )

    if row["status"] == "published":
        conn.close()
        return {
            "message": "Dataset already published.",
            "dataset": public_dataset(row)
        }

    analysis_value = row["analysis"]
    cleaning_value = row["cleaning_stats"]

    analyzed = bool(
        analysis_value
        and str(analysis_value).strip() not in ("{}", "null", "None")
        and cleaning_value
        and str(cleaning_value).strip() not in ("{}", "null", "None")
    )

    if not analyzed:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="Analyze First. Please analyze the dataset before publishing."
        )

    if seller_price < 3 or seller_price > 500:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="Price must be between $3 and $500."
        )

    published_at = now()

    conn.execute(
        """
        UPDATE datasets
        SET status='published',
            seller_price=?,
            published_at=?
        WHERE id=?
        """,
        (seller_price, published_at, dataset_id)
    )

    conn.commit()

    updated = conn.execute(
        "SELECT * FROM datasets WHERE id=?",
        (dataset_id,)
    ).fetchone()

    conn.close()

    return {
        "message": "Dataset published successfully.",
        "dataset": public_dataset(updated)
    }
# MARKETPLACE: SEARCH REQUIRED

# ============================================================



@app.get("/datasets")

def marketplace(search: str = "", user=Depends(current_user)):

    require_role(user, "buyer")

    search = search.strip().lower()

    like = f"%{search}%"



    like = f"%{search}%"

    conn = db()

    rows = conn.execute(

        """

        SELECT * FROM datasets

        WHERE status='published'

          AND (LOWER(name) LIKE ? OR LOWER(category) LIKE ?)

        ORDER BY COALESCE(published_at, created_at) DESC

        """,

        (like, like),

    ).fetchall()

    conn.close()

    return {"success": True, "datasets": [public_dataset(row) for row in rows]}



# ============================================================

# SELLER DATASETS

# ============================================================



@app.get("/seller/datasets")

def seller_datasets(user=Depends(current_user)):

    require_role(user, "seller")

    conn = db()

    rows = conn.execute(

        "SELECT * FROM datasets WHERE seller_id=? ORDER BY created_at DESC", (user["id"],)

    ).fetchall()

    conn.close()

    return {"datasets": [public_dataset(row) for row in rows]}



# ============================================================

# DATASET DETAILS

# ============================================================



@app.get("/dataset/{dataset_id}")

def dataset_details(dataset_id: str):

    conn = db()

    row = conn.execute("SELECT * FROM datasets WHERE id=? AND status='published'", (dataset_id,)).fetchone()

    conn.close()

    if not row:

        raise HTTPException(status_code=404, detail="Dataset not found.")

    return {"dataset": public_dataset(row)}



# ============================================================

# DOWNLOAD

# ============================================================



@app.get("/download-cleaned/{dataset_id}")

def download(dataset_id: str, user=Depends(current_user)):

    conn = db()

    row = conn.execute("SELECT * FROM datasets WHERE id=? AND status='published'", (dataset_id,)).fetchone()

    if not row:

        conn.close()

        raise HTTPException(status_code=404, detail="Dataset not found.")



    allowed = row["seller_id"] == user["id"] and user["role"] == "seller"

    if user["role"] == "buyer":

        paid = conn.execute(

            "SELECT 1 FROM purchases WHERE buyer_id=? AND dataset_id=? AND status='paid' LIMIT 1",

            (user["id"], dataset_id),

        ).fetchone()

        allowed = paid is not None

    conn.close()



    if not allowed:

        raise HTTPException(status_code=403, detail="You must purchase this dataset before downloading it.")



    path = Path(row["cleaned_path"])

    if not path.exists():

        raise HTTPException(status_code=404, detail="Cleaned file not found.")

    return FileResponse(path=path, filename=row["cleaned_filename"], media_type="text/csv")



# ============================================================

# PURCHASE

# ============================================================



@app.post("/purchase")

def purchase(request: PurchaseRequest, user=Depends(current_user)):

    require_role(user, "buyer")

    conn = db()

    item = conn.execute("SELECT * FROM datasets WHERE id=? AND status='published'", (request.dataset_id,)).fetchone()

    if not item:

        conn.close()

        raise HTTPException(status_code=404, detail="Dataset not found.")

    if item["seller_id"] == user["id"]:

        conn.close()

        raise HTTPException(status_code=400, detail="You cannot buy your own dataset.")



    old = conn.execute(

        "SELECT * FROM purchases WHERE buyer_id=? AND dataset_id=? AND status='paid' LIMIT 1",

        (user["id"], request.dataset_id),

    ).fetchone()

    if old:

        conn.close()

        return {"message": "Dataset already purchased.", "purchase": dict(old)}



    purchase_id = new_id("purchase")

    purchased_at = now()

    wallet_address = request.wallet_address or user.get("wallet_address")

    conn.execute(

        """

        INSERT INTO purchases(

            id,dataset_id,dataset_name,buyer_id,buyer_name,buyer_email,seller_id,seller_name,

            price,currency,wallet_address,transaction_hash,status,purchased_at,dataset_deleted

        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)

        """,

        (

            purchase_id, request.dataset_id, item["name"], user["id"], user["name"], user["email"],

            item["seller_id"], item["seller_name"], item["predicted_price"], "USD",

            wallet_address, request.transaction_hash, "paid", purchased_at,

        ),

    )

    conn.commit()

    row = conn.execute("SELECT * FROM purchases WHERE id=?", (purchase_id,)).fetchone()

    conn.close()

    return {"message": "Dataset purchased successfully.", "purchase": dict(row)}



# ============================================================

# BUYER PURCHASES

# ============================================================



@app.get("/buyer/purchases")

def buyer_purchases(user=Depends(current_user)):

    require_role(user, "buyer")

    conn = db()

    rows = conn.execute(

        "SELECT * FROM purchases WHERE buyer_id=? ORDER BY purchased_at DESC", (user["id"],)

    ).fetchall()

    conn.close()

    return {"purchases": [dict(row) for row in rows]}



# ============================================================

# SELLER SALES / WHO PURCHASED

# ============================================================



@app.get("/seller/sales")

def seller_sales(user=Depends(current_user)):

    require_role(user, "seller")

    conn = db()

    rows = conn.execute(

        "SELECT * FROM purchases WHERE seller_id=? AND status='paid' ORDER BY purchased_at DESC",

        (user["id"],),

    ).fetchall()

    conn.close()

    result = [dict(row) for row in rows]

    total = sum(float(x["price"]) for x in result)

    return {"sales": result, "sales_count": len(result), "total_sales": round(total, 2)}



# ============================================================

# DELETE DATASET

# ============================================================



@app.delete("/delete-dataset/{dataset_id}")

def delete_dataset(dataset_id: str, user=Depends(current_user)):

    require_role(user, "seller")

    conn = db()

    row = conn.execute("SELECT * FROM datasets WHERE id=?", (dataset_id,)).fetchone()

    if not row:

        conn.close()

        raise HTTPException(status_code=404, detail="Dataset not found.")

    if row["seller_id"] != user["id"]:

        conn.close()

        raise HTTPException(status_code=403, detail="You do not own this dataset.")



    for p in (row["original_path"], row["cleaned_path"]):

        if p and Path(p).exists():

            try:

                Path(p).unlink()

            except Exception:

                pass



    conn.execute("UPDATE purchases SET dataset_deleted=1 WHERE dataset_id=?", (dataset_id,))

    conn.execute("DELETE FROM datasets WHERE id=?", (dataset_id,))

    conn.commit()

    conn.close()

    return {"message": "Dataset deleted successfully.", "dataset_id": dataset_id}



# ============================================================

# HEALTH

# ============================================================



@app.get("/")

def root():

    return {"name": "DataMarket API", "status": "running", "version": "4.0.0", "database": "SQLite"}





@app.get("/health")

def health():

    conn = db()

    users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    published = conn.execute("SELECT COUNT(*) FROM datasets WHERE status='published'").fetchone()[0]

    pending = conn.execute("SELECT COUNT(*) FROM datasets WHERE status='pending'").fetchone()[0]

    purchases = conn.execute("SELECT COUNT(*) FROM purchases").fetchone()[0]

    conn.close()

    return {

        "status": "ok",

        "users": users,

        "published_datasets": published,

        "pending_datasets": pending,

        "purchases": purchases,

        "database": str(DB_PATH),

    }
