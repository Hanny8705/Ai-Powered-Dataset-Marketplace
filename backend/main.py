from fastapi import (
    FastAPI,
    UploadFile,
    File,
    HTTPException,
    Depends,
    Header,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
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

import pandas as pd


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title="DataMarket API",
    version="3.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DIRECTORIES
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"

ORIGINAL_DIR = DATA_DIR / "original"

CLEANED_DIR = DATA_DIR / "cleaned"


ORIGINAL_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

CLEANED_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# MEMORY DATABASE
# ============================================================

users = {}

sessions = {}

pending_datasets = {}

datasets = {}

purchases = {}


# ============================================================
# MODELS
# ============================================================

class RegisterRequest(BaseModel):

    name: str

    email: EmailStr

    password: str

    role: str


class LoginRequest(BaseModel):

    email: EmailStr

    password: str

    role: str


class WalletRequest(BaseModel):

    wallet_address: str


class PurchaseRequest(BaseModel):

    dataset_id: str

    transaction_hash: Optional[str] = None

    wallet_address: Optional[str] = None


# ============================================================
# HELPERS
# ============================================================

def now():

    return datetime.now(
        timezone.utc
    ).isoformat()


def normalize_email(email):

    return (
        str(email)
        .strip()
        .lower()
    )


def normalize_role(role):

    role = (
        role
        .strip()
        .lower()
    )

    if role not in {
        "buyer",
        "seller",
    }:

        raise HTTPException(
            status_code=400,
            detail="Role must be buyer or seller.",
        )

    return role


def new_id(prefix):

    return (
        prefix
        + "_"
        + secrets.token_hex(8)
    )


def safe_filename(filename):

    filename = Path(
        filename or "dataset"
    ).name

    filename = re.sub(
        r"[^a-zA-Z0-9._-]",
        "_",
        filename,
    )

    return filename or "dataset"


# ============================================================
# PASSWORD
# ============================================================

def hash_password(password):

    salt = os.urandom(16)

    iterations = 310000

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        iterations,
    )

    return (
        f"pbkdf2_sha256$"
        f"{iterations}$"
        f"{salt.hex()}$"
        f"{digest.hex()}"
    )


def verify_password(
    password,
    stored,
):

    try:

        algorithm, iterations, salt, expected = (
            stored.split("$")
        )

        if algorithm != "pbkdf2_sha256":

            return False

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            bytes.fromhex(salt),
            int(iterations),
        )

        return hmac.compare_digest(
            actual.hex(),
            expected,
        )

    except Exception:

        return False


# ============================================================
# PUBLIC USER
# ============================================================

def public_user(user):

    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "wallet_address":
            user.get("wallet_address"),
        "created_at":
            user["created_at"],
    }


# ============================================================
# AUTH
# ============================================================

def create_session(user_id):

    token = secrets.token_urlsafe(48)

    sessions[token] = {
        "user_id": user_id,
        "created_at": now(),
    }

    return token


def current_user(
    authorization:
    Optional[str] = Header(None),
):

    if not authorization:

        raise HTTPException(
            status_code=401,
            detail="Authorization token required.",
        )


    if not authorization.lower().startswith(
        "bearer "
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid authorization format.",
        )


    token = authorization.split(
        " ",
        1,
    )[1].strip()


    session = sessions.get(
        token
    )


    if not session:

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired session.",
        )


    user = users.get(
        session["user_key"]
    )


    if not user:

        raise HTTPException(
            status_code=401,
            detail="User not found.",
        )


    return user


def require_role(
    user,
    role,
):

    if user["role"] != role:

        raise HTTPException(
            status_code=403,
            detail=f"{role.capitalize()} account required.",
        )

    return user


# ============================================================
# REGISTER
# ============================================================

@app.post("/register")
def register(
    request: RegisterRequest,
):

    name = request.name.strip()

    email = normalize_email(
        request.email
    )

    role = normalize_role(
        request.role
    )

    password = request.password


    if len(name) < 2:

        raise HTTPException(
            status_code=400,
            detail="Name must contain at least 2 characters.",
        )


    if len(password) < 6:

        raise HTTPException(
            status_code=400,
            detail="Password must contain at least 6 characters.",
        )


    # ========================================================
    # IMPORTANT:
    #
    # EMAIL MUST BE UNIQUE GLOBALLY.
    #
    # seller@gmail.com -> seller ONLY
    # buyer@gmail.com  -> buyer ONLY
    #
    # Same email cannot create another role.
    # ========================================================

    for existing_user in users.values():

        if existing_user["email"] == email:

            raise HTTPException(
                status_code=409,
                detail=(
                    "This email is already registered. "
                    "Please use a different email for "
                    "your Buyer or Seller account."
                ),
            )


    user_id = new_id(
        "user"
    )


    # Internal unique key

    user_key = user_id


    user = {

        "id":
            user_id,

        "name":
            name,

        "email":
            email,

        "role":
            role,

        "password_hash":
            hash_password(password),

        "wallet_address":
            None,

        "created_at":
            now(),

    }


    users[user_key] = user


    return {

        "message":
            "Account created successfully.",

        "user":
            public_user(user),

    }


# ============================================================
# LOGIN
# ============================================================

@app.post("/login")
def login(
    request: LoginRequest,
):

    email = normalize_email(
        request.email
    )

    role = normalize_role(
        request.role
    )


    # --------------------------------------------------------
    # Find exact email
    # --------------------------------------------------------

    user_key = None

    user = None


    for key, existing_user in users.items():

        if existing_user["email"] == email:

            user_key = key

            user = existing_user

            break


    if not user:

        raise HTTPException(
            status_code=401,
            detail="No account found with this email.",
        )


    # --------------------------------------------------------
    # Role must match account role
    # --------------------------------------------------------

    if user["role"] != role:

        raise HTTPException(
            status_code=401,
            detail=(
                f"This email belongs to a "
                f"{user['role']} account. "
                f"Please select {user['role']}."
            ),
        )


    # --------------------------------------------------------
    # Password
    # --------------------------------------------------------

    if not verify_password(
        request.password,
        user["password_hash"],
    ):

        raise HTTPException(
            status_code=401,
            detail="Incorrect password.",
        )


    # Store internal key for session

    user["session_key"] = user_key


    token = create_session(
        user_key
    )


    return {

        "message":
            "Login successful.",

        "token":
            token,

        "user":
            public_user(user),

    }


# ============================================================
# LOGOUT
# ============================================================

@app.post("/logout")
def logout(
    authorization:
    Optional[str] = Header(None),
):

    if authorization:

        try:

            token = authorization.split(
                " ",
                1,
            )[1]

            sessions.pop(
                token,
                None,
            )

        except Exception:

            pass


    return {
        "message":
            "Logged out successfully."
    }


# ============================================================
# ME
# ============================================================

@app.get("/me")
def me(
    user=Depends(current_user),
):

    return {
        "user":
            public_user(user)
    }


# ============================================================
# WALLET
# ============================================================

@app.post("/wallet")
def wallet(
    request: WalletRequest,
    user=Depends(current_user),
):

    address = (
        request.wallet_address
        .strip()
    )


    if len(address) < 10:

        raise HTTPException(
            status_code=400,
            detail="Invalid wallet address.",
        )


    user["wallet_address"] = address


    return {

        "message":
            "Wallet connected successfully.",

        "wallet_address":
            address,

    }


# ============================================================
# DATAFRAME
# ============================================================

def read_dataframe(
    filename,
    content,
):

    extension = Path(
        filename
    ).suffix.lower()


    try:

        if extension == ".csv":

            return pd.read_csv(
                io.BytesIO(content)
            )


        if extension in {
            ".xlsx",
            ".xls",
        }:

            return pd.read_excel(
                io.BytesIO(content)
            )


        if extension == ".json":

            return pd.DataFrame(
                json.loads(
                    content.decode()
                )
            )


    except Exception as error:

        raise HTTPException(
            status_code=400,
            detail=(
                "Could not read dataset: "
                + str(error)
            ),
        )


    raise HTTPException(
        status_code=400,
        detail=(
            "Supported formats: "
            "CSV, XLSX, XLS, JSON."
        ),
    )


# ============================================================
# NORMALIZE DATASET
# ============================================================

def normalized_dataframe(df):

    work = df.copy()


    work.columns = [
        str(c)
        .strip()
        .lower()
        .replace(" ", "_")
        for c in work.columns
    ]


    for column in work.columns:

        work[column] = (
            work[column]
            .fillna("")
            .astype(str)
            .str.strip()
            .str.lower()
            .str.replace(
                r"\s+",
                " ",
                regex=True,
            )
        )


    work = work.dropna(
        how="all"
    )


    work = work.reindex(
        sorted(
            work.columns
        ),
        axis=1,
    )


    try:

        work = work.sort_values(
            by=list(
                work.columns
            )
        )

    except Exception:

        pass


    return work.reset_index(
        drop=True
    )


def dataset_hash(df):

    normalized = normalized_dataframe(df)


    text = normalized.to_csv(
        index=False
    )


    return hashlib.sha256(
        text.encode()
    ).hexdigest()


def file_hash(content):

    return hashlib.sha256(
        content
    ).hexdigest()


# ============================================================
# CLEAN
# ============================================================

def clean_dataset(df):

    cleaned = df.copy()


    original_rows = len(
        cleaned
    )


    original_columns = len(
        cleaned.columns
    )


    # Column names

    names = []

    used = {}


    for index, column in enumerate(
        cleaned.columns
    ):

        name = str(
            column
        ).strip()


        name = re.sub(
            r"\s+",
            "_",
            name,
        )


        name = re.sub(
            r"[^a-zA-Z0-9_]",
            "_",
            name,
        )


        name = name.strip("_")


        if not name:

            name = (
                f"column_{index + 1}"
            )


        count = used.get(
            name,
            0,
        )


        if count:

            name = (
                f"{name}_{count + 1}"
            )


        used[name] = count + 1

        names.append(name)


    cleaned.columns = names


    # Empty rows/columns

    cleaned = cleaned.dropna(
        how="all"
    )

    cleaned = cleaned.dropna(
        axis=1,
        how="all"
    )


    # Trim strings

    for column in cleaned.columns:

        if (
            cleaned[column].dtype
            == "object"
        ):

            cleaned[column] = (
                cleaned[column]
                .apply(
                    lambda value:
                    value.strip()
                    if isinstance(
                        value,
                        str,
                    )
                    else value
                )
            )


    # Duplicates

    duplicates = int(
        cleaned.duplicated()
        .sum()
    )


    cleaned = (
        cleaned
        .drop_duplicates()
    )


    # Missing values

    missing = int(
        cleaned.isna()
        .sum()
        .sum()
    )


    for column in cleaned.columns:

        if (
            cleaned[column]
            .isna()
            .sum()
            == 0
        ):

            continue


        if pd.api.types.is_numeric_dtype(
            cleaned[column]
        ):

            value = (
                cleaned[column]
                .median()
            )


            if pd.isna(value):

                value = 0


            cleaned[column] = (
                cleaned[column]
                .fillna(value)
            )

        else:

            mode = (
                cleaned[column]
                .mode()
            )


            value = (
                mode.iloc[0]
                if len(mode)
                else "Unknown"
            )


            cleaned[column] = (
                cleaned[column]
                .fillna(value)
            )


    cleaned = cleaned.reset_index(
        drop=True
    )


    return cleaned, {

        "original_rows":
            original_rows,

        "cleaned_rows":
            len(cleaned),

        "original_columns":
            original_columns,

        "cleaned_columns":
            len(cleaned.columns),

        "duplicates_removed":
            duplicates,

        "missing_values_filled":
            missing,

    }


# ============================================================
# CATEGORY
# ============================================================

def category(
    filename,
    columns,
):

    text = (
        filename.lower()
        + " "
        + " ".join(
            str(c).lower()
            for c in columns
        )
    )


    mapping = {

        "Finance": [
            "finance",
            "income",
            "revenue",
            "loan",
            "credit",
            "bank",
            "transaction",
        ],

        "Marketing": [
            "marketing",
            "campaign",
            "lead",
            "click",
            "conversion",
            "advertising",
        ],

        "Healthcare": [
            "health",
            "medical",
            "patient",
            "hospital",
            "diagnosis",
        ],

        "E-commerce": [
            "order",
            "product",
            "purchase",
            "customer",
            "sales",
            "cart",
        ],

        "Education": [
            "student",
            "school",
            "college",
            "university",
            "course",
            "grade",
        ],

        "Technology": [
            "software",
            "server",
            "device",
            "computer",
            "api",
            "developer",
        ],

    }


    best = "General"

    score = 0


    for name, words in mapping.items():

        current = sum(
            1
            for word in words
            if word in text
        )


        if current > score:

            score = current

            best = name


    return best


# ============================================================
# QUALITY
# ============================================================

def quality_score(
    df,
    stats,
):

    score = 100


    total_cells = max(
        len(df)
        * max(len(df.columns), 1),
        1,
    )


    missing_ratio = (
        stats["missing_values_filled"]
        /
        total_cells
    )


    duplicate_ratio = (
        stats["duplicates_removed"]
        /
        max(
            stats["original_rows"],
            1,
        )
    )


    score -= min(
        30,
        missing_ratio * 100,
    )


    score -= min(
        25,
        duplicate_ratio * 100,
    )


    if len(df) >= 100:

        score += 5

    elif len(df) >= 50:

        score += 3


    if len(df.columns) >= 5:

        score += 3


    return max(
        0,
        min(
            100,
            round(score),
        ),
    )


# ============================================================
# PRICE
# ============================================================

def predicted_price(
    df,
    quality,
    category_name,
):

    price = 8

    price += min(
        45,
        len(df) * .035
    )

    price += min(
        25,
        len(df.columns) * 2.5
    )

    price += (
        quality * .22
    )


    bonuses = {

        "Finance": 12,

        "Healthcare": 12,

        "Marketing": 8,

        "Technology": 8,

        "E-commerce": 7,

        "Education": 6,

        "General": 2,

    }


    price += bonuses.get(
        category_name,
        2,
    )


    return round(
        min(
            499,
            max(
                9,
                price,
            ),
        ),
        2,
    )


# ============================================================
# ANALYSIS
# ============================================================

def analysis_text(
    filename,
    df,
    stats,
    quality,
    price,
    category_name,
):

    missing = stats[
        "missing_values_filled"
    ]

    duplicates = stats[
        "duplicates_removed"
    ]


    if missing:

        missing_text = (
            f"{missing} missing values "
            f"were handled."
        )

    else:

        missing_text = (
            "No missing values required filling."
        )


    if duplicates:

        duplicate_text = (
            f"{duplicates} duplicate rows "
            f"were removed."
        )

    else:

        duplicate_text = (
            "No duplicate rows were found."
        )


    return (
        f"The dataset '{filename}' was analyzed "
        f"successfully. After cleaning, it contains "
        f"{len(df)} rows and {len(df.columns)} columns. "
        f"{missing_text} {duplicate_text} "
        f"The estimated quality score is "
        f"{quality}/100. "
        f"The dataset is classified under "
        f"{category_name}. "
        f"The AI recommended marketplace price "
        f"is ${price:.2f}, based on dataset size, "
        f"structure and estimated quality."
    )


# ============================================================
# DUPLICATE CHECK
# ============================================================

def duplicate_exists(
    f_hash,
    d_hash,
):

    for item in datasets.values():

        if (
            item["file_hash"]
            == f_hash
        ):

            return item


        if (
            item["dataset_hash"]
            == d_hash
        ):

            return item


    for item in pending_datasets.values():

        if (
            item["file_hash"]
            == f_hash
        ):

            return item


        if (
            item["dataset_hash"]
            == d_hash
        ):

            return item


    return None


# ============================================================
# ANALYZE DATASET
# ============================================================

@app.post("/analyze-dataset")
async def analyze_dataset(
    file: UploadFile = File(...),
    user=Depends(current_user),
):

    require_role(
        user,
        "seller",
    )


    filename = safe_filename(
        file.filename
    )


    content = await file.read()


    if not content:

        raise HTTPException(
            status_code=400,
            detail="File is empty.",
        )


    f_hash = file_hash(
        content
    )


    df = read_dataframe(
        filename,
        content,
    )


    d_hash = dataset_hash(
        df
    )


    duplicate = duplicate_exists(
        f_hash,
        d_hash,
    )


    if duplicate:

        raise HTTPException(
            status_code=409,
            detail=(
                "This dataset or an equivalent "
                "normalized dataset already exists."
            ),
        )


    cleaned, stats = clean_dataset(
        df
    )


    q = quality_score(
        cleaned,
        stats,
    )


    cat = category(
        filename,
        cleaned.columns,
    )


    price = predicted_price(
        cleaned,
        q,
        cat,
    )


    analysis = analysis_text(
        filename,
        cleaned,
        stats,
        q,
        price,
        cat,
    )


    dataset_id = new_id(
        "dataset"
    )


    original_path = (
        ORIGINAL_DIR
        /
        f"{dataset_id}_{filename}"
    )


    original_path.write_bytes(
        content
    )


    cleaned_filename = (
        f"{Path(filename).stem}"
        f"_cleaned_{dataset_id}.csv"
    )


    cleaned_path = (
        CLEANED_DIR
        /
        cleaned_filename
    )


    cleaned.to_csv(
        cleaned_path,
        index=False,
    )


    item = {

        "id":
            dataset_id,

        "seller_id":
            user["id"],

        "seller_name":
            user["name"],

        "seller_email":
            user["email"],

        "name":
            filename,

        "category":
            cat,

        "rows":
            len(cleaned),

        "columns":
            len(cleaned.columns),

        "quality_score":
            q,

        "predicted_price":
            price,

        "analysis":
            analysis,

        "cleaning_stats":
            stats,

        "file_hash":
            f_hash,

        "dataset_hash":
            d_hash,

        "original_path":
            str(original_path),

        "cleaned_path":
            str(cleaned_path),

        "cleaned_filename":
            cleaned_filename,

        "status":
            "pending",

        "created_at":
            now(),

    }


    pending_datasets[
        dataset_id
    ] = item


    preview = json.loads(
        cleaned
        .head(10)
        .to_json(
            orient="records",
            date_format="iso",
        )
    )


    return {

        "message":
            "Dataset analyzed successfully.",

        "dataset": {

            "id":
                dataset_id,

            "name":
                filename,

            "category":
                cat,

            "rows":
                len(cleaned),

            "columns":
                len(cleaned.columns),

            "quality_score":
                q,

            "predicted_price":
                price,

            "price":
                price,

            "analysis":
                analysis,

            "cleaning_stats":
                stats,

            "preview":
                preview,

            "status":
                "pending",

            "seller":
                user["name"],

        },

    }


# ============================================================
# PENDING DATASET
# ============================================================

@app.get(
    "/pending-dataset/{dataset_id}"
)
def pending_dataset(
    dataset_id: str,
    user=Depends(current_user),
):

    require_role(
        user,
        "seller",
    )


    item = pending_datasets.get(
        dataset_id
    )


    if not item:

        raise HTTPException(
            status_code=404,
            detail="Pending dataset not found.",
        )


    if item["seller_id"] != user["id"]:

        raise HTTPException(
            status_code=403,
            detail="You do not own this dataset.",
        )


    df = pd.read_csv(
        item["cleaned_path"]
    )


    return {

        "dataset": {

            "id":
                item["id"],

            "name":
                item["name"],

            "category":
                item["category"],

            "rows":
                item["rows"],

            "columns":
                item["columns"],

            "quality_score":
                item["quality_score"],

            "predicted_price":
                item["predicted_price"],

            "price":
                item["predicted_price"],

            "analysis":
                item["analysis"],

            "cleaning_stats":
                item["cleaning_stats"],

            "preview":
                json.loads(
                    df.head(10)
                    .to_json(
                        orient="records"
                    )
                ),

            "status":
                "pending",

        }

    }


# ============================================================
# PUBLISH
# ============================================================

@app.post(
    "/publish-dataset/{dataset_id}"
)
def publish(
    dataset_id: str,
    user=Depends(current_user),
):

    require_role(
        user,
        "seller",
    )


    item = pending_datasets.get(
        dataset_id
    )


    if not item:

        raise HTTPException(
            status_code=404,
            detail="Pending dataset not found.",
        )


    if item["seller_id"] != user["id"]:

        raise HTTPException(
            status_code=403,
            detail="You do not own this dataset.",
        )


    item["status"] = "published"

    item["published_at"] = now()


    datasets[
        dataset_id
    ] = item


    del pending_datasets[
        dataset_id
    ]


    return {

        "message":
            "Dataset published successfully.",

        "dataset":
            public_dataset(item),

    }


# ============================================================
# PUBLIC DATASET
# ============================================================

def public_dataset(item):

    return {

        "id":
            item["id"],

        "name":
            item["name"],

        "category":
            item["category"],

        "rows":
            item["rows"],

        "columns":
            item["columns"],

        "quality_score":
            item["quality_score"],

        "predicted_price":
            item["predicted_price"],

        "price":
            item["predicted_price"],

        "analysis":
            item["analysis"],

        "cleaning_stats":
            item["cleaning_stats"],

        "status":
            item["status"],

        "seller":
            item["seller_name"],

        "seller_id":
            item["seller_id"],

        "created_at":
            item["created_at"],

        "published_at":
            item.get(
                "published_at"
            ),

    }


# ============================================================
# MARKETPLACE
# ============================================================

@app.get("/datasets")
def marketplace():

    result = [
        public_dataset(item)
        for item in datasets.values()
    ]


    result.sort(
        key=lambda item:
        item.get(
            "published_at",
            "",
        ),
        reverse=True,
    )


    return {
        "datasets": result
    }


# ============================================================
# SELLER DATASETS
# ============================================================

@app.get("/seller/datasets")
def seller_datasets(
    user=Depends(current_user),
):

    require_role(
        user,
        "seller",
    )


    result = []


    for item in datasets.values():

        if (
            item["seller_id"]
            ==
            user["id"]
        ):

            result.append(
                public_dataset(item)
            )


    for item in pending_datasets.values():

        if (
            item["seller_id"]
            ==
            user["id"]
        ):

            result.append(
                public_dataset(item)
            )


    result.sort(
        key=lambda item:
        item.get(
            "created_at",
            "",
        ),
        reverse=True,
    )


    return {
        "datasets": result
    }


# ============================================================
# DATASET DETAILS
# ============================================================

@app.get(
    "/dataset/{dataset_id}"
)
def dataset_details(
    dataset_id: str,
):

    item = datasets.get(
        dataset_id
    )


    if not item:

        raise HTTPException(
            status_code=404,
            detail="Dataset not found.",
        )


    return {
        "dataset":
            public_dataset(item)
    }


# ============================================================
# DOWNLOAD
# ============================================================

@app.get(
    "/download-cleaned/{dataset_id}"
)
def download(
    dataset_id: str,
    user=Depends(current_user),
):

    item = datasets.get(
        dataset_id
    )


    if not item:

        raise HTTPException(
            status_code=404,
            detail="Dataset not found.",
        )


    allowed = False


    # Seller owner

    if (
        user["role"] == "seller"
        and
        item["seller_id"]
        ==
        user["id"]
    ):

        allowed = True


    # Buyer purchase

    if user["role"] == "buyer":

        for purchase in purchases.values():

            if (
                purchase["buyer_id"]
                ==
                user["id"]
                and
                purchase["dataset_id"]
                ==
                dataset_id
                and
                purchase["status"]
                ==
                "paid"
            ):

                allowed = True

                break


    if not allowed:

        raise HTTPException(
            status_code=403,
            detail=(
                "You must purchase this dataset "
                "before downloading it."
            ),
        )


    path = Path(
        item["cleaned_path"]
    )


    if not path.exists():

        raise HTTPException(
            status_code=404,
            detail="Cleaned file not found.",
        )


    return FileResponse(
        path=path,
        filename=item[
            "cleaned_filename"
        ],
        media_type="text/csv",
    )


# ============================================================
# PURCHASE
# ============================================================

@app.post("/purchase")
def purchase(
    request: PurchaseRequest,
    user=Depends(current_user),
):

    require_role(
        user,
        "buyer",
    )


    item = datasets.get(
        request.dataset_id
    )


    if not item:

        raise HTTPException(
            status_code=404,
            detail="Dataset not found.",
        )


    if (
        item["seller_id"]
        ==
        user["id"]
    ):

        raise HTTPException(
            status_code=400,
            detail="You cannot buy your own dataset.",
        )


    # Already purchased

    for old in purchases.values():

        if (
            old["buyer_id"]
            ==
            user["id"]
            and
            old["dataset_id"]
            ==
            request.dataset_id
            and
            old["status"]
            ==
            "paid"
        ):

            return {

                "message":
                    "Dataset already purchased.",

                "purchase":
                    old,

            }


    purchase_id = new_id(
        "purchase"
    )


    purchase_data = {

        "id":
            purchase_id,

        "dataset_id":
            request.dataset_id,

        "dataset_name":
            item["name"],

        "buyer_id":
            user["id"],

        "buyer_name":
            user["name"],

        "buyer_email":
            user["email"],

        "seller_id":
            item["seller_id"],

        "seller_name":
            item["seller_name"],

        "price":
            item["predicted_price"],

        "currency":
            "USD",

        "wallet_address":
            request.wallet_address
            or
            user.get(
                "wallet_address"
            ),

        "transaction_hash":
            request.transaction_hash,

        "status":
            "paid",

        "purchased_at":
            now(),

    }


    purchases[
        purchase_id
    ] = purchase_data


    return {

        "message":
            "Dataset purchased successfully.",

        "purchase":
            purchase_data,

    }


# ============================================================
# BUYER PURCHASES
# ============================================================

@app.get(
    "/buyer/purchases"
)
def buyer_purchases(
    user=Depends(current_user),
):

    require_role(
        user,
        "buyer",
    )


    result = [

        purchase

        for purchase in purchases.values()

        if purchase["buyer_id"]
        ==
        user["id"]

    ]


    result.sort(
        key=lambda x:
        x.get(
            "purchased_at",
            "",
        ),
        reverse=True,
    )


    return {
        "purchases": result
    }


# ============================================================
# SELLER SALES
# ============================================================

@app.get(
    "/seller/sales"
)
def seller_sales(
    user=Depends(current_user),
):

    require_role(
        user,
        "seller",
    )


    result = [

        purchase

        for purchase in purchases.values()

        if (
            purchase["seller_id"]
            ==
            user["id"]
            and
            purchase["status"]
            ==
            "paid"
        )

    ]


    total = sum(
        float(
            purchase["price"]
        )
        for purchase in result
    )


    return {

        "sales":
            result,

        "sales_count":
            len(result),

        "total_sales":
            round(
                total,
                2,
            ),

    }


# ============================================================
# DELETE FILES
# ============================================================

def remove_files(item):

    for key in [
        "original_path",
        "cleaned_path",
    ]:

        path_string = item.get(key)


        if not path_string:

            continue


        try:

            path = Path(
                path_string
            )


            if path.exists():

                path.unlink()

        except Exception:

            pass


# ============================================================
# DELETE DATASET
# ============================================================

@app.delete(
    "/delete-dataset/{dataset_id}"
)
def delete_dataset(
    dataset_id: str,
    user=Depends(current_user),
):

    require_role(
        user,
        "seller",
    )


    source = "published"


    item = datasets.get(
        dataset_id
    )


    if not item:

        source = "pending"

        item = pending_datasets.get(
            dataset_id
        )


    if not item:

        raise HTTPException(
            status_code=404,
            detail="Dataset not found.",
        )


    if (
        item["seller_id"]
        !=
        user["id"]
    ):

        raise HTTPException(
            status_code=403,
            detail="You do not own this dataset.",
        )


    remove_files(item)


    # Keep purchase records as historical
    # records, but mark dataset deleted.

    for purchase in purchases.values():

        if (
            purchase["dataset_id"]
            ==
            dataset_id
        ):

            purchase[
                "dataset_deleted"
            ] = True


    if source == "published":

        del datasets[
            dataset_id
        ]

    else:

        del pending_datasets[
            dataset_id
        ]


    return {

        "message":
            "Dataset deleted successfully.",

        "dataset_id":
            dataset_id,

    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/")
def root():

    return {

        "name":
            "DataMarket API",

        "status":
            "running",

        "version":
            "3.0.0",

    }


@app.get("/health")
def health():

    return {

        "status":
            "ok",

        "users":
            len(users),

        "published_datasets":
            len(datasets),

        "pending_datasets":
            len(pending_datasets),

        "purchases":
            len(purchases),

    }