from dotenv import load_dotenv
from pathlib import Path
import os

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request
from fastapi.responses import StreamingResponse
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr, BeforeValidator, ConfigDict
from typing import List, Optional, Annotated, Any
from datetime import datetime, timezone, timedelta, date
from bson import ObjectId
import logging
import bcrypt
import jwt

# ---------------------------------------------------------------- DB
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI(title="Assoclub CRM")
api = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("assoclub")

JWT_ALGORITHM = "HS256"


def get_jwt_secret() -> str:
    return os.environ["JWT_SECRET"]


# ---------------------------------------------------------------- Helpers
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_access_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "type": "access",
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


PyObjectId = Annotated[str, BeforeValidator(str)]


def oid() -> str:
    return str(ObjectId())


async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Non authentifié")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="Utilisateur introuvable")
        user["id"] = str(user["_id"])
        user.pop("_id", None)
        user.pop("password_hash", None)
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expirée")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Jeton invalide")


def clean(doc: dict) -> dict:
    if not doc:
        return doc
    doc["id"] = str(doc.pop("_id"))
    doc.pop("password_hash", None)
    return doc


# ---------------------------------------------------------------- Models
class RegisterInput(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str = "membre"


class LoginInput(BaseModel):
    email: EmailStr
    password: str


class MemberInput(BaseModel):
    first_name: str
    last_name: str
    email: Optional[str] = ""
    phone: Optional[str] = ""
    address: Optional[str] = ""
    membership_type: str = "Standard"
    cotisation_amount: float = 0
    cotisation_status: str = "active"  # active | expired | pending
    cotisation_expiry: Optional[str] = None
    join_date: Optional[str] = None
    avatar_url: Optional[str] = ""
    notes: Optional[str] = ""


class TransactionInput(BaseModel):
    type: str  # income | expense
    category: Optional[str] = ""   # libellé de synthèse (optionnel) — le compte comptable prime
    amount: float
    date: str
    description: Optional[str] = ""
    method: Optional[str] = "Virement"
    member_id: Optional[str] = None
    tiers_id: Optional[str] = None          # contact lié (tiers) — obligatoire sauf comptes sans tiers
    exercise: Optional[str] = None
    pole_id: Optional[str] = None
    account_code: Optional[str] = None
    ventilation: List[dict] = []            # [{account_code, pole_id, amount}] — la somme doit = amount


class EmployeeInput(BaseModel):
    first_name: str
    last_name: str
    email: Optional[str] = ""
    phone: Optional[str] = ""
    position: str = ""
    contract_type: str = "CDI"
    monthly_salary: float = 0
    hourly_rate: float = 0
    hire_date: Optional[str] = None
    status: str = "active"
    avatar_url: Optional[str] = ""
    eclat_group: Optional[str] = None
    coefficient: Optional[int] = None
    grille: Optional[str] = None   # clé de grille de paie (prof | anim | generale...)
    address: Optional[str] = ""
    travel_km: Optional[float] = 0           # distance domicile → structure (aller simple), pour les frais km
    salary_elements: List[dict] = []   # éléments propres au salarié [{label, amount}] (frais de déplacement, ancienneté...)
    employment_lines: List[dict] = []  # lignes d'emploi ÉCLAT [{grille, coefficient, hours}] (un salarié peut cumuler 2 grilles)


class ShiftInput(BaseModel):
    employee_id: str
    date: str
    start_time: str
    end_time: str
    note: Optional[str] = ""


class PayslipInput(BaseModel):
    employee_id: str
    month: str  # YYYY-MM
    gross_salary: float
    hours: Optional[float] = 0
    status: str = "draft"  # draft | paid
    eclat_group: Optional[str] = None
    coefficient: Optional[int] = None


# ---------------------------------------------------------------- AUTH ROUTES
@api.post("/auth/register")
async def register(data: RegisterInput):
    email = data.email.lower()
    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Cet email est déjà utilisé")
    doc = {
        "name": data.name,
        "email": email,
        "password_hash": hash_password(data.password),
        "role": data.role,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    res = await db.users.insert_one(doc)
    uid = str(res.inserted_id)
    token = create_access_token(uid, email, data.role)
    return {"token": token, "user": {"id": uid, "name": data.name, "email": email, "role": data.role}}


@api.post("/auth/login")
async def login(data: LoginInput):
    email = data.email.lower()
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")
    uid = str(user["_id"])
    token = create_access_token(uid, email, user["role"])
    return {"token": token, "user": {"id": uid, "name": user["name"], "email": email, "role": user["role"]}}


@api.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return user


@api.post("/auth/logout")
async def logout(user: dict = Depends(get_current_user)):
    return {"ok": True}


# ---------------------------------------------------------------- MEMBERS
@api.get("/members")
async def list_members(search: Optional[str] = None, status: Optional[str] = None,
                       user: dict = Depends(get_current_user)):
    q: dict = {}
    if status and status != "all":
        q["cotisation_status"] = status
    docs = await db.members.find(q).sort("last_name", 1).to_list(1000)
    members = [clean(d) for d in docs]
    if search:
        s = search.lower()
        members = [m for m in members if s in f"{m.get('first_name','')} {m.get('last_name','')} {m.get('email','')}".lower()]
    return members


@api.post("/members")
async def create_member(data: MemberInput, user: dict = Depends(get_current_user)):
    doc = data.model_dump()
    if not doc.get("join_date"):
        doc["join_date"] = datetime.now(timezone.utc).date().isoformat()
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    doc["history"] = [{"date": doc["join_date"], "event": "Adhésion créée"}]
    res = await db.members.insert_one(doc)
    return clean(await db.members.find_one({"_id": res.inserted_id}))


@api.get("/members/{member_id}")
async def get_member(member_id: str, user: dict = Depends(get_current_user)):
    doc = await db.members.find_one({"_id": ObjectId(member_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Membre introuvable")
    return clean(doc)


@api.put("/members/{member_id}")
async def update_member(member_id: str, data: MemberInput, user: dict = Depends(get_current_user)):
    await db.members.update_one({"_id": ObjectId(member_id)}, {"$set": data.model_dump()})
    doc = await db.members.find_one({"_id": ObjectId(member_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Membre introuvable")
    return clean(doc)


@api.delete("/members/{member_id}")
async def delete_member(member_id: str, user: dict = Depends(get_current_user)):
    await db.members.delete_one({"_id": ObjectId(member_id)})
    return {"ok": True}


@api.post("/members/{member_id}/relance")
async def relance_member(member_id: str, user: dict = Depends(get_current_user)):
    event = {"date": datetime.now(timezone.utc).date().isoformat(), "event": "Relance de cotisation envoyée"}
    await db.members.update_one({"_id": ObjectId(member_id)}, {"$push": {"history": event}})
    return {"ok": True, "message": "Relance enregistrée"}


# ---------------------------------------------------------------- FINANCES
@api.get("/transactions")
async def list_transactions(type: Optional[str] = None, category: Optional[str] = None,
                            exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    q: dict = {}
    if exercise:
        q["exercise"] = exercise
    if type and type != "all":
        q["type"] = type
    if category and category != "all":
        q["category"] = category
    docs = await db.transactions.find(q).sort("date", -1).to_list(2000)
    return [clean(d) for d in docs]


# Préfixes de comptes pour lesquels aucun tiers n'est pertinent (frais bancaires, intérêts, revenus de titres, transferts).
NO_TIERS_PREFIXES = ("627", "661", "762", "791")


def _tiers_required(codes: list) -> bool:
    # Un tiers est requis sauf si TOUS les comptes utilisés sont des comptes « sans tiers ».
    codes = [c for c in codes if c]
    if not codes:
        return True
    return not all(any(c.startswith(p) for p in NO_TIERS_PREFIXES) for c in codes)


def _normalize_transaction(doc: dict) -> dict:
    # Nettoie la ventilation, vérifie que sa somme = montant total, et impose le tiers si nécessaire.
    vent = []
    for v in (doc.get("ventilation") or []):
        amt = round(float(v.get("amount", 0) or 0), 2)
        if amt == 0 and not v.get("account_code"):
            continue
        vent.append({"account_code": v.get("account_code") or "", "pole_id": v.get("pole_id") or None, "event_id": v.get("event_id") or None, "amount": amt})
    amount = round(float(doc.get("amount", 0)), 2)
    if vent:
        s = round(sum(v["amount"] for v in vent), 2)
        if abs(s - amount) > 0.01:
            raise HTTPException(status_code=400, detail=f"La ventilation ({s:.2f} €) ne correspond pas au montant total ({amount:.2f} €).")
        # Le compte/pôle « principal » reprend la 1re ligne de ventilation (pour les récaps existants).
        doc["account_code"] = vent[0]["account_code"] or doc.get("account_code")
        doc["pole_id"] = vent[0]["pole_id"] if vent[0].get("pole_id") else doc.get("pole_id")
    doc["ventilation"] = vent
    codes = [doc.get("account_code")] + [v["account_code"] for v in vent]
    if _tiers_required(codes) and not doc.get("tiers_id"):
        raise HTTPException(status_code=400, detail="Un tiers (contact) est obligatoire pour cette transaction.")
    return doc


@api.post("/transactions")
async def create_transaction(data: TransactionInput, user: dict = Depends(get_current_user)):
    doc = data.model_dump()
    doc["exercise"] = doc.get("exercise") or await get_current_exercise_label()
    await assert_exercise_open(doc["exercise"])
    doc = _normalize_transaction(doc)
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    res = await db.transactions.insert_one(doc)
    return clean(await db.transactions.find_one({"_id": res.inserted_id}))


@api.get("/transactions/undeposited")
async def list_undeposited_transactions(kind: str, exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    # Transactions encaissées (recettes) par chèque ou espèces, non encore rattachées à un bordereau de remise.
    method = "Espèces" if kind == "especes" else "Chèque"
    q: dict = {"method": method, "type": "income", "$or": [{"bordereau_id": {"$exists": False}}, {"bordereau_id": None}]}
    if exercise:
        q["exercise"] = exercise
    docs = await db.transactions.find(q).sort("date", 1).to_list(2000)
    out = []
    for d in docs:
        c = clean(d)
        c["tiers_name"] = ""
        if d.get("tiers_id") and ObjectId.is_valid(d["tiers_id"]):
            ct = await db.contacts.find_one({"_id": ObjectId(d["tiers_id"])})
            if ct:
                c["tiers_name"] = f"{ct.get('first_name','')} {ct.get('last_name','')}".strip()
        out.append(c)
    return out


@api.put("/transactions/{tx_id}")
async def update_transaction(tx_id: str, data: TransactionInput, user: dict = Depends(get_current_user)):
    doc = _normalize_transaction(data.model_dump())
    await db.transactions.update_one({"_id": ObjectId(tx_id)}, {"$set": doc})
    return clean(await db.transactions.find_one({"_id": ObjectId(tx_id)}))


@api.delete("/transactions/{tx_id}")
async def delete_transaction(tx_id: str, user: dict = Depends(get_current_user)):
    await db.transactions.delete_one({"_id": ObjectId(tx_id)})
    return {"ok": True}


@api.get("/finances/summary")
async def finances_summary(exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    q = {"exercise": exercise} if exercise else {}
    docs = await db.transactions.find(q).to_list(5000)
    income = sum(d["amount"] for d in docs if d["type"] == "income")
    expense = sum(d["amount"] for d in docs if d["type"] == "expense")
    # by month
    monthly: dict = {}
    for d in docs:
        m = d["date"][:7]
        monthly.setdefault(m, {"month": m, "income": 0, "expense": 0})
        monthly[m][d["type"]] += d["amount"]
    months = sorted(monthly.values(), key=lambda x: x["month"])[-6:]
    # Répartition des dépenses par compte comptable (fallback catégorie si pas de compte)
    plan = await db.plan_accounts.find({}).to_list(1000)
    labels = {a["code"]: a["label"] for a in plan}
    cats: dict = {}
    for d in docs:
        if d["type"] != "expense":
            continue
        vlines = d.get("ventilation") or [{"account_code": d.get("account_code"), "amount": d.get("amount", 0)}]
        for l in vlines:
            code = l.get("account_code")
            name = labels.get(code) if code and code in labels else (d.get("category") or "Autre")
            cats[name] = round(cats.get(name, 0) + float(l.get("amount", 0) or 0), 2)
    categories = [{"category": k, "amount": v} for k, v in sorted(cats.items(), key=lambda x: -x[1])]
    return {
        "income": income,
        "expense": expense,
        "balance": income - expense,
        "monthly": months,
        "categories": categories,
    }


# ---------------------------------------------------------------- EMPLOYEES
@api.get("/employees")
async def list_employees(user: dict = Depends(get_current_user)):
    docs = await db.employees.find({}).sort("last_name", 1).to_list(1000)
    return [clean(d) for d in docs]


@api.post("/employees")
async def create_employee(data: EmployeeInput, user: dict = Depends(get_current_user)):
    doc = data.model_dump()
    if not doc.get("hire_date"):
        doc["hire_date"] = datetime.now(timezone.utc).date().isoformat()
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    res = await db.employees.insert_one(doc)
    return clean(await db.employees.find_one({"_id": res.inserted_id}))


@api.put("/employees/{emp_id}")
async def update_employee(emp_id: str, data: EmployeeInput, user: dict = Depends(get_current_user)):
    await db.employees.update_one({"_id": ObjectId(emp_id)}, {"$set": data.model_dump()})
    return clean(await db.employees.find_one({"_id": ObjectId(emp_id)}))


@api.delete("/employees/{emp_id}")
async def delete_employee(emp_id: str, user: dict = Depends(get_current_user)):
    await db.employees.delete_one({"_id": ObjectId(emp_id)})
    await db.shifts.delete_many({"employee_id": emp_id})
    return {"ok": True}


# ---------------------------------------------------------------- SCHEDULE
@api.get("/shifts")
async def list_shifts(start: Optional[str] = None, end: Optional[str] = None,
                      user: dict = Depends(get_current_user)):
    q: dict = {}
    if start and end:
        q["date"] = {"$gte": start, "$lte": end}
    docs = await db.shifts.find(q).sort("date", 1).to_list(2000)
    return [clean(d) for d in docs]


@api.post("/shifts")
async def create_shift(data: ShiftInput, user: dict = Depends(get_current_user)):
    doc = data.model_dump()
    res = await db.shifts.insert_one(doc)
    return clean(await db.shifts.find_one({"_id": res.inserted_id}))


@api.delete("/shifts/{shift_id}")
async def delete_shift(shift_id: str, user: dict = Depends(get_current_user)):
    await db.shifts.delete_one({"_id": ObjectId(shift_id)})
    return {"ok": True}


# ---------------------------------------------------------------- PAYROLL
@api.get("/payslips")
async def list_payslips(month: Optional[str] = None, user: dict = Depends(get_current_user)):
    q: dict = {}
    if month:
        q["month"] = month
    docs = await db.payslips.find(q).sort("month", -1).to_list(2000)
    return [clean(d) for d in docs]


@api.post("/payslips")
async def create_payslip(data: PayslipInput, user: dict = Depends(get_current_user)):
    doc = data.model_dump()
    # Simplified French payroll: ~22% charges salariales
    doc["charges"] = round(doc["gross_salary"] * 0.22, 2)
    doc["net_salary"] = round(doc["gross_salary"] - doc["charges"], 2)
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    res = await db.payslips.insert_one(doc)
    return clean(await db.payslips.find_one({"_id": res.inserted_id}))


@api.put("/payslips/{slip_id}/pay")
async def pay_payslip(slip_id: str, user: dict = Depends(get_current_user)):
    slip = await db.payslips.find_one({"_id": ObjectId(slip_id)})
    if not slip:
        raise HTTPException(status_code=404, detail="Fiche de paie introuvable")
    await db.payslips.update_one({"_id": ObjectId(slip_id)}, {"$set": {"status": "paid"}})
    # Record expense transaction
    emp = await db.employees.find_one({"_id": ObjectId(slip["employee_id"])}) if ObjectId.is_valid(slip["employee_id"]) else None
    name = f"{emp['first_name']} {emp['last_name']}" if emp else "Salarié"
    await db.transactions.insert_one({
        "type": "expense", "category": "Salaires", "account_code": "6411",
        "amount": slip["gross_salary"], "date": datetime.now(timezone.utc).date().isoformat(),
        "description": f"Salaire {name} - {slip['month']}", "method": "Virement",
        "exercise": await get_current_exercise_label(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return clean(await db.payslips.find_one({"_id": ObjectId(slip_id)}))


@api.delete("/payslips/{slip_id}")
async def delete_payslip(slip_id: str, user: dict = Depends(get_current_user)):
    await db.payslips.delete_one({"_id": ObjectId(slip_id)})
    return {"ok": True}


# ---------------------------------------------------------------- DASHBOARD
@api.get("/dashboard")
async def dashboard(exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    ex = exercise or await get_current_exercise_label()
    students = await db.students.find({"exercise": ex}).to_list(5000)
    active = [s for s in students if s.get("cotisation_status") == "active"]
    expired = [s for s in students if s.get("cotisation_status") == "expired"]
    txs = await db.transactions.find({"exercise": ex}).to_list(5000)
    income = sum(t["amount"] for t in txs if t["type"] == "income")
    expense = sum(t["amount"] for t in txs if t["type"] == "expense")
    cotisations = sum(t["amount"] for t in txs if t["type"] == "income" and (
        t.get("category") in ("Cotisations", "Écolage") or (t.get("account_code") or "").startswith("706") or t.get("account_code") == "7561"))
    employees = await db.employees.find({}).to_list(1000)
    masse = sum(e.get("monthly_salary", 0) for e in employees if e.get("status") == "active")

    monthly: dict = {}
    for t in txs:
        m = t["date"][:7]
        monthly.setdefault(m, {"month": m, "income": 0, "expense": 0})
        monthly[m][t["type"]] += t["amount"]
    months = sorted(monthly.values(), key=lambda x: x["month"])[-6:]

    recent = sorted(students, key=lambda s: s.get("created_at", ""), reverse=True)[:5]
    recent_members = [{
        "id": str(s["_id"]), "first_name": s.get("first_name", ""), "last_name": s.get("last_name", ""),
        "membership_type": "Élève", "cotisation_status": s.get("cotisation_status", "pending"),
        "join_date": (s.get("created_at", "") or "")[:10], "avatar_url": s.get("avatar_url", ""),
    } for s in recent]

    # Prochaines manifestations (à venir sur l'exercice)
    today_s = datetime.now(timezone.utc).date().isoformat()
    ev_docs = await db.events.find({"exercise": ex}).to_list(2000)
    upcoming = [{"id": str(e["_id"]), "name": e.get("name", ""), "date": e.get("date"),
                 "location": e.get("location", ""), "status": e.get("status", "open")}
                for e in sorted([e for e in ev_docs if (e.get("date") or "") >= today_s], key=lambda e: e.get("date") or "")[:5]]

    # Comptes bancaires + solde total
    accts = await db.bank_accounts.find({}).to_list(500)
    transfers = await db.transfers.find({}).to_list(5000)
    banks = []
    for a in accts:
        aid = str(a["_id"]); bal = a.get("initial_balance", 0)
        for t in transfers:
            if t.get("to_id") == aid:
                bal += t.get("amount", 0)
            if t.get("from_id") == aid:
                bal -= t.get("amount", 0)
        banks.append({"id": aid, "name": a.get("name", ""), "type": a.get("type", ""),
                      "color": a.get("color", "#2563EB"), "balance": round(bal, 2)})
    bank_total = round(sum(b["balance"] for b in banks), 2)

    # Stats élèves (effectif, majeurs/mineurs, sexe, instruments, cursus)
    minors = len([s for s in students if s.get("is_minor")])
    gmap = {"H": 0, "F": 0, "autre": 0, "nr": 0}
    for s in students:
        g = s.get("gender") or ""
        gmap[g if g in ("H", "F", "autre") else "nr"] += 1
    insc_docs = await db.inscriptions.find({"exercise": ex}).to_list(5000)

    def _classify_line(l):
        ct = (l.get("course_type") or "").lower()
        if ct in ("individuel", "theorique", "pratique", "eveil"):
            return ct
        lab = (l.get("label") or "").lower()
        if any(k in lab for k in ("formation musicale", "solf", "théoriqu", "theoriqu")):
            return "theorique"
        if any(k in lab for k in ("pratique collective", "collectif", "chorale", "ensemble", "orchestre")):
            return "pratique"
        if "veil" in lab:
            return "eveil"
        if "individuel" in lab or "cursus" in lab:
            return "individuel"
        return "autre"

    per_student: dict = {}
    inst_students: dict = {}
    for ins in insc_docs:
        sid = ins.get("student_id")
        ps = per_student.setdefault(sid, {"instru": False, "theo": False, "coll": False})
        for l in ins.get("lines", []):
            cat = _classify_line(l)
            if cat == "individuel":
                ps["instru"] = True
                disc = l.get("discipline") or l.get("label") or "Instrument"
                inst_students.setdefault(disc, set()).add(sid)
            elif cat == "theorique":
                ps["theo"] = True
            elif cat == "pratique":
                ps["coll"] = True
    by_instrument = [{"instrument": k, "count": len(v)} for k, v in sorted(inst_students.items(), key=lambda x: -len(x[1]))]
    theorique_count = len([1 for v in per_student.values() if v["theo"]])
    pratique_count = len([1 for v in per_student.values() if v["coll"]])
    combos = {"instru_theo_coll": 0, "instru_theo": 0, "instru_coll": 0, "instru_seul": 0}
    total_instru = 0
    for v in per_student.values():
        if not v["instru"]:
            continue
        total_instru += 1
        if v["theo"] and v["coll"]:
            combos["instru_theo_coll"] += 1
        elif v["theo"]:
            combos["instru_theo"] += 1
        elif v["coll"]:
            combos["instru_coll"] += 1
        else:
            combos["instru_seul"] += 1
    # Répartition par communes (commune de l'élève, sinon celle de son contact lié) + dans/hors CC
    cids = [s["contact_id"] for s in students if s.get("contact_id") and ObjectId.is_valid(s.get("contact_id"))]
    cmap = {}
    if cids:
        for ct in await db.contacts.find({"_id": {"$in": [ObjectId(c) for c in cids]}}).to_list(5000):
            cmap[str(ct["_id"])] = ct
    commune_map: dict = {}
    cc_in = cc_out = cc_unknown = 0
    for s in students:
        ct = cmap.get(s.get("contact_id") or "")
        city = s.get("commune_deleguee") or s.get("city") or (ct or {}).get("commune_deleguee") or (ct or {}).get("city") or ""
        cc = s.get("cc_savoir_faire")
        if cc is None:
            cc = (ct or {}).get("cc_savoir_faire")
        if city:
            commune_map[city] = commune_map.get(city, 0) + 1
        if cc is True:
            cc_in += 1
        elif cc is False:
            cc_out += 1
        else:
            cc_unknown += 1
    by_commune = [{"commune": k, "count": v} for k, v in sorted(commune_map.items(), key=lambda x: -x[1])]

    student_stats = {
        "total": len(students), "minors": minors, "majors": len(students) - minors, "by_gender": gmap,
        "by_instrument": by_instrument, "theorique_count": theorique_count, "pratique_count": pratique_count,
        "cursus_combos": combos, "total_instru": total_instru,
        "by_commune": by_commune, "cc": {"inside": cc_in, "outside": cc_out, "unknown": cc_unknown},
    }

    # Cotisations restant à payer (échéances non soldées)
    stu_name = {str(s["_id"]): f"{s.get('first_name','')} {s.get('last_name','')}".strip() for s in students}
    outstanding = []
    for ins in insc_docs:
        remaining = round(sum(x.get("amount", 0) for x in ins.get("schedule", []) if x.get("status") != "paid"), 2)
        if remaining > 0.01:
            outstanding.append({"student": stu_name.get(ins.get("student_id"), "—"), "remaining": remaining})
    outstanding.sort(key=lambda x: -x["remaining"])
    outstanding_total = round(sum(o["remaining"] for o in outstanding), 2)

    return {
        "cotisations_collected": cotisations, "active_members": len(active),
        "expired_members": len(expired), "total_members": len(students),
        "treasury": income - expense, "income": income, "expense": expense,
        "payroll": masse, "employee_count": len(employees),
        "monthly": months, "recent_members": recent_members, "exercise": ex,
        "upcoming_events": upcoming, "bank_accounts": banks, "bank_total": bank_total,
        "student_stats": student_stats, "outstanding_cotisations": outstanding[:12],
        "outstanding_total": outstanding_total,
    }


# ================= ÉCOLE DE MUSIQUE : PÉDAGOGIE =================
class TeacherInput(BaseModel):
    first_name: str
    last_name: str
    email: Optional[str] = ""
    phone: Optional[str] = ""
    disciplines: List[str] = []
    employee_id: Optional[str] = None
    color: Optional[str] = "#0D9488"
    status: str = "active"
    avatar_url: Optional[str] = ""


class RoomInput(BaseModel):
    name: str
    capacity: int = 1
    equipment: Optional[str] = ""
    color: Optional[str] = "#4F46E5"


class CourseInput(BaseModel):
    name: str
    type: str = "individuel"  # individuel | theorique | pratique | eveil
    discipline: Optional[str] = ""
    pole_id: Optional[str] = None
    level: Optional[str] = ""          # niveau du groupe (ex. FM Kids 1, Ados 1...)
    teacher_id: Optional[str] = None
    room_id: Optional[str] = None
    tariff_id: Optional[str] = None
    day: Optional[str] = ""
    start_time: Optional[str] = ""
    duration_min: int = 30
    capacity: int = 1
    exercise: Optional[str] = None     # groupe rattaché à un exercice (niveaux changent chaque année)


class TariffInput(BaseModel):
    label: str
    category: str = "cursus"  # cursus | option | eveil | theorique | pratique | location | cotisation
    audience: str = "tous"    # adulte | enfant_etudiant | tous
    duration_min: Optional[int] = None
    amount: float = 0
    active: bool = True


class StudentInput(BaseModel):
    first_name: str
    last_name: str
    birth_date: Optional[str] = None
    gender: Optional[str] = ""   # H | F | autre
    email: Optional[str] = ""
    phone: Optional[str] = ""
    address: Optional[str] = ""
    postal_code: Optional[str] = ""
    city: Optional[str] = ""
    commune_code: Optional[str] = ""
    commune_deleguee: Optional[str] = ""
    cc_savoir_faire: Optional[bool] = None
    is_minor: bool = False
    responsable_name: Optional[str] = ""
    responsable_relation: Optional[str] = "Parent"
    responsable_email: Optional[str] = ""
    responsable_phone: Optional[str] = ""
    cotisation_status: str = "pending"
    avatar_url: Optional[str] = ""
    notes: Optional[str] = ""
    exercise: Optional[str] = None


class InscriptionInput(BaseModel):
    student_id: str
    school_year: str
    lines: List[dict] = []       # [{label, amount, tariff_id, course_id}]
    discounts: List[dict] = []   # [{label, amount}]
    cotisation: float = 25
    payment_mode: str = "mensuel"  # annuel | trimestriel | mensuel
    payment_method: Optional[str] = ""
    notes: Optional[str] = ""


def current_school_year() -> str:
    now = datetime.now(timezone.utc)
    return f"{now.year}-{now.year+1}" if now.month >= 9 else f"{now.year-1}-{now.year}"


def build_schedule(mode: str, cotisation: float, ecolage: float, start_year: int) -> list:
    sched = []
    if mode == "annuel":
        sched.append({"label": "Paiement annuel (septembre)", "due_date": f"{start_year}-09-05",
                      "amount": round(cotisation + ecolage, 2)})
    elif mode == "trimestriel":
        part = round(ecolage / 3, 2)
        plan = [(f"{start_year}-09-05", "1er trimestre", round(cotisation + part, 2)),
                (f"{start_year+1}-01-05", "2e trimestre", part),
                (f"{start_year+1}-04-05", "3e trimestre", round(ecolage - 2 * part, 2))]
        for d, lbl, amt in plan:
            sched.append({"label": lbl, "due_date": d, "amount": amt})
    else:  # mensuel : 10 mois de septembre à juin
        part = round(ecolage / 10, 2)
        months = [(9, start_year), (10, start_year), (11, start_year), (12, start_year),
                  (1, start_year + 1), (2, start_year + 1), (3, start_year + 1),
                  (4, start_year + 1), (5, start_year + 1), (6, start_year + 1)]
        names = ["Septembre", "Octobre", "Novembre", "Décembre", "Janvier",
                 "Février", "Mars", "Avril", "Mai", "Juin"]
        for i, ((m, y), nm) in enumerate(zip(months, names)):
            if i == 0:
                amt = round(cotisation + part, 2)
            elif i == 9:
                amt = round(ecolage - part * 9, 2)
            else:
                amt = part
            sched.append({"label": nm, "due_date": f"{y}-{m:02d}-05", "amount": amt})
    for s in sched:
        s.update({"status": "pending", "method": "", "paid_date": None})
    return sched


# ---- Teachers
@api.get("/teachers")
async def list_teachers(user: dict = Depends(get_current_user)):
    docs = await db.teachers.find({}).sort("last_name", 1).to_list(1000)
    return [clean(d) for d in docs]


@api.post("/teachers")
async def create_teacher(data: TeacherInput, user: dict = Depends(get_current_user)):
    res = await db.teachers.insert_one(data.model_dump())
    return clean(await db.teachers.find_one({"_id": res.inserted_id}))


@api.put("/teachers/{tid}")
async def update_teacher(tid: str, data: TeacherInput, user: dict = Depends(get_current_user)):
    await db.teachers.update_one({"_id": ObjectId(tid)}, {"$set": data.model_dump()})
    return clean(await db.teachers.find_one({"_id": ObjectId(tid)}))


@api.delete("/teachers/{tid}")
async def delete_teacher(tid: str, user: dict = Depends(get_current_user)):
    await db.teachers.delete_one({"_id": ObjectId(tid)})
    return {"ok": True}


# ---- Rooms
@api.get("/rooms")
async def list_rooms(user: dict = Depends(get_current_user)):
    docs = await db.rooms.find({}).sort("name", 1).to_list(1000)
    return [clean(d) for d in docs]


@api.post("/rooms")
async def create_room(data: RoomInput, user: dict = Depends(get_current_user)):
    res = await db.rooms.insert_one(data.model_dump())
    return clean(await db.rooms.find_one({"_id": res.inserted_id}))


@api.put("/rooms/{rid}")
async def update_room(rid: str, data: RoomInput, user: dict = Depends(get_current_user)):
    await db.rooms.update_one({"_id": ObjectId(rid)}, {"$set": data.model_dump()})
    return clean(await db.rooms.find_one({"_id": ObjectId(rid)}))


@api.delete("/rooms/{rid}")
async def delete_room(rid: str, user: dict = Depends(get_current_user)):
    await db.rooms.delete_one({"_id": ObjectId(rid)})
    return {"ok": True}


# ---- Courses
@api.get("/courses")
async def list_courses(user: dict = Depends(get_current_user)):
    docs = await db.courses.find({}).sort("name", 1).to_list(1000)
    return [clean(d) for d in docs]


@api.post("/courses")
async def create_course(data: CourseInput, user: dict = Depends(get_current_user)):
    res = await db.courses.insert_one(data.model_dump())
    return clean(await db.courses.find_one({"_id": res.inserted_id}))


@api.put("/courses/{cid}")
async def update_course(cid: str, data: CourseInput, user: dict = Depends(get_current_user)):
    await db.courses.update_one({"_id": ObjectId(cid)}, {"$set": data.model_dump()})
    return clean(await db.courses.find_one({"_id": ObjectId(cid)}))


@api.delete("/courses/{cid}")
async def delete_course(cid: str, user: dict = Depends(get_current_user)):
    await db.courses.delete_one({"_id": ObjectId(cid)})
    return {"ok": True}


# ---- Tariffs
@api.get("/tariffs")
async def list_tariffs(user: dict = Depends(get_current_user)):
    docs = await db.tariffs.find({}).sort("amount", 1).to_list(1000)
    return [clean(d) for d in docs]


@api.post("/tariffs")
async def create_tariff(data: TariffInput, user: dict = Depends(get_current_user)):
    res = await db.tariffs.insert_one(data.model_dump())
    return clean(await db.tariffs.find_one({"_id": res.inserted_id}))


@api.put("/tariffs/{tid}")
async def update_tariff(tid: str, data: TariffInput, user: dict = Depends(get_current_user)):
    await db.tariffs.update_one({"_id": ObjectId(tid)}, {"$set": data.model_dump()})
    return clean(await db.tariffs.find_one({"_id": ObjectId(tid)}))


@api.delete("/tariffs/{tid}")
async def delete_tariff(tid: str, user: dict = Depends(get_current_user)):
    await db.tariffs.delete_one({"_id": ObjectId(tid)})
    return {"ok": True}


# ---- Students
@api.get("/students")
async def list_students(search: Optional[str] = None, exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    q = {"exercise": exercise} if exercise else {}
    docs = await db.students.find(q).sort("last_name", 1).to_list(2000)
    students = [clean(d) for d in docs]
    for s in students:
        s["inscription_count"] = await db.inscriptions.count_documents({"student_id": s["id"]})
    if search:
        q = search.lower()
        students = [s for s in students if q in f"{s.get('first_name','')} {s.get('last_name','')} {s.get('responsable_name','')}".lower()]
    return students


@api.post("/students")
async def create_student(data: StudentInput, user: dict = Depends(get_current_user)):
    doc = data.model_dump()
    doc["exercise"] = doc.get("exercise") or await get_current_exercise_label()
    await assert_exercise_open(doc["exercise"])
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    res = await db.students.insert_one(doc)
    return clean(await db.students.find_one({"_id": res.inserted_id}))


@api.get("/students/{sid}")
async def get_student(sid: str, user: dict = Depends(get_current_user)):
    doc = await db.students.find_one({"_id": ObjectId(sid)})
    if not doc:
        raise HTTPException(status_code=404, detail="Élève introuvable")
    return clean(doc)


@api.put("/students/{sid}")
async def update_student(sid: str, data: StudentInput, user: dict = Depends(get_current_user)):
    await db.students.update_one({"_id": ObjectId(sid)}, {"$set": data.model_dump()})
    return clean(await db.students.find_one({"_id": ObjectId(sid)}))


@api.delete("/students/{sid}")
async def delete_student(sid: str, user: dict = Depends(get_current_user)):
    await db.students.delete_one({"_id": ObjectId(sid)})
    await db.inscriptions.delete_many({"student_id": sid})
    return {"ok": True}


# ---- Inscriptions
@api.get("/inscriptions")
async def list_inscriptions(student_id: Optional[str] = None, school_year: Optional[str] = None,
                            user: dict = Depends(get_current_user)):
    q: dict = {}
    if student_id:
        q["student_id"] = student_id
    if school_year:
        q["school_year"] = school_year
    docs = await db.inscriptions.find(q).sort("created_at", -1).to_list(2000)
    return [clean(d) for d in docs]


@api.post("/inscriptions")
async def create_inscription(data: InscriptionInput, user: dict = Depends(get_current_user)):
    ecolage = round(sum(float(l.get("amount", 0)) for l in data.lines), 2)
    disc = round(sum(float(d.get("amount", 0)) for d in data.discounts), 2)
    ecolage_net = round(ecolage - disc, 2)
    cotisation = float(data.cotisation)
    try:
        start_year = int(data.school_year.split("-")[0])
    except Exception:
        start_year = datetime.now(timezone.utc).year
    schedule = build_schedule(data.payment_mode, cotisation, ecolage_net, start_year)
    await assert_exercise_open(data.school_year)
    doc = data.model_dump()
    doc["exercise"] = data.school_year
    doc.update({
        "ecolage": ecolage, "discount_total": disc, "ecolage_net": ecolage_net,
        "total": round(cotisation + ecolage_net, 2), "schedule": schedule,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    res = await db.inscriptions.insert_one(doc)
    await db.students.update_one({"_id": ObjectId(data.student_id)}, {"$set": {"cotisation_status": "active"}})
    return clean(await db.inscriptions.find_one({"_id": res.inserted_id}))


@api.put("/inscriptions/{iid}")
async def update_inscription(iid: str, data: InscriptionInput, user: dict = Depends(get_current_user)):
    # Édition d'une inscription existante (changement d'instrument/formule, montants, mode, cotisation).
    # Les échéances déjà PAYÉES sont préservées ; seul le restant dû est recalculé selon le mode.
    insc = await db.inscriptions.find_one({"_id": ObjectId(iid)})
    if not insc:
        raise HTTPException(status_code=404, detail="Inscription introuvable")
    await assert_exercise_open(data.school_year)
    ecolage = round(sum(float(l.get("amount", 0)) for l in data.lines), 2)
    disc = round(sum(float(d.get("amount", 0)) for d in data.discounts), 2)
    ecolage_net = round(ecolage - disc, 2)
    cotisation = float(data.cotisation)
    total = round(cotisation + ecolage_net, 2)
    try:
        start_year = int(data.school_year.split("-")[0])
    except Exception:
        start_year = datetime.now(timezone.utc).year
    paid = [s for s in (insc.get("schedule") or []) if s.get("status") == "paid"]
    paid_sum = round(sum(float(s.get("amount", 0)) for s in paid), 2)
    if paid:
        remaining = round(total - paid_sum, 2)
        pending = build_schedule(data.payment_mode, 0, remaining, start_year) if remaining > 0.005 else []
        schedule = paid + pending
    else:
        schedule = build_schedule(data.payment_mode, cotisation, ecolage_net, start_year)
    upd = data.model_dump()
    upd["exercise"] = data.school_year
    upd.update({"ecolage": ecolage, "discount_total": disc, "ecolage_net": ecolage_net,
                "total": total, "schedule": schedule,
                "updated_at": datetime.now(timezone.utc).isoformat()})
    await db.inscriptions.update_one({"_id": ObjectId(iid)}, {"$set": upd})
    return clean(await db.inscriptions.find_one({"_id": ObjectId(iid)}))

# ---- Remises (discounts) paramétrables
class DiscountInput(BaseModel):
    label: str
    amount: float = 0


@api.get("/discounts")
async def list_discounts(user: dict = Depends(get_current_user)):
    if await db.discounts.count_documents({}) == 0:
        await db.discounts.insert_many([
            {"label": "Fratrie (2e membre de la famille)", "amount": 40},
            {"label": "Cours / pratique supplémentaire", "amount": 40},
        ])
    docs = await db.discounts.find({}).sort("label", 1).to_list(200)
    return [clean(d) for d in docs]


@api.post("/discounts")
async def create_discount(data: DiscountInput, user: dict = Depends(get_current_user)):
    res = await db.discounts.insert_one(data.model_dump())
    return clean(await db.discounts.find_one({"_id": res.inserted_id}))


@api.put("/discounts/{did}")
async def update_discount(did: str, data: DiscountInput, user: dict = Depends(get_current_user)):
    await db.discounts.update_one({"_id": ObjectId(did)}, {"$set": data.model_dump()})
    return clean(await db.discounts.find_one({"_id": ObjectId(did)}))


@api.delete("/discounts/{did}")
async def delete_discount(did: str, user: dict = Depends(get_current_user)):
    await db.discounts.delete_one({"_id": ObjectId(did)})
    return {"ok": True}


# ---- Planning global : créneaux (cours collectifs/groupes + cours individuels des inscriptions)
@api.get("/planning")
async def planning(exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    ex = exercise or await get_current_exercise_label()
    slots = []
    # Cours collectifs / théoriques / éveil = groupes à créneau fixe
    courses = await db.courses.find({}).to_list(2000)
    for c in courses:
        if c.get("type") == "individuel":
            continue
        if not c.get("day") or not c.get("start_time"):
            continue
        slots.append({
            "label": c.get("name", ""), "type": c.get("type", ""), "kind": "groupe",
            "day": c.get("day"), "start_time": c.get("start_time"), "duration_min": c.get("duration_min", 60),
            "teacher_id": c.get("teacher_id"), "room_id": c.get("room_id"), "who": c.get("name", ""),
        })
    # Cours individuels = lignes d'inscription avec créneau attribué
    inscriptions = await db.inscriptions.find({"exercise": ex}).to_list(5000)
    for ins in inscriptions:
        st = await db.students.find_one({"_id": ObjectId(ins["student_id"])}) if ins.get("student_id") else None
        who = f"{st.get('first_name','')} {st.get('last_name','')}".strip() if st else ""
        for l in ins.get("lines", []):
            if l.get("course_type") == "individuel" and l.get("day") and l.get("start_time"):
                slots.append({
                    "label": l.get("discipline") or l.get("label", ""), "type": l.get("course_type", "individuel"), "kind": "individuel",
                    "day": l.get("day"), "start_time": l.get("start_time"), "duration_min": l.get("duration_min", 30),
                    "teacher_id": l.get("teacher_id"), "room_id": l.get("room_id"), "who": who,
                })
    return {"exercise": ex, "slots": slots}




async def _create_ecolage_txn(insc: dict, item: dict, method: str, paid_date: str) -> str:
    # Crée la recette d'écolage correspondant à une échéance encaissée et renvoie l'id de la transaction (pour pouvoir l'annuler).
    stu = await db.students.find_one({"_id": ObjectId(insc["student_id"])}) if ObjectId.is_valid(insc["student_id"]) else None
    name = f"{stu['first_name']} {stu['last_name']}" if stu else "Élève"
    res = await db.transactions.insert_one({
        "type": "income", "category": "Écolage", "account_code": "7061", "amount": round(item["amount"], 2),
        "date": paid_date, "description": f"Écolage {name} — {item['label']} ({insc['school_year']})",
        "method": method, "exercise": insc.get("school_year"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return str(res.inserted_id)


@api.put("/inscriptions/{iid}/pay/{idx}")
async def pay_inscription_installment(iid: str, idx: int, body: dict = None,
                                      user: dict = Depends(get_current_user)):
    # Encaisse une échéance : la marque « payée », crée la recette et mémorise l'id de la transaction.
    insc = await db.inscriptions.find_one({"_id": ObjectId(iid)})
    if not insc or idx >= len(insc.get("schedule", [])):
        raise HTTPException(status_code=404, detail="Échéance introuvable")
    if insc["schedule"][idx].get("status") == "paid":
        raise HTTPException(status_code=400, detail="Échéance déjà encaissée")
    await assert_exercise_open(insc.get("school_year"))
    method = (body or {}).get("method", insc.get("payment_method") or "Virement")
    paid_date = (body or {}).get("paid_date") or datetime.now(timezone.utc).date().isoformat()
    if (body or {}).get("amount") is not None:
        insc["schedule"][idx]["amount"] = round(float(body["amount"]), 2)
    txn_id = await _create_ecolage_txn(insc, insc["schedule"][idx], method, paid_date)
    insc["schedule"][idx].update({"status": "paid", "method": method, "paid_date": paid_date, "txn_id": txn_id})
    await db.inscriptions.update_one({"_id": ObjectId(iid)}, {"$set": {"schedule": insc["schedule"]}})
    return clean(await db.inscriptions.find_one({"_id": ObjectId(iid)}))


@api.put("/inscriptions/{iid}/schedule/{idx}")
async def edit_installment(iid: str, idx: int, body: dict, user: dict = Depends(get_current_user)):
    # Édite librement une échéance (libellé, montant, date d'échéance, moyen, statut) et synchronise la recette liée.
    insc = await db.inscriptions.find_one({"_id": ObjectId(iid)})
    if not insc or idx >= len(insc.get("schedule", [])):
        raise HTTPException(status_code=404, detail="Échéance introuvable")
    item = insc["schedule"][idx]
    was_paid = item.get("status") == "paid"
    for k in ("label", "due_date", "method"):
        if k in body and body[k] is not None:
            item[k] = body[k]
    if body.get("amount") is not None:
        item["amount"] = round(float(body["amount"]), 2)
    if "status" in body and body["status"]:
        item["status"] = body["status"]
    now_paid = item.get("status") == "paid"
    if now_paid and not was_paid:
        # passage à payé → création de la recette
        item["paid_date"] = body.get("paid_date") or datetime.now(timezone.utc).date().isoformat()
        item["txn_id"] = await _create_ecolage_txn(insc, item, item.get("method") or "Virement", item["paid_date"])
    elif was_paid and not now_paid:
        # annulation du paiement → suppression de la recette
        if item.get("txn_id"):
            await db.transactions.delete_one({"_id": ObjectId(item["txn_id"])})
        item["txn_id"] = None
        item["paid_date"] = None
    elif was_paid and now_paid and item.get("txn_id"):
        # déjà payé mais montant/moyen modifié → mise à jour de la recette
        await db.transactions.update_one({"_id": ObjectId(item["txn_id"])}, {"$set": {"amount": item["amount"], "method": item.get("method") or "Virement"}})
    await db.inscriptions.update_one({"_id": ObjectId(iid)}, {"$set": {"schedule": insc["schedule"]}})
    return clean(await db.inscriptions.find_one({"_id": ObjectId(iid)}))


@api.post("/inscriptions/{iid}/schedule")
async def add_installment(iid: str, body: dict, user: dict = Depends(get_current_user)):
    # Ajoute une échéance manuelle (ex. régularisation d'un mois oublié payé le double le mois suivant).
    insc = await db.inscriptions.find_one({"_id": ObjectId(iid)})
    if not insc:
        raise HTTPException(status_code=404, detail="Inscription introuvable")
    item = {"label": body.get("label", "Échéance"), "due_date": body.get("due_date", datetime.now(timezone.utc).date().isoformat()),
            "amount": round(float(body.get("amount", 0)), 2), "status": "pending", "method": body.get("method", ""), "paid_date": None}
    sched = insc.get("schedule", []) + [item]
    await db.inscriptions.update_one({"_id": ObjectId(iid)}, {"$set": {"schedule": sched}})
    return clean(await db.inscriptions.find_one({"_id": ObjectId(iid)}))


@api.delete("/inscriptions/{iid}/schedule/{idx}")
async def delete_installment(iid: str, idx: int, user: dict = Depends(get_current_user)):
    # Supprime une échéance et, si elle était payée, la recette associée.
    insc = await db.inscriptions.find_one({"_id": ObjectId(iid)})
    if not insc or idx >= len(insc.get("schedule", [])):
        raise HTTPException(status_code=404, detail="Échéance introuvable")
    item = insc["schedule"][idx]
    if item.get("txn_id"):
        await db.transactions.delete_one({"_id": ObjectId(item["txn_id"])})
    sched = [s for i, s in enumerate(insc["schedule"]) if i != idx]
    await db.inscriptions.update_one({"_id": ObjectId(iid)}, {"$set": {"schedule": sched}})
    return clean(await db.inscriptions.find_one({"_id": ObjectId(iid)}))



@api.delete("/inscriptions/{iid}")
async def delete_inscription(iid: str, user: dict = Depends(get_current_user)):
    await db.inscriptions.delete_one({"_id": ObjectId(iid)})
    return {"ok": True}


# ================= EXERCICES, CONTACTS, UTILISATEURS =================
class ContactInput(BaseModel):
    first_name: str
    last_name: str
    type: Optional[str] = None  # legacy (conservé pour compat)
    types: List[str] = []  # statuts multiples: adherent|eleve|donateur|fournisseur|benevole|ca|...
    payer_contact_id: Optional[str] = None  # payeur / responsable (lien familial)
    email: Optional[str] = ""
    phone: Optional[str] = ""
    address: Optional[str] = ""
    postal_code: Optional[str] = ""
    city: Optional[str] = ""
    commune_code: Optional[str] = ""          # code INSEE de la commune
    commune_deleguee: Optional[str] = ""       # commune déléguée si commune nouvelle
    cc_savoir_faire: Optional[bool] = None   # True=dans la CC des Savoir-Faire, False=hors CC, None=inconnu
    organization: Optional[str] = ""
    notes: Optional[str] = ""
    tags: List[str] = []


class ExerciseInput(BaseModel):
    label: str
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    status: str = "open"  # open | closed


class UserInput(BaseModel):
    name: str
    email: EmailStr
    password: Optional[str] = None
    role: str = "membre"


async def get_current_exercise_label() -> str:
    cur = await db.exercises.find_one({"is_current": True})
    return cur["label"] if cur else current_school_year()


async def assert_exercise_open(label: Optional[str]):
    if not label:
        return
    ex = await db.exercises.find_one({"label": label})
    if ex and ex.get("status") == "closed":
        raise HTTPException(status_code=400, detail=f"L'exercice {label} est clôturé. Rouvrez-le pour pouvoir le modifier.")


# ---- Exercises
@api.get("/exercises")
async def list_exercises(user: dict = Depends(get_current_user)):
    docs = await db.exercises.find({}).sort("label", -1).to_list(100)
    return [clean(d) for d in docs]


@api.post("/exercises")
async def create_exercise(data: ExerciseInput, user: dict = Depends(get_current_user)):
    doc = data.model_dump()
    try:
        sy = int(doc["label"].split("-")[0])
        doc["start_date"] = doc.get("start_date") or f"{sy}-09-01"
        doc["end_date"] = doc.get("end_date") or f"{sy + 1}-08-31"
    except Exception:
        pass
    doc["is_current"] = await db.exercises.count_documents({}) == 0
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    res = await db.exercises.insert_one(doc)
    return clean(await db.exercises.find_one({"_id": res.inserted_id}))


@api.put("/exercises/{eid}")
async def update_exercise(eid: str, data: ExerciseInput, user: dict = Depends(get_current_user)):
    await db.exercises.update_one({"_id": ObjectId(eid)}, {"$set": data.model_dump()})
    return clean(await db.exercises.find_one({"_id": ObjectId(eid)}))


@api.post("/exercises/{eid}/close")
async def close_exercise(eid: str, user: dict = Depends(get_current_user)):
    await db.exercises.update_one({"_id": ObjectId(eid)}, {"$set": {"status": "closed"}})
    return clean(await db.exercises.find_one({"_id": ObjectId(eid)}))


@api.post("/exercises/{eid}/reopen")
async def reopen_exercise(eid: str, user: dict = Depends(get_current_user)):
    await db.exercises.update_one({"_id": ObjectId(eid)}, {"$set": {"status": "open"}})
    return clean(await db.exercises.find_one({"_id": ObjectId(eid)}))


@api.post("/exercises/{eid}/set-current")
async def set_current_exercise(eid: str, user: dict = Depends(get_current_user)):
    await db.exercises.update_many({}, {"$set": {"is_current": False}})
    await db.exercises.update_one({"_id": ObjectId(eid)}, {"$set": {"is_current": True}})
    return clean(await db.exercises.find_one({"_id": ObjectId(eid)}))


@api.delete("/exercises/{eid}")
async def delete_exercise(eid: str, user: dict = Depends(get_current_user)):
    ex = await db.exercises.find_one({"_id": ObjectId(eid)})
    if ex and ex.get("is_current"):
        raise HTTPException(status_code=400, detail="Impossible de supprimer l'exercice courant")
    await db.exercises.delete_one({"_id": ObjectId(eid)})
    return {"ok": True}


# ---- Contacts (annuaire persistant, hors exercice)
@api.get("/contacts")
async def list_contacts(type: Optional[str] = None, search: Optional[str] = None, user: dict = Depends(get_current_user)):
    q: dict = {}
    if type and type != "all":
        q["types"] = type
    docs = await db.contacts.find(q).sort("last_name", 1).to_list(5000)
    items = [clean(d) for d in docs]
    if search:
        s = search.lower()
        items = [c for c in items if s in f"{c.get('first_name','')} {c.get('last_name','')} {c.get('email','')} {c.get('organization','')}".lower()]
    return items


@api.post("/contacts")
async def create_contact(data: ContactInput, user: dict = Depends(get_current_user)):
    doc = data.model_dump()
    if not doc.get("types") and doc.get("type"):
        doc["types"] = [doc["type"]]
    doc["type"] = doc["types"][0] if doc.get("types") else "contact"
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    res = await db.contacts.insert_one(doc)
    return clean(await db.contacts.find_one({"_id": res.inserted_id}))


@api.put("/contacts/{cid}")
async def update_contact(cid: str, data: ContactInput, user: dict = Depends(get_current_user)):
    doc = data.model_dump()
    if not doc.get("types") and doc.get("type"):
        doc["types"] = [doc["type"]]
    doc["type"] = doc["types"][0] if doc.get("types") else "contact"
    await db.contacts.update_one({"_id": ObjectId(cid)}, {"$set": doc})
    return clean(await db.contacts.find_one({"_id": ObjectId(cid)}))


@api.post("/contacts/{cid}/create-student")
async def create_student_from_contact(cid: str, user: dict = Depends(get_current_user)):
    c = await db.contacts.find_one({"_id": ObjectId(cid)})
    if not c:
        raise HTTPException(status_code=404, detail="Contact introuvable")
    ex = await get_current_exercise_label()
    await assert_exercise_open(ex)
    existing = await db.students.find_one({"contact_id": cid, "exercise": ex})
    if existing:
        return {"ok": True, "student": clean(existing), "already": True}
    payer = None
    if c.get("payer_contact_id"):
        payer = await db.contacts.find_one({"_id": ObjectId(c["payer_contact_id"])})
    student = {
        "first_name": c.get("first_name", ""), "last_name": c.get("last_name", ""),
        "email": c.get("email", ""), "phone": c.get("phone", ""), "address": c.get("address", ""),
        "contact_id": cid, "is_minor": bool(payer),
        "responsable_name": f"{payer.get('first_name','')} {payer.get('last_name','')}".strip() if payer else "",
        "responsable_relation": "Parent", "responsable_email": payer.get("email", "") if payer else "",
        "responsable_phone": payer.get("phone", "") if payer else "",
        "cotisation_status": "pending", "avatar_url": "", "notes": "",
        "exercise": ex, "created_at": datetime.now(timezone.utc).isoformat(),
    }
    res = await db.students.insert_one(student)
    # ajoute le statut "eleve" au contact
    types = c.get("types") or ([c["type"]] if c.get("type") else [])
    if "eleve" not in types:
        types.append("eleve")
        await db.contacts.update_one({"_id": ObjectId(cid)}, {"$set": {"types": types, "type": types[0]}})
    return {"ok": True, "student": clean(await db.students.find_one({"_id": res.inserted_id}))}


@api.delete("/contacts/{cid}")
async def delete_contact(cid: str, user: dict = Depends(get_current_user)):
    await db.contacts.delete_one({"_id": ObjectId(cid)})
    return {"ok": True}


# ---- Users (administration)
@api.get("/users")
async def list_users(user: dict = Depends(get_current_user)):
    docs = await db.users.find({}).sort("name", 1).to_list(1000)
    return [clean(d) for d in docs]


@api.post("/users")
async def create_user_admin(data: UserInput, user: dict = Depends(get_current_user)):
    email = data.email.lower()
    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Cet email existe déjà")
    doc = {"name": data.name, "email": email, "role": data.role,
           "password_hash": hash_password(data.password or "changeme123"),
           "created_at": datetime.now(timezone.utc).isoformat()}
    res = await db.users.insert_one(doc)
    return clean(await db.users.find_one({"_id": res.inserted_id}))


@api.put("/users/{uid}")
async def update_user_admin(uid: str, data: UserInput, user: dict = Depends(get_current_user)):
    upd = {"name": data.name, "email": data.email.lower(), "role": data.role}
    if data.password:
        upd["password_hash"] = hash_password(data.password)
    await db.users.update_one({"_id": ObjectId(uid)}, {"$set": upd})
    return clean(await db.users.find_one({"_id": ObjectId(uid)}))


@api.delete("/users/{uid}")
async def delete_user_admin(uid: str, user: dict = Depends(get_current_user)):
    if str(user.get("id")) == uid:
        raise HTTPException(status_code=400, detail="Impossible de supprimer votre propre compte")
    await db.users.delete_one({"_id": ObjectId(uid)})
    return {"ok": True}


async def seed_exercises():
    if await db.exercises.count_documents({}) > 0:
        return
    cy = int(current_school_year().split("-")[0])

    def mk(sy, status, is_current=False):
        return {"label": f"{sy}-{sy + 1}", "start_date": f"{sy}-09-01", "end_date": f"{sy + 1}-08-31",
                "status": status, "is_current": is_current, "created_at": datetime.now(timezone.utc).isoformat()}
    await db.exercises.insert_many([mk(cy - 1, "closed"), mk(cy, "open", True), mk(cy + 1, "open")])


async def seed_contacts():
    if await db.contacts.count_documents({}) > 0:
        return
    data = [
        {"first_name": "Fondation", "last_name": "Musique Pour Tous", "type": "donateur", "email": "contact@fmpt.fr", "phone": "01 40 00 00 00", "organization": "Fondation MPT", "address": "Paris", "notes": "Donateur annuel", "tags": ["mécène"]},
        {"first_name": "Sono", "last_name": "Lyonnaise", "type": "fournisseur", "email": "ventes@sonolyon.fr", "phone": "04 78 00 00 00", "organization": "Sono Lyon", "address": "Lyon", "notes": "Instruments & sonorisation", "tags": []},
        {"first_name": "Service Culture", "last_name": "Mairie", "type": "partenaire", "email": "culture@mairie.fr", "phone": "04 72 00 00 00", "organization": "Mairie", "address": "", "notes": "Subventions municipales", "tags": ["subvention"]},
        {"first_name": "Paul", "last_name": "Durand", "type": "ca", "email": "paul.durand@email.fr", "phone": "06 00 00 00 00", "organization": "", "address": "", "notes": "Trésorier du conseil d'administration", "tags": ["bureau"]},
        {"first_name": "Sophie", "last_name": "Martin", "type": "adherent", "email": "sophie.martin@email.fr", "phone": "06 12 34 56 78", "organization": "", "address": "Lyon", "notes": "Parent d'élève", "tags": []},
    ]
    for d in data:
        d["created_at"] = datetime.now(timezone.utc).isoformat()
    await db.contacts.insert_many(data)


# ================= COMPTA ANALYTIQUE, PAIE ÉCLAT, PATRIMOINE, MANIFESTATIONS =================
ECLAT_V1 = 7.23
ECLAT_V2 = 6.81
ECLAT_FULLTIME_HOURS = 151.67
ECLAT_GROUPS = [
    {"group": "A", "coefficient": 257}, {"group": "B", "coefficient": 265},
    {"group": "C", "coefficient": 285}, {"group": "D", "coefficient": 305},
    {"group": "E", "coefficient": 325}, {"group": "F", "coefficient": 350},
    {"group": "G", "coefficient": 375}, {"group": "H", "coefficient": 400},
    {"group": "I", "coefficient": 450}, {"group": "J", "coefficient": 500},
]


def eclat_monthly(coefficient: int, hours: float = ECLAT_FULLTIME_HOURS) -> float:
    base = (257 * ECLAT_V1) + ((coefficient - 257) * ECLAT_V2)
    return round(base * (hours / ECLAT_FULLTIME_HOURS), 2)


class PoleInput(BaseModel):
    name: str
    color: Optional[str] = "#2563EB"


class AccountInput(BaseModel):
    code: str
    label: str
    type: str  # produit | charge


class InstrumentInput(BaseModel):
    name: str
    category: Optional[str] = ""
    brand: Optional[str] = ""
    serial_number: Optional[str] = ""
    value: float = 0
    insurance_company: Optional[str] = ""
    insurance_policy: Optional[str] = ""
    insurance_expiry: Optional[str] = None
    status: str = "available"  # available | loaned | maintenance
    notes: Optional[str] = ""


class LoanInput(BaseModel):
    instrument_id: str
    borrower_name: str
    student_id: Optional[str] = None
    start_date: Optional[str] = None
    due_date: Optional[str] = None
    deposit: float = 0
    notes: Optional[str] = ""


class EventInput(BaseModel):
    name: str
    date: Optional[str] = None
    location: Optional[str] = ""
    description: Optional[str] = ""
    status: str = "open"  # open | closed
    pole_ids: List[str] = []
    exercise: Optional[str] = None


class SaleInput(BaseModel):
    label: str
    category: str = "billetterie"  # billetterie | buvette | autre
    unit_price: float = 0
    qty: int = 1
    payment_method: str = "especes"  # especes | cb | cheque | offert
    tendered: Optional[float] = None
    change: Optional[float] = None
    ticket_id: Optional[str] = None


class TabInput(BaseModel):
    name: str
    items: List[dict] = []  # [{name, price, category, qty}]


class TabPayInput(BaseModel):
    payment_method: str = "especes"
    tendered: Optional[float] = None
    change: Optional[float] = None


class CaisseOpenInput(BaseModel):
    amount: float = 0
    denoms: dict = {}


class CaisseCloseInput(BaseModel):
    cash_counted: Optional[float] = None
    cash_close_denoms: dict = {}


class InventoryInput(BaseModel):
    name: str
    category: str = "buvette"  # buvette | cuisine | fourniture | autre
    unit: str = "unité"  # unité | litre | kg | carton | fût ...
    quantity: float = 0
    threshold: float = 0
    notes: Optional[str] = ""
    exercise: Optional[str] = None


@api.get("/eclat/grid")
async def eclat_grid(user: dict = Depends(get_current_user)):
    return {"v1": ECLAT_V1, "v2": ECLAT_V2, "full_time_hours": ECLAT_FULLTIME_HOURS,
            "groups": [{**g, "monthly_full": eclat_monthly(g["coefficient"])} for g in ECLAT_GROUPS]}


# ---- Pôles analytiques
@api.get("/poles")
async def list_poles(user: dict = Depends(get_current_user)):
    docs = await db.poles.find({}).sort("name", 1).to_list(100)
    return [clean(d) for d in docs]


@api.post("/poles")
async def create_pole(data: PoleInput, user: dict = Depends(get_current_user)):
    res = await db.poles.insert_one(data.model_dump())
    return clean(await db.poles.find_one({"_id": res.inserted_id}))


@api.put("/poles/{pid}")
async def update_pole(pid: str, data: PoleInput, user: dict = Depends(get_current_user)):
    await db.poles.update_one({"_id": ObjectId(pid)}, {"$set": data.model_dump()})
    return clean(await db.poles.find_one({"_id": ObjectId(pid)}))


@api.delete("/poles/{pid}")
async def delete_pole(pid: str, user: dict = Depends(get_current_user)):
    await db.poles.delete_one({"_id": ObjectId(pid)})
    return {"ok": True}


# ---- Plan comptable
@api.get("/accounts")
async def list_accounts(user: dict = Depends(get_current_user)):
    docs = await db.accounts.find({}).sort("code", 1).to_list(500)
    return [clean(d) for d in docs]


@api.post("/accounts")
async def create_account(data: AccountInput, user: dict = Depends(get_current_user)):
    res = await db.accounts.insert_one(data.model_dump())
    return clean(await db.accounts.find_one({"_id": res.inserted_id}))


@api.delete("/accounts/{aid}")
async def delete_account(aid: str, user: dict = Depends(get_current_user)):
    await db.accounts.delete_one({"_id": ObjectId(aid)})
    return {"ok": True}


@api.get("/analytics/summary")
async def analytics_summary(exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    q = {"exercise": exercise} if exercise else {}
    txs = await db.transactions.find(q).to_list(5000)
    poles = await db.poles.find({}).to_list(100)
    res = {str(p["_id"]): {"pole": p["name"], "color": p.get("color", "#2563EB"), "income": 0, "expense": 0} for p in poles}
    res["none"] = {"pole": "Non affecté", "color": "#CBD5E1", "income": 0, "expense": 0}
    for t in txs:
        pid = t.get("pole_id") or "none"
        if pid not in res:
            pid = "none"
        res[pid][t["type"]] += t["amount"]
    by_account: dict = {}
    for t in txs:
        code = t.get("account_code") or "—"
        by_account.setdefault(code, {"account": code, "income": 0, "expense": 0})
        by_account[code][t["type"]] += t["amount"]
    return {"poles": list(res.values()), "accounts": sorted(by_account.values(), key=lambda x: x["account"])}


# ---- Patrimoine : instruments
@api.get("/instruments")
async def list_instruments(user: dict = Depends(get_current_user)):
    docs = await db.instruments.find({}).sort("name", 1).to_list(2000)
    return [clean(d) for d in docs]


@api.post("/instruments")
async def create_instrument(data: InstrumentInput, user: dict = Depends(get_current_user)):
    doc = data.model_dump()
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    res = await db.instruments.insert_one(doc)
    return clean(await db.instruments.find_one({"_id": res.inserted_id}))


@api.put("/instruments/{iid}")
async def update_instrument(iid: str, data: InstrumentInput, user: dict = Depends(get_current_user)):
    await db.instruments.update_one({"_id": ObjectId(iid)}, {"$set": data.model_dump()})
    return clean(await db.instruments.find_one({"_id": ObjectId(iid)}))


@api.delete("/instruments/{iid}")
async def delete_instrument(iid: str, user: dict = Depends(get_current_user)):
    await db.instruments.delete_one({"_id": ObjectId(iid)})
    return {"ok": True}


# ---- Patrimoine : prêts
@api.get("/loans")
async def list_loans(user: dict = Depends(get_current_user)):
    docs = await db.loans.find({}).sort("start_date", -1).to_list(2000)
    return [clean(d) for d in docs]


@api.post("/loans")
async def create_loan(data: LoanInput, user: dict = Depends(get_current_user)):
    doc = data.model_dump()
    doc["status"] = "active"
    doc["return_date"] = None
    doc["start_date"] = doc.get("start_date") or datetime.now(timezone.utc).date().isoformat()
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    res = await db.loans.insert_one(doc)
    await db.instruments.update_one({"_id": ObjectId(data.instrument_id)}, {"$set": {"status": "loaned"}})
    return clean(await db.loans.find_one({"_id": res.inserted_id}))


@api.post("/loans/{lid}/return")
async def return_loan(lid: str, user: dict = Depends(get_current_user)):
    loan = await db.loans.find_one({"_id": ObjectId(lid)})
    if not loan:
        raise HTTPException(status_code=404, detail="Prêt introuvable")
    await db.loans.update_one({"_id": ObjectId(lid)}, {"$set": {"status": "returned", "return_date": datetime.now(timezone.utc).date().isoformat()}})
    await db.instruments.update_one({"_id": ObjectId(loan["instrument_id"])}, {"$set": {"status": "available"}})
    return clean(await db.loans.find_one({"_id": ObjectId(lid)}))


@api.delete("/loans/{lid}")
async def delete_loan(lid: str, user: dict = Depends(get_current_user)):
    loan = await db.loans.find_one({"_id": ObjectId(lid)})
    if loan and loan.get("status") == "active" and ObjectId.is_valid(loan.get("instrument_id", "")):
        await db.instruments.update_one({"_id": ObjectId(loan["instrument_id"])}, {"$set": {"status": "available"}})
    await db.loans.delete_one({"_id": ObjectId(lid)})
    return {"ok": True}


# ---- Manifestations & caisse
@api.get("/events")
async def list_events(exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    q = {"exercise": exercise} if exercise else {}
    docs = await db.events.find(q).sort("date", -1).to_list(2000)
    events = [clean(d) for d in docs]
    for ev in events:
        sales = await db.event_sales.find({"event_id": ev["id"]}).to_list(5000)
        ev["caisse_total"] = round(sum(s["unit_price"] * s.get("qty", 1) for s in sales if s.get("payment_method") != "offert"), 2)
        ev["sales_count"] = len(sales)
    return events


@api.post("/events")
async def create_event(data: EventInput, user: dict = Depends(get_current_user)):
    doc = data.model_dump()
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    res = await db.events.insert_one(doc)
    return clean(await db.events.find_one({"_id": res.inserted_id}))


@api.put("/events/{eid}")
async def update_event(eid: str, data: EventInput, user: dict = Depends(get_current_user)):
    await db.events.update_one({"_id": ObjectId(eid)}, {"$set": data.model_dump()})
    return clean(await db.events.find_one({"_id": ObjectId(eid)}))


@api.delete("/events/{eid}")
async def delete_event(eid: str, user: dict = Depends(get_current_user)):
    await db.events.delete_one({"_id": ObjectId(eid)})
    await db.event_sales.delete_many({"event_id": eid})
    return {"ok": True}


@api.get("/events/{eid}/sales")
async def list_sales(eid: str, user: dict = Depends(get_current_user)):
    docs = await db.event_sales.find({"event_id": eid}).sort("created_at", -1).to_list(5000)
    return [clean(d) for d in docs]


@api.post("/events/{eid}/sales")
async def create_sale(eid: str, data: SaleInput, user: dict = Depends(get_current_user)):
    doc = data.model_dump()
    doc["event_id"] = eid
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    res = await db.event_sales.insert_one(doc)
    return clean(await db.event_sales.find_one({"_id": res.inserted_id}))


@api.delete("/sales/{sid}")
async def delete_sale(sid: str, user: dict = Depends(get_current_user)):
    await db.event_sales.delete_one({"_id": ObjectId(sid)})
    return {"ok": True}


@api.post("/events/{eid}/open-caisse")
async def open_caisse(eid: str, data: CaisseOpenInput, user: dict = Depends(get_current_user)):
    await db.events.update_one({"_id": ObjectId(eid)}, {"$set": {
        "cash_open": round(data.amount, 2), "cash_open_denoms": data.denoms,
        "caisse_opened_at": datetime.now(timezone.utc).isoformat(),
    }})
    return clean(await db.events.find_one({"_id": ObjectId(eid)}))


async def _event_recap(eid: str) -> dict:
    ev = await db.events.find_one({"_id": ObjectId(eid)})
    sales = await db.event_sales.find({"event_id": eid}).to_list(5000)
    by_method = {"especes": 0.0, "cb": 0.0, "cheque": 0.0, "offert": 0.0}
    for s in sales:
        m = s.get("payment_method", "especes")
        by_method[m] = round(by_method.get(m, 0.0) + s["unit_price"] * s.get("qty", 1), 2)
    cash_open = round((ev or {}).get("cash_open", 0) or 0, 2)
    revenue = round(by_method["especes"] + by_method["cb"] + by_method["cheque"], 2)
    return {
        "by_method": {k: round(v, 2) for k, v in by_method.items()},
        "cash_open": cash_open,
        "theoretical_cash": round(cash_open + by_method["especes"], 2),
        "revenue": revenue,
        "sales_count": len(sales),
        "cash_counted": (ev or {}).get("cash_counted"),
        "cash_ecart": (ev or {}).get("cash_ecart"),
    }


@api.get("/events/{eid}/recap")
async def event_recap(eid: str, user: dict = Depends(get_current_user)):
    return await _event_recap(eid)


@api.post("/events/{eid}/close")
async def close_event(eid: str, data: Optional[CaisseCloseInput] = None, user: dict = Depends(get_current_user)):
    ev = await db.events.find_one({"_id": ObjectId(eid)})
    if not ev:
        raise HTTPException(status_code=404, detail="Manifestation introuvable")
    if ev.get("status") == "closed":
        return {"ok": True, "total": 0, "already_closed": True}
    # Recette = ventes non offertes uniquement
    sales = await db.event_sales.find({"event_id": eid}).to_list(5000)
    total = round(sum(s["unit_price"] * s.get("qty", 1) for s in sales if s.get("payment_method") != "offert"), 2)
    recap = await _event_recap(eid)
    set_fields = {"status": "closed", "recap": recap, "caisse_closed_at": datetime.now(timezone.utc).isoformat()}
    if data and data.cash_counted is not None:
        set_fields["cash_counted"] = round(data.cash_counted, 2)
        set_fields["cash_close_denoms"] = data.cash_close_denoms
        set_fields["cash_ecart"] = round(data.cash_counted - recap["theoretical_cash"], 2)
    await db.events.update_one({"_id": ObjectId(eid)}, {"$set": set_fields})
    if total > 0:
        ex = ev.get("exercise") or await get_current_exercise_label()
        await assert_exercise_open(ex)
        pole_ids = ev.get("pole_ids") or []
        now = datetime.now(timezone.utc).isoformat()
        today = datetime.now(timezone.utc).date().isoformat()
        if pole_ids:
            # Répartition équitable de la recette entre les pôles organisateurs
            share = round(total / len(pole_ids), 2)
            remainder = round(total - share * len(pole_ids), 2)
            for i, pid in enumerate(pole_ids):
                amt = round(share + (remainder if i == 0 else 0), 2)
                await db.transactions.insert_one({
                    "type": "income", "category": "Manifestations", "amount": amt,
                    "date": today,
                    "description": f"Recette manifestation : {ev['name']}", "method": "Caisse",
                    "exercise": ex, "pole_id": pid, "account_code": "7063",
                    "created_at": now,
                })
        else:
            await db.transactions.insert_one({
                "type": "income", "category": "Manifestations", "amount": total,
                "date": today,
                "description": f"Recette manifestation : {ev['name']}", "method": "Caisse",
                "exercise": ex, "pole_id": None, "account_code": "7063",
                "created_at": now,
            })
    return {"ok": True, "total": total}


# ---- Ardoises (tabs) persistées
@api.get("/events/{eid}/tabs")
async def list_tabs(eid: str, user: dict = Depends(get_current_user)):
    docs = await db.event_tabs.find({"event_id": eid, "status": "open"}).sort("created_at", 1).to_list(500)
    return [clean(d) for d in docs]


@api.post("/events/{eid}/tabs")
async def create_tab(eid: str, data: TabInput, user: dict = Depends(get_current_user)):
    ev = await db.events.find_one({"_id": ObjectId(eid)})
    if not ev:
        raise HTTPException(status_code=404, detail="Manifestation introuvable")
    doc = data.model_dump()
    doc.update({"event_id": eid, "status": "open", "exercise": ev.get("exercise"),
                "created_at": datetime.now(timezone.utc).isoformat()})
    res = await db.event_tabs.insert_one(doc)
    return clean(await db.event_tabs.find_one({"_id": res.inserted_id}))


@api.put("/tabs/{tid}")
async def update_tab(tid: str, data: TabInput, user: dict = Depends(get_current_user)):
    await db.event_tabs.update_one({"_id": ObjectId(tid)}, {"$set": {"name": data.name, "items": data.items}})
    return clean(await db.event_tabs.find_one({"_id": ObjectId(tid)}))


@api.delete("/tabs/{tid}")
async def delete_tab(tid: str, user: dict = Depends(get_current_user)):
    await db.event_tabs.delete_one({"_id": ObjectId(tid)})
    return {"ok": True}


@api.post("/tabs/{tid}/pay")
async def pay_tab(tid: str, data: TabPayInput, user: dict = Depends(get_current_user)):
    tab = await db.event_tabs.find_one({"_id": ObjectId(tid)})
    if not tab:
        raise HTTPException(status_code=404, detail="Ardoise introuvable")
    now = datetime.now(timezone.utc).isoformat()
    for it in tab.get("items", []):
        await db.event_sales.insert_one({
            "event_id": tab["event_id"], "label": it["name"], "category": it.get("category", "autre"),
            "unit_price": it["price"], "qty": it["qty"], "payment_method": data.payment_method,
            "tendered": data.tendered, "change": data.change, "ticket_id": tid, "created_at": now,
        })
    await db.event_tabs.update_one({"_id": ObjectId(tid)}, {"$set": {"status": "paid", "paid_at": now, "payment_method": data.payment_method}})
    return {"ok": True}


# ---- Inventaire des produits (Logistique & Matériel)
@api.get("/inventory")
async def list_inventory(exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    q = {"exercise": exercise} if exercise else {}
    docs = await db.inventory.find(q).sort("name", 1).to_list(2000)
    return [clean(d) for d in docs]


@api.post("/inventory")
async def create_inventory(data: InventoryInput, user: dict = Depends(get_current_user)):
    res = await db.inventory.insert_one(data.model_dump())
    return clean(await db.inventory.find_one({"_id": res.inserted_id}))


@api.put("/inventory/{iid}")
async def update_inventory(iid: str, data: InventoryInput, user: dict = Depends(get_current_user)):
    await db.inventory.update_one({"_id": ObjectId(iid)}, {"$set": data.model_dump()})
    return clean(await db.inventory.find_one({"_id": ObjectId(iid)}))


@api.post("/inventory/{iid}/adjust")
async def adjust_inventory(iid: str, body: dict, user: dict = Depends(get_current_user)):
    delta = float(body.get("delta", 0))
    doc = await db.inventory.find_one({"_id": ObjectId(iid)})
    if not doc:
        raise HTTPException(status_code=404, detail="Produit introuvable")
    newq = max(0, round(doc.get("quantity", 0) + delta, 2))
    await db.inventory.update_one({"_id": ObjectId(iid)}, {"$set": {"quantity": newq}})
    return clean(await db.inventory.find_one({"_id": ObjectId(iid)}))


@api.delete("/inventory/{iid}")
async def delete_inventory(iid: str, user: dict = Depends(get_current_user)):
    await db.inventory.delete_one({"_id": ObjectId(iid)})
    return {"ok": True}


async def seed_compta():
    if await db.poles.count_documents({}) == 0:
        await db.poles.insert_many([
            {"name": "Enseignement", "color": "#2563EB"},
            {"name": "Événementiel", "color": "#0EA5E9"},
            {"name": "Administration", "color": "#6366F1"},
            {"name": "Vie associative", "color": "#64748B"},
        ])
    if await db.accounts.count_documents({}) == 0:
        await db.accounts.insert_many([
            {"code": "606", "label": "Achats non stockés (fournitures)", "type": "charge"},
            {"code": "613", "label": "Locations (salles, matériel)", "type": "charge"},
            {"code": "616", "label": "Assurances", "type": "charge"},
            {"code": "625", "label": "Déplacements, missions", "type": "charge"},
            {"code": "626", "label": "Frais postaux et télécom", "type": "charge"},
            {"code": "641", "label": "Rémunérations du personnel", "type": "charge"},
            {"code": "645", "label": "Charges sociales", "type": "charge"},
            {"code": "681", "label": "Dotations aux amortissements", "type": "charge"},
            {"code": "706", "label": "Prestations de services (écolage)", "type": "produit"},
            {"code": "756", "label": "Cotisations", "type": "produit"},
            {"code": "740", "label": "Subventions d'exploitation", "type": "produit"},
            {"code": "754", "label": "Dons et mécénat", "type": "produit"},
            {"code": "758", "label": "Produits divers (manifestations)", "type": "produit"},
        ])


async def seed_patrimoine():
    if await db.instruments.count_documents({}) > 0:
        return
    today = datetime.now(timezone.utc).date()
    insts = [
        {"name": "Piano droit Yamaha", "category": "Clavier", "brand": "Yamaha", "serial_number": "YP-10234", "value": 4200, "insurance_company": "MAIF", "insurance_policy": "ASSO-0098", "insurance_expiry": (today + timedelta(days=200)).isoformat(), "status": "available", "notes": "Salle Mozart"},
        {"name": "Guitare classique", "category": "Cordes", "brand": "Alhambra", "serial_number": "AL-552", "value": 650, "insurance_company": "MAIF", "insurance_policy": "ASSO-0098", "insurance_expiry": (today + timedelta(days=200)).isoformat(), "status": "available", "notes": ""},
        {"name": "Violon 3/4", "category": "Cordes", "brand": "Stentor", "serial_number": "ST-8841", "value": 380, "insurance_company": "MAIF", "insurance_policy": "ASSO-0098", "insurance_expiry": (today - timedelta(days=10)).isoformat(), "status": "available", "notes": "Assurance à renouveler"},
        {"name": "Clarinette Sib", "category": "Vents", "brand": "Buffet Crampon", "serial_number": "BC-2201", "value": 900, "insurance_company": "MAIF", "insurance_policy": "ASSO-0098", "insurance_expiry": (today + timedelta(days=90)).isoformat(), "status": "available", "notes": ""},
    ]
    for i in insts:
        i["created_at"] = datetime.now(timezone.utc).isoformat()
    res = await db.instruments.insert_many(insts)
    vid = str(res.inserted_ids[2])
    await db.loans.insert_one({"instrument_id": vid, "borrower_name": "Léo Martin", "student_id": None,
                               "start_date": (today - timedelta(days=30)).isoformat(),
                               "due_date": (today + timedelta(days=240)).isoformat(), "deposit": 160,
                               "status": "active", "return_date": None, "notes": "Prêt saison",
                               "created_at": datetime.now(timezone.utc).isoformat()})
    await db.instruments.update_one({"_id": res.inserted_ids[2]}, {"$set": {"status": "loaned"}})


async def seed_events():
    if await db.events.count_documents({}) > 0:
        return
    today = datetime.now(timezone.utc).date()
    res = await db.events.insert_one({"name": "Concert de Noël", "date": (today + timedelta(days=20)).isoformat(),
                                      "location": "Grande salle", "description": "Concert des élèves", "status": "open",
                                      "pole_ids": [], "exercise": current_school_year(),
                                      "created_at": datetime.now(timezone.utc).isoformat()})
    eid = str(res.inserted_id)
    await db.event_sales.insert_many([
        {"event_id": eid, "label": "Entrée adulte", "category": "billetterie", "unit_price": 8, "qty": 45, "created_at": datetime.now(timezone.utc).isoformat()},
        {"event_id": eid, "label": "Entrée enfant", "category": "billetterie", "unit_price": 4, "qty": 30, "created_at": datetime.now(timezone.utc).isoformat()},
        {"event_id": eid, "label": "Boisson", "category": "buvette", "unit_price": 2, "qty": 80, "created_at": datetime.now(timezone.utc).isoformat()},
    ])


# ================= BORDEREAUX DE REMISE (espèces / chèques) =================
class BordereauInput(BaseModel):
    account_id: Optional[str] = None
    kind: str = "cheque"  # especes | cheque
    date: Optional[str] = None
    lines: List[dict] = []  # construit depuis les transactions sélectionnées
    transaction_ids: List[str] = []  # transactions (chèque/espèces) à rattacher à ce bordereau
    exercise: Optional[str] = None


@api.get("/bordereaux")
async def list_bordereaux(exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    # Liste les bordereaux de remise de l'exercice (du plus récent au plus ancien).
    q = {"exercise": exercise} if exercise else {}
    docs = await db.bordereaux.find(q).sort("number", -1).to_list(2000)
    return [clean(d) for d in docs]


@api.post("/bordereaux")
async def create_bordereau(data: BordereauInput, user: dict = Depends(get_current_user)):
    # Crée un bordereau à partir des transactions sélectionnées, qui sont marquées « remises ».
    doc = data.model_dump()
    doc["exercise"] = doc.get("exercise") or await get_current_exercise_label()
    doc["date"] = doc.get("date") or datetime.now(timezone.utc).date().isoformat()
    tx_ids = [t for t in (doc.get("transaction_ids") or []) if ObjectId.is_valid(t)]
    if tx_ids:
        lines = []
        for tid in tx_ids:
            t = await db.transactions.find_one({"_id": ObjectId(tid)})
            if not t:
                continue
            tiers = ""
            if t.get("tiers_id") and ObjectId.is_valid(t["tiers_id"]):
                ct = await db.contacts.find_one({"_id": ObjectId(t["tiers_id"])})
                if ct:
                    tiers = f"{ct.get('first_name','')} {ct.get('last_name','')}".strip()
            lines.append({
                "payer": tiers or t.get("description", ""), "bank": "", "number": "",
                "label": t.get("description", ""), "amount": round(t.get("amount", 0), 2),
                "date": t.get("date", ""), "txn_id": tid,
            })
        doc["lines"] = lines
    if not doc.get("lines"):
        raise HTTPException(status_code=400, detail="Sélectionnez au moins une transaction à remettre.")
    doc["total"] = round(sum(float(l.get("amount", 0)) for l in doc.get("lines", [])), 2)
    seq = await db.bordereaux.count_documents({"exercise": doc["exercise"]}) + 1
    doc["number"] = f"BORD-{doc['exercise']}-{seq:04d}"
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    res = await db.bordereaux.insert_one(doc)
    for tid in tx_ids:
        await db.transactions.update_one({"_id": ObjectId(tid)}, {"$set": {"bordereau_id": str(res.inserted_id)}})
    return clean(await db.bordereaux.find_one({"_id": res.inserted_id}))


@api.delete("/bordereaux/{bid}")
async def delete_bordereau(bid: str, user: dict = Depends(get_current_user)):
    # Supprime un bordereau et libère les transactions rattachées (redeviennent « non remises »).
    await db.transactions.update_many({"bordereau_id": bid}, {"$unset": {"bordereau_id": ""}})
    await db.bordereaux.delete_one({"_id": ObjectId(bid)})
    return {"ok": True}


@api.get("/bordereaux/{bid}/pdf")
async def bordereau_pdf(bid: str, user: dict = Depends(get_current_user)):
    # Génère le PDF du bordereau de remise (en-tête compte bancaire + tableau des lignes + total).
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    import io
    b = await db.bordereaux.find_one({"_id": ObjectId(bid)})
    if not b:
        raise HTTPException(status_code=404, detail="Bordereau introuvable")
    acct = await db.bank_accounts.find_one({"_id": ObjectId(b["account_id"])}) if b.get("account_id") else None
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=15 * mm)
    styles = getSampleStyleSheet()
    kind_label = "ESPÈCES" if b["kind"] == "especes" else "CHÈQUES"
    elems = [Paragraph(f"<b>Bordereau de remise {kind_label}</b>", styles["Title"]),
             Paragraph(f"N° {b['number']} — {b['date']}", styles["Normal"])]
    if acct:
        elems.append(Paragraph(f"Compte : {acct.get('name','')} · {acct.get('bank_name','')} · IBAN {acct.get('iban','')}", styles["Normal"]))
    elems.append(Spacer(1, 6 * mm))
    if b["kind"] == "cheque":
        headers = ["Émetteur", "Banque", "N° chèque", "Montant"]
        rows = [[l.get("payer", ""), l.get("bank", ""), l.get("number", ""), f"{float(l.get('amount',0)):.2f}"] for l in b.get("lines", [])]
    else:
        headers = ["Libellé", "Montant"]
        rows = [[l.get("label", ""), f"{float(l.get('amount',0)):.2f}"] for l in b.get("lines", [])]
    rows.append(["" for _ in headers[:-1]] + [f"TOTAL : {b.get('total',0):.2f} €"])
    t = Table([headers] + rows, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2563EB")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -2), 0.4, colors.HexColor("#CBD5E1")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
    ]))
    elems.append(t)
    doc.build(elems)
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/pdf",
                             headers={"Content-Disposition": f"attachment; filename={b['number']}.pdf"})


# ================= COMPTES BANCAIRES, VIREMENTS, CATALOGUE CAISSE =================
class BankAccountInput(BaseModel):
    name: str
    type: str = "bancaire"  # bancaire | caisse | livret
    iban: Optional[str] = ""
    bic: Optional[str] = ""
    bank_name: Optional[str] = ""      # nom de la banque
    holder: Optional[str] = ""          # titulaire du compte
    account_number: Optional[str] = ""  # numéro de compte
    initial_balance: float = 0
    color: Optional[str] = "#2563EB"


class TransferInput(BaseModel):
    from_id: str
    to_id: str
    amount: float
    date: Optional[str] = None
    note: Optional[str] = ""


class CatalogItemInput(BaseModel):
    name: str
    price: float = 0
    category: str = "buvette"
    image_url: Optional[str] = ""
    color: Optional[str] = "#2563EB"


@api.get("/bank-accounts")
async def list_bank_accounts(user: dict = Depends(get_current_user)):
    accts = await db.bank_accounts.find({}).sort("name", 1).to_list(200)
    transfers = await db.transfers.find({}).to_list(5000)
    out = []
    for a in accts:
        aid = str(a["_id"])
        bal = a.get("initial_balance", 0)
        for t in transfers:
            if t.get("to_id") == aid:
                bal += t["amount"]
            if t.get("from_id") == aid:
                bal -= t["amount"]
        c = clean(a)
        c["balance"] = round(bal, 2)
        out.append(c)
    return out


@api.post("/bank-accounts")
async def create_bank_account(data: BankAccountInput, user: dict = Depends(get_current_user)):
    res = await db.bank_accounts.insert_one(data.model_dump())
    return clean(await db.bank_accounts.find_one({"_id": res.inserted_id}))


@api.put("/bank-accounts/{aid}")
async def update_bank_account(aid: str, data: BankAccountInput, user: dict = Depends(get_current_user)):
    await db.bank_accounts.update_one({"_id": ObjectId(aid)}, {"$set": data.model_dump()})
    return clean(await db.bank_accounts.find_one({"_id": ObjectId(aid)}))


@api.delete("/bank-accounts/{aid}")
async def delete_bank_account(aid: str, user: dict = Depends(get_current_user)):
    await db.bank_accounts.delete_one({"_id": ObjectId(aid)})
    return {"ok": True}


@api.get("/transfers")
async def list_transfers(user: dict = Depends(get_current_user)):
    docs = await db.transfers.find({}).sort("date", -1).to_list(2000)
    return [clean(d) for d in docs]


@api.post("/transfers")
async def create_transfer(data: TransferInput, user: dict = Depends(get_current_user)):
    if data.from_id == data.to_id:
        raise HTTPException(status_code=400, detail="Les deux comptes doivent être différents")
    if data.amount <= 0:
        raise HTTPException(status_code=400, detail="Montant invalide")
    doc = data.model_dump()
    doc["date"] = doc.get("date") or datetime.now(timezone.utc).date().isoformat()
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    res = await db.transfers.insert_one(doc)
    return clean(await db.transfers.find_one({"_id": res.inserted_id}))


@api.delete("/transfers/{tid}")
async def delete_transfer(tid: str, user: dict = Depends(get_current_user)):
    await db.transfers.delete_one({"_id": ObjectId(tid)})
    return {"ok": True}


@api.get("/catalog")
async def list_catalog(user: dict = Depends(get_current_user)):
    docs = await db.catalog.find({}).sort("name", 1).to_list(500)
    return [clean(d) for d in docs]


@api.post("/catalog")
async def create_catalog_item(data: CatalogItemInput, user: dict = Depends(get_current_user)):
    res = await db.catalog.insert_one(data.model_dump())
    return clean(await db.catalog.find_one({"_id": res.inserted_id}))


@api.put("/catalog/{cid}")
async def update_catalog_item(cid: str, data: CatalogItemInput, user: dict = Depends(get_current_user)):
    await db.catalog.update_one({"_id": ObjectId(cid)}, {"$set": data.model_dump()})
    return clean(await db.catalog.find_one({"_id": ObjectId(cid)}))


@api.delete("/catalog/{cid}")
async def delete_catalog_item(cid: str, user: dict = Depends(get_current_user)):
    await db.catalog.delete_one({"_id": ObjectId(cid)})
    return {"ok": True}


async def seed_bank():
    if await db.bank_accounts.count_documents({}) > 0:
        return
    accts = [
        {"name": "Compte courant", "type": "bancaire", "iban": "FR76 3000 4000 0100 0001", "initial_balance": 3500, "color": "#2563EB"},
        {"name": "Caisse espèces", "type": "caisse", "iban": "", "initial_balance": 250, "color": "#059669"},
        {"name": "Livret A", "type": "livret", "iban": "", "initial_balance": 8000, "color": "#6366F1"},
    ]
    res = await db.bank_accounts.insert_many(accts)
    ids = [str(x) for x in res.inserted_ids]
    await db.transfers.insert_one({"from_id": ids[0], "to_id": ids[1], "amount": 200,
                                   "date": datetime.now(timezone.utc).date().isoformat(),
                                   "note": "Approvisionnement caisse", "created_at": datetime.now(timezone.utc).isoformat()})


async def seed_catalog():
    if await db.catalog.count_documents({}) > 0:
        return
    i1 = "https://images.unsplash.com/photo-1613462847848-f65a8b231bb5?crop=entropy&cs=srgb&fm=jpg&w=300&q=80"
    i2 = "https://images.unsplash.com/photo-1626229693339-6f086b9da8d2?crop=entropy&cs=srgb&fm=jpg&w=300&q=80"
    i3 = "https://images.unsplash.com/photo-1638595780050-270f8bb48ad5?crop=entropy&cs=srgb&fm=jpg&w=300&q=80"
    i4 = "https://images.unsplash.com/photo-1638595780052-122245f1fa9a?crop=entropy&cs=srgb&fm=jpg&w=300&q=80"
    items = [
        {"name": "Bière", "price": 2.5, "category": "buvette", "image_url": i3, "color": "#D97706"},
        {"name": "Soda", "price": 2, "category": "buvette", "image_url": i2, "color": "#0EA5E9"},
        {"name": "Eau", "price": 1, "category": "buvette", "image_url": "", "color": "#38BDF8"},
        {"name": "Café", "price": 1.5, "category": "buvette", "image_url": "", "color": "#92400E"},
        {"name": "Chips", "price": 1.5, "category": "buvette", "image_url": i1, "color": "#CA8A04"},
        {"name": "Pâtisserie", "price": 2, "category": "buvette", "image_url": i4, "color": "#DB2777"},
        {"name": "Sandwich", "price": 3.5, "category": "buvette", "image_url": "", "color": "#16A34A"},
        {"name": "Entrée adulte", "price": 8, "category": "billetterie", "image_url": "", "color": "#2563EB"},
        {"name": "Entrée enfant", "price": 4, "category": "billetterie", "image_url": "", "color": "#6366F1"},
    ]
    await db.catalog.insert_many(items)


# ================= LISTES DE RÉFÉRENCE (libellés éditables) =================
import re as _re
import unicodedata as _ud


def _slugify(text: str) -> str:
    t = _ud.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    t = _re.sub(r"[^a-zA-Z0-9]+", "_", t).strip("_").lower()
    return t or "option"


# key -> {title, group, locked, usage:[{collection, field}], items:[{value,label}]}
REF_LISTS_SEED = {
    "income_category": {"title": "Catégories de recettes", "group": "Comptabilité",
        "usage": [{"collection": "transactions", "field": "category"}],
        "items": ["Cotisations", "Écolage", "Subventions", "Dons", "Événements", "Ventes", "Autre"]},
    "expense_category": {"title": "Catégories de dépenses", "group": "Comptabilité",
        "usage": [{"collection": "transactions", "field": "category"}],
        "items": ["Loyer", "Matériel", "Événements", "Assurance", "Salaires", "Déplacements", "Autre"]},
    "payment_method": {"title": "Moyens de règlement (comptabilité)", "group": "Comptabilité",
        "usage": [{"collection": "transactions", "field": "method"}],
        "items": ["Virement", "Carte", "Espèces", "Chèque", "Prélèvement"]},
    "contact_type": {"title": "Types de contact", "group": "Adhérents & contacts",
        "usage": [{"collection": "contacts", "field": "type"}],
        "items": [("adherent", "Adhérent"), ("eleve", "Élève"), ("donateur", "Donateur"),
                  ("fournisseur", "Fournisseur"), ("partenaire", "Partenaire"), ("benevole", "Bénévole"),
                  ("tiers", "Tiers"), ("ca", "Conseil d'admin."), ("contact", "Contact")]},
    "course_type": {"title": "Types de cours", "group": "Activités & pédagogie",
        "usage": [{"collection": "courses", "field": "type"}],
        "items": [("individuel", "Individuel"), ("theorique", "Théorique"),
                  ("pratique", "Pratique collective"), ("eveil", "Éveil musical")]},
    "course_day": {"title": "Jours de cours", "group": "Activités & pédagogie",
        "usage": [{"collection": "courses", "field": "day"}],
        "items": ["Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi"]},
    "tariff_category": {"title": "Catégories de tarif", "group": "Cotisations & tarifs",
        "usage": [{"collection": "tariffs", "field": "category"}],
        "items": [("cursus", "Cursus"), ("option", "Option"), ("eveil", "Éveil"), ("theorique", "Théorique"),
                  ("pratique", "Pratique collective"), ("location", "Location"), ("cotisation", "Cotisation")]},
    "tariff_audience": {"title": "Publics de tarif", "group": "Cotisations & tarifs",
        "usage": [{"collection": "tariffs", "field": "audience"}],
        "items": [("tous", "Tous"), ("adulte", "Adulte"), ("enfant_etudiant", "Enfant / Étudiant")]},
    "caisse_category": {"title": "Catégories d'articles (caisse)", "group": "Logistique & matériel",
        "usage": [{"collection": "catalog", "field": "category"}, {"collection": "event_sales", "field": "category"}],
        "items": [("buvette", "Buvette"), ("billetterie", "Billetterie"), ("autre", "Autre")]},
    "stock_category": {"title": "Catégories de stock", "group": "Logistique & matériel",
        "usage": [{"collection": "inventory", "field": "category"}],
        "items": [("buvette", "Buvette"), ("cuisine", "Cuisine"), ("fourniture", "Fournitures"), ("autre", "Autre")]},
    "stock_unit": {"title": "Unités de stock", "group": "Logistique & matériel",
        "usage": [{"collection": "inventory", "field": "unit"}],
        "items": ["unité", "litre", "kg", "carton", "fût", "bouteille", "sachet", "barquette"]},
    "instrument_category": {"title": "Catégories d'instruments", "group": "Logistique & matériel",
        "usage": [{"collection": "instruments", "field": "category"}],
        "items": ["Cordes", "Vents", "Bois", "Cuivres", "Percussions", "Claviers", "Accessoire", "Autre"]},
    "instrument_status": {"title": "Statuts d'instruments (système)", "group": "Logistique & matériel", "locked": True,
        "usage": [{"collection": "instruments", "field": "status"}],
        "items": [("available", "Disponible"), ("loaned", "Prêté"), ("maintenance", "Maintenance")]},
    "caisse_payment_method": {"title": "Moyens de paiement caisse (système)", "group": "Logistique & matériel", "locked": True,
        "usage": [{"collection": "event_sales", "field": "payment_method"}],
        "items": [("especes", "Espèces"), ("cb", "Carte (TPE)"), ("cheque", "Chèque"), ("offert", "Offert")]},
    "discipline": {"title": "Disciplines / Instruments", "group": "Activités & pédagogie",
        "usage": [{"collection": "courses", "field": "discipline"}],
        "items": ["Piano", "Guitare", "Violon", "Violoncelle", "Batterie", "Chant", "Flûte", "Saxophone", "Trompette", "Formation musicale"]},
    "student_relation": {"title": "Lien du responsable", "group": "Adhérents & contacts",
        "usage": [{"collection": "students", "field": "responsable_relation"}],
        "items": ["Parent", "Mère", "Père", "Tuteur", "Grand-parent", "Autre"]},
    "bordereau_kind": {"title": "Types de bordereau (système)", "group": "Comptabilité", "locked": True,
        "usage": [{"collection": "bordereaux", "field": "kind"}],
        "items": [("especes", "Espèces"), ("cheque", "Chèques")]},
}


def _norm_items(raw) -> list:
    out = []
    for it in raw:
        if isinstance(it, tuple):
            out.append({"value": it[0], "label": it[1]})
        else:
            out.append({"value": it, "label": it})
    return out


async def seed_ref_lists():
    for key, cfg in REF_LISTS_SEED.items():
        if await db.ref_lists.find_one({"key": key}):
            continue
        await db.ref_lists.insert_one({
            "key": key, "title": cfg["title"], "group": cfg["group"],
            "locked": cfg.get("locked", False), "usage": cfg["usage"],
            "items": _norm_items(cfg["items"]),
        })


class RefItemInput(BaseModel):
    label: str


@api.get("/ref-lists")
async def list_ref_lists(user: dict = Depends(get_current_user)):
    docs = await db.ref_lists.find({}).to_list(200)
    return [clean(d) for d in docs]


async def _get_ref(key: str) -> dict:
    doc = await db.ref_lists.find_one({"key": key})
    if not doc:
        raise HTTPException(status_code=404, detail="Liste introuvable")
    return doc


@api.post("/ref-lists/{key}/items")
async def add_ref_item(key: str, data: RefItemInput, user: dict = Depends(get_current_user)):
    doc = await _get_ref(key)
    if doc.get("locked"):
        raise HTTPException(status_code=400, detail="Cette liste système n'accepte pas de nouvelles options.")
    label = data.label.strip()
    if not label:
        raise HTTPException(status_code=400, detail="Libellé requis")
    existing = {i["value"] for i in doc["items"]}
    value = _slugify(label)
    while value in existing:
        value = f"{value}_{_slugify(str(datetime.now().microsecond))[:3]}"
    doc["items"].append({"value": value, "label": label})
    await db.ref_lists.update_one({"key": key}, {"$set": {"items": doc["items"]}})
    return clean(await _get_ref(key))


@api.put("/ref-lists/{key}/items/{value}")
async def rename_ref_item(key: str, value: str, data: RefItemInput, user: dict = Depends(get_current_user)):
    doc = await _get_ref(key)
    label = data.label.strip()
    if not label:
        raise HTTPException(status_code=400, detail="Libellé requis")
    found = False
    for it in doc["items"]:
        if it["value"] == value:
            it["label"] = label
            found = True
    if not found:
        raise HTTPException(status_code=404, detail="Option introuvable")
    await db.ref_lists.update_one({"key": key}, {"$set": {"items": doc["items"]}})
    return clean(await _get_ref(key))


@api.delete("/ref-lists/{key}/items/{value}")
async def delete_ref_item(key: str, value: str, user: dict = Depends(get_current_user)):
    doc = await _get_ref(key)
    if doc.get("locked"):
        raise HTTPException(status_code=400, detail="Cette liste système ne peut pas être modifiée.")
    # Blocage si l'option est encore utilisée
    used = 0
    for u in doc.get("usage", []):
        used += await db[u["collection"]].count_documents({u["field"]: value})
    if used > 0:
        raise HTTPException(status_code=400, detail=f"Impossible de supprimer : cette option est utilisée par {used} enregistrement(s).")
    doc["items"] = [i for i in doc["items"] if i["value"] != value]
    await db.ref_lists.update_one({"key": key}, {"$set": {"items": doc["items"]}})
    return clean(await _get_ref(key))




# ================= PARAMÈTRES ASSOCIATION =================
class AssociationInput(BaseModel):
    name: str = ""
    address: str = ""
    postal_code: str = ""
    city: str = ""
    rna: str = ""
    siret: str = ""
    object: str = ""
    signatory_name: str = ""
    signatory_role: str = "Président(e)"
    general_interest: bool = True


@api.get("/association")
async def get_association(user: dict = Depends(get_current_user)):
    doc = await db.settings.find_one({"key": "association"})
    return (doc or {}).get("data", AssociationInput().model_dump())


@api.put("/association")
async def set_association(data: AssociationInput, user: dict = Depends(get_current_user)):
    await db.settings.update_one({"key": "association"}, {"$set": {"data": data.model_dump()}}, upsert=True)
    return data.model_dump()


# ================= REÇUS FISCAUX (Cerfa 11580) =================
class ReceiptInput(BaseModel):
    contact_id: Optional[str] = None
    donor_name: str = ""
    donor_address: str = ""
    kind: str = "don"  # don | cotisation
    amount: float = 0
    date: Optional[str] = None
    payment_method: str = "Chèque"
    exercise: Optional[str] = None


def _amount_to_words_eur(n: float) -> str:
    units = ["zéro", "un", "deux", "trois", "quatre", "cinq", "six", "sept", "huit", "neuf", "dix",
             "onze", "douze", "treize", "quatorze", "quinze", "seize", "dix-sept", "dix-huit", "dix-neuf"]
    tens = {20: "vingt", 30: "trente", 40: "quarante", 50: "cinquante", 60: "soixante", 70: "soixante-dix", 80: "quatre-vingt", 90: "quatre-vingt-dix"}

    def below_hundred(x):
        if x < 20:
            return units[x]
        t = (x // 10) * 10
        r = x % 10
        if t in (70, 90):
            base = tens[t - 10]
            return f"{base}-{units[10 + r]}" if r or t == 70 else base
        word = tens[t]
        if r == 1 and t != 80:
            return f"{word}-et-un"
        if r:
            return f"{word}-{units[r]}"
        return word + ("s" if t == 80 else "")

    def below_thousand(x):
        if x < 100:
            return below_hundred(x)
        h = x // 100
        r = x % 100
        head = ("cent" if h == 1 else f"{units[h]}-cent")
        return head if r == 0 else f"{head}-{below_hundred(r)}"

    euros = int(n)
    cents = int(round((n - euros) * 100))
    if euros < 1000:
        w = below_thousand(euros)
    else:
        th = euros // 1000
        r = euros % 1000
        head = "mille" if th == 1 else f"{below_thousand(th)}-mille"
        w = head if r == 0 else f"{head}-{below_thousand(r)}"
    out = f"{w} euros"
    if cents:
        out += f" et {below_hundred(cents)} centimes"
    return out.capitalize()


@api.get("/receipts")
async def list_receipts(exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    q = {"exercise": exercise} if exercise else {}
    docs = await db.receipts.find(q).sort("number", -1).to_list(5000)
    return [clean(d) for d in docs]


@api.post("/receipts")
async def create_receipt(data: ReceiptInput, user: dict = Depends(get_current_user)):
    doc = data.model_dump()
    doc["exercise"] = doc.get("exercise") or await get_current_exercise_label()
    doc["date"] = doc.get("date") or datetime.now(timezone.utc).date().isoformat()
    if doc.get("contact_id"):
        c = await db.contacts.find_one({"_id": ObjectId(doc["contact_id"])})
        if c:
            doc["donor_name"] = doc["donor_name"] or f"{c.get('first_name','')} {c.get('last_name','')}".strip()
            doc["donor_address"] = doc["donor_address"] or " ".join(filter(None, [c.get("address", "")]))
    seq = await db.receipts.count_documents({"exercise": doc["exercise"]}) + 1
    doc["number"] = f"{doc['exercise']}-{seq:04d}"
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    res = await db.receipts.insert_one(doc)
    return clean(await db.receipts.find_one({"_id": res.inserted_id}))


@api.delete("/receipts/{rid}")
async def delete_receipt(rid: str, user: dict = Depends(get_current_user)):
    await db.receipts.delete_one({"_id": ObjectId(rid)})
    return {"ok": True}


@api.get("/receipts/{rid}/pdf")
async def receipt_pdf(rid: str, user: dict = Depends(get_current_user)):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas
    import io
    r = await db.receipts.find_one({"_id": ObjectId(rid)})
    if not r:
        raise HTTPException(status_code=404, detail="Reçu introuvable")
    asso = (await db.settings.find_one({"key": "association"}) or {}).get("data", {})
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    W, H = A4
    y = H - 25 * mm

    def line(txt, size=10, dy=6 * mm, bold=False, x=25 * mm):
        nonlocal y
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.drawString(x, y, txt)
        y -= dy

    line("REÇU AU TITRE DES DONS À CERTAINS ORGANISMES D'INTÉRÊT GÉNÉRAL", 12, 8 * mm, True)
    line("Article 200, 238 bis et 885-0 V bis A du Code général des impôts (Cerfa n°11580*04)", 8, 10 * mm)
    line(f"Reçu n° {r.get('number','')}", 11, 8 * mm, True)
    line("Bénéficiaire du don :", 10, 6 * mm, True)
    line(asso.get("name", "—"))
    if asso.get("object"):
        line(f"Objet : {asso.get('object')}", 9)
    line(" ".join(filter(None, [asso.get("address", ""), asso.get("postal_code", ""), asso.get("city", "")])) or "—")
    if asso.get("rna") or asso.get("siret"):
        line(f"RNA : {asso.get('rna','—')}    SIRET : {asso.get('siret','—')}", 9)
    y -= 4 * mm
    line("Donateur :", 10, 6 * mm, True)
    line(r.get("donor_name", "—"))
    if r.get("donor_address"):
        line(r.get("donor_address"), 9)
    y -= 4 * mm
    kind_label = "cotisation" if r.get("kind") == "cotisation" else "don"
    line(f"L'organisme reconnaît avoir reçu au titre de {kind_label} la somme de :", 10, 6 * mm, True)
    line(f"{r.get('amount',0):.2f} €  ({_amount_to_words_eur(float(r.get('amount',0)))})", 12, 8 * mm, True)
    line(f"Date du versement : {r.get('date','')}", 10)
    line(f"Mode de versement : {r.get('payment_method','')}", 10)
    line("Forme du don : Déclaration de don manuel", 10)
    y -= 6 * mm
    line(f"Fait à {asso.get('city','')}, le {datetime.now(timezone.utc).date().isoformat()}", 10, 10 * mm)
    line(f"{asso.get('signatory_role','Président(e)')} : {asso.get('signatory_name','')}", 10, 6 * mm)
    line("Signature", 9)
    c.showPage()
    c.save()
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/pdf",
                             headers={"Content-Disposition": f"attachment; filename=recu_{r.get('number','')}.pdf"})


# ================= PRÉVISIONNELS & COMPTE DE RÉSULTAT (3 colonnes) =================
class BudgetInput(BaseModel):
    lines: List[dict] = []            # [{account_code, voted, revised}]
    voted_locked: Optional[bool] = None


@api.get("/budget")
async def get_budget(exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    ex = exercise or await get_current_exercise_label()
    doc = await db.budgets.find_one({"exercise": ex})
    return {"exercise": ex, "voted_locked": (doc or {}).get("voted_locked", False),
            "lines": (doc or {}).get("account_lines", [])}


@api.put("/budget")
async def set_budget(data: BudgetInput, exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    ex = exercise or await get_current_exercise_label()
    existing = await db.budgets.find_one({"exercise": ex}) or {}
    locked = existing.get("voted_locked", False)
    if data.voted_locked is not None:
        locked = data.voted_locked
    new_lines = {}
    for l in data.lines:
        code = l.get("account_code")
        if not code:
            continue
        new_lines[code] = {"account_code": code,
                           "voted": round(float(l.get("voted", 0) or 0), 2),
                           "revised": round(float(l.get("revised", 0) or 0), 2)}
    # Si le prévisionnel a déjà été voté en AG (verrouillé), on fige la colonne « voté ».
    if existing.get("voted_locked") and data.voted_locked is not False:
        old = {l["account_code"]: l for l in existing.get("account_lines", [])}
        for code, ln in new_lines.items():
            if code in old:
                ln["voted"] = old[code].get("voted", ln["voted"])
    await db.budgets.update_one({"exercise": ex},
                                {"$set": {"account_lines": list(new_lines.values()), "voted_locked": locked, "exercise": ex}},
                                upsert=True)
    return {"exercise": ex, "voted_locked": locked, "lines": list(new_lines.values())}


@api.get("/finances/compte-resultat")
async def compte_resultat(exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    # Compte de résultat 3 colonnes (Prévu voté AG / Réel / Prévu révisé), regroupé par groupe de comptes.
    ex = exercise or await get_current_exercise_label()
    plan = await db.plan_accounts.find({}).sort("code", 1).to_list(1000)
    by_code = {a["code"]: a for a in plan}
    # Réel : agrégation par compte, en tenant compte de la ventilation.
    txs = await db.transactions.find({"exercise": ex}).to_list(10000)
    real: dict = {}
    for t in txs:
        vlines = t.get("ventilation") or [{"account_code": t.get("account_code"), "amount": t.get("amount", 0)}]
        for l in vlines:
            code = l.get("account_code") or "—"
            real[code] = round(real.get(code, 0) + float(l.get("amount", 0) or 0), 2)
    # Budget voté / révisé par compte.
    budget_doc = await db.budgets.find_one({"exercise": ex}) or {}
    bud = {l["account_code"]: l for l in budget_doc.get("account_lines", [])}
    voted_locked = budget_doc.get("voted_locked", False)
    # Comptes à afficher : tous ceux avec une valeur (réel, voté ou révisé).
    codes = set(real.keys()) | set(bud.keys())
    codes = {c for c in codes if c in by_code}
    groups: dict = {}
    for code in codes:
        acc = by_code[code]
        g = acc.get("group", "Autres")
        groups.setdefault(g, {"group": g, "sens": acc.get("sens", "expense"), "rows": []})
        v = bud.get(code, {})
        groups[g]["rows"].append({
            "code": code, "label": acc.get("label", ""),
            "voted": round(float(v.get("voted", 0) or 0), 2),
            "real": round(real.get(code, 0), 2),
            "revised": round(float(v.get("revised", 0) or 0), 2),
        })
    out_groups = []
    for g in sorted(groups.keys()):
        grp = groups[g]
        grp["rows"].sort(key=lambda r: r["code"])
        grp["subtotal"] = {
            "voted": round(sum(r["voted"] for r in grp["rows"]), 2),
            "real": round(sum(r["real"] for r in grp["rows"]), 2),
            "revised": round(sum(r["revised"] for r in grp["rows"]), 2),
        }
        out_groups.append(grp)
    sum_sens = lambda sens, f: round(sum(r[f] for grp in out_groups if grp["sens"] == sens for r in grp["rows"]), 2)
    produits = {f: sum_sens("income", f) for f in ("voted", "real", "revised")}
    charges = {f: sum_sens("expense", f) for f in ("voted", "real", "revised")}
    resultat = {f: round(produits[f] - charges[f], 2) for f in ("voted", "real", "revised")}
    return {"exercise": ex, "voted_locked": voted_locked, "groups": out_groups,
            "totals": {"produits": produits, "charges": charges, "resultat": resultat}}


# ================= EXPORTS CSV / PDF =================
def _csv_response(rows: list, headers: list, filename: str):
    import io, csv
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(headers)
    for r in rows:
        w.writerow(r)
    out = io.BytesIO(buf.getvalue().encode("utf-8-sig"))
    return StreamingResponse(out, media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename={filename}"})


def _pdf_table(title: str, headers: list, rows: list, filename: str, col_widths=None):
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    import io
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=15 * mm)
    styles = getSampleStyleSheet()
    data = [headers] + rows
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2563EB")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F1F5F9")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elems = [Paragraph(f"<b>{title}</b>", styles["Title"]), Spacer(1, 6 * mm), t]
    doc.build(elems)
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/pdf",
                             headers={"Content-Disposition": f"attachment; filename={filename}"})


@api.get("/exports/journal")
async def export_journal(exercise: Optional[str] = None, fmt: str = "csv", user: dict = Depends(get_current_user)):
    ex = exercise or await get_current_exercise_label()
    txs = await db.transactions.find({"exercise": ex}).sort("date", 1).to_list(10000)
    poles = {str(p["_id"]): p["name"] for p in await db.poles.find({}).to_list(200)}
    headers = ["Date", "Type", "Catégorie", "Description", "Moyen", "Pôle", "Compte", "Montant"]
    rows = []
    for t in txs:
        rows.append([
            t.get("date", ""), "Recette" if t["type"] == "income" else "Dépense",
            t.get("category", ""), t.get("description", ""), t.get("method", ""),
            poles.get(t.get("pole_id"), ""), t.get("account_code", ""), f"{t.get('amount',0):.2f}",
        ])
    name = f"journal_{ex}"
    if fmt == "pdf":
        return _pdf_table(f"Journal comptable — {ex}", headers, rows, f"{name}.pdf")
    return _csv_response(rows, headers, f"{name}.csv")


@api.get("/exports/students")
async def export_students(exercise: Optional[str] = None, fmt: str = "csv", user: dict = Depends(get_current_user)):
    ex = exercise or await get_current_exercise_label()
    studs = await db.students.find({"exercise": ex}).sort("last_name", 1).to_list(5000)
    headers = ["Nom", "Prénom", "Naissance", "Email", "Téléphone", "Responsable", "Cotisation"]
    rows = []
    for s in studs:
        rows.append([
            s.get("last_name", ""), s.get("first_name", ""), s.get("birth_date", "") or "",
            s.get("email", ""), s.get("phone", ""), s.get("responsable_name", ""), s.get("cotisation_status", ""),
        ])
    name = f"eleves_{ex}"
    if fmt == "pdf":
        return _pdf_table(f"Liste des élèves — {ex}", headers, rows, f"{name}.pdf")
    return _csv_response(rows, headers, f"{name}.csv")


async def migrate_contacts_types():
    cursor = db.contacts.find({"types": {"$exists": False}})
    async for c in cursor:
        t = c.get("type") or "contact"
        await db.contacts.update_one({"_id": c["_id"]}, {"$set": {"types": [t]}})



# ================= PLAN COMPTABLE PARAMÉTRABLE =================
class AccountPlanInput(BaseModel):
    code: str                 # ex. "6011"
    label: str                # ex. "Instruments"
    group: str                # ex. "60. Achats"
    sens: str = "expense"     # expense | income


# Plan comptable pré-chargé (modifiable ensuite via l'interface)
PLAN_COMPTABLE_SEED = [
    # --- DÉPENSES ---
    ("6011", "Instruments", "60. Achats", "expense"), ("6012", "Partitions", "60. Achats", "expense"),
    ("6051", "Équipement informatique et bureautique", "60. Achats", "expense"), ("6064", "Fournitures administratives", "60. Achats", "expense"),
    ("6068", "Autres matériels et fournitures", "60. Achats", "expense"), ("6071", "Boissons pour buvettes", "60. Achats", "expense"),
    ("6072", "Alimentation pour buvettes et repas", "60. Achats", "expense"), ("6073", "Ustensiles pour buvettes", "60. Achats", "expense"),
    ("6074", "Décoration pour manifestations", "60. Achats", "expense"),
    ("6111", "Rémunération d'une prestation", "61. Services Extérieurs", "expense"), ("6132", "Locations immobilières", "61. Services Extérieurs", "expense"),
    ("6135", "Location de matériels", "61. Services Extérieurs", "expense"), ("6136", "Location de logiciels", "61. Services Extérieurs", "expense"),
    ("6155", "Entretien, réparation d'instrument", "61. Services Extérieurs", "expense"), ("6161", "Assurance Responsabilité Civile", "61. Services Extérieurs", "expense"),
    ("6186", "Achats de cadeaux", "61. Services Extérieurs", "expense"),
    ("6237", "Tracts et affiches", "62. Autres Services Extérieurs", "expense"), ("6251", "Voyages et déplacements", "62. Autres Services Extérieurs", "expense"),
    ("6257", "Réception de personnes extérieures", "62. Autres Services Extérieurs", "expense"), ("6265", "Téléphonie et internet", "62. Autres Services Extérieurs", "expense"),
    ("6275", "Frais sur effets (chéquier, CB…)", "62. Autres Services Extérieurs", "expense"),
    ("6333", "Participation à la formation professionnelle", "63. Impôts, Taxes et Versements Assimilés", "expense"),
    ("6411", "Salaires nets", "64. Charges de Personnel", "expense"), ("6451", "URSSAF", "64. Charges de Personnel", "expense"),
    ("6516", "Droits d'auteurs et de reproduction (SACEM)", "65. Autres Charges de Gestion Courante", "expense"),
    ("6586", "Cotisations liées à la vie statutaire", "65. Autres Charges de Gestion Courante", "expense"),
    ("6615", "Intérêts compte courants de dépôt", "66. Charges Financières", "expense"),
    # --- RECETTES ---
    ("7011", "Ventes de prestations musicales", "70. Ventes de Produits Finis et Marchandises", "income"),
    ("7061", "Frais d'écolage", "70. Ventes de Produits Finis et Marchandises", "income"), ("7062", "Stages", "70. Ventes de Produits Finis et Marchandises", "income"),
    ("7063", "Entrées concerts", "70. Ventes de Produits Finis et Marchandises", "income"), ("7071", "Produits des buvettes", "70. Ventes de Produits Finis et Marchandises", "income"),
    ("7081", "Recettes non liées à l'activité (loto…)", "70. Ventes de Produits Finis et Marchandises", "income"),
    ("7083", "Location d'instruments", "70. Ventes de Produits Finis et Marchandises", "income"),
    ("7421", "Grand Est - FDVA", "74. Subvention d'Exploitation", "income"), ("7431", "Haute-Marne - SDDEA", "74. Subvention d'Exploitation", "income"),
    ("7441", "Fayl-Billot", "74. Subvention d'Exploitation", "income"), ("7442", "Haute-Amance", "74. Subvention d'Exploitation", "income"),
    ("7452", "Guyonvelle", "74. Subvention d'Exploitation", "income"), ("7453", "Champsevraine", "74. Subvention d'Exploitation", "income"),
    ("7461", "Communauté de Communes des Savoir-faire", "74. Subvention d'Exploitation", "income"),
    ("7516", "Droits d'auteurs et de reproduction", "75. Autres Produits de Gestion Courante", "income"),
    ("7541", "Dons concerts ou manifestations", "75. Autres Produits de Gestion Courante", "income"), ("7542", "Mécénat", "75. Autres Produits de Gestion Courante", "income"),
    ("7543", "Dons privés", "75. Autres Produits de Gestion Courante", "income"), ("7561", "Cotisation des adhérents", "75. Autres Produits de Gestion Courante", "income"),
    ("7587", "Indemnités d'assurance", "75. Autres Produits de Gestion Courante", "income"),
    ("7621", "Revenus des titres immobilisés", "76. Produits Financiers", "income"),
    ("7721", "Remboursement de charges de personnel", "77. Produits Exceptionnels", "income"),
    ("7911", "Remboursement frais de formations", "79. Transferts de charges", "income"),
]


async def seed_plan_comptable():
    # Pré-charge le plan comptable au premier démarrage (idempotent par code).
    for code, label, group, sens in PLAN_COMPTABLE_SEED:
        if not await db.plan_accounts.find_one({"code": code}):
            await db.plan_accounts.insert_one({"code": code, "label": label, "group": group, "sens": sens})


@api.get("/plan-accounts")
async def list_plan_accounts(user: dict = Depends(get_current_user)):
    # Renvoie tous les comptes du plan, triés par code.
    docs = await db.plan_accounts.find({}).sort("code", 1).to_list(1000)
    return [clean(d) for d in docs]


@api.post("/plan-accounts")
async def create_plan_account(data: AccountPlanInput, user: dict = Depends(get_current_user)):
    # Crée un compte (code unique).
    if await db.plan_accounts.find_one({"code": data.code}):
        raise HTTPException(status_code=400, detail="Ce code de compte existe déjà.")
    res = await db.plan_accounts.insert_one(data.model_dump())
    return clean(await db.plan_accounts.find_one({"_id": res.inserted_id}))


@api.put("/plan-accounts/{aid}")
async def update_plan_account(aid: str, data: AccountPlanInput, user: dict = Depends(get_current_user)):
    # Modifie un compte (libellé, groupe, sens, code).
    await db.plan_accounts.update_one({"_id": ObjectId(aid)}, {"$set": data.model_dump()})
    return clean(await db.plan_accounts.find_one({"_id": ObjectId(aid)}))


@api.delete("/plan-accounts/{aid}")
async def delete_plan_account(aid: str, user: dict = Depends(get_current_user)):
    # Supprime un compte s'il n'est pas utilisé par une transaction.
    acc = await db.plan_accounts.find_one({"_id": ObjectId(aid)})
    if acc and await db.transactions.count_documents({"account_code": acc["code"]}) > 0:
        raise HTTPException(status_code=400, detail="Compte utilisé par des transactions : suppression impossible.")
    await db.plan_accounts.delete_one({"_id": ObjectId(aid)})
    return {"ok": True}


# ================= PAIE PARAMÉTRABLE, HEURES PROFS, EXPORTS PDF COMPTA =================
PAYROLL_DEFAULT = {
    "grilles": [
        {"key": "prof", "label": "Professeurs", "etp_hours": 24},
        {"key": "anim", "label": "Animateurs", "etp_hours": 26},
        {"key": "generale", "label": "Générale", "etp_hours": 35},
    ],
    "eclat": {"v1": 7.23, "v2": 6.81, "monthly_hours": 151.67},
    "travel": {"rate_per_km": 0.21, "trips_per_week": 2, "weeks_per_year": 36, "base_address": ""},
    "elements": [
        {"label": "Frais de déplacement", "amount": 0},
        {"label": "Prime d'ancienneté", "amount": 0},
    ],
}


@api.get("/geo/distance")
async def geo_distance(address: str, user: dict = Depends(get_current_user)):
    # Estime la distance (km, à vol d'oiseau) entre l'adresse du salarié et l'adresse de référence (barème paramétrable).
    import httpx
    from math import radians, sin, cos, asin, sqrt
    settings_doc = await db.settings.find_one({"key": "payroll"})
    base_addr = ((settings_doc or {}).get("data", {}).get("travel", {}) or {}).get("base_address", "")
    if not base_addr or not address:
        return {"km": None, "detail": "Adresse de référence (Paramètres de paie) ou adresse salarié manquante."}

    async def _geo(q):
        try:
            async with httpx.AsyncClient(timeout=8) as c:
                r = await c.get("https://api-adresse.data.gouv.fr/search/", params={"q": q, "limit": 1})
                feats = (r.json() or {}).get("features") or []
                if feats:
                    lon, lat = feats[0]["geometry"]["coordinates"]
                    return (lat, lon)
        except Exception:
            return None
        return None
    a = await _geo(address)
    b = await _geo(base_addr)
    if not a or not b:
        return {"km": None, "detail": "Géocodage impossible."}
    dlat = radians(b[0] - a[0]); dlon = radians(b[1] - a[1])
    h = sin(dlat / 2) ** 2 + cos(radians(a[0])) * cos(radians(b[0])) * sin(dlon / 2) ** 2
    return {"km": round(2 * 6371 * asin(sqrt(h)), 1)}


class PayrollSettingsInput(BaseModel):
    grilles: List[dict] = []
    eclat: dict = {}
    travel: dict = {}
    elements: List[dict] = []


@api.get("/payroll-settings")
async def get_payroll_settings(user: dict = Depends(get_current_user)):
    doc = await db.settings.find_one({"key": "payroll"})
    if not doc:
        await db.settings.update_one({"key": "payroll"}, {"$set": {"data": PAYROLL_DEFAULT}}, upsert=True)
        return PAYROLL_DEFAULT
    return doc.get("data", PAYROLL_DEFAULT)


@api.put("/payroll-settings")
async def set_payroll_settings(data: PayrollSettingsInput, user: dict = Depends(get_current_user)):
    await db.settings.update_one({"key": "payroll"}, {"$set": {"data": data.model_dump()}}, upsert=True)
    return data.model_dump()


@api.get("/teachers/hours")
async def teachers_hours(exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    # Résumé des heures de cours hebdomadaires par professeur et par discipline (cours collectifs + cours individuels attribués).
    ex = exercise or await get_current_exercise_label()
    teachers = await db.teachers.find({}).to_list(1000)
    tmap = {str(t["_id"]): t for t in teachers}
    employees = {str(e["_id"]): e for e in await db.employees.find({}).to_list(1000)}
    courses = await db.courses.find({}).to_list(2000)
    inscriptions = await db.inscriptions.find({"exercise": ex}).to_list(5000)
    settings_doc = await db.settings.find_one({"key": "payroll"})
    settings = (settings_doc or {}).get("data", PAYROLL_DEFAULT)
    agg: dict = {}

    def ensure(tid):
        t = tmap.get(tid)
        if not t:
            return None
        if tid not in agg:
            emp = employees.get(t.get("employee_id") or "")
            agg[tid] = {
                "teacher_id": tid, "name": f"{t.get('first_name','')} {t.get('last_name','')}".strip(),
                "grille": (emp or {}).get("grille") or t.get("grille"),
                "coefficient": (emp or {}).get("coefficient"),
                "by_discipline": {}, "total_hours": 0.0,
            }
        return agg[tid]

    def add(tid, disc, hours):
        a = ensure(tid)
        if not a:
            return
        d = disc or "Autre"
        a["by_discipline"][d] = round(a["by_discipline"].get(d, 0) + hours, 2)
        a["total_hours"] = round(a["total_hours"] + hours, 2)

    for c in courses:
        if c.get("type") == "individuel" or not c.get("teacher_id"):
            continue
        add(c["teacher_id"], c.get("discipline") or c.get("name"), (c.get("duration_min", 60) or 60) / 60)
    for ins in inscriptions:
        for l in ins.get("lines", []):
            if l.get("course_type") == "individuel" and l.get("teacher_id"):
                add(l["teacher_id"], l.get("discipline") or "Individuel", (l.get("duration_min", 30) or 30) / 60)

    grilles = {g["key"]: g for g in settings.get("grilles", [])}
    # Index tolérant : on résout la grille par clé OU par libellé (insensible à la casse).
    gidx = {}
    for g in settings.get("grilles", []):
        gidx[str(g.get("key", "")).strip().lower()] = g
        gidx[str(g.get("label", "")).strip().lower()] = g
    v1 = settings.get("eclat", {}).get("v1", 7.23)
    v2 = settings.get("eclat", {}).get("v2", 6.81)
    out = []
    for a in agg.values():
        coef, grille = a.get("coefficient"), a.get("grille")
        a["eclat_base_est"] = None
        a["quotite"] = None
        gobj = gidx.get(str(grille or "").strip().lower())
        if coef and gobj and gobj.get("etp_hours"):
            etp = gobj["etp_hours"]
            base = (257 * v1) + ((coef - 257) * v2)
            quot = a["total_hours"] / etp
            a["quotite"] = round(quot, 3)
            a["eclat_base_est"] = round(base * quot, 2)
        out.append(a)
    out.sort(key=lambda x: -x["total_hours"])
    return {"exercise": ex, "grilles": settings.get("grilles", []), "teachers": out}


def _pdf_compte_resultat(data: dict, title: str, only_real: bool):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    import io
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=15 * mm)
    styles = getSampleStyleSheet()
    headers = ["Compte"] + (["Réel"] if only_real else ["Voté AG", "Réel", "Révisé"])
    ncol = len(headers)

    def money(v):
        return f"{v:,.2f} €".replace(",", " ").replace(".", ",")

    def row_for(r):
        if only_real:
            return [f"{r['code']} — {r['label']}", money(r["real"])]
        return [f"{r['code']} — {r['label']}", money(r["voted"]), money(r["real"]), money(r["revised"])]

    def sub_for(g):
        s = g["subtotal"]
        if only_real:
            return [f"Sous-total {g['group'].split('.')[0]}", money(s["real"])]
        return [f"Sous-total {g['group'].split('.')[0]}", money(s["voted"]), money(s["real"]), money(s["revised"])]

    rows = []
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2563EB")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")),
        ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
    ]
    rows.append(headers)
    ridx = 1
    for sens, lbl in (("income", "PRODUITS (RECETTES)"), ("expense", "CHARGES (DÉPENSES)")):
        groups = [g for g in data["groups"] if g["sens"] == sens]
        if not groups:
            continue
        rows.append([lbl] + ["" for _ in range(ncol - 1)])
        style_cmds.append(("BACKGROUND", (0, ridx), (-1, ridx), colors.HexColor("#E2E8F0")))
        style_cmds.append(("FONTNAME", (0, ridx), (-1, ridx), "Helvetica-Bold"))
        ridx += 1
        for g in groups:
            rows.append([g["group"]] + ["" for _ in range(ncol - 1)])
            style_cmds.append(("FONTNAME", (0, ridx), (0, ridx), "Helvetica-Bold"))
            ridx += 1
            for r in g["rows"]:
                rows.append(row_for(r)); ridx += 1
            rows.append(sub_for(g))
            style_cmds.append(("FONTNAME", (0, ridx), (-1, ridx), "Helvetica-Bold"))
            style_cmds.append(("BACKGROUND", (0, ridx), (-1, ridx), colors.HexColor("#F1F5F9")))
            ridx += 1
    tot = data["totals"]
    if only_real:
        totrows = [["TOTAL PRODUITS", money(tot["produits"]["real"])],
                   ["TOTAL CHARGES", money(tot["charges"]["real"])],
                   ["RÉSULTAT", money(tot["resultat"]["real"])]]
    else:
        totrows = [["TOTAL PRODUITS", money(tot["produits"]["voted"]), money(tot["produits"]["real"]), money(tot["produits"]["revised"])],
                   ["TOTAL CHARGES", money(tot["charges"]["voted"]), money(tot["charges"]["real"]), money(tot["charges"]["revised"])],
                   ["RÉSULTAT", money(tot["resultat"]["voted"]), money(tot["resultat"]["real"]), money(tot["resultat"]["revised"])]]
    for tr in totrows:
        rows.append(tr)
        style_cmds.append(("FONTNAME", (0, ridx), (-1, ridx), "Helvetica-Bold"))
        style_cmds.append(("BACKGROUND", (0, ridx), (-1, ridx), colors.HexColor("#DBEAFE")))
        ridx += 1
    colw = [75 * mm] + [(105 * mm) / (ncol - 1)] * (ncol - 1)
    t = Table(rows, colWidths=colw, repeatRows=1)
    t.setStyle(TableStyle(style_cmds))
    elems = [Paragraph(f"<b>{title}</b>", styles["Title"]),
             Paragraph(f"Exercice {data['exercise']}", styles["Normal"]), Spacer(1, 6 * mm), t]
    doc.build(elems)
    buf.seek(0)
    return buf


@api.get("/exports/previsionnel")
async def export_previsionnel(exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    ex = exercise or await get_current_exercise_label()
    data = await compte_resultat(exercise=ex, user=user)
    buf = _pdf_compte_resultat(data, "Compte de résultat prévisionnel (3 colonnes)", only_real=False)
    return StreamingResponse(buf, media_type="application/pdf",
                             headers={"Content-Disposition": f"attachment; filename=previsionnel_{ex}.pdf"})


@api.get("/exports/compte-resultat")
async def export_compte_resultat(exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    ex = exercise or await get_current_exercise_label()
    data = await compte_resultat(exercise=ex, user=user)
    buf = _pdf_compte_resultat(data, "Compte de résultat réel", only_real=True)
    return StreamingResponse(buf, media_type="application/pdf",
                             headers={"Content-Disposition": f"attachment; filename=compte_resultat_{ex}.pdf"})


# SIREN de la Communauté de communes des Savoir-Faire (référence officielle BANATIC).
CC_SAVOIR_FAIRE_SIREN = "200070332"


@api.get("/communes")
async def communes_by_postal(code_postal: str, user: dict = Depends(get_current_user)):
    # Retourne les communes d'un code postal (API officielle geo.api.gouv.fr) avec drapeau d'appartenance à la CC des Savoir-Faire.
    import re
    import httpx
    if not re.fullmatch(r"\d{5}", code_postal or ""):
        return []
    url = f"https://geo.api.gouv.fr/communes?codePostal={code_postal}&fields=nom,code,codeEpci&format=json"
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(url)
            data = r.json() if r.status_code == 200 else []
    except Exception:
        data = []
    out = [{"nom": c.get("nom"), "code": c.get("code"), "cc": c.get("codeEpci") == CC_SAVOIR_FAIRE_SIREN} for c in data]
    out.sort(key=lambda x: x["nom"] or "")
    return out


def _seniority_points(hire_date: Optional[str]) -> int:
    # Ancienneté ÉCLAT : +2 points par année complète depuis la date d'entrée.
    if not hire_date:
        return 0
    try:
        from datetime import date
        y, m, d = [int(x) for x in hire_date[:10].split("-")]
        hd = date(y, m, d)
        t = datetime.now(timezone.utc).date()
        years = t.year - hd.year - (1 if (t.month, t.day) < (hd.month, hd.day) else 0)
        return max(0, years) * 2
    except Exception:
        return 0


@api.get("/employees/payroll")
async def employees_payroll(user: dict = Depends(get_current_user)):
    # Calcul paramétrable du salaire ÉCLAT par salarié : plusieurs lignes d'emploi (grilles cumulables) + ancienneté + éléments propres.
    settings_doc = await db.settings.find_one({"key": "payroll"})
    settings = (settings_doc or {}).get("data", PAYROLL_DEFAULT)
    gidx = {}
    for g in settings.get("grilles", []):
        gidx[str(g.get("key", "")).strip().lower()] = g
        gidx[str(g.get("label", "")).strip().lower()] = g
    v1 = settings.get("eclat", {}).get("v1", 7.23)
    v2 = settings.get("eclat", {}).get("v2", 6.81)
    emps = await db.employees.find({}).sort("last_name", 1).to_list(1000)
    out = []
    for e in emps:
        pts = _seniority_points(e.get("hire_date"))
        el = e.get("employment_lines") or []
        if not el and e.get("grille") and e.get("coefficient"):
            el = [{"grille": e.get("grille"), "coefficient": e.get("coefficient"), "hours": 0}]
        lines = []
        total = 0.0
        for l in el:
            g = gidx.get(str(l.get("grille") or "").strip().lower())
            coef = int(l.get("coefficient") or 0)
            eff = coef + pts if coef else 0
            hours = float(l.get("hours") or 0)
            etp = (g or {}).get("etp_hours") or 0
            quot = (hours / etp) if etp else 0
            base = ((257 * v1) + ((eff - 257) * v2)) if coef else 0
            sal = round(base * quot, 2)
            total += sal
            lines.append({"grille": l.get("grille"), "grille_label": (g or {}).get("label", ""),
                          "coefficient": coef, "anciennete_points": pts, "effective_coef": eff,
                          "hours": hours, "etp_hours": etp, "quotite": round(quot, 3),
                          "base": round(base, 2), "salary": sal})
        elem_total = round(sum(float(x.get("amount") or 0) for x in (e.get("salary_elements") or [])), 2)
        tcfg = settings.get("travel", {})
        km = float(e.get("travel_km") or 0)
        travel = round(km * 2 * float(tcfg.get("trips_per_week") or 0) * (float(tcfg.get("weeks_per_year") or 0) / 12.0) * float(tcfg.get("rate_per_km") or 0), 2)
        out.append({"id": str(e["_id"]), "name": f"{e.get('first_name','')} {e.get('last_name','')}".strip(),
                    "hire_date": e.get("hire_date"), "anciennete_points": pts, "lines": lines,
                    "elements_total": elem_total, "travel_km": km, "travel_allowance": travel,
                    "salary_total": round(total + elem_total + travel, 2)})
    return {"eclat": settings.get("eclat", {}), "grilles": settings.get("grilles", []), "employees": out}


class AssignInput(BaseModel):
    line_index: int
    course_id: Optional[str] = ""
    level: Optional[str] = ""


@api.put("/inscriptions/{iid}/assign")
async def assign_inscription_group(iid: str, data: AssignInput, user: dict = Depends(get_current_user)):
    # Affecte un élève à un cours/groupe précis pour une ligne de son inscription (fait après coup, une fois le niveau connu).
    ins = await db.inscriptions.find_one({"_id": ObjectId(iid)})
    if not ins:
        raise HTTPException(status_code=404, detail="Inscription introuvable")
    lines = ins.get("lines", [])
    if 0 <= data.line_index < len(lines):
        lines[data.line_index]["course_id"] = data.course_id or ""
        lines[data.line_index]["level"] = data.level or ""
    await db.inscriptions.update_one({"_id": ObjectId(iid)}, {"$set": {"lines": lines}})
    return clean(await db.inscriptions.find_one({"_id": ObjectId(iid)}))


@api.get("/affectations")
async def list_affectations(exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    # Vue d'affectation : lignes d'inscription (par discipline) à placer dans un cours/groupe, + les groupes disponibles.
    ex = exercise or await get_current_exercise_label()
    courses = await db.courses.find({}).to_list(2000)
    cmap = {str(c["_id"]): c for c in courses}
    insc = await db.inscriptions.find({"exercise": ex}).to_list(5000)
    students = {str(s["_id"]): s for s in await db.students.find({"exercise": ex}).to_list(5000)}
    rows = []
    for ins in insc:
        sid = ins.get("student_id")
        st = students.get(sid)
        sname = f"{st.get('first_name','')} {st.get('last_name','')}".strip() if st else "—"
        for idx, l in enumerate(ins.get("lines", [])):
            ct = (l.get("course_type") or "").lower()
            if ct not in ("individuel", "theorique", "pratique", "eveil"):
                continue
            cid = l.get("course_id") or ""
            rows.append({"inscription_id": str(ins["_id"]), "line_index": idx, "student_id": sid,
                         "student": sname, "category": ct, "discipline": l.get("discipline") or l.get("label") or "",
                         "course_id": cid, "course_name": cmap.get(cid, {}).get("name", "") if cid else "",
                         "level": l.get("level", "")})
    return {"exercise": ex, "rows": rows,
            "courses": [{"id": str(c["_id"]), "name": c.get("name"), "type": c.get("type"),
                         "discipline": c.get("discipline"), "level": c.get("level", ""), "pole_id": c.get("pole_id"),
                         "capacity": c.get("capacity", 1), "exercise": c.get("exercise")} for c in courses]}


@api.get("/events/{eid}/bilan")
async def event_bilan(eid: str, user: dict = Depends(get_current_user)):
    # Bilan financier d'une manifestation par sous-catégorie comptable (via la ventilation des transactions sur l'évènement).
    plan = await db.plan_accounts.find({}).to_list(1000)
    labels = {a["code"]: a for a in plan}
    txs = await db.transactions.find({"$or": [{"ventilation.event_id": eid}, {"event_id": eid}]}).to_list(20000)
    income: dict = {}
    expense: dict = {}
    ti = te = 0.0
    for t in txs:
        vlines = [l for l in (t.get("ventilation") or []) if l.get("event_id") == eid]
        if not vlines and t.get("event_id") == eid:
            vlines = [{"account_code": t.get("account_code"), "amount": t.get("amount", 0)}]
        for l in vlines:
            code = l.get("account_code") or "—"
            amt = float(l.get("amount") or 0)
            if t.get("type") == "income":
                income[code] = round(income.get(code, 0) + amt, 2); ti += amt
            else:
                expense[code] = round(expense.get(code, 0) + amt, 2); te += amt

    def rows(b):
        return [{"code": c, "label": labels.get(c, {}).get("label", ""), "group": labels.get(c, {}).get("group", ""), "amount": v}
                for c, v in sorted(b.items())]
    return {"event_id": eid, "income": rows(income), "expense": rows(expense),
            "total_income": round(ti, 2), "total_expense": round(te, 2), "result": round(ti - te, 2)}


@api.get("/communes-deleguees")
async def communes_deleguees(code: str, user: dict = Depends(get_current_user)):
    # Communes déléguées d'une commune nouvelle (API officielle), filtrées par code INSEE de la commune (chefLieu).
    import re
    import httpx
    if not re.fullmatch(r"\d{5}", code or ""):
        return []
    dep = code[:2]
    url = f"https://geo.api.gouv.fr/communes_associees_deleguees?codeDepartement={dep}&fields=nom,code,chefLieu"
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(url)
            data = r.json() if r.status_code == 200 else []
    except Exception:
        data = []
    out = [{"nom": c.get("nom"), "code": c.get("code")} for c in data if c.get("chefLieu") == code]
    out.sort(key=lambda x: x["nom"] or "")
    return out


async def _compute_stat(d: dict, exercise: Optional[str]):
    ex = exercise or await get_current_exercise_label()
    dim = d["dimension"]; measure = d.get("measure", "count"); source = d["source"]
    buckets: dict = {}
    if source == "students":
        students = await db.students.find({"exercise": ex}).to_list(5000)
        insc = await db.inscriptions.find({"exercise": ex}).to_list(5000)
        poles = {str(p["_id"]): p.get("name") for p in await db.poles.find({}).to_list(500)}
        courses = {str(c["_id"]): c for c in await db.courses.find({}).to_list(2000)}
        cids = [s["contact_id"] for s in students if s.get("contact_id") and ObjectId.is_valid(s.get("contact_id"))]
        cmap = {str(c["_id"]): c for c in await db.contacts.find({"_id": {"$in": [ObjectId(x) for x in cids]}}).to_list(5000)} if cids else {}

        def add(k):
            buckets[k] = buckets.get(k, 0) + 1
        if dim in ("commune", "sexe", "age", "cc"):
            for s in students:
                if dim == "sexe":
                    add({"H": "Hommes", "F": "Femmes", "autre": "Autre"}.get(s.get("gender"), "Non renseigné"))
                elif dim == "age":
                    add("Mineur" if s.get("is_minor") else "Majeur")
                elif dim == "commune":
                    ct = cmap.get(s.get("contact_id") or "")
                    add(s.get("commune_deleguee") or s.get("city") or (ct or {}).get("commune_deleguee") or (ct or {}).get("city") or "Non renseigné")
                else:
                    ct = cmap.get(s.get("contact_id") or ""); cc = s.get("cc_savoir_faire")
                    if cc is None:
                        cc = (ct or {}).get("cc_savoir_faire")
                    add("Dans la CC" if cc is True else ("Hors CC" if cc is False else "Non renseigné"))
        elif dim == "formule":
            for ins in insc:
                types = {(l.get("course_type") or "").lower() for l in ins.get("lines", [])}
                if "individuel" in types:
                    add("Cursus (instrument)")
                elif "eveil" in types:
                    add("Éveil / petite enfance")
                elif "theorique" in types and "pratique" in types:
                    add("Théorique + pratique collective")
                elif "theorique" in types:
                    add("Théorique seul")
                elif "pratique" in types:
                    add("Pratique collective seule")
                else:
                    add("Autre / à affecter")
        else:
            for ins in insc:
                for l in ins.get("lines", []):
                    if dim == "discipline":
                        v = l.get("discipline") or l.get("label")
                        if v:
                            add(v)
                    elif dim == "niveau":
                        v = l.get("level")
                        if v:
                            add(v)
                    elif dim == "pole":
                        c = courses.get(l.get("course_id") or ""); pid = (c or {}).get("pole_id")
                        if pid:
                            add(poles.get(pid, "?"))
    else:
        txs = await db.transactions.find({"exercise": ex}).to_list(10000)
        plan = {a["code"]: a for a in await db.plan_accounts.find({}).to_list(1000)}
        poles = {str(p["_id"]): p.get("name") for p in await db.poles.find({}).to_list(500)}
        events = {str(e["_id"]): e.get("name") for e in await db.events.find({}).to_list(2000)}
        for t in txs:
            vlines = t.get("ventilation") or [{"account_code": t.get("account_code"), "pole_id": t.get("pole_id"), "event_id": None, "amount": t.get("amount", 0)}]
            for l in vlines:
                amt = float(l.get("amount") or 0)
                if dim == "compte":
                    code = l.get("account_code") or "—"; k = f"{code} {plan.get(code, {}).get('label', '')}".strip()
                elif dim == "pole":
                    k = poles.get(l.get("pole_id"), "Non affecté")
                elif dim == "manifestation":
                    k = events.get(l.get("event_id"), "Hors manifestation")
                elif dim == "mois":
                    k = (t.get("date") or "")[:7] or "?"
                elif dim == "type":
                    k = "Recette" if t.get("type") == "income" else "Dépense"
                else:
                    k = "?"
                buckets[k] = round(buckets.get(k, 0) + (amt if measure == "sum" else 1), 2)
    rows = sorted([{"label": k, "value": v} for k, v in buckets.items()], key=lambda x: -x["value"])
    return {"rows": rows, "total": round(sum(r["value"] for r in rows), 2), "measure": measure,
            "chart": d.get("chart", "bar"), "name": d.get("name")}


class StatDefInput(BaseModel):
    name: str
    source: str = "students"      # students | finances
    dimension: str = "commune"
    measure: str = "count"        # count | sum
    chart: str = "bar"            # bar | pie | table
    pinned: bool = False
    order: int = 0


class ReorderInput(BaseModel):
    ids: List[str] = []


@api.get("/stats")
async def list_stats(user: dict = Depends(get_current_user)):
    return [clean(d) for d in await db.stat_defs.find({}).sort([("order", 1), ("created_at", 1)]).to_list(500)]


@api.post("/stats")
async def create_stat(data: StatDefInput, user: dict = Depends(get_current_user)):
    doc = data.model_dump(); doc["created_at"] = datetime.now(timezone.utc).isoformat()
    doc["order"] = await db.stat_defs.count_documents({})
    r = await db.stat_defs.insert_one(doc)
    return clean(await db.stat_defs.find_one({"_id": r.inserted_id}))


@api.put("/stats/reorder")
async def reorder_stats(data: ReorderInput, user: dict = Depends(get_current_user)):
    for i, sid in enumerate(data.ids):
        if ObjectId.is_valid(sid):
            await db.stat_defs.update_one({"_id": ObjectId(sid)}, {"$set": {"order": i}})
    return {"ok": True}


@api.put("/stats/{sid}")
async def update_stat(sid: str, data: StatDefInput, user: dict = Depends(get_current_user)):
    await db.stat_defs.update_one({"_id": ObjectId(sid)}, {"$set": data.model_dump()})
    return clean(await db.stat_defs.find_one({"_id": ObjectId(sid)}))


@api.delete("/stats/{sid}")
async def delete_stat(sid: str, user: dict = Depends(get_current_user)):
    await db.stat_defs.delete_one({"_id": ObjectId(sid)})
    return {"ok": True}


@api.get("/stats/{sid}/data")
async def stat_data(sid: str, exercise: Optional[str] = None, user: dict = Depends(get_current_user)):
    d = await db.stat_defs.find_one({"_id": ObjectId(sid)})
    if not d:
        raise HTTPException(status_code=404, detail="Statistique introuvable")
    return await _compute_stat(d, exercise)


app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------- SEED
async def seed():
    # Admin + treasurer users
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@assoclub.fr")
    admin_pw = os.environ.get("ADMIN_PASSWORD", "Admin2026!")
    if not await db.users.find_one({"email": admin_email}):
        await db.users.insert_one({"name": "Président", "email": admin_email,
                                   "password_hash": hash_password(admin_pw), "role": "admin",
                                   "created_at": datetime.now(timezone.utc).isoformat()})
    else:
        existing = await db.users.find_one({"email": admin_email})
        if not verify_password(admin_pw, existing["password_hash"]):
            await db.users.update_one({"email": admin_email}, {"$set": {"password_hash": hash_password(admin_pw)}})
    if not await db.users.find_one({"email": "tresorier@assoclub.fr"}):
        await db.users.insert_one({"name": "Élodie Bernard", "email": "tresorier@assoclub.fr",
                                   "password_hash": hash_password("Tresor2026!"), "role": "tresorier",
                                   "created_at": datetime.now(timezone.utc).isoformat()})

    if await db.members.count_documents({}) > 0:
        return

    today = datetime.now(timezone.utc).date()
    avatars = [
        "https://images.unsplash.com/photo-1607746882042-944635dfe10e?crop=entropy&cs=srgb&fm=jpg&w=200&q=80",
        "https://images.unsplash.com/photo-1758691737605-69a0e78bd193?crop=entropy&cs=srgb&fm=jpg&w=200&q=80",
        "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?crop=entropy&cs=srgb&fm=jpg&w=200&q=80",
        "https://images.unsplash.com/photo-1758600587815-b654d1405e83?crop=entropy&cs=srgb&fm=jpg&w=200&q=80",
    ]
    members = [
        ("Sophie", "Martin", "sophie.martin@email.fr", "06 12 34 56 78", "Bienfaiteur", 120, "active", 180),
        ("Claire", "Dubois", "claire.dubois@email.fr", "06 98 76 54 32", "Standard", 50, "active", 90),
        ("Jean", "Moreau", "jean.moreau@email.fr", "07 11 22 33 44", "Standard", 50, "expired", -20),
        ("Lucas", "Petit", "lucas.petit@email.fr", "06 55 44 33 22", "Étudiant", 25, "pending", 10),
        ("Emma", "Laurent", "emma.laurent@email.fr", "07 66 77 88 99", "Famille", 80, "active", 150),
        ("Thomas", "Garnier", "thomas.garnier@email.fr", "06 33 22 11 00", "Standard", 50, "expired", -5),
        ("Léa", "Roux", "lea.roux@email.fr", "07 44 55 66 77", "Bienfaiteur", 120, "active", 200),
        ("Hugo", "Vincent", "hugo.vincent@email.fr", "06 22 33 44 55", "Étudiant", 25, "active", 120),
    ]
    docs = []
    for i, (fn, ln, em, ph, mt, amt, st, days) in enumerate(members):
        join = today - timedelta(days=365 - i * 20)
        docs.append({
            "first_name": fn, "last_name": ln, "email": em, "phone": ph, "address": f"{i+3} rue des Lilas, Lyon",
            "membership_type": mt, "cotisation_amount": amt, "cotisation_status": st,
            "cotisation_expiry": (today + timedelta(days=days)).isoformat(),
            "join_date": join.isoformat(), "avatar_url": avatars[i % len(avatars)],
            "notes": "", "created_at": datetime.now(timezone.utc).isoformat(),
            "history": [{"date": join.isoformat(), "event": "Adhésion créée"}],
        })
    await db.members.insert_many(docs)

    # Transactions over last 6 months
    cats_exp = ["Loyer", "Matériel", "Événements", "Assurance", "Salaires"]
    txs = []
    for mth in range(6, 0, -1):
        d = (today.replace(day=1) - timedelta(days=mth * 30))
        txs.append({"type": "income", "category": "Cotisations", "amount": 450 + mth * 30,
                    "date": d.isoformat(), "description": "Cotisations du mois", "method": "Virement",
                    "created_at": datetime.now(timezone.utc).isoformat()})
        txs.append({"type": "income", "category": "Subventions", "amount": 800 if mth % 2 == 0 else 0,
                    "date": d.isoformat(), "description": "Subvention municipale", "method": "Virement",
                    "created_at": datetime.now(timezone.utc).isoformat()})
        txs.append({"type": "expense", "category": cats_exp[mth % len(cats_exp)], "amount": 320 + mth * 25,
                    "date": d.isoformat(), "description": "Dépense courante", "method": "Carte",
                    "created_at": datetime.now(timezone.utc).isoformat()})
    txs = [t for t in txs if t["amount"] > 0]
    for t in txs:
        t["exercise"] = current_school_year()
    await db.transactions.insert_many(txs)

    # Employees
    emps = [
        ("Jean", "Moreau", "Coordinateur", "CDI", 2200, 0, avatars[2]),
        ("Élodie", "Bernard", "Animatrice", "CDD", 1800, 0, avatars[3]),
        ("Karim", "Haddad", "Agent d'entretien", "CDI", 0, 14.5, avatars[0]),
    ]
    edocs = []
    for fn, ln, pos, ct, sal, hr, av in emps:
        edocs.append({"first_name": fn, "last_name": ln, "email": f"{fn.lower()}@asso.fr", "phone": "06 00 00 00 00",
                      "position": pos, "contract_type": ct, "monthly_salary": sal, "hourly_rate": hr,
                      "hire_date": (today - timedelta(days=400)).isoformat(), "status": "active",
                      "avatar_url": av, "created_at": datetime.now(timezone.utc).isoformat()})
    res = await db.employees.insert_many(edocs)
    emp_ids = [str(x) for x in res.inserted_ids]

    # Shifts for current week
    monday = today - timedelta(days=today.weekday())
    shifts = []
    for di in range(5):
        day = (monday + timedelta(days=di)).isoformat()
        shifts.append({"employee_id": emp_ids[0], "date": day, "start_time": "09:00", "end_time": "17:00", "note": "Bureau"})
        if di % 2 == 0:
            shifts.append({"employee_id": emp_ids[1], "date": day, "start_time": "14:00", "end_time": "18:00", "note": "Animation"})
        if di in (1, 3):
            shifts.append({"employee_id": emp_ids[2], "date": day, "start_time": "18:00", "end_time": "20:00", "note": "Entretien locaux"})
    await db.shifts.insert_many(shifts)

    # Payslips current month
    cur_month = today.strftime("%Y-%m")
    for eid, (fn, ln, pos, ct, sal, hr, av) in zip(emp_ids, emps):
        gross = sal if sal else round(hr * 120, 2)
        await db.payslips.insert_one({
            "employee_id": eid, "month": cur_month, "gross_salary": gross, "hours": 0 if sal else 120,
            "charges": round(gross * 0.22, 2), "net_salary": round(gross * 0.78, 2), "status": "draft",
            "created_at": datetime.now(timezone.utc).isoformat()})
    logger.info("Seed terminé")


async def seed_ecole():
    if await db.tariffs.count_documents({}) > 0:
        return
    today = datetime.now(timezone.utc).date()
    av = [
        "https://images.unsplash.com/photo-1607746882042-944635dfe10e?crop=entropy&cs=srgb&fm=jpg&w=200&q=80",
        "https://images.unsplash.com/photo-1758691737605-69a0e78bd193?crop=entropy&cs=srgb&fm=jpg&w=200&q=80",
        "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?crop=entropy&cs=srgb&fm=jpg&w=200&q=80",
    ]
    tariffs = [
        {"label": "Cursus individuel 30 min (adulte)", "category": "cursus", "audience": "adulte", "duration_min": 30, "amount": 420, "active": True},
        {"label": "Cursus individuel 45 min (adulte)", "category": "cursus", "audience": "adulte", "duration_min": 45, "amount": 630, "active": True},
        {"label": "Cursus individuel 1 h (adulte)", "category": "cursus", "audience": "adulte", "duration_min": 60, "amount": 840, "active": True},
        {"label": "Cursus individuel 30 min (enfant/étudiant)", "category": "cursus", "audience": "enfant_etudiant", "duration_min": 30, "amount": 380, "active": True},
        {"label": "Cursus individuel 45 min (enfant/étudiant)", "category": "cursus", "audience": "enfant_etudiant", "duration_min": 45, "amount": 570, "active": True},
        {"label": "Cursus individuel 1 h (enfant/étudiant)", "category": "cursus", "audience": "enfant_etudiant", "duration_min": 60, "amount": 760, "active": True},
        {"label": "Éveil musical (4 à 7 ans)", "category": "eveil", "audience": "tous", "duration_min": None, "amount": 160, "active": True},
        {"label": "Cours théorique collectif (FM / FR) hors cursus", "category": "theorique", "audience": "tous", "duration_min": None, "amount": 140, "active": True},
        {"label": "Pratique collective hors cursus", "category": "pratique", "audience": "tous", "duration_min": None, "amount": 95, "active": True},
        {"label": "Location d'instrument", "category": "location", "audience": "tous", "duration_min": None, "amount": 90, "active": True},
        {"label": "Cotisation obligatoire (admin + assurance)", "category": "cotisation", "audience": "tous", "duration_min": None, "amount": 25, "active": True},
    ]
    await db.tariffs.insert_many(tariffs)

    teachers = [
        {"first_name": "Marie", "last_name": "Lefèvre", "email": "marie.lefevre@ecole.fr", "phone": "06 10 20 30 40", "disciplines": ["Piano", "Formation musicale"], "color": "#0D9488", "status": "active", "avatar_url": av[0]},
        {"first_name": "Antoine", "last_name": "Girard", "email": "antoine.girard@ecole.fr", "phone": "06 11 22 33 44", "disciplines": ["Guitare", "Basse"], "color": "#4F46E5", "status": "active", "avatar_url": av[2]},
        {"first_name": "Nadia", "last_name": "Benali", "email": "nadia.benali@ecole.fr", "phone": "06 55 66 77 88", "disciplines": ["Chorale", "Batucada"], "color": "#D97706", "status": "active", "avatar_url": av[1]},
    ]
    tres = await db.teachers.insert_many(teachers)
    tids = [str(x) for x in tres.inserted_ids]

    rooms = [
        {"name": "Salle Mozart", "capacity": 6, "equipment": "Piano droit, pupitres", "color": "#0D9488"},
        {"name": "Studio MAO", "capacity": 4, "equipment": "Ampli, batterie, matériel MAO", "color": "#4F46E5"},
        {"name": "Grande salle", "capacity": 20, "equipment": "Gradins, sono", "color": "#D97706"},
    ]
    rres = await db.rooms.insert_many(rooms)
    rids = [str(x) for x in rres.inserted_ids]

    courses = [
        {"name": "Piano (individuel)", "type": "individuel", "discipline": "Piano", "teacher_id": tids[0], "room_id": rids[0], "day": "Lundi", "start_time": "17:00", "duration_min": 60, "capacity": 1},
        {"name": "Guitare (individuel)", "type": "individuel", "discipline": "Guitare", "teacher_id": tids[1], "room_id": rids[1], "day": "Mardi", "start_time": "18:00", "duration_min": 30, "capacity": 1},
        {"name": "Éveil musical", "type": "eveil", "discipline": "", "teacher_id": tids[0], "room_id": rids[2], "day": "Mercredi", "start_time": "10:00", "duration_min": 45, "capacity": 10},
        {"name": "Chorale", "type": "pratique", "discipline": "Chant", "teacher_id": tids[2], "room_id": rids[2], "day": "Jeudi", "start_time": "19:00", "duration_min": 120, "capacity": 20},
        {"name": "Formation musicale", "type": "theorique", "discipline": "", "teacher_id": tids[0], "room_id": rids[0], "day": "Vendredi", "start_time": "17:00", "duration_min": 60, "capacity": 12},
    ]
    await db.courses.insert_many(courses)

    students = [
        {"first_name": "Léo", "last_name": "Martin", "birth_date": "2014-05-12", "email": "", "phone": "", "address": "4 rue des Écoles, Lyon", "is_minor": True, "responsable_name": "Sophie Martin", "responsable_relation": "Mère", "responsable_email": "sophie.martin@email.fr", "responsable_phone": "06 12 34 56 78", "cotisation_status": "active", "avatar_url": av[2], "notes": "", "created_at": datetime.now(timezone.utc).isoformat()},
        {"first_name": "Chloé", "last_name": "Petit", "birth_date": "2012-09-03", "email": "", "phone": "", "address": "9 av. de la Gare, Lyon", "is_minor": True, "responsable_name": "Marc Petit", "responsable_relation": "Père", "responsable_email": "marc.petit@email.fr", "responsable_phone": "06 98 76 54 32", "cotisation_status": "pending", "avatar_url": av[1], "notes": "", "created_at": datetime.now(timezone.utc).isoformat()},
        {"first_name": "Julien", "last_name": "Roche", "birth_date": "1990-02-20", "email": "julien.roche@email.fr", "phone": "07 44 55 66 77", "address": "2 pl. Bellecour, Lyon", "is_minor": False, "responsable_name": "", "responsable_relation": "", "responsable_email": "", "responsable_phone": "", "cotisation_status": "active", "avatar_url": av[0], "notes": "", "created_at": datetime.now(timezone.utc).isoformat()},
    ]
    sy_students = current_school_year()
    for s in students:
        s["exercise"] = sy_students
    sres = await db.students.insert_many(students)
    sids = [str(x) for x in sres.inserted_ids]

    sy = current_school_year()
    start_year = int(sy.split("-")[0])
    lines = [{"label": "Cursus individuel 30 min (enfant/étudiant)", "amount": 380, "tariff_id": "", "course_id": ""},
             {"label": "Pratique collective hors cursus", "amount": 95, "tariff_id": "", "course_id": ""}]
    disc = [{"label": "Réduction cours/pratique supplémentaire", "amount": 40}]
    ecolage = 475.0
    ecolage_net = 435.0
    await db.inscriptions.insert_one({
        "student_id": sids[0], "school_year": sy, "lines": lines, "discounts": disc,
        "cotisation": 25, "payment_mode": "mensuel", "payment_method": "Espèces", "notes": "",
        "ecolage": ecolage, "discount_total": 40.0, "ecolage_net": ecolage_net,
        "total": 460.0, "schedule": build_schedule("mensuel", 25, ecolage_net, start_year),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    logger.info("Seed école terminé")


@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await seed()
    await seed_ecole()
    await seed_exercises()
    await seed_contacts()
    await seed_compta()
    await seed_patrimoine()
    await seed_events()
    await seed_bank()
    await seed_catalog()
    await seed_ref_lists()
    await seed_plan_comptable()
    await migrate_contacts_types()


@app.on_event("shutdown")
async def shutdown():
    client.close()
