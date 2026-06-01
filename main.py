from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv
import pyodbc
import bcrypt
import os
from datetime import datetime
import json as _json

load_dotenv()

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.environ["SECRET_KEY"])
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

MB4_CONN = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    f"SERVER={os.environ['DB_SERVER']};DATABASE={os.environ['DB_MB4']};"
    f"UID={os.environ['DB_USER']};PWD={os.environ['DB_PASSWORD']};"
)
REPORT_CONN = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    f"SERVER={os.environ['DB_SERVER']};DATABASE={os.environ['DB_REPORT']};"
    f"UID={os.environ['DB_USER']};PWD={os.environ['DB_PASSWORD']};"
)

def get_mb4():    return pyodbc.connect(MB4_CONN)
def get_report(): return pyodbc.connect(REPORT_CONN)

ACCESS_LABELS = {
    0: ("Наблюдатель",  "Вы можете просматривать изменения"),
    1: ("Пользователь", "Вы можете создавать и редактировать только свои изменения"),
    2: ("Главный",      "Вы можете создавать и редактировать любые комментарии"),
    3: ("Администратор","Вы можете создавать и редактировать любые комментарии"),
}

def current_user(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return user

def require_admin(user=Depends(current_user)):
    if user.get("access", 0) < 3:
        raise HTTPException(status_code=403, detail="Недостаточно прав")
    return user

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def log_visit(user: dict, action: str, detail: str, ip: str):
    try:
        conn = get_report()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO dbo.VisitLog (Username, FullName, Action, Detail, IP, CreatedAt) "
            "VALUES (?,?,?,?,?,GETDATE())",
            user.get("username",""), user.get("fullname",""), action, detail, ip
        )
        conn.commit()
        conn.close()
    except:
        pass

def sync_history_comment(log_id: int, comment_text: str):
    try:
        conn = get_mb4()
        cur = conn.cursor()
        cur.execute(
            "EXEC dbo.UpdateHistoryComment @HistoryId=?, @Comment=?",
            log_id, comment_text
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[WARN] sync_history_comment failed for LogId={log_id}: {e}")


# ── Авторизация ───────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.session.get("user"):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request=request, name="login.html", context={"error": None})


@app.post("/login", response_class=HTMLResponse)
async def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = get_client_ip(request)
    try:
        conn = get_report(); cur = conn.cursor()
        cur.execute(
            "SELECT Id, PasswordHash, FullName, Access FROM dbo.WebUsers WHERE Username=? AND IsActive=1",
            username
        )
        row = cur.fetchone(); conn.close()
        if row and bcrypt.checkpw(password.encode(), row.PasswordHash.encode()):
            access = int(row.Access)
            label, desc = ACCESS_LABELS.get(access, ("Пользователь", ""))
            user = {
                "id": row.Id, "username": username,
                "fullname": row.FullName,
                "access": access,
                "access_label": label,
                "access_desc": desc,
            }
            request.session["user"] = user
            log_visit(user, "login", "Авторизация", ip)
            return RedirectResponse("/", status_code=302)
        return templates.TemplateResponse(request=request, name="login.html",
                                          context={"error": "Неверный логин или пароль"})
    except Exception as e:
        return templates.TemplateResponse(request=request, name="login.html",
                                          context={"error": f"Ошибка подключения: {str(e)}"})


@app.get("/logout")
async def logout(request: Request):
    user = request.session.get("user", {})
    ip = get_client_ip(request)
    log_visit(user, "logout", "Выход", ip)
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


# ── Главная ───────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user=Depends(current_user)):
    try:
        conn = get_mb4(); cur = conn.cursor()
        cur.execute("""
            SELECT CONVERT(VARCHAR(10),C.StartTime,120) AS StartDate,
                   CONVERT(VARCHAR(10),C.EndTime,120)   AS EndDate,
                   A.Name AS PeriodType
            FROM dbo.Cases C
            INNER JOIN dbo.Analyses A ON C.AnalysisSfId = A.SfId
            WHERE A.Name IN (N'Суточный', N'Накопительный')
            ORDER BY C.StartTime DESC, C.EndTime DESC
        """)
        all_periods = [{"start": r.StartDate, "end": r.EndDate, "type": r.PeriodType}
                       for r in cur.fetchall()]
        conn.close()
    except:
        all_periods = []

    return templates.TemplateResponse(request=request, name="index.html", context={
        "user": user,
        "daily":      [p for p in all_periods if p["type"] == "Суточный"],
        "cumulative": [p for p in all_periods if p["type"] == "Накопительный"],
    })


# ── Логи ──────────────────────────────────────────────────────────────────────
@app.get("/logs", response_class=HTMLResponse)
async def get_logs(request: Request, start: str, end: str, user=Depends(current_user)):
    ip = get_client_ip(request)
    log_visit(user, "view_period", f"{start} → {end}", ip)
    try:
        conn_mb4 = get_mb4(); cur = conn_mb4.cursor()
        cur.execute(
            "EXEC dbo.clientLogGetPeriod_JoinAttributes @starttime=?, @endtime=?, @OnlySearchDate=1",
            start, end
        )
        columns = [col[0] for col in cur.description]
        logs = [dict(zip(columns, row)) for row in cur.fetchall()]
        conn_mb4.close()

        log_ids = [r["LogId"] for r in logs if r.get("LogId")]
        comment_history = {}
        sign_history = {}
        if log_ids:
            conn_rep = get_report(); cur2 = conn_rep.cursor()
            ph = ",".join("?" * len(log_ids))
            # Комментарии
            cur2.execute(
                f"SELECT LogId,ChangeNo,Comment,CreatedBy,CreatedAt,Type "
                f"FROM dbo.LogComments WHERE LogId IN ({ph}) ORDER BY LogId,ChangeNo",
                log_ids
            )
            for r in cur2.fetchall():
                comment_history.setdefault(r.LogId, []).append({
                    "no": r.ChangeNo, "text": r.Comment,
                    "by": r.CreatedBy,
                    "at": r.CreatedAt.strftime("%d.%m.%Y %H:%M") if r.CreatedAt else "",
                    "type": r.Type
                })
            # Признаки
            try:
                cur2.execute(
                    f"SELECT LogId,ChangeNo,Sign,CreatedBy,CreatedAt,Type "
                    f"FROM dbo.SignComments WHERE LogId IN ({ph}) ORDER BY LogId,ChangeNo",
                    log_ids
                )
                for r in cur2.fetchall():
                    sign_history.setdefault(r.LogId, []).append({
                        "no": r.ChangeNo, "text": r.Sign,
                        "by": r.CreatedBy,
                        "at": r.CreatedAt.strftime("%d.%m.%Y %H:%M") if r.CreatedAt else "",
                        "type": r.Type
                    })
            except Exception:
                pass  # Таблица SignComments может ещё не существовать
            conn_rep.close()

        for log in logs:
            lid = log.get("LogId")
            hist  = comment_history.get(lid, [])
            shist = sign_history.get(lid, [])
            log["comment_history"]      = hist
            log["comment_history_json"] = _json.dumps(hist, ensure_ascii=False)
            log["sign_history_json"]    = _json.dumps(shist, ensure_ascii=False)
            log["Комментарий"]       = log.get("Комментарий") or ""
            log["Комментарий автор"] = log.get("Комментарий автор") or ""
            cd = log.get("Комментарий дата")
            log["Комментарий дата"]  = cd.strftime("%d.%m.%Y %H:%M") if isinstance(cd, datetime) else (cd or "")
            log["current_change_no"] = hist[-1]["no"] if hist else 0
            log["Признак"]           = log.get("Признак") or (shist[-1]["text"] if shist else "")
            log["sign_change_no"]    = shist[-1]["no"] if shist else 0

        # Собираем уникальные типы объектов для фильтров
        obj_types = sorted(set(l.get("Тип объекта","") for l in logs if l.get("Тип объекта","")))

        return templates.TemplateResponse(request=request, name="logs.html", context={
            "user": user, "logs": logs, "start": start, "end": end,
            "columns": columns, "obj_types": obj_types
        })
    except Exception as e:
        return templates.TemplateResponse(request=request, name="error.html",
                                          context={"user": user, "error": str(e)})


# ── API: сохранить комментарий ────────────────────────────────────────────────
@app.post("/api/comment")
async def save_comment(request: Request, user=Depends(current_user)):
    data         = await request.json()
    log_id       = data.get("log_id")
    comment_text = data.get("comment", "").strip()
    client_no    = int(data.get("change_no", 0))
    row_user     = data.get("row_user", "")
    access       = user.get("access", 0)
    fullname     = user["fullname"]

    if not log_id:
        raise HTTPException(status_code=400, detail="log_id обязателен")
    if access == 0:
        raise HTTPException(status_code=403, detail="Нет прав на добавление комментариев")
    if access == 1 and row_user != fullname:
        raise HTTPException(status_code=403,
            detail=f"Вы можете комментировать только свои изменения")

    try:
        conn = get_report(); cur = conn.cursor()
        cur.execute(
            "SELECT TOP 1 Id,ChangeNo,Comment,CreatedBy,CreatedAt "
            "FROM dbo.LogComments WHERE LogId=? ORDER BY Id DESC", log_id
        )
        last = cur.fetchone()
        db_no = last.ChangeNo if last else 0

        if db_no > client_no:
            at_str = last.CreatedAt.strftime("%d.%m.%Y %H:%M") if last.CreatedAt else ""
            conn.close()
            return JSONResponse({"conflict": True, "db_no": db_no,
                                 "db_text": last.Comment, "db_by": last.CreatedBy, "db_at": at_str})

        if not comment_text:
            conn.close()
            return JSONResponse({"ok": True, "by": fullname, "at": "", "no": db_no, "type": "none"})

        change_no = db_no + 1
        rec_type  = "Updated" if last else "Inserted"
        cur.execute(
            "INSERT INTO dbo.LogComments (LogId,ChangeNo,Comment,CreatedBy,CreatedAt,Type) VALUES (?,?,?,?,GETDATE(),?)",
            log_id, change_no, comment_text, fullname, rec_type
        )
        conn.commit()
        cur.execute("SELECT TOP 1 CreatedAt FROM dbo.LogComments WHERE LogId=? ORDER BY Id DESC", log_id)
        r = cur.fetchone(); conn.close()
        
        sync_history_comment(log_id, comment_text)
        
        return JSONResponse({"ok": True, "by": fullname,
                             "at": r.CreatedAt.strftime("%d.%m.%Y %H:%M") if r else "",
                             "no": change_no, "type": rec_type})
    except HTTPException: raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Логи за произвольный период (OnlySearchDate=0) ───────────────────────────
@app.get("/logs_custom", response_class=HTMLResponse)
async def get_logs_custom(request: Request, start: str, end: str, user=Depends(current_user)):
    ip = get_client_ip(request)
    log_visit(user, "view_custom", f"{start} → {end}", ip)
    try:
        conn_mb4 = get_mb4(); cur = conn_mb4.cursor()
        cur.execute(
            "EXEC dbo.clientLogGetPeriod_JoinAttributes @starttime=?, @endtime=?, @OnlySearchDate=0",
            start, end
        )
        columns = [col[0] for col in cur.description]
        logs = [dict(zip(columns, row)) for row in cur.fetchall()]
        conn_mb4.close()

        log_ids = [r["LogId"] for r in logs if r.get("LogId")]
        comment_history = {}
        sign_history = {}
        if log_ids:
            conn_rep = get_report(); cur2 = conn_rep.cursor()
            ph = ",".join("?" * len(log_ids))
            # Комментарии
            cur2.execute(
                f"SELECT LogId,ChangeNo,Comment,CreatedBy,CreatedAt,Type "
                f"FROM dbo.LogComments WHERE LogId IN ({ph}) ORDER BY LogId,ChangeNo",
                log_ids
            )
            for r in cur2.fetchall():
                comment_history.setdefault(r.LogId, []).append({
                    "no": r.ChangeNo, "text": r.Comment,
                    "by": r.CreatedBy,
                    "at": r.CreatedAt.strftime("%d.%m.%Y %H:%M") if r.CreatedAt else "",
                    "type": r.Type
                })
            # Признаки
            try:
                cur2.execute(
                    f"SELECT LogId,ChangeNo,Sign,CreatedBy,CreatedAt,Type "
                    f"FROM dbo.SignComments WHERE LogId IN ({ph}) ORDER BY LogId,ChangeNo",
                    log_ids
                )
                for r in cur2.fetchall():
                    sign_history.setdefault(r.LogId, []).append({
                        "no": r.ChangeNo, "text": r.Sign,
                        "by": r.CreatedBy,
                        "at": r.CreatedAt.strftime("%d.%m.%Y %H:%M") if r.CreatedAt else "",
                        "type": r.Type
                    })
            except Exception:
                pass  # Таблица SignComments может ещё не существовать
            conn_rep.close()

        for log in logs:
            lid = log.get("LogId")
            hist  = comment_history.get(lid, [])
            shist = sign_history.get(lid, [])
            log["comment_history"]      = hist
            log["comment_history_json"] = _json.dumps(hist, ensure_ascii=False)
            log["sign_history_json"]    = _json.dumps(shist, ensure_ascii=False)
            log["Комментарий"]       = log.get("Комментарий") or ""
            log["Комментарий автор"] = log.get("Комментарий автор") or ""
            cd = log.get("Комментарий дата")
            log["Комментарий дата"]  = cd.strftime("%d.%m.%Y %H:%M") if isinstance(cd, datetime) else (cd or "")
            log["current_change_no"] = hist[-1]["no"] if hist else 0
            log["Признак"]           = log.get("Признак") or (shist[-1]["text"] if shist else "")
            log["sign_change_no"]    = shist[-1]["no"] if shist else 0

        obj_types = sorted(set(l.get("Тип объекта","") for l in logs if l.get("Тип объекта","")))

        return templates.TemplateResponse(request=request, name="logs.html", context={
            "user": user, "logs": logs, "start": start, "end": end,
            "columns": columns, "obj_types": obj_types,
            "custom_period": True  # флаг чтобы показать что это произвольный период
        })
    except Exception as e:
        return templates.TemplateResponse(request=request, name="error.html",
                                          context={"user": user, "error": str(e)})


# ── API: статистика ───────────────────────────────────────────────────────────
@app.get("/api/stats")
async def get_stats(request: Request, start: str = None, end: str = None, user=Depends(current_user)):
    """Статистика изменений из MB4 за период"""
    try:
        conn = get_mb4(); cur = conn.cursor()
        # Если период не указан — берём текущий год
        if not start:
            start = f"{datetime.now().year}-01-01"
        if not end:
            end = datetime.now().strftime("%Y-%m-%d")

        cur.execute("""
            EXEC dbo.clientLogGetPeriod_JoinAttributes @starttime=?, @endtime=?, @OnlySearchDate=0
        """, start, end)
        columns = [col[0] for col in cur.description]
        rows = [dict(zip(columns, row)) for row in cur.fetchall()]
        conn.close()

        # Агрегируем
        from collections import defaultdict, Counter
        obj_change = defaultdict(Counter)
        user_counts = Counter()
        by_month = defaultdict(Counter)
        total = len(rows)

        for row in rows:
            ot = row.get("Тип объекта") or "Неизвестно"
            ct = row.get("Тип изменения") or "Неизвестно"
            u  = row.get("Пользователь") or "Неизвестно"
            dt_str = row.get("Время действия") or ""
            obj_change[ot][ct] += 1
            user_counts[u] += 1
            try:
                month = dt_str[:7]  # "26.03.2" -> берём иначе
                # формат "26.03.2026 12:10:53" -> month = "2026-03"
                parts = dt_str.split(" ")[0].split(".")
                if len(parts) == 3:
                    month = f"{parts[2]}-{parts[1]}"
                by_month[month][ot] += 1
            except: pass

        safe_types = {"НОФ", "Присадки", "Зависимость"}

        obj_summary = []
        for ot, counts in sorted(obj_change.items(), key=lambda x: -sum(x[1].values())):
            obj_summary.append({
                "type": ot,
                "total": sum(counts.values()),
                "safe": ot in safe_types,
                "breakdown": dict(counts)
            })

        # Топ пользователей
        top_users = [{"name": u, "count": c} for u, c in user_counts.most_common(10)]

        # По месяцам — все типы
        months_sorted = sorted(by_month.keys())
        all_obj_types = list(obj_change.keys())
        monthly = []
        for m in months_sorted:
            entry = {"month": m}
            for ot in all_obj_types:
                entry[ot] = by_month[m].get(ot, 0)
            monthly.append(entry)

        return JSONResponse({
            "total": total,
            "obj_summary": obj_summary,
            "top_users": top_users,
            "monthly": monthly,
            "all_obj_types": all_obj_types,
            "safe_types": list(safe_types),
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── API: последние комментарии ────────────────────────────────────────────────
@app.get("/api/recent_comments")
async def recent_comments(request: Request, days: int = 0, months: int = 1, user=Depends(require_admin)):
    try:
        conn = get_report(); cur = conn.cursor()
        # Если указаны дни — используем DATEADD(day,...), иначе DATEADD(month,...)
        if days > 0:
            cur.execute("""
                SELECT TOP 500 LogId,ChangeNo,Comment,CreatedBy,CreatedAt,Type
                FROM dbo.LogComments
                WHERE CreatedAt >= DATEADD(day,?,GETDATE())
                ORDER BY CreatedAt DESC
            """, -abs(days))
        else:
            cur.execute("""
                SELECT TOP 500 LogId,ChangeNo,Comment,CreatedBy,CreatedAt,Type
                FROM dbo.LogComments
                WHERE CreatedAt >= DATEADD(month,?,GETDATE())
                ORDER BY CreatedAt DESC
            """, -abs(months))
        rows = []
        for r in cur.fetchall():
            rows.append({"log_id": r.LogId, "change_no": r.ChangeNo, "comment": r.Comment,
                         "by": r.CreatedBy, "at": r.CreatedAt.strftime("%d.%m.%Y %H:%M") if r.CreatedAt else "",
                         "type": r.Type})
        conn.close()
        return JSONResponse(rows)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── API: журнал посещений ─────────────────────────────────────────────────────
@app.get("/api/visit_log")
async def visit_log(request: Request, days: int = 0, months: int = 1, user=Depends(require_admin)):
    try:
        conn = get_report(); cur = conn.cursor()
        if days > 0:
            cur.execute("""
                SELECT TOP 500 FullName, Username, Action, Detail, IP, CreatedAt
                FROM dbo.VisitLog
                WHERE CreatedAt >= DATEADD(day,?,GETDATE())
                ORDER BY CreatedAt DESC
            """, -abs(days))
        else:
            cur.execute("""
                SELECT TOP 500 FullName, Username, Action, Detail, IP, CreatedAt
                FROM dbo.VisitLog
                WHERE CreatedAt >= DATEADD(month,?,GETDATE())
                ORDER BY CreatedAt DESC
            """, -abs(months))
        rows = []
        for r in cur.fetchall():
            rows.append({"fullname": r.FullName, "username": r.Username,
                         "action": r.Action, "detail": r.Detail, "ip": r.IP,
                         "at": r.CreatedAt.strftime("%d.%m.%Y %H:%M") if r.CreatedAt else ""})
        conn.close()
        return JSONResponse(rows)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── API: логирование действий (Excel, статистика) ─────────────────────────────
@app.post("/api/log_action")
async def log_action(request: Request, user=Depends(current_user)):
    data   = await request.json()
    action = data.get("action", "")
    detail = data.get("detail", "")
    ip     = get_client_ip(request)
    readable = {
        "export_excel": f"Выгрузил Excel: {detail}",
        "open_stats":   f"Открыл статистику: {detail}",
    }.get(action, detail)
    log_visit(user, action, readable, ip)
    return JSONResponse({"ok": True})                         

    
# ── API: сохранить признак ────────────────────────────────────────────────────
@app.post("/api/sign")
async def save_sign(request: Request, user=Depends(current_user)):
    data      = await request.json()
    log_id    = data.get("log_id")
    sign_text = data.get("sign", "").strip()
    client_no = int(data.get("change_no", 0))
    row_user  = data.get("row_user", "")
    access    = user.get("access", 0)
    fullname  = user["fullname"]

    if not log_id:
        raise HTTPException(status_code=400, detail="log_id обязателен")
    if access == 0:
        raise HTTPException(status_code=403, detail="Нет прав на добавление признака")
    if access == 1 and row_user != fullname:
        raise HTTPException(status_code=403, detail="Вы можете изменять только свои записи")

    try:
        conn = get_report(); cur = conn.cursor()
        cur.execute(
            "SELECT TOP 1 Id,ChangeNo,Sign,CreatedBy,CreatedAt "
            "FROM dbo.SignComments WHERE LogId=? ORDER BY Id DESC",
            log_id
        )
        last  = cur.fetchone()
        db_no = last.ChangeNo if last else 0

        if db_no > client_no:
            at_str = last.CreatedAt.strftime("%d.%m.%Y %H:%M") if last.CreatedAt else ""
            conn.close()
            return JSONResponse({"conflict": True, "db_no": db_no,
                                 "db_text": last.Sign, "db_by": last.CreatedBy, "db_at": at_str})

        if not sign_text:
            conn.close()
            return JSONResponse({"ok": True, "by": fullname, "at": "", "no": db_no, "type": "none"})

        change_no = db_no + 1
        rec_type  = "Updated" if last else "Inserted"
        cur.execute(
            "INSERT INTO dbo.SignComments (LogId,ChangeNo,Sign,CreatedBy,CreatedAt,Type) "
            "VALUES (?,?,?,?,GETDATE(),?)",
            log_id, change_no, sign_text, fullname, rec_type
        )
        conn.commit()
        cur.execute("SELECT TOP 1 CreatedAt FROM dbo.SignComments WHERE LogId=? ORDER BY Id DESC", log_id)
        r = cur.fetchone(); conn.close()
        return JSONResponse({
            "ok": True, "by": fullname,
            "at": r.CreatedAt.strftime("%d.%m.%Y %H:%M") if r else "",
            "no": change_no, "type": rec_type
        })
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── Страница: Документация ────────────────────────────────────────────────────
@app.get("/docs_page", response_class=HTMLResponse)
async def documentation_page(request: Request, user=Depends(current_user)):
    # Логируем посещение документации
    ip = get_client_ip(request)
    log_visit(user, "view_docs", "Просмотр документации", ip)
    
    return templates.TemplateResponse(
        request=request, 
        name="docs.html", 
        context={"user": user}
    )


# ── API: справочник признаков ─────────────────────────────────────────────────
@app.get("/api/sign_presets")
async def get_sign_presets(request: Request, user=Depends(current_user)):
    try:
        conn = get_report(); cur = conn.cursor()
        cur.execute(
            "SELECT Id, Name FROM dbo.SignPresets WHERE IsActive=1 ORDER BY SortOrder, Name"
        )
        rows = [{"id": r.Id, "name": r.Name} for r in cur.fetchall()]
        conn.close()
        return JSONResponse(rows)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/sign_presets")
async def add_sign_preset(request: Request, user=Depends(require_admin)):
    data = await request.json()
    name = data.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Название обязательно")
    try:
        conn = get_report(); cur = conn.cursor()
        cur.execute(
            "INSERT INTO dbo.SignPresets (Name, IsActive, SortOrder) VALUES (?, 1, 100)", name
        )
        conn.commit()
        cur.execute("SELECT TOP 1 Id FROM dbo.SignPresets WHERE Name=? ORDER BY Id DESC", name)
        new_id = cur.fetchone().Id
        conn.close()
        return JSONResponse({"ok": True, "id": new_id, "name": name})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/sign_presets/{preset_id}")
async def delete_sign_preset(
    preset_id: int, request: Request, user=Depends(require_admin)
):
    try:
        conn = get_report(); cur = conn.cursor()
        cur.execute("UPDATE dbo.SignPresets SET IsActive=0 WHERE Id=?", preset_id)
        conn.commit(); conn.close()
        return JSONResponse({"ok": True})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Страница: Админ панель ────────────────────────────────────────────────────
@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request, user=Depends(require_admin)):
    return templates.TemplateResponse(request=request, name="admin.html", context={"user": user})


@app.post("/api/create_user")
async def create_user(request: Request, user=Depends(require_admin)):
    data = await request.json()
    username = data.get("username","").strip()
    password = data.get("password","").strip()
    fullname = data.get("fullname", username).strip()
    access   = int(data.get("access", 0))
    if not username or not password:
        raise HTTPException(status_code=400, detail="Логин и пароль обязательны")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        conn = get_report(); cur = conn.cursor()
        # Проверяем — существует ли уже пользователь с таким логином
        cur.execute("SELECT Id, Access FROM dbo.WebUsers WHERE Username=?", username)
        existing = cur.fetchone()

        if existing:
            # Обновляем пароль, доступ (и FullName если передан отличный от логина)
            # IsActive не трогаем
            cur.execute(
                "UPDATE dbo.WebUsers SET PasswordHash=?, FullName=?, Access=? WHERE Username=?",
                hashed, fullname, access, username
            )
            conn.commit(); conn.close()
            return JSONResponse({"ok": True, "updated": True,
                                 "message": f"Данные пользователя обновлены!"})
        else:
            cur.execute(
                "INSERT INTO dbo.WebUsers (Username,PasswordHash,FullName,IsActive,Access) VALUES (?,?,?,1,?)",
                username, hashed, fullname, access
            )
            conn.commit(); conn.close()
            return JSONResponse({"ok": True, "updated": False,
                                 "message": f"Пользователь «{fullname}» зарегистрирован"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))