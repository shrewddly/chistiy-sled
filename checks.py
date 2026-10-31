from __future__ import annotations

import asyncio
import hashlib
import urllib.parse

import aiohttp

USER_AGENT = "ChistiySledBot/2.0 (personal data self-audit)"
XON_TIMEOUT = aiohttp.ClientTimeout(total=40)
CRT_TIMEOUT = aiohttp.ClientTimeout(total=90)
PWNED_TIMEOUT = aiohttp.ClientTimeout(total=20)
LEAKCHECK_TIMEOUT = aiohttp.ClientTimeout(total=30)

_XON_SEM = asyncio.Semaphore(4)
_CRT_SEM = asyncio.Semaphore(2)
_LEAKCHECK_SEM = asyncio.Semaphore(4)

DATA_LABELS = {
    "data_Passwords": "Пароли",
    "data_Historical passwords": "Старые пароли",
    "data_Email addresses": "Email-адреса",
    "data_Usernames": "Логины",
    "data_Names": "Имена",
    "data_Phone numbers": "Телефоны",
    "data_Physical addresses": "Адреса",
    "data_Dates of birth": "Даты рождения",
    "data_Genders": "Пол",
    "data_Security questions and answers": "Секретные вопросы",
    "data_Mothers maiden names": "Девичья фамилия матери",
    "data_Private Messages": "Личные сообщения",
    "data_Chat logs": "Логи чатов",
    "data_IP addresses": "IP-адреса",
    "data_Geographic locations": "Геолокация",
    "data_Device information": "Данные устройств",
    "data_Employers": "Работодатели",
    "data_Job titles": "Должности",
    "data_Social media profiles": "Соцсети",
    "data_Instant messenger identities": "Мессенджеры",
    "data_Passport numbers": "Паспортные данные",
    "data_Government IDs": "Гос. документы",
    "data_Government issued IDs": "Гос. документы",
    "data_Social security numbers": "Соц. номера",
    "data_Nationalities": "Гражданство",
    "data_Licence Plates": "Номера авто",
    "data_Payment card details": "Данные карт",
    "data_Bank account numbers": "Банковские счета",
    "data_Credit scores": "Кредитный рейтинг",
    "data_Purchases": "Покупки",
    "data_Subscriptions": "Подписки",
    "data_Website activity": "Активность на сайтах",
    "data_Browsing histories": "История браузера",
    "data_Profile Photos": "Фото профиля",
    "data_Auth tokens": "Токены доступа",
    "data_AI Prompts": "Запросы к ИИ",
    "data_Support Tickets": "Обращения в поддержку",
    "data_Hobbies": "Хобби",
    "data_Spoken languages": "Языки",
}

BREACH_DATA_RU = {
    "Email addresses": "email",
    "Passwords": "пароли",
    "Names": "имена",
    "Phone numbers": "телефоны",
    "Usernames": "логины",
    "Physical addresses": "адреса",
    "Dates of birth": "даты рождения",
    "IP addresses": "IP",
    "Passport numbers": "паспортные данные",
    "Government IDs": "гос. документы",
    "Payment card details": "карты",
    "Bank account numbers": "банковские счета",
    "Security questions and answers": "секретные вопросы",
    "Private messages": "личные сообщения",
    "Historical passwords": "старые пароли",
    "Geographic locations": "геолокация",
    "Device information": "устройства",
    "Employers": "работодатели",
    "Job titles": "должности",
    "Social media profiles": "соцсети",
    "Genders": "пол",
}


def label(name: str) -> str:
    if name in DATA_LABELS:
        return DATA_LABELS[name]
    return name.removeprefix("data_").replace("_", " ").strip().capitalize()


def breach_data_ru(raw: str) -> list[str]:
    items = [i.strip() for i in raw.split(";") if i.strip()] if raw else []
    return [BREACH_DATA_RU.get(item, item.lower()) for item in items]


LEAK_FIELD_RU = {
    "email": "email",
    "password": "пароли",
    "phone": "телефоны",
    "name": "имена",
    "first_name": "имена",
    "last_name": "фамилии",
    "late_name": "фамилии",
    "middle_name": "отчество",
    "username": "логины",
    "profile_name": "профили",
    "dob": "даты рождения",
    "gender": "пол",
    "address": "адреса",
    "address1": "адреса",
    "city": "города",
    "state": "регионы",
    "region": "регионы",
    "area": "районы",
    "country": "страны",
    "zip": "индексы",
    "ip": "IP",
    "ip1": "IP",
    "ip2": "IP",
    "telegram_id": "Telegram ID",
    "id": "ID",
    "ssn": "SSN",
    "qqmail": "QQ",
    "company_name": "работодатели",
    "origin": "источники",
}


def leak_field(name: str) -> str:
    return LEAK_FIELD_RU.get(name.strip().lower(), name.strip().replace("_", " "))


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if not domain:
        return "***"
    visible = local[:2] if len(local) > 2 else local[:1]
    return f"{visible}***@{domain}"


async def leakcheck(session: aiohttp.ClientSession, query: str) -> dict:
    url = "https://leakcheck.io/api/public?check=" + urllib.parse.quote(query, safe="")
    try:
        async with _LEAKCHECK_SEM:
            async with session.get(url, headers={"User-Agent": USER_AGENT}, timeout=LEAKCHECK_TIMEOUT) as resp:
                if resp.status == 429:
                    return {"ok": False, "error": "rate_limit"}
                if resp.status != 200:
                    return {"ok": False, "error": f"http_{resp.status}"}
                try:
                    data = await resp.json(content_type=None)
                except ValueError:
                    return {"ok": False, "error": "bad_json"}
    except asyncio.TimeoutError:
        return {"ok": False, "error": "timeout"}
    except aiohttp.ClientError:
        return {"ok": False, "error": "network"}
    return _parse_leakcheck(data)


def _parse_leakcheck(data: object) -> dict:
    empty = {"ok": True, "found": 0, "fields": [], "sources": [], "source_count": 0}
    if not isinstance(data, dict):
        return {"ok": False, "error": "bad_json"}
    if data.get("success") is False:
        if str(data.get("error") or "").strip().lower() == "not found":
            return empty
        return {"ok": False, "error": "api"}
    try:
        found = int(data.get("found") or 0)
    except (TypeError, ValueError):
        found = 0
    fields = [f for f in (data.get("fields") or []) if isinstance(f, str)]
    sources = []
    for source in data.get("sources") or []:
        if not isinstance(source, dict):
            continue
        name = str(source.get("name") or "").strip()
        if not name:
            continue
        sources.append({"name": name, "date": str(source.get("date") or "").strip()})
    return {
        "ok": True,
        "found": found,
        "fields": fields,
        "sources": sources[:50],
        "source_count": len(sources),
    }


async def xon_email(session: aiohttp.ClientSession, email: str) -> dict:
    url = "https://api.xposedornot.com/v1/breach-analytics?email=" + urllib.parse.quote(email, safe="")
    try:
        async with _XON_SEM:
            async with session.get(url, headers={"User-Agent": USER_AGENT}, timeout=XON_TIMEOUT) as resp:
                if resp.status == 429:
                    return {"ok": False, "error": "rate_limit"}
                if resp.status != 200:
                    return {"ok": False, "error": f"http_{resp.status}"}
                try:
                    data = await resp.json(content_type=None)
                except ValueError:
                    return {"ok": False, "error": "bad_json"}
    except asyncio.TimeoutError:
        return {"ok": False, "error": "timeout"}
    except aiohttp.ClientError:
        return {"ok": False, "error": "network"}
    return _parse_xon(data)


def _parse_xon(data: object) -> dict:
    empty = {"ok": True, "found": False, "sites": [], "details": [], "exposed": [], "risk": None, "pastes": 0}
    if not isinstance(data, dict) or "Error" in data:
        return empty

    summary = data.get("BreachesSummary") or {}
    sites = [s.strip() for s in str(summary.get("site") or "").split(";") if s.strip()]

    details: list[dict] = []
    breached = data.get("ExposedBreaches")
    if isinstance(breached, dict):
        details = [d for d in (breached.get("breaches_details") or []) if isinstance(d, dict)]

    exposed: list[tuple[str, int]] = []
    risk = None
    metrics = data.get("BreachMetrics")
    if isinstance(metrics, dict):
        def walk(nodes: list) -> None:
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                children = node.get("children")
                if children:
                    walk(children)
                else:
                    value = node.get("value")
                    if isinstance(value, int) and value > 0:
                        exposed.append((label(str(node.get("name") or "")), value))

        walk(metrics.get("xposed_data") or [])
        risk_list = metrics.get("risk") or []
        if risk_list and isinstance(risk_list[0], dict):
            risk = risk_list[0]
    exposed.sort(key=lambda item: item[1], reverse=True)

    pastes = 0
    paste_summary = data.get("PastesSummary")
    if isinstance(paste_summary, dict):
        try:
            pastes = int(paste_summary.get("cnt") or 0)
        except (TypeError, ValueError):
            pastes = 0

    return {
        "ok": True,
        "found": bool(sites or details),
        "sites": sites,
        "details": details,
        "exposed": exposed,
        "risk": risk,
        "pastes": pastes,
    }


async def pwned_password(session: aiohttp.ClientSession, password: str) -> dict:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    url = "https://api.pwnedpasswords.com/range/" + prefix
    try:
        async with session.get(url, headers={"User-Agent": USER_AGENT}, timeout=PWNED_TIMEOUT) as resp:
            if resp.status != 200:
                return {"ok": False, "error": f"http_{resp.status}"}
            body = await resp.text()
    except asyncio.TimeoutError:
        return {"ok": False, "error": "timeout"}
    except aiohttp.ClientError:
        return {"ok": False, "error": "network"}
    for line in body.splitlines():
        hash_part, _, count = line.partition(":")
        if hash_part == suffix:
            try:
                return {"ok": True, "count": int(count)}
            except ValueError:
                return {"ok": True, "count": 0}
    return {"ok": True, "count": 0}


async def crt_subdomains(session: aiohttp.ClientSession, domain: str) -> dict:
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    try:
        async with _CRT_SEM:
            async with session.get(url, headers={"User-Agent": USER_AGENT}, timeout=CRT_TIMEOUT) as resp:
                if resp.status != 200:
                    return {"ok": False, "error": f"http_{resp.status}"}
                try:
                    rows = await resp.json(content_type=None)
                except ValueError:
                    return {"ok": False, "error": "bad_json"}
    except asyncio.TimeoutError:
        return {"ok": False, "error": "timeout"}
    except aiohttp.ClientError:
        return {"ok": False, "error": "network"}

    names: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.").strip(".")
            if name and name.endswith("." + domain):
                names.add(name)
    return {"ok": True, "names": sorted(names)[:500]}


SOCIAL_SITES = (
    "site:vk.com OR site:ok.ru OR site:instagram.com OR site:t.me "
    "OR site:facebook.com OR site:twitter.com OR site:x.com"
)


def trace_links(identifier: str) -> list[tuple[str, str]]:
    q = identifier.strip()
    quoted = f'"{q}"'
    docs = f'{quoted} (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx)'
    social = f"{quoted} ({SOCIAL_SITES})"
    return [
        ("Google", "https://www.google.com/search?q=" + urllib.parse.quote(quoted)),
        ("Яндекс", "https://yandex.ru/search/?text=" + urllib.parse.quote(quoted)),
        ("DuckDuckGo", "https://duckduckgo.com/?q=" + urllib.parse.quote(quoted)),
        ("Google: соцсети", "https://www.google.com/search?q=" + urllib.parse.quote(social)),
        ("Google: документы", "https://www.google.com/search?q=" + urllib.parse.quote(docs)),
        ("GitHub", "https://github.com/search?q=" + urllib.parse.quote(quoted) + "&type=code"),
    ]
