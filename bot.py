from __future__ import annotations

import asyncio
import html
import logging
import os
import re
import time
import urllib.parse
from pathlib import Path

import aiohttp
from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    BotCommand,
    CallbackQuery,
    ErrorEvent,
    FSInputFile,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
    ReplyKeyboardMarkup,
)
from aiogram.utils.keyboard import InlineKeyboardBuilder, ReplyKeyboardBuilder

import checks
import db
from cleanup import CHECKLIST, CONSENT_TEXT

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
WELCOME_IMG = BASE_DIR / "assets" / "welcome.jpg"


def load_env(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


load_env(BASE_DIR / ".env")
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("chistiy-sled")

router = Router()
_last_check: dict[tuple[int, str], float] = {}
_email_cache: dict[tuple[int, str], tuple[float, str]] = {}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$")
DOMAIN_RE = re.compile(r"^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

RISK_RU = {
    "critical": ("🔴", "критический"),
    "high": ("🟠", "высокий"),
    "moderate": ("🟡", "средний"),
    "low": ("🟢", "низкий"),
}

TEMPLATE_TITLES = {
    "site_removal": "Требование сайту удалить персональные данные",
    "hosting_abuse": "Жалоба хостеру (abuse)",
    "search_engines": "Как подать заявление в поисковики и РКН",
}

BTN_SELF = "🛡 Проверить себя"
BTN_CLEAN = "🧹 Зачистка"
BTN_DOMAIN = "🌐 Мой домен"
BTN_TEMPLATES = "📄 Шаблоны"
BTN_REPORT = "📊 Отчёт"
BTN_HELP = "ℹ️ Помощь"

HOME_TEXT = (
    "🛡 <b>Чистый след</b>\n\n"
    "Проверяю, что о вас видно в сети, и помогаю это закрыть.\n\n"
    "Бесплатно. Только ваши данные.\n"
    "Выберите раздел кнопками ниже — писать ничего не нужно."
)

SELF_TEXT = "🛡 <b>Проверить себя</b>\n\nЧто проверим?"


class EmailStates(StatesGroup):
    waiting = State()


class PasswordStates(StatesGroup):
    waiting = State()


class TraceStates(StatesGroup):
    waiting = State()


class DomainStates(StatesGroup):
    waiting = State()
    confirm = State()


def approved(uid: int) -> bool:
    user = db.get_user(uid)
    return bool(user and user["consent"])


def cooldown_ok(uid: int, action: str = "default", seconds: float = 8.0) -> bool:
    key = (uid, action)
    now = time.monotonic()
    if now - _last_check.get(key, 0.0) < seconds:
        return False
    _last_check[key] = now
    return True


async def say(target: Message | CallbackQuery, text: str, **kwargs) -> None:
    if isinstance(target, CallbackQuery):
        if target.message:
            await target.message.answer(text, **kwargs)
        else:
            await target.bot.send_message(target.from_user.id, text, **kwargs)
    else:
        await target.answer(text, **kwargs)


async def require_consent(target: Message | CallbackQuery) -> bool:
    if approved(target.from_user.id):
        return True
    text = "Сначала подтвердите, что проверяете свои данные: /start"
    if isinstance(target, CallbackQuery):
        try:
            await target.answer(text, show_alert=True)
        except TelegramBadRequest:
            pass
    else:
        await target.answer(text)
    return False


def nav_kb() -> ReplyKeyboardMarkup:
    kb = ReplyKeyboardBuilder()
    kb.button(text=BTN_SELF)
    kb.button(text=BTN_CLEAN)
    kb.button(text=BTN_DOMAIN)
    kb.button(text=BTN_TEMPLATES)
    kb.button(text=BTN_REPORT)
    kb.button(text=BTN_HELP)
    kb.adjust(2, 2, 2)
    return kb.as_markup(
        resize_keyboard=True,
        is_persistent=True,
        input_field_placeholder="Выберите раздел ниже",
    )


def consent_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="✅ Это мои данные", callback_data="consent:yes")],
            [InlineKeyboardButton(text="❌ Отмена", callback_data="consent:no")],
        ]
    )


def self_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="📧 Утечки по email", callback_data="act:email"),
                InlineKeyboardButton(text="🔑 Пароль", callback_data="act:password"),
            ],
            [InlineKeyboardButton(text="🔎 Поисковые следы", callback_data="act:trace")],
            [InlineKeyboardButton(text="🏠 Главная", callback_data="act:home")],
        ]
    )


def home_inline() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🛡 Проверить себя", callback_data="act:self")],
        ]
    )


async def send_home(target: Message | CallbackQuery, photo: bool = False) -> None:
    message = target.message if isinstance(target, CallbackQuery) else target
    if photo and WELCOME_IMG.exists():
        await message.answer_photo(FSInputFile(WELCOME_IMG), caption=HOME_TEXT, reply_markup=nav_kb())
        return
    await message.answer(HOME_TEXT, reply_markup=nav_kb())


async def send_self_menu(target: Message | CallbackQuery) -> None:
    await say(target, SELF_TEXT, reply_markup=self_kb())


async def send_help(target: Message | CallbackQuery) -> None:
    await say(
        target,
        "ℹ️ <b>Как это работает</b>\n\n"
        "Всё бесплатно:\n"
        "• email — открытая база XposedOrNot\n"
        "• пароль — HIBP Pwned Passwords (k-anonymity, сам пароль не отправляется)\n"
        "• домен — публичные CT-логи crt.sh\n\n"
        "Бот работает только с вашими данными и не ищет людей.\n\n"
        "«Стереть всё» из утечек невозможно: данные из дампов не отзываются. "
        "Чек-лист показывает реальный максимум — сменить доступы, убрать из выдачи, подать заявления.\n\n"
        "Команды не обязательны — всё есть на кнопках.",
        reply_markup=InlineKeyboardMarkup(
            inline_keyboard=[[InlineKeyboardButton(text="🏠 Главная", callback_data="act:home")]]
        ),
    )


def cleanup_view(uid: int, index: int) -> tuple[str, InlineKeyboardMarkup]:
    total = len(CHECKLIST)
    index = max(0, min(index, total - 1))
    done = db.done_items(uid)
    done_count = sum(1 for item in CHECKLIST if item["id"] in done)
    item = CHECKLIST[index]
    is_done = item["id"] in done

    text = (
        f"🧹 <b>План зачистки</b> · {index + 1}/{total} · выполнено {done_count}/{total}\n\n"
        f"{'✅ ' if is_done else ''}<b>{html.escape(item['title'])}</b>\n\n"
        f"{item['desc']}"
    )
    rows = [[InlineKeyboardButton(text=label, url=url)] for label, url in item["links"]]
    rows.append(
        [
            InlineKeyboardButton(
                text="↩️ Снять отметку" if is_done else "✅ Готово",
                callback_data=f"clean:toggle:{index}",
            )
        ]
    )
    nav = []
    if index > 0:
        nav.append(InlineKeyboardButton(text="◀️", callback_data=f"clean:page:{index - 1}"))
    nav.append(InlineKeyboardButton(text=f"{index + 1}/{total}", callback_data="clean:noop"))
    if index < total - 1:
        nav.append(InlineKeyboardButton(text="▶️", callback_data=f"clean:page:{index + 1}"))
    rows.append(nav)
    rows.append([InlineKeyboardButton(text="🏠 Главная", callback_data="act:home")])
    return text, InlineKeyboardMarkup(inline_keyboard=rows)


async def start_cleanup(target: Message | CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    text, kb = cleanup_view(target.from_user.id, 0)
    await say(target, text, reply_markup=kb)


def report_text(uid: int) -> str:
    user = db.get_user(uid)
    done = db.done_items(uid)
    done_count = sum(1 for item in CHECKLIST if item["id"] in done)
    lines = ["📊 <b>Ваш отчёт</b>", ""]
    if user and user["last_email"]:
        risk = user["last_risk"]
        _, risk_ru = RISK_RU.get(str(risk or "").lower(), ("", ""))
        risk_text = f" · риск: {risk_ru}" if risk_ru else ""
        lines.append(
            f"📧 <code>{html.escape(user['last_email'])}</code>\n"
            f"   Утечек: <b>{user['last_breaches']}</b>{risk_text} · {user['last_check_at']}"
        )
    else:
        lines.append("📧 Email ещё не проверялся")
    lines.append(f"🧹 План зачистки: <b>{done_count}/{len(CHECKLIST)}</b>")
    nxt = next((item for item in CHECKLIST if item["id"] not in done), None)
    if nxt:
        lines.append(f"Следующий шаг: <b>{html.escape(nxt['title'])}</b>")
    else:
        lines.append("✅ Все пункты закрыты.")
    lines += ["", "Данные из утёкших баз удалить нельзя — можно снизить риск. Пункт 8 в плане."]
    return "\n".join(lines)


async def send_report(target: Message | CallbackQuery, state: FSMContext | None = None) -> None:
    if state:
        await state.clear()
    uid = target.from_user.id
    await say(
        target,
        report_text(uid),
        reply_markup=InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    InlineKeyboardButton(text="🧹 План зачистки", callback_data="act:cleanup"),
                    InlineKeyboardButton(text="🛡 Проверить себя", callback_data="act:self"),
                ]
            ]
        ),
    )


async def send_templates(target: Message | CallbackQuery) -> None:
    paths = sorted(TEMPLATES_DIR.glob("*.txt"))
    if not paths:
        await say(target, "Шаблоны не найдены — проверьте папку templates в каталоге бота.")
        return
    message = target.message if isinstance(target, CallbackQuery) else target
    await say(target, "📄 <b>Шаблоны заявлений</b>\n\nЗамените [скобки] на свои данные перед отправкой.")
    for path in paths:
        caption = TEMPLATE_TITLES.get(path.stem, path.stem)
        await message.answer_document(FSInputFile(path), caption=caption)


def fmt_email(email: str, data: dict) -> str:
    risk = data.get("risk") or {}
    emoji, risk_ru = RISK_RU.get(str(risk.get("risk_label") or "").lower(), ("⚪", "неизвестен"))
    score = risk.get("risk_score")
    risk_line = f"{emoji} Риск: <b>{risk_ru}</b>" + (f" · {score}/100" if isinstance(score, int) else "")
    total = len(data["sites"]) or len(data["details"])
    pastes = data.get("pastes") or 0

    lines = [
        "🔓 <b>Утечки найдены</b>",
        f"<code>{html.escape(email)}</code>",
        "",
        risk_line,
        f"Утечек: <b>{total}</b>" + (f" · паст: {pastes}" if pastes else ""),
        "",
    ]
    exposed = data.get("exposed") or []
    if exposed:
        lines.append("<b>Что утекло</b>")
        for name, value in exposed[:8]:
            lines.append(f"• {html.escape(name)} — {value}")
        if len(exposed) > 8:
            lines.append(f"…и ещё {len(exposed) - 8} категорий")
        lines.append("")
    details = sorted(
        data["details"],
        key=lambda d: (str(d.get("verified")) == "Yes", str(d.get("xposed_date") or "")),
        reverse=True,
    )
    if details:
        lines.append("<b>Крупные утечки</b>")
        for item in details[:4]:
            name = html.escape(str(item.get("breach") or "—"))
            year = html.escape(str(item.get("xposed_date") or ""))
            tail = ", ".join(checks.breach_data_ru(str(item.get("xposed_data") or ""))[:4])
            line = f"• <b>{name}</b>" + (f" · {year}" if year else "")
            if tail:
                line += f"\n  {html.escape(tail)}"
            lines.append(line)
        lines.append("")
    lines += [
        "<b>Что делать</b>",
        "1. Смените пароль от этой почты и от всех сервисов, где он повторялся.",
        "2. Включите 2FA.",
        "3. Если утекли документы — пройдите план зачистки.",
    ]
    return "\n".join(lines)


def fmt_not_found(email: str) -> str:
    return (
        "✅ <b>Утечек не найдено</b>\n"
        f"<code>{html.escape(email)}</code>\n\n"
        "Хороший знак, но не гарантия: базы покрывают не всё. "
        "Проверьте пароли и пройдите план зачистки."
    )


def fmt_domain(domain: str, names: list[str]) -> str:
    lines = [f"🌐 <b>{html.escape(domain)}</b>"]
    if names:
        lines.append(f"Поддоменов в CT-логах: <b>{len(names)}</b>\n")
        for name in names[:30]:
            lines.append(f"• <code>{html.escape(name)}</code>")
        if len(names) > 30:
            lines.append(f"…и ещё {len(names) - 30}.")
    else:
        lines.append("Поддомены в CT-логах не найдены (возможно, wildcard-сертификат).")
    lines += [
        "",
        "CT-логи публичны: по ним видно инфраструктуру, которую вы могли забыть, — тестовые и старые стенды. Проверьте, что всё ещё нужно и закрыто.",
    ]
    return "\n".join(lines)


def domain_links(domain: str) -> InlineKeyboardMarkup:
    q = urllib.parse.quote(domain)
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="crt.sh", url=f"https://crt.sh/?q=%25.{q}")],
            [InlineKeyboardButton(text="Shodan", url=f"https://www.shodan.io/search?q={q}")],
            [InlineKeyboardButton(text="Google: site:", url="https://www.google.com/search?q=" + urllib.parse.quote("site:" + domain))],
            [InlineKeyboardButton(text="🏠 Главная", callback_data="act:home")],
        ]
    )


async def start_email(target: Message | CallbackQuery, state: FSMContext) -> None:
    await state.set_state(EmailStates.waiting)
    await say(
        target,
        "📧 Пришлите email — проверю утечки по бесплатной открытой базе.\n\n"
        "Обычно 5–15 секунд. /cancel — отмена.",
    )


async def start_password(target: Message | CallbackQuery, state: FSMContext) -> None:
    await state.set_state(PasswordStates.waiting)
    await say(
        target,
        "🔑 <b>Проверка пароля</b>\n\n"
        "Отправьте пароль одним сообщением — я сразу удалю его из чата и проверю по базе утечек. "
        "Нигде не сохраняется.\n\n"
        "Если это пароль от почты или банка — не рискуйте, используйте файл "
        "<code>tools\\check_password.bat</code> в папке бота.\n\n"
        "Проверка бесплатная. /cancel — отмена.",
    )


async def start_trace(target: Message | CallbackQuery, state: FSMContext) -> None:
    await state.set_state(TraceStates.waiting)
    await say(
        target,
        "🔎 Пришлите email, телефон, старый ник или ФИО — соберу поисковые запросы.\n\n"
        "Бот ничего не собирает сам: вы сами откроете ссылки. /cancel — отмена.",
    )


async def start_domain(target: Message | CallbackQuery, state: FSMContext) -> None:
    await state.set_state(DomainStates.waiting)
    await say(
        target,
        "🌐 Пришлите домен, который принадлежит вам (например, example.ru).\n\n"
        "Проверяю публичные CT-логи. /cancel — отмена.",
    )


@router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext) -> None:
    await state.clear()
    db.ensure_user(message.from_user.id)
    if approved(message.from_user.id):
        await send_home(message, photo=True)
    else:
        await message.answer(CONSENT_TEXT, reply_markup=consent_kb())


@router.message(Command("help"))
async def cmd_help(message: Message, state: FSMContext) -> None:
    await state.clear()
    await send_help(message)


@router.message(Command("cancel"))
async def cmd_cancel(message: Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer("Ок, отменил. Выберите раздел кнопкой ниже 👇", reply_markup=nav_kb())


@router.message(Command("email"))
async def cmd_email(message: Message, state: FSMContext) -> None:
    await state.clear()
    if await require_consent(message):
        await start_email(message, state)


@router.message(Command("password"))
async def cmd_password(message: Message, state: FSMContext) -> None:
    await state.clear()
    if await require_consent(message):
        await start_password(message, state)


@router.message(Command("trace"))
async def cmd_trace(message: Message, state: FSMContext) -> None:
    await state.clear()
    if await require_consent(message):
        await start_trace(message, state)


@router.message(Command("domain"))
async def cmd_domain(message: Message, state: FSMContext) -> None:
    await state.clear()
    if await require_consent(message):
        await start_domain(message, state)


@router.message(Command("cleanup"))
async def cmd_cleanup(message: Message, state: FSMContext) -> None:
    if not await require_consent(message):
        return
    await start_cleanup(message, state)


@router.message(Command("templates"))
async def cmd_templates(message: Message, state: FSMContext) -> None:
    await state.clear()
    if await require_consent(message):
        await send_templates(message)


@router.message(Command("report"))
async def cmd_report(message: Message, state: FSMContext) -> None:
    if not await require_consent(message):
        return
    await send_report(message, state)


@router.message(F.text == BTN_SELF)
async def btn_self(message: Message, state: FSMContext) -> None:
    await state.clear()
    if not await require_consent(message):
        return
    await send_self_menu(message)


@router.message(F.text == BTN_CLEAN)
async def btn_clean(message: Message, state: FSMContext) -> None:
    if not await require_consent(message):
        return
    await start_cleanup(message, state)


@router.message(F.text == BTN_DOMAIN)
async def btn_domain(message: Message, state: FSMContext) -> None:
    await state.clear()
    if await require_consent(message):
        await start_domain(message, state)


@router.message(F.text == BTN_TEMPLATES)
async def btn_templates(message: Message, state: FSMContext) -> None:
    await state.clear()
    if await require_consent(message):
        await send_templates(message)


@router.message(F.text == BTN_REPORT)
async def btn_report(message: Message, state: FSMContext) -> None:
    if not await require_consent(message):
        return
    await send_report(message, state)


@router.message(F.text == BTN_HELP)
async def btn_help(message: Message, state: FSMContext) -> None:
    await state.clear()
    await send_help(message)


@router.callback_query(F.data == "consent:yes")
async def cb_consent_yes(call: CallbackQuery) -> None:
    db.set_consent(call.from_user.id, True)
    try:
        await call.message.edit_text("✅ Подтверждено.")
    except TelegramBadRequest:
        pass
    await send_home(call, photo=True)
    await call.answer()


@router.callback_query(F.data == "consent:no")
async def cb_consent_no(call: CallbackQuery) -> None:
    try:
        await call.message.edit_text(
            "Ок. Без подтверждения бот ничего не проверяет — это защита от использования для чужих данных."
        )
    except TelegramBadRequest:
        pass
    await call.answer()


@router.callback_query(F.data == "act:home")
async def cb_home(call: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    if not await require_consent(call):
        return
    await send_home(call)
    await call.answer()


@router.callback_query(F.data == "act:self")
async def cb_self(call: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    if not await require_consent(call):
        return
    await send_self_menu(call)
    await call.answer()


@router.callback_query(F.data == "act:email")
async def cb_email(call: CallbackQuery, state: FSMContext) -> None:
    if not await require_consent(call):
        return
    await call.answer()
    await state.clear()
    await start_email(call, state)


@router.callback_query(F.data == "act:password")
async def cb_password(call: CallbackQuery, state: FSMContext) -> None:
    if not await require_consent(call):
        return
    await call.answer()
    await state.clear()
    await start_password(call, state)


@router.callback_query(F.data == "act:trace")
async def cb_trace(call: CallbackQuery, state: FSMContext) -> None:
    if not await require_consent(call):
        return
    await call.answer()
    await state.clear()
    await start_trace(call, state)


@router.callback_query(F.data == "act:cleanup")
async def cb_cleanup(call: CallbackQuery, state: FSMContext) -> None:
    if not await require_consent(call):
        return
    await start_cleanup(call, state)
    await call.answer()


@router.callback_query(F.data == "act:report")
async def cb_report(call: CallbackQuery, state: FSMContext) -> None:
    if not await require_consent(call):
        return
    await send_report(call, state)
    await call.answer()


@router.callback_query(F.data.startswith("clean:page:"))
async def cb_clean_page(call: CallbackQuery) -> None:
    if not await require_consent(call):
        return
    try:
        index = int(call.data.rsplit(":", 1)[1])
    except (ValueError, IndexError):
        await call.answer()
        return
    text, kb = cleanup_view(call.from_user.id, index)
    try:
        await call.message.edit_text(text, reply_markup=kb)
    except TelegramBadRequest:
        await call.message.answer(text, reply_markup=kb)
    await call.answer()


@router.callback_query(F.data.startswith("clean:toggle:"))
async def cb_clean_toggle(call: CallbackQuery) -> None:
    if not await require_consent(call):
        return
    try:
        index = int(call.data.rsplit(":", 1)[1])
    except (ValueError, IndexError):
        await call.answer()
        return
    index = max(0, min(index, len(CHECKLIST) - 1))
    now_done = db.toggle_item(call.from_user.id, CHECKLIST[index]["id"])
    text, kb = cleanup_view(call.from_user.id, index)
    try:
        await call.message.edit_text(text, reply_markup=kb)
    except TelegramBadRequest:
        await call.message.answer(text, reply_markup=kb)
    await call.answer("Отмечено" if now_done else "Снято")


@router.callback_query(F.data == "clean:noop")
async def cb_clean_noop(call: CallbackQuery) -> None:
    await call.answer()


@router.message(EmailStates.waiting)
async def email_input(message: Message, state: FSMContext) -> None:
    text = (message.text or "").strip().lower()
    if text.startswith("/"):
        await state.clear()
        await message.answer("Ок, отменил. Выберите раздел кнопкой ниже 👇", reply_markup=nav_kb())
        return
    if not EMAIL_RE.match(text) or len(text) > 254:
        await message.answer("Это не похоже на email. Пример: name@example.com. Ещё раз или /cancel.")
        return
    await state.clear()
    if not cooldown_ok(message.from_user.id, "email", 20):
        await message.answer("Слишком часто — подождите пару секунд и попробуйте снова.")
        return

    cache_key = (message.from_user.id, text)
    cached = _email_cache.get(cache_key)
    if cached and time.monotonic() - cached[0] < 600:
        await message.answer(cached[1], reply_markup=email_result_kb())
        return

    status = await message.answer("Проверяю утечки…")
    async with aiohttp.ClientSession() as session:
        result = await checks.xon_email(session, text)
    if not result["ok"]:
        errors = {
            "rate_limit": "База сейчас ограничивает запросы. Подождите минуту и попробуйте снова.",
            "timeout": "База не ответила вовремя. Попробуйте позже.",
            "network": "Сетевая ошибка. Попробуйте позже.",
        }
        await status.edit_text(errors.get(result["error"], f"Сервис вернул ошибку ({html.escape(result['error'])})."))
        return

    if result["found"]:
        text_out = fmt_email(text, result)
        risk = result.get("risk") or {}
        risk_label = str(risk.get("risk_label") or "").lower() or None
        breaches = len(result["sites"]) or len(result["details"])
        db.save_email_check(message.from_user.id, text, breaches, risk_label)
    else:
        text_out = fmt_not_found(text)
        db.save_email_check(message.from_user.id, text, 0, None)

    _email_cache[cache_key] = (time.monotonic(), text_out)
    await status.edit_text(text_out[:4000], reply_markup=email_result_kb())


def email_result_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="🧹 План зачистки", callback_data="act:cleanup"),
                InlineKeyboardButton(text="📊 Отчёт", callback_data="act:report"),
            ]
        ]
    )


@router.message(PasswordStates.waiting)
async def password_input(message: Message, state: FSMContext) -> None:
    raw = message.text or ""
    if raw.strip().startswith("/"):
        await state.clear()
        await message.answer("Ок, отменил. Выберите раздел кнопкой ниже 👇", reply_markup=nav_kb())
        return
    deleted = True
    try:
        await message.delete()
    except TelegramBadRequest:
        deleted = False
    await state.clear()

    if not raw or len(raw) > 200:
        await message.answer(
            ("Пароль слишком длинный или пустой. " if raw else "Пустое сообщение. ")
            + ("Удалите сообщение вручную." if not deleted else "Отправьте пароль ещё раз или /cancel.")
        )
        return
    if not cooldown_ok(message.from_user.id, "password", 2):
        await message.answer("Слишком часто — подождите пару секунд.")
        return

    async with aiohttp.ClientSession() as session:
        result = await checks.pwned_password(session, raw)
    note = "" if deleted else "\n\n⚠️ Не смог удалить ваше сообщение — удалите вручную."
    if not result["ok"]:
        errors = {
            "timeout": "База не ответила вовремя.",
            "network": "Сетевая ошибка.",
        }
        await message.answer(errors.get(result["error"], "Сервис вернул ошибку.") + note)
        return
    count = result["count"]
    if count:
        pretty = f"{count:,}".replace(",", " ")
        text_out = (
            "⚠️ <b>Пароль засвечен</b>\n\n"
            f"Встречается в утечках <b>{pretty}</b> раз. Смените его везде, где он стоит, и включите 2FA."
            + note
        )
    else:
        text_out = (
            "✅ <b>Этот пароль в утечках не найден</b>\n\n"
            "Не гарантия стойкости: держите уникальные пароли в менеджере." + note
        )
    await message.answer(
        text_out,
        reply_markup=InlineKeyboardMarkup(
            inline_keyboard=[
                [InlineKeyboardButton(text="🧹 План зачистки", callback_data="act:cleanup")],
                [InlineKeyboardButton(text="🏠 Главная", callback_data="act:home")],
            ]
        ),
    )


@router.message(TraceStates.waiting)
async def trace_input(message: Message, state: FSMContext) -> None:
    text = (message.text or "").strip()
    if text.startswith("/"):
        await state.clear()
        await message.answer("Ок, отменил. Выберите раздел кнопкой ниже 👇", reply_markup=nav_kb())
        return
    if len(text) < 2 or len(text) > 120:
        await message.answer("Слишком короткий или длинный запрос (2–120 символов). Ещё раз или /cancel.")
        return
    await state.clear()
    kb = InlineKeyboardBuilder()
    for label, url in checks.trace_links(text):
        kb.button(text=label, url=url)
    kb.adjust(2, 2, 2)
    kb.row(InlineKeyboardButton(text="📧 Утечки по email", callback_data="act:email"))
    kb.row(InlineKeyboardButton(text="🏠 Главная", callback_data="act:home"))
    await message.answer(
        f"🔎 <b>Поисковые следы</b>\n\nЗапрос: <code>{html.escape(text)}</code>\n\n"
        "Кнопки ниже открывают обычные поисковые запросы — бот ничего не собирает и не хранит. "
        "Проверяйте только свои данные.",
        reply_markup=kb.as_markup(),
    )


@router.message(DomainStates.waiting)
async def domain_input(message: Message, state: FSMContext) -> None:
    text = (message.text or "").strip().lower()
    if text.startswith("/"):
        await state.clear()
        await message.answer("Ок, отменил. Выберите раздел кнопкой ниже 👇", reply_markup=nav_kb())
        return
    domain = re.sub(r"^https?://", "", text).split("/")[0].split(":")[0].strip(".")
    if not DOMAIN_RE.match(domain):
        await message.answer("Это не похоже на домен. Пример: example.ru. Ещё раз или /cancel.")
        return
    await state.update_data(domain=domain)
    await state.set_state(DomainStates.confirm)
    await message.answer(
        f"Проверю публичные CT-логи для <b>{html.escape(domain)}</b>.\n\n"
        "Подтвердите, что домен ваш: бот для собственной инфраструктуры.",
        reply_markup=InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    InlineKeyboardButton(text="✅ Да, мой домен", callback_data="domain:ok"),
                    InlineKeyboardButton(text="❌ Отмена", callback_data="domain:cancel"),
                ]
            ]
        ),
    )


@router.callback_query(F.data == "domain:ok")
async def cb_domain_ok(call: CallbackQuery, state: FSMContext) -> None:
    data = await state.get_data()
    domain = data.get("domain")
    await state.clear()
    if not domain:
        await call.answer("Домен потерялся, начните заново: кнопка «🌐 Мой домен»", show_alert=True)
        return
    await call.answer()
    try:
        await call.message.edit_reply_markup(reply_markup=None)
    except TelegramBadRequest:
        pass
    if not cooldown_ok(call.from_user.id, "domain"):
        await call.message.answer("Слишком часто — подождите пару секунд.")
        return
    status = await call.message.answer("Смотрю сертификаты в CT-логах… Это может занять до минуты.")
    async with aiohttp.ClientSession() as session:
        result = await checks.crt_subdomains(session, domain)
    if not result["ok"]:
        await status.edit_text(
            "Не удалось получить данные: crt.sh часто перегружен. Попробуйте через пару минут."
        )
        return
    await status.edit_text(fmt_domain(domain, result["names"]), reply_markup=domain_links(domain))


@router.callback_query(F.data == "domain:cancel")
async def cb_domain_cancel(call: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    try:
        await call.message.edit_text("Ок, отменил.")
    except TelegramBadRequest:
        await call.message.answer("Ок, отменил.")
    await call.answer()


@router.message(F.text)
async def fallback(message: Message) -> None:
    await message.answer("Выберите раздел кнопкой ниже 👇", reply_markup=nav_kb())


@router.errors()
async def on_error(event: ErrorEvent) -> bool:
    log.error("Unhandled error: %s", event.exception, exc_info=event.exception)
    return True


async def main() -> None:
    if not BOT_TOKEN:
        print(
            "Не задан BOT_TOKEN.\n"
            "1. Создайте файл .env в папке бота (можно скопировать .env.example).\n"
            "2. Вставьте токен из @BotFather: BOT_TOKEN=123456:AA...\n"
            "3. Запустите start.bat снова.\n"
        )
        return
    db.init(BASE_DIR / "data" / "bot.db")
    bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(router)
    await bot.set_my_commands(
        [
            BotCommand(command="start", description="Главное меню"),
            BotCommand(command="email", description="Утечки по email"),
            BotCommand(command="password", description="Проверить пароль"),
            BotCommand(command="trace", description="Поисковые следы"),
            BotCommand(command="domain", description="Поддомены домена"),
            BotCommand(command="cleanup", description="План зачистки"),
            BotCommand(command="templates", description="Шаблоны заявлений"),
            BotCommand(command="report", description="Отчёт"),
            BotCommand(command="help", description="Как это работает"),
        ]
    )
    await bot.delete_webhook(drop_pending_updates=True)
    log.info("Bot started")
    await dp.start_polling(bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        print("Остановлено.")
