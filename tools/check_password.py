"""Локальная проверка пароля по базе HaveIBeenPwned (k-anonymity).

Пароль не покидает компьютер: наружу уходят только первые 5 символов SHA-1.
"""
from __future__ import annotations

import getpass
import hashlib
import urllib.request

API = "https://api.pwnedpasswords.com/range/"
HEADERS = {"User-Agent": "selfcheck-local"}


def pwned_count(password: str) -> int:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    request = urllib.request.Request(API + prefix, headers=HEADERS)
    with urllib.request.urlopen(request, timeout=20) as response:
        body = response.read().decode("utf-8", "replace")
    for line in body.splitlines():
        hash_part, _, count = line.partition(":")
        if hash_part == suffix:
            return int(count)
    return 0


def report(password: str) -> None:
    try:
        count = pwned_count(password)
    except Exception as exc:
        print(f"Не удалось проверить: {exc}")
        return
    if count:
        print(f"⚠️  Пароль найден в утечках {count:,} раз. Не используйте его — смените везде, где он стоит.".replace(",", " "))
    else:
        print("✅ Этого пароля нет в базе HIBP. Это не гарантия стойкости — просто он ещё не засветился.")


def main() -> None:
    print("Проверка пароля по базе утечек HIBP.")
    print("Пароль не отправляется целиком: уходит только первые 5 символов SHA-1.\n")
    while True:
        try:
            password = getpass.getpass("Пароль (ввод скрыт, пусто — выход): ")
        except (KeyboardInterrupt, EOFError):
            print("\nВыход.")
            return
        if not password:
            return
        report(password)
        print()


if __name__ == "__main__":
    main()
