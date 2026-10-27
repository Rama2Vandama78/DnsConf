#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apply_pins.py — авто-пины вырезанных зон в NextDNS + гигиена зон + уборка мусора.

Кто чем владеет:
  - воркер DnsConf (04:30 МСК) — весь redirect_filtered.hosts (донор-хилинг);
    зон-доменов в списке нет, поэтому воркер их реврайтов не создаёт, не лечит
    и не удаляет: пины живут своей жизнью и воркеру не видны.
  - этот скрипт (05:05 МСК) — 6 вырезанных зон (chatgpt/grok-кластер) целиком:
    * ставит недостающие пины (POST) и чинит сбитые (PUT);
    * гигиена зон: удаляет любой зон-реврайт, которого нет в списке пинов
      (мусор www.oaistatic.com / oaiusercontent.com / www.oaiusercontent.com и
      протухшие зеркала убираются автоматически);
    * перед установкой проверяет живость IP (SNI-проба): основной мёртв —
      chatgpt-пины откатываются на запасной, grok-пины — на второй IP;
    * оба IP мертвы — существующие пины не трогает (лучше протухший пин, чем
      его удаление: без пина домён получит реальный IP и DPI его придушит).

Ручные пины внутри зон скрипт считает мусором и удаляет: новые домены добавляй
в CHATGPT_PINS / GROK_PINS, а не руками в UI.

Секреты — те же, что у воркера (environment DNS):
  CLIENT_ID   — id профиля NextDNS (my.nextdns.io -> Endpoints)
  AUTH_SECRET — API-ключ NextDNS (my.nextdns.io/account); воркер шлёт его
                заголовком X-Api-Key — этот скрипт делает так же.

Контракт API повторяет воркер (NextDnsRewriteClient, RewriteDto/CreateRewriteDto):
  GET    /profiles/{id}/rewrites       -> {"data": [{"id","name","content"}]}
  POST   /profiles/{id}/rewrites      <- {"name": домен, "content": ip}
  PUT    /profiles/{id}/rewrites/{id} <- {"name": домен, "content": ip}
  DELETE /profiles/{id}/rewrites/{id}
Лимит — 60 запросов/мин, окно сбрасывается через 60 с после последнего запроса:
временные коды (429/524/5xx) повторяем через 60 с до 3 попыток, между мутациями
пауза 1.2 с. Ответ 200 с телом {"errors": ...} считается ошибкой (как у воркера).

Идемпотентен: хоть каждый день запускай — лишнего не сделает.
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

API = "https://api.nextdns.io/profiles"
CLIENT_ID = os.environ.get("CLIENT_ID", "").strip()
API_KEY = os.environ.get("AUTH_SECRET", "").strip()
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0"
ALIVE_CODES = {"200", "301", "302", "307", "308", "400", "403", "404", "421"}

IP_PRIMARY = "143.20.64.192"   # chatgpt-кластер: Дом.ру-доказан (T32/T37/T40)
IP_BACKUP = "181.215.40.49"    # запасной для chatgpt + основной для grok (T37/T39)

ZONES = ["chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com",
         "grok.com", "x.ai"]

CHATGPT_PINS = [
    "chatgpt.com", "www.chatgpt.com", "ab.chatgpt.com", "operator.chatgpt.com",
    "sora.chatgpt.com", "webrtc.chatgpt.com",
    "oaistatic.com", "cdn.oaistatic.com",
    "files.oaiusercontent.com", "sdmntprpolandcentral.oaiusercontent.com",
    "sdmntpritalynorth.oaiusercontent.com", "sdmntprnortheu.oaiusercontent.com",
    "sdmntprukwest.oaiusercontent.com",
    "openai.com", "www.openai.com", "api.openai.com", "auth.openai.com",
    "auth0.openai.com", "platform.openai.com", "cdn.platform.openai.com",
    "chat.openai.com", "android.chat.openai.com", "ios.chat.openai.com",
    "tcr9i.chat.openai.com", "developers.openai.com", "bps.openai.com",
    "videos.openai.com",
]
GROK_PINS = [
    "grok.com", "www.grok.com", "assets.grok.com",
    "accounts.x.ai", "api.x.ai", "x.ai", "www.x.ai",
    "assets.x.ai", "console.x.ai", "grok.x.ai",
]

PIN_SET = {d.lower() for d in CHATGPT_PINS + GROK_PINS}
PACING = 1.2          # сек между мутациями — держимся под лимитом 60/мин
RETRY_DELAY = 60      # окно rate-limit NextDNS: 60 с после последнего запроса
RETRY_ATTEMPTS = 3


def sni_alive(host, ip, timeout=8):
    """SNI-проба как в T39: жив ли vhost host на IP."""
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
           "--resolve", f"{host}:443:{ip}", "--max-time", str(timeout),
           "-A", UA, f"https://{host}/"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 6)
        return out.stdout.strip() in ALIVE_CODES
    except Exception:
        return False


def body_errors(body):
    """NextDNS умеет отвечать 200 с телом-ошибкой — воркер это проверяет."""
    return isinstance(body, dict) and bool(body.get("errors"))


def api(method, path, payload=None, attempt=1):
    """Вызов NextDNS API. 429/524/5xx — временные: ждём 60 с и повторяем."""
    req = urllib.request.Request(
        f"{API}/{CLIENT_ID}{path}",
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers={"X-Api-Key": API_KEY, "Content-Type": "application/json",
                 "User-Agent": "dnsconf-pins/1.1"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            body = json.loads(raw) if raw.strip() else None
            return r.status, body
    except urllib.error.HTTPError as e:
        code = e.code
        if (code in (429, 524) or code >= 500) and attempt < RETRY_ATTEMPTS:
            print(f"    {method} {path}: {code}, жду {RETRY_DELAY} c "
                  f"(попытка {attempt + 1}/{RETRY_ATTEMPTS})")
            time.sleep(RETRY_DELAY)
            return api(method, path, payload, attempt + 1)
        try:
            detail = e.read().decode()[:200]
        except Exception:
            detail = ""
        return code, detail
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"


def in_zone(domain):
    d = domain.lower().rstrip(".")
    return any(d == z or d.endswith("." + z) for z in ZONES)


def main():
    if not CLIENT_ID or not API_KEY:
        print("Нет CLIENT_ID/AUTH_SECRET — добавь секреты в environment DNS (как у воркера).")
        return 1

    # --- 1) живость пин-IP ---------------------------------------------------
    print("[1] SNI-проверка пин-IP...")
    chatgpt_ip = None
    if sni_alive("chatgpt.com", IP_PRIMARY):
        chatgpt_ip = IP_PRIMARY
        print(f"    chatgpt-пины -> {IP_PRIMARY} (жив)")
    elif sni_alive("chatgpt.com", IP_BACKUP):
        chatgpt_ip = IP_BACKUP
        print(f"    ВНИМАНИЕ: {IP_PRIMARY} мёртв -> chatgpt-пины на {IP_BACKUP}")
    else:
        print(f"    {IP_PRIMARY} и {IP_BACKUP} оба мертвы -> chatgpt-пины НЕ трогаю.")
    grok_ip = None
    if sni_alive("grok.com", IP_BACKUP):
        grok_ip = IP_BACKUP
        print(f"    grok-пины -> {IP_BACKUP} (жив)")
    elif sni_alive("grok.com", IP_PRIMARY):
        grok_ip = IP_PRIMARY
        print(f"    ВНИМАНИЕ: {IP_BACKUP} мёртв -> grok-пины на {IP_PRIMARY}")
    else:
        print("    оба IP мертвы для grok -> grok-пины НЕ трогаю.")

    # --- 2) существующие реврайты --------------------------------------------
    print("[2] Читаю реврайты из NextDNS...")
    status, existing = api("GET", "/rewrites")
    if status != 200:
        print(f"    ОШИБКА API ({status}): {existing}")
        if status in (401, 403):
            print("    AUTH_SECRET не принят как API-ключ NextDNS.")
            print("    Проверь ключ на my.nextdns.io/account (тот же, что у воркера),")
            print("    или поставь пины руками через UI my.nextdns.io.")
        return 1
    if isinstance(existing, dict):
        existing = existing.get("data") or existing.get("items") or []
    by_domain = {}
    for item in existing:
        if not isinstance(item, dict):
            continue
        d = str(item.get("name") or "").lower().strip()
        if d:
            by_domain[d] = {"id": item.get("id"),
                            "ip": str(item.get("content") or "")}
    print(f"    найдено реврайтов: {len(by_domain)}")

    # --- 3) ставим/чиним пины -------------------------------------------------
    created = updated = kept = errors = 0
    jobs = []
    if chatgpt_ip:
        jobs += [(d, chatgpt_ip) for d in CHATGPT_PINS]
    if grok_ip:
        jobs += [(d, grok_ip) for d in GROK_PINS]
    for domain, ip in jobs:
        cur = by_domain.get(domain.lower())
        if cur is None:
            st, body = api("POST", "/rewrites", {"name": domain, "content": ip})
            if st in (200, 201) and not body_errors(body):
                created += 1
                print(f"    + {domain} -> {ip}")
            else:
                errors += 1
                print(f"    ! {domain}: POST {st} {body}")
            time.sleep(PACING)
        elif cur["ip"] != ip:
            st, body = api("PUT", f"/rewrites/{cur['id']}",
                           {"name": domain, "content": ip})
            if st in (200, 204) and not body_errors(body):
                updated += 1
                print(f"    * {domain}: {cur['ip']} -> {ip}")
            else:
                errors += 1
                print(f"    ! {domain}: PUT {st} {body}")
            time.sleep(PACING)
        else:
            kept += 1

    # --- 4) гигиена зон: мусор и протухшие зон-реврайты ------------------------
    deleted = 0
    for d, cur in by_domain.items():
        if d in PIN_SET or not cur["id"] or not in_zone(d):
            continue
        st, body = api("DELETE", f"/rewrites/{cur['id']}")
        if st in (200, 204) and not body_errors(body):
            deleted += 1
            print(f"    - гигиена зон: удалён {d} ({cur['ip']})")
        else:
            errors += 1
            print(f"    ! гигиена {d}: DELETE {st} {body}")
        time.sleep(PACING)

    print(f"[3] Итог: создано {created}, обновлено {updated}, уже ок {kept}, "
          f"удалено мусора/трупов {deleted}, ошибок {errors}")
    if chatgpt_ip or grok_ip:
        print(f"    chatgpt-кластер -> {chatgpt_ip or 'без изменений'}; "
              f"grok-кластер -> {grok_ip or 'без изменений'}")
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
