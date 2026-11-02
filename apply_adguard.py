#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apply_adguard.py — карта зеркал RFL на personal AdGuard DNS одним PUT-ом.

Канал для телефона: «Частный DNS» = <hash>.d.adguard-dns.com (DoT/853,
который Дом.ру не режет — имя не брендовое, проверено тестом Б).
Этот скрипт — единственный источник правил сервера (замена воркера DnsConf
и apply_pins.py в новом канале; NextDNS-пайплайн остаётся холодным запасом).

Что делает каждый запуск:
  1. Флот-скан пинов chatgpt/grok/4pda (T67): PROVEN (Дом.ру-проверенные)
     -> свежие ответы донора -> известный флот; первое зеркало, прошедшее
     SNI-пробу, становится пином — ротация флота лечится сама (Т66). T68:
     КАЖДАЯ пин-зона сканируется отдельно — один общий пин кластеру ломал
     oaiusercontent.com, когда зеркало перестало обслуживать его vhost.
  2. Донор-хилинг: каждый домен redirect_filtered.hosts (минус 0.0.0.0-реклама,
     минус пин-зоны) спрашиваем у RFL DoH:
       * IP из флота зеркал  => домен зеркалится, нужно правило $dnsrewrite;
       * IP не из флота      => сверяем с dns.google: совпал/похож (та же /16)
                                => ИНЕРТНЫЙ реврайт, правило НЕ нужно — обычный
                                резолв AdGuard ответит так же; не совпал =>
                                новое зеркальное плечо, правило ставим.
       * приватный IP (10.x/192.168.x — внутренность RFL, T68) => не зеркало,
                                ответ пропускается (wiki/jira.last.fm).
     3. Коллапс: зона целиком во флоте и её апекс зеркалится => ОДНО правило
        ||зона^$dnsrewrite=NOERROR;A;<IP> (покрывает и все поддомены);
        зона смешанная => по правилу на зеркальный хост.
  4. SNI-верификация (T68): каждое A-правило пробуется на живость; мёртвое
     зеркало -> перепин на следующий ответ донора; все мертвы -> правило
     НЕ ставится: для DNS-only-блокированных сервисов реальный IP лучше
     мёртвого зеркала (так ломались scdn.co/spotifycdn.com/oaiusercontent).
  5. Лимиты аккаунта читаются ДО деплоя (GET /account/limits): если правил
     больше лимита — чёрный список зон не трогаем, мусорные громоздкие зоны
     (крупнейшие, не критичные) отбрасываем и печатаем список. MUST_KEEP
     защищает и музыкальный кластер (T68: last.fm + audioscrobbler + deezer
     + tidal — сервисы сами гео-блокируют РФ, зеркало — единственный путь,
     а их правила выкидывались обрезкой 340->100).
  6. PUT /dns_servers/{id}/settings c user_rules_settings.rules — правила
     сервера заменяются ЦЕЛИКОМ (ручные правила из дашборда затрёт — не пиши
     их туда, только в этот пайплайн).

Защита от пустых деплоев (PUT не выполняется, старые правила живут):
  - донор недоступен в начале / ошибок запросов > 30%;
  - разрешено меньше половины доменов файла;
  - нет правила хотя бы одной пин-зоны.

Секрет: ADGUARD_API_KEY (environment DNS). Авторизация: Authorization: ApiKey
Контракт api.adguard-dns.io/oapi/v1 (спецификация: /swagger/openapi.json):
  GET  /account/limits            -> {user_rules: {limit, used}, ...}
  GET  /dns_servers               -> v1: голый массив [{id, name, default}],
                                     v2: {items: [...]} — принимаем оба формата
  POST /dns_servers               <- {"name": "Main"}   (если сервера нет)
  GET  /dns_servers/{id}/settings -> {..., user_rules_settings: {...}}
  PUT  /dns_servers/{id}/settings <- {"user_rules_settings": {...}}
Ошибки: 400 + FIELD_REACHED_LIMIT / INSUFFICIENT_LICENSE_TYPE = тариф/лимит;
429/5xx — временные, ждём 60 с, до 3 попыток (окно как у NextDNS).

Отладка локально: ADGUARD_DRY=1 (без API, только сборка правил),
ADGUARD_DRY_LIMIT=N (взять первые N доменов), HOSTS_FILE=путь,
ADGUARD_HEALTHCHECK=1 (проверка задеплоенных пинов; всё живо — выход
без деплоя; режим для запуска каждые 2 часа из healthcheck.yml).
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

API = "https://api.adguard-dns.io/oapi/v1"
API_KEY = os.environ.get("ADGUARD_API_KEY", "").strip()

DONOR = "https://ys39tfku2v.cloudflare-gateway.com/dns-query"   # RFL DoH
CONTROL = "https://dns.google/resolve"                          # Google DoH
HOSTS_FILE = os.environ.get("HOSTS_FILE", "redirect_filtered.hosts")
DRY = os.environ.get("ADGUARD_DRY", "") == "1"
DRY_LIMIT = int(os.environ.get("ADGUARD_DRY_LIMIT", "0") or 0)
HEALTHCHECK = os.environ.get("ADGUARD_HEALTHCHECK", "") == "1"

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0"
ALIVE_CODES = {"200", "301", "302", "307", "308", "400", "403", "404", "421"}
DNS_PACING = 0.35      # сек между DoH-запросами (воркер DnsConf шёл с 1 с)
RETRY_DELAY = 20       # пауза при 429/5xx DoH
RETRY_ATTEMPTS = 3
API_RETRY_DELAY = 60   # окно rate-limit API AdGuard
API_RETRIES = 3
MIN_RESOLVED_FRACTION = 0.5

# --- флот-скан (T67): пины выбираются автоматически на каждом прогоне ---
# Ротация зеркал (смерть .192 в Т66) — не ручная работа: скрипт сканирует
# кандидатов SNI-пробой и пинит первое живое зеркало для каждой зоны.
# PROVEN — подтверждённые из сети Дом.ру (всегда первыми; .49 проверен:
# grok 200 + 4pda 200 у юзера, обслуживает и весь chatgpt-кластер + claude
# через cf-challenge, который Chrome проходит), далее свежие ответы
# донора, далее известный флот. Вырезанные IP не рассматриваются.
PROVEN = ["181.215.40.49"]
FLEET_FALLBACK = ["5.175.161.40", "45.13.237.213", "37.221.93.141",
                  "37.221.93.128", "5.175.161.3", "37.221.94.10"]
CHATGPT_PIN_ZONES = ["chatgpt.com", "openai.com", "oaistatic.com",
                     "oaiusercontent.com"]
GROK_PIN_ZONES = ["grok.com", "x.ai"]
PIN_ZONES = CHATGPT_PIN_ZONES + GROK_PIN_ZONES
P4PDA = "4pda.to"
P4PDA_BACKUP = "181.215.40.49"

# IP, вырезанные Дом.ру (проверено с домашней сети юзера, T37/T66): донор
# RFL любит выдавать их ПЕРВЫМ ответом (лотерея) — donor_a их пропускает.
CUT_IPS = {"31.25.239.132"}

# Критичные домены вне пин-зон: донорный IP проверяется SNI-пробой; мёртв
# -> следующий ответ донора; все мертвы -> без правила. claude-кластер
# (блок Дом.ру DNS-only, реальный IP достижим; api.claude.ai vhost'а нет
# ни на одном зеркале — зонный пин claude НЕ ставим) + музыкальный кластер
# юзера (T68: last.fm/deezer/tidal сами гео-блокируют РФ с 03.2026 —
# зеркало единственный путь; last.fm жив на 8 зеркалах флота, но правило
# выкидывалось обрезкой лимита 340->100).
CRITICAL_MIRROR_DOMAINS = {"claude.ai", "anthropic.com", "claude.com",
                           "last.fm", "www.last.fm", "ws.audioscrobbler.com",
                           "deezer.com", "tidal.com"}

# Healthcheck (ADGUARD_HEALTHCHECK=1): жёсткие пины обязаны существовать
# и жить; мягкие (музыкальный кластер, T68) — только если правило
# задеплоено: зеркало умерло -> полный прогон, правила нет -> ночной
# ребилд решит сам (форсировать 2-часовой прогон из-за пустого правила
# не стоит).
HEALTH_PROBE_DOMAINS = ("chatgpt.com", "grok.com", P4PDA)
HEALTH_SOFT_DOMAINS = ("last.fm", "ws.audioscrobbler.com")

# Известные блоки флота зеркал (RFL smart + malw). Список — оптимизация:
# незнакомый блок всё равно ловится сверкой с dns.google.
FLEET_PREFIXES = (
    "143.20.64.", "181.215.40.", "37.221.93.", "37.221.94.",
    "5.175.161.", "5.175.160.", "31.25.239.", "45.13.237.",
    "45.13.236.", "45.13.238.", "31.25.238.", "193.233.112.",
    "159.194.200.", "206.223.251.", "179.254.166.", "191.217.212.",
)

# Зоны, которые НЕ выбрасываются при обрезке по лимиту (жизненно важные).
MUST_KEEP = set(PIN_ZONES) | {
    P4PDA, "claude.ai", "anthropic.com",
    "google.com", "googleapis.com", "googleusercontent.com",
    "googlevideo.com", "youtube.com", "ytimg.com", "ggpht.com",
    "gstatic.com", "spotify.com", "spotifycdn.com", "scdn.co",
    "facebook.com", "instagram.com", "cdninstagram.com", "fbcdn.net",
    "telegram.org", "discord.com", "twitter.com", "x.com", "netflix.com",
    "last.fm", "audioscrobbler.com", "deezer.com", "tidal.com",
}

MULTI_TLD = {
    "co.uk", "org.uk", "net.uk", "ac.uk", "gov.uk", "co.jp", "co.kr",
    "co.in", "co.nz", "co.za", "com.au", "net.au", "org.au", "com.br",
    "com.tr", "com.tw", "com.cn", "com.hk", "com.sg", "com.my",
    "com.mx", "com.ar", "com.pl", "com.ua", "com.vn", "com.pk",
}


def zone_of(domain):
    p = domain.split(".")
    if len(p) >= 3 and ".".join(p[-2:]) in MULTI_TLD:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def is_fleet(ip):
    return ip.startswith(FLEET_PREFIXES)


def http_json(url, headers=None, timeout=15):
    """GET -> (status, parsed_json_or_text). 429/5xx — пауза и повтор."""
    req = urllib.request.Request(url, headers=headers or {"User-Agent": UA})
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read().decode()
                body = json.loads(raw) if raw.strip() else None
                return r.status, body
        except urllib.error.HTTPError as e:
            if (e.code == 429 or e.code >= 500) and attempt < RETRY_ATTEMPTS:
                time.sleep(RETRY_DELAY)
                continue
            try:
                detail = e.read().decode()[:200]
            except Exception:
                detail = ""
            return e.code, detail
        except Exception as e:
            if attempt < RETRY_ATTEMPTS:
                time.sleep(RETRY_DELAY)
                continue
            return 0, f"{type(e).__name__}: {e}"
    return 0, "retries exhausted"


def is_private_ip(ip):
    """RFC1918/loopback/link-local/CGNAT — донор иногда отдаёт такие
    (wiki/jira.last.fm -> 10.22.234.x, T68): это внутренние адреса RFL,
    снаружи недостижимы — зеркалом не считаются."""
    o = ip.split(".")
    try:
        a, b = int(o[0]), int(o[1])
    except (ValueError, IndexError):
        return True
    return (a in (0, 10, 127)
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or (a == 169 and b == 254)
            or (a == 100 and 64 <= b <= 127))


def donor_a_all(domain):
    """Все НЕ-вырезанные A-ответы донора, в исходном порядке (T67).
    Дом.ру-вырезанные IP из CUT_IPS пропускаем: донор ставит их первыми
    (лотерея), для клиента это мёртвый адрес при живом глобально.
    Приватные IP (T68) — тоже: внутренность RFL, не зеркало."""
    st, body = http_json(f"{DONOR}?name={domain}&type=A",
                         {"accept": "application/dns-json", "User-Agent": UA})
    if st != 200 or not isinstance(body, dict):
        return []
    ans = body.get("Answer") or []
    return [a["data"] for a in ans
            if a.get("type") == 1 and (a.get("data") or "").count(".") == 3
            and a["data"] not in CUT_IPS and not is_private_ip(a["data"])]


def donor_a(domain):
    """Первый НЕ-вырезанный A-ответ донора."""
    ips = donor_a_all(domain)
    return ips[0] if ips else None


def control_a(domain):
    """Ответ независимого резолвера (dns.google) — контроль инертности."""
    st, body = http_json(f"{CONTROL}?name={domain}&type=A",
                         {"accept": "application/dns-json", "User-Agent": UA})
    if st != 200 or not isinstance(body, dict):
        return None            # недоступен/заблокирован
    ans = body.get("Answer") or []
    return [a["data"] for a in ans
            if a.get("type") == 1 and (a.get("data") or "").count(".") == 3]


def similar(ips_a, ips_b):
    """Похожие ли ответы: пересечение по IP или по /16 (CDN-гейты)."""
    if not ips_b:              # контроль пуст/0.0.0.0 -> заблокирован
        return False
    s16_a = {".".join(i.split(".")[:2]) for i in ips_a}
    s16_b = {".".join(i.split(".")[:2]) for i in ips_b}
    return bool(set(ips_a) & set(ips_b) or s16_a & s16_b)


def sni_alive(host, ip, timeout=8):
    """SNI-проба как в T39/apply_pins: жив ли vhost host на IP."""
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
           "--resolve", f"{host}:443:{ip}", "--max-time", str(timeout),
           "-A", UA, f"https://{host}/"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout + 6)
        return out.stdout.strip() in ALIVE_CODES
    except Exception:
        return False


def pick_mirror(probe_domain, extra=()):
    """Живое зеркало для probe_domain (флот-скан T67): PROVEN -> свежие
    ответы донора -> известный флот. Первое прошедшее SNI-пробу побеждает,
    вырезанные IP не рассматриваются. Возвращает IP или None."""
    cands = []
    for ip in list(PROVEN) + list(extra) + FLEET_FALLBACK:
        if ip not in cands and ip not in CUT_IPS and not is_private_ip(ip):
            cands.append(ip)
    for ip in cands:
        if sni_alive(probe_domain, ip):
            return ip
    return None


A_RULE_RE = re.compile(
    r"^\|\|([a-z0-9._-]+)\^\$dnsrewrite=NOERROR;A;(\d+\.\d+\.\d+\.\d+)$")


def verify_rules(flat_rules):
    """SNI-верификация собранных правил перед деплоем (T68).

    Правило с мёртвым зеркалом ХУЖЕ отсутствия правила: почти весь список
    блокируется Дом.ру только по DNS (реальные IP живы), поэтому мёртвое
    зеркало = сломанный сервис, а «нет правила» = рабочий реальный IP.
    Каждое A-правило пробуем; мёртвое -> остальные ответы донора ->
    живое ставим (перепин); не нашли -> правило снимается. Пин-зоны уже
    проверены флот-сканом по каждой зоне, 4pda закреплён за живым зеркалом
    — их не трогаем. Пробы в 4 потока (+3-5 мин к прогону)."""
    keep, targets = [], []
    skip = set(PIN_ZONES) | {P4PDA}
    for r in flat_rules:
        m = A_RULE_RE.match(r)
        if m and m.group(1) not in skip:
            targets.append((r, m.group(1), m.group(2)))
        else:
            keep.append(r)
    with ThreadPoolExecutor(max_workers=4) as ex:
        alive = list(ex.map(lambda t: sni_alive(t[1], t[2]), targets))
    repinned, dropped = [], []
    for (r, dom, ip), ok in zip(targets, alive):
        if ok:
            keep.append(r)
            continue
        alt = next((c for c in donor_a_all(dom)
                    if c != ip and sni_alive(dom, c)), None)
        if alt:
            keep.append(f"||{dom}^$dnsrewrite=NOERROR;A;{alt}")
            repinned.append(f"{dom}: {ip} мёртв -> {alt}")
        else:
            dropped.append(f"{dom} ({ip})")
    return keep, repinned, dropped


def deployed_pin_rules():
    """A-реврайты probe-доменов с сервера AdGuard: {домен: IP}.
    None, если сервер или настройки недоступны."""
    st, data = adguard_api("GET", "/dns_servers")
    if st != 200 or not isinstance(data, (list, dict)):
        return None
    items = data if isinstance(data, list) else (data.get("items") or [])
    items = [s for s in items if isinstance(s, dict)]
    if not items:
        return None
    srv = next((s for s in items if s.get("default")), items[0])
    sid = srv.get("id")
    if not sid:
        return None
    st, cur = adguard_api("GET", f"/dns_servers/{sid}/settings")
    if st != 200 or not isinstance(cur, dict):
        return None
    rules = ((cur.get("user_rules_settings") or {}).get("rules")) or []
    out = {}
    for r in rules:
        for dom in HEALTH_PROBE_DOMAINS + HEALTH_SOFT_DOMAINS:
            pref = f"||{dom}^$dnsrewrite=NOERROR;A;"
            if r.startswith(pref):
                out[dom] = r[len(pref):]
    return out


def pins_healthy():
    """Healthcheck (T67/T68): жёсткие пины задеплоены и SNI-живы; мягкие
    (музыка) — если правило есть, зеркало обязано жить."""
    pins = deployed_pin_rules()
    if pins is None:
        print("[0] Правила сервера не читаются — запускаю полный прогон.")
        return False
    ok = True
    for dom in HEALTH_PROBE_DOMAINS:
        ip = pins.get(dom)
        if not ip:
            print(f"[0] {dom}: пина нет — запускаю полный прогон.")
            ok = False
        elif not sni_alive(dom, ip):
            print(f"[0] {dom}: зеркало {ip} мёртво — запускаю полный прогон.")
            ok = False
        else:
            print(f"[0] {dom} @ {ip}: жив")
    for dom in HEALTH_SOFT_DOMAINS:
        ip = pins.get(dom)
        if ip and not sni_alive(dom, ip):
            print(f"[0] {dom}: зеркало {ip} мёртво — запускаю полный прогон.")
            ok = False
        elif ip:
            print(f"[0] {dom} @ {ip}: жив")
    return ok


def adguard_api(method, path, payload=None, attempt=1):
    """API AdGuard DNS. Authorization: ApiKey <key>. 429/5xx -> пауза 60 c."""
    req = urllib.request.Request(
        API + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers={"Authorization": f"ApiKey {API_KEY}",
                 "Content-Type": "application/json",
                 "User-Agent": "dnsconf-adguard/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            raw = r.read().decode()
            return r.status, json.loads(raw) if raw.strip() else None
    except urllib.error.HTTPError as e:
        code = e.code
        if (code == 429 or code >= 500) and attempt < API_RETRIES:
            print(f"    {method} {path}: {code}, жду {API_RETRY_DELAY} c "
                  f"(попытка {attempt + 1}/{API_RETRIES})")
            time.sleep(API_RETRY_DELAY)
            return adguard_api(method, path, payload, attempt + 1)
        try:
            body = json.loads(e.read().decode())
        except Exception:
            body = None
        return code, body
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"


def parse_hosts(path):
    """Домены из hosts-файла: 0.0.0.0/локал-строки/пин-зоны выкидываем."""
    domains = []
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            parts = ln.split()
            ip = parts[0]
            if ip in ("0.0.0.0", "127.0.0.1") or ip.startswith((":", "ff0",
                                                                "fe80")):
                continue
            for dom in parts[1:]:
                d = dom.lower().rstrip(".")
                clean = d.replace(".", "").replace("-", "")
                if "." not in d or not clean.isalnum():
                    continue
                if any(d == z or d.endswith("." + z) for z in PIN_ZONES):
                    continue
                if d == P4PDA or d.endswith("." + P4PDA):
                    continue
                domains.append(d)
    seen, out = set(), []
    for d in domains:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def main():
    if not DRY and not API_KEY:
        print("Нет ADGUARD_API_KEY — добавь секрет в environment DNS "
              "(как CLIENT_ID/AUTH_SECRET).")
        return 1

    # --- [0] healthcheck: живы ли задеплоенные пины? -------------------------
    if HEALTHCHECK and not DRY:
        print("[0] Healthcheck задеплоенных пинов...")
        if pins_healthy():
            print("[0] Всё живо — деплой не нужен.")
            return 0
        print("[0] Проблема найдена — перехожу к полному прогону.")

    # --- [1] флот-скан: живые зеркала для пинов -------------------------------
    # T68: каждая пин-зона сканируется ОТДЕЛЬНО (раньше один IP по пробе
    # chatgpt.com ставился всему кластеру: oaiusercontent.com на зеркале
    # умер — правило стало ломать загрузку файлов в ChatGPT, хотя без
    # правила реальные IP работают).
    print("[1] Флот-скан по зонам: PROVEN -> донор -> флот...")
    zone_pins = {}
    for z in CHATGPT_PIN_ZONES + GROK_PIN_ZONES:
        zone_pins[z] = pick_mirror(z, donor_a_all(z))
        print(f"    {z} -> {zone_pins[z] or 'живого зеркала нет (реальный DNS)'}")
    p4 = pick_mirror(P4PDA, donor_a_all(P4PDA)) or P4PDA_BACKUP
    print(f"    {P4PDA} -> {p4}")

    # --- [2] донор-хилинг общего списка ---------------------------------------
    domains = parse_hosts(HOSTS_FILE)
    if DRY and DRY_LIMIT:
        domains = domains[:DRY_LIMIT]
    print(f"[2] Донор-хилинг: {len(domains)} доменов "
          f"(RFL DoH, пауза {DNS_PACING} c)")

    mirrored = {}          # домен -> IP зеркала (флот или незнакомое плечо)
    inert = failures = unverified = 0
    health_probe = donor_a("chatgpt.com")
    if not health_probe:
        print("    КРИТИЧНО: донор не отвечает — деплой отменён "
              "(старые правила не тронуты).")
        return 1
    for i, dom in enumerate(domains, 1):
        ip = donor_a(dom)
        if ip is None:
            failures += 1
        elif is_fleet(ip):
            if dom in CRITICAL_MIRROR_DOMAINS and not sni_alive(dom, ip):
                alt = next((c for c in donor_a_all(dom)
                            if sni_alive(dom, c)), None)
                print(f"    {dom}: {ip} мёртв (SNI) -> "
                      f"{alt or 'без правила (реальный IP)'}")
                if alt:
                    mirrored[dom] = alt
            else:
                mirrored[dom] = ip
        else:
            ctrl = control_a(dom)
            if ctrl is None:
                unverified += 1        # контроль недоступен — пропускаем
            elif similar([ip], ctrl):
                inert += 1             # реальный IP — правило не нужно
            else:
                mirrored[dom] = ip    # новое зеркальное плечо
        time.sleep(DNS_PACING)
        if i % 250 == 0:
            print(f"    ...{i}/{len(domains)} (зеркал: {len(mirrored)}, "
                  f"инертных: {inert}, ошибок: {failures})")
    print(f"[3] Разрешено: зеркал {len(mirrored)}, инертных {inert}, "
          f"контроль недоступен {unverified}, ошибок {failures}")
    if failures > 0.3 * len(domains):
        print("    КРИТИЧНО: >30% ошибок запросов — деплой отменён.")
        return 1
    if len(mirrored) < MIN_RESOLVED_FRACTION * max(len(domains) - inert, 1):
        print("    КРИТИЧНО: разрешено подозрительно мало — отмена "
              "(защита от пустого деплоя).")
        return 1

    # --- [4] сборка правил -----------------------------------------------------
    rules = {}
    # пин-зоны: зонные правила с пер-зонным IP из флот-скана [1]; живого
    # зеркала нет — правило не ставим: домен уйдёт на реальный DNS
    # (блок Dom.ru DNS-only, реальные IP достижимы).
    for z in CHATGPT_PIN_ZONES + GROK_PIN_ZONES:
        if zone_pins.get(z):
            rules[z] = [f"||{z}^$dnsrewrite=NOERROR;A;{zone_pins[z]}"]
    # 4pda: A-реврайт + гашение утечек type-65 (HTTPS RR) и AAAA.
    # 4pda.to публикует HTTPS-RR с РЕАЛЬНЫМИ ipv4hint Cloudflare (под
    # РКН-DPI с 05.2021). Chrome при «Частный DNS» считает резолвер
    # secure и ходит по ipv4hint МИМО A-реврайта -> реальные IP -> DPI.
    # У chatgpt/grok/claude блок DNS-only (реальные IP живы) — утечка там
    # безвредна, эти правила им не нужны. Блок type-65/AAAA возвращает
    # браузер к A-реврайту на зеркало (класс svcb-утечки, Т22).
    rules[P4PDA] = [
        f"||{P4PDA}^$dnsrewrite=NOERROR;A;{p4}",
        f"||{P4PDA}^$dnstype=HTTPS",
        f"||{P4PDA}^$dnstype=AAAA",
    ]
    # зоны файла: группировка
    by_zone = {}
    for dom, ip in mirrored.items():
        by_zone.setdefault(zone_of(dom), {})[dom] = ip
    for z, hosts in by_zone.items():
        if z in rules:            # пин-зона/4pda уже назначена
            continue
        apex = hosts.get(z)
        uniq_ips = set(hosts.values())
        # зонное правило: апекс зеркалится, либо все хосты зоны делят один IP
        if len(hosts) >= 3 and (apex or len(uniq_ips) == 1):
            rules[z] = [f"||{z}^$dnsrewrite=NOERROR;A;{apex or uniq_ips.pop()}"]
        else:                             # смешанная/мелкая зона: по хостам
            emitted = [d for d in sorted(hosts)
                       if not any(a != d and d.endswith("." + a)
                                  for a in hosts)]
            rules[z] = [f"||{d}^$dnsrewrite=NOERROR;A;{hosts[d]}" for d in emitted]

    flat = [r for v in rules.values() for r in v]
    # SNI-верификация (T68): мёртвое зеркало -> перепин на живой ответ
    # донора -> иначе правило снимается (реальный IP лучше мёртвого).
    flat, repinned, dead_dropped = verify_rules(flat)
    if repinned:
        print(f"[4] SNI-верификация: перепиновано {len(repinned)}")
        for s in repinned[:10]:
            print(f"    {s}")
    if dead_dropped:
        print(f"[4] SNI-верификация: снято мёртвых {len(dead_dropped)} "
              f"(реальный IP лучше мёртвого зеркала)")
        for s in dead_dropped[:15]:
            print(f"    {s}")
    print(f"[4] Правил после сборки и верификации: {len(flat)}")

    if DRY:
        out = os.path.join(os.path.dirname(os.path.abspath(HOSTS_FILE)),
                           "adguard_rules_preview.txt")
        with open(out, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(flat)) + "\n")
        print(f"[dry-run] Без PUT. Превью правил: {out} ({len(flat)} шт.)")
        return 0

    # --- [5] лимиты аккаунта ---------------------------------------------------
    st, lim = adguard_api("GET", "/account/limits")
    capacity = None
    if st == 200 and isinstance(lim, dict):
        ur = (lim.get("user_rules") or {})
        capacity = ur.get("limit")
        print(f"[5] Лимит правил тарифа: {capacity} "
              f"(занято: {ur.get('used')})")
    else:
        print(f"[5] Лимит не прочитан ({st}): {lim}")
    if capacity is not None:
        if capacity == 0:
            print("    На тарифе правила НЕ доступны — нужен Personal "
                  "(~$2.49/мес, бывают скидки). PUT пропущен.")
            return 1
        dropped = []
        if len(flat) > capacity:
            # порядок выбрасывания: сначала громоздкие по-хостовые зоны
            # (крупнейшие сверху — общественный балласт), затем одиночные
            # зоны по алфавиту; MUST_KEEP не трогаем
            multi = [(z, v) for z, v in rules.items()
                     if z not in MUST_KEEP and len(v) > 1]
            multi.sort(key=lambda kv: -len(kv[1]))
            order = [z for z, _ in multi]
            order += sorted(z for z, v in rules.items()
                            if z not in MUST_KEEP and len(v) == 1)
            for z in order:
                if len(flat) <= capacity:
                    break
                v = rules[z]
                flat = [r for r in flat if r not in set(v)]
                dropped.append(f"{z} (-{len(v)})")
            if len(flat) > capacity:
                print(f"    НЕ ВЛЕЗЛО даже после обрезки: {len(flat)} > "
                      f"{capacity} — нужен тариф выше или короче список.")
                return 1
            print(f"    Обрезано до лимита, отброшено: {', '.join(dropped[:15])}"
                  + (" ..." if len(dropped) > 15 else ""))

    # --- [6] сервер -----------------------------------------------------------
    st, data = adguard_api("GET", "/dns_servers")
    if st != 200:
        print(f"[6] ОШИБКА API ({st}): {data}")
        if st in (401, 403):
            print("    ADGUARD_API_KEY не принят. Пересоздай ключ: adguard-dns.io"
                  " -> Dashboard -> email -> User preferences -> API keys.")
        return 1
    # v1 отдаёт голый массив серверов (так и случилось в прогоне CI #1),
    # v2 — {items: [...]} (пагинация). Принимаем оба формата, чтобы
    # переезд AdGuard с v1 (удаление в январе 2027) на v2 не ломал скрипт.
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("items") or []
    else:
        items = []
    items = [s for s in items if isinstance(s, dict)]
    if items:
        srv = next((s for s in items if s.get("default")), items[0])
        print(f"[6] Сервер: «{srv.get('name')}» (id {srv.get('id')})")
    else:
        st, srv = adguard_api("POST", "/dns_servers", {"name": "Main"})
        if st != 200 or not isinstance(srv, dict):
            print(f"[6] Не удалось создать сервер ({st}): {srv}")
            return 1
        print(f"[6] Создан сервер «Main» (id {srv.get('id')})")
    sid = srv.get("id")
    if not sid:
        print(f"[6] ОШИБКА: в ответе API нет id сервера: {srv}")
        return 1

    # --- [7] деплой --------------------------------------------------------------
    st, cur = adguard_api("GET", f"/dns_servers/{sid}/settings")
    old_n = None
    if st == 200 and isinstance(cur, dict):
        old_n = ((cur.get("user_rules_settings") or {}).get("rules_count"))
    payload = {"user_rules_settings": {"enabled": True,
                                       "rules": sorted(flat)}}
    st, resp = adguard_api("PUT", f"/dns_servers/{sid}/settings", payload)
    if st == 200:
        new_n = len(flat)
        pins_txt = ", ".join(f"{z}={ip}" for z, ip in sorted(zone_pins.items())
                             if ip)
        print(f"[7] ГОТОВО: правил на сервере {new_n} "
              f"(было: {old_n if old_n is not None else '?'}). "
              f"Пины: {pins_txt or '—'}; 4pda: {p4}")
        return 0
    print(f"[7] ОШИБКА PUT ({st}): {resp}")
    if isinstance(resp, dict):
        for f in (resp.get("fields") or [])[:5]:
            print(f"    поле {f.get('field')}: {f.get('message')} "
                  f"({f.get('error_code')})")
        code = resp.get("error_code")
        if code == "FIELD_REACHED_LIMIT":
            print("    Превышен лимит правил тарифа — апгрейд до Personal.")
        if code == "INSUFFICIENT_LICENSE_TYPE":
            print("    Тариф не поддерживает правила — нужен Personal "
                  "(~$2.49/мес, бывают скидки).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
