#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apply_adguard.py — карта зеркал RFL на personal AdGuard DNS одним PUT-ом.

Канал для телефона: «Частный DNS» = <hash>.d.adguard-dns.com (DoT/853,
который Дом.ру не режет — имя не брендовое, проверено тестом Б).
Этот скрипт — единственный источник правил сервера (замена воркера DnsConf
и apply_pins.py в новом канале; NextDNS-пайплайн остаётся холодным запасом).

Что делает каждый запуск:
  1. SNI-проверка пин-IP кластера chatgpt/grok (как apply_pins.py):
     primary мёртв -> откат на backup, оба мертвы -> берём ответ донора.
  2. Донор-хилинг: каждый домен redirect_filtered.hosts (минус 0.0.0.0-реклама,
     минус пин-зоны) спрашиваем у RFL DoH:
       * IP из флота зеркал  => домен зеркалится, нужно правило $dnsrewrite;
       * IP не из флота      => сверяем с dns.google: совпал/похож (та же /16)
                                => ИНЕРТНЫЙ реврайт, правило НЕ нужно — обычный
                                резолв AdGuard ответит так же; не совпал =>
                                новое зеркальное плечо, правило ставим.
  3. Коллапс: зона целиком во флоте и её апекс зеркалится => ОДНО правило
     ||зона^$dnsrewrite=NOERROR;A;<IP> (покрывает и все поддомены);
     зона смешанная => по правилу на зеркальный хост.
  4. Лимиты аккаунта читаются ДО деплоя (GET /account/limits): если правил
     больше лимита — критичные зоны не трогаем, громоздкий балласт
     (крупнейшие зоны) отбрасываем и печатаем список.
  5. PUT /dns_servers/{id}/settings c user_rules_settings.rules — правила
     сервера заменяются ЦЕЛИКОМ (ручные правила из дашборда затрёт — не пиши
     их туда, только в этот пайплайн).

Защита от пустых деплоев (PUT не выполняется, старые правила живут):
  - донор недоступен в начале / ошибок запросов > 30%;
  - разрешено меньше половины доменов файла;
  - нет правила хотя бы одной пин-зоны.

Секрет: ADGUARD_API_KEY (environment DNS). Авторизация: Authorization: ApiKey
Контракт api.adguard-dns.io/oapi/v1 (спецификация: /swagger/openapi.json):
  GET  /account/limits            -> {user_rules: {limit, used}, ...}
  GET  /dns_servers               -> {items: [{id, name, default, ...}]}
  POST /dns_servers               <- {"name": "Main"}   (если сервера нет)
  GET  /dns_servers/{id}/settings -> {..., user_rules_settings: {...}}
  PUT  /dns_servers/{id}/settings <- {"user_rules_settings": {...}}
Ошибки: 400 + FIELD_REACHED_LIMIT / INSUFFICIENT_LICENSE_TYPE = тариф/лимит;
429/5xx — временные, ждём 60 с, до 3 попыток.

Отладка локально: ADGUARD_DRY=1 (без API, только сборка правил),
ADGUARD_DRY_LIMIT=N (взять первые N доменов), HOSTS_FILE=путь.
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

API = "https://api.adguard-dns.io/oapi/v1"
API_KEY = os.environ.get("ADGUARD_API_KEY", "").strip()

DONOR = "https://ys39tfku2v.cloudflare-gateway.com/dns-query"   # RFL DoH
CONTROL = "https://dns.google/resolve"                          # Google DoH
HOSTS_FILE = os.environ.get("HOSTS_FILE", "redirect_filtered.hosts")
DRY = os.environ.get("ADGUARD_DRY", "") == "1"
DRY_LIMIT = int(os.environ.get("ADGUARD_DRY_LIMIT", "0") or 0)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0"
ALIVE_CODES = {"200", "301", "302", "307", "308", "400", "403", "404", "421"}
DNS_PACING = 0.35      # сек между DoH-запросами (воркер DnsConf шёл с 1 c)
RETRY_DELAY = 20       # пауза при 429/5xx DoH
RETRY_ATTEMPTS = 3
API_RETRY_DELAY = 60   # окно rate-limit API AdGuard
API_RETRIES = 3
MIN_RESOLVED_FRACTION = 0.5

# --- пины кластера (доказанные Дом.ру T32/T37/T39/T40, как в apply_pins.py) ---
IP_PRIMARY = "143.20.64.192"    # chatgpt-кластер
IP_BACKUP = "181.215.40.49"     # запасной chatgpt + основной grok
CHATGPT_PIN_ZONES = ["chatgpt.com", "openai.com", "oaistatic.com",
                     "oaiusercontent.com"]
GROK_PIN_ZONES = ["grok.com", "x.ai"]
PIN_ZONES = CHATGPT_PIN_ZONES + GROK_PIN_ZONES
P4PDA = "4pda.to"
P4PDA_BACKUP = "181.215.40.49"

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


def donor_a(domain):
    """Первый A-ответ донора (RFL DoH, JSON-совместимый с Cloudflare)."""
    st, body = http_json(f"{DONOR}?name={domain}&type=A",
                         {"accept": "application/dns-json", "User-Agent": UA})
    if st != 200 or not isinstance(body, dict):
        return None
    ans = body.get("Answer") or []
    ips = [a["data"] for a in ans
           if a.get("type") == 1 and (a.get("data") or "").count(".") == 3]
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

    # --- [1] живость пин-IP --------------------------------------------------
    print("[1] SNI-проверка пин-IP кластера...")
    chatgpt_ip, grok_ip = None, None
    if sni_alive("chatgpt.com", IP_PRIMARY):
        chatgpt_ip = IP_PRIMARY
        print(f"    chatgpt-кластер -> {IP_PRIMARY} (жив)")
    elif sni_alive("chatgpt.com", IP_BACKUP):
        chatgpt_ip = IP_BACKUP
        print(f"    ВНИМАНИЕ: {IP_PRIMARY} мёртв -> кластер на {IP_BACKUP}")
    else:
        print(f"    {IP_PRIMARY} и {IP_BACKUP} оба мертвы — IP возьмёт донор")
    if sni_alive("grok.com", IP_BACKUP):
        grok_ip = IP_BACKUP
        print(f"    grok-кластер -> {IP_BACKUP} (жив)")
    elif sni_alive("grok.com", IP_PRIMARY):
        grok_ip = IP_PRIMARY
        print(f"    ВНИМАНИЕ: {IP_BACKUP} мёртв -> grok на {IP_PRIMARY}")
    else:
        print(f"    оба IP мертвы для grok — IP возьмёт донор")

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
    # пин-зоны: зонные правила (SNI-IP, иначе донор)
    for z in CHATGPT_PIN_ZONES:
        ip = chatgpt_ip or donor_a(z) or IP_PRIMARY
        rules[z] = [f"||{z}^$dnsrewrite=NOERROR;A;{ip}"]
    for z in GROK_PIN_ZONES:
        ip = grok_ip or donor_a(z) or IP_BACKUP
        rules[z] = [f"||{z}^$dnsrewrite=NOERROR;A;{ip}"]
    # 4pda: донор + SNI, запасной — проверенный IP
    p4 = donor_a(P4PDA) or P4PDA_BACKUP
    if p4 != P4PDA_BACKUP and not sni_alive(P4PDA, p4):
        print(f"    4pda: донор дал {p4}, мёртв -> {P4PDA_BACKUP}")
        p4 = P4PDA_BACKUP
    rules[P4PDA] = [f"||{P4PDA}^$dnsrewrite=NOERROR;A;{p4}"]
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
    print(f"[4] Правил собрано: {len(flat)} "
          f"(зонных: {sum(1 for v in rules.values() if len(v) == 1)}, "
          f"по-хостовых: {sum(len(v) for v in rules.values() if len(v) > 1)})")

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
    items = (data or {}).get("items") or []
    if items:
        srv = next((s for s in items if s.get("default")), items[0])
        print(f"[6] Сервер: «{srv.get('name')}» (id {srv.get('id')})")
    else:
        st, srv = adguard_api("POST", "/dns_servers", {"name": "Main"})
        if st != 200:
            print(f"[6] Не удалось создать сервер ({st}): {srv}")
            return 1
        print(f"[6] Создан сервер «Main» (id {srv.get('id')})")
    sid = srv["id"]

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
        print(f"[7] ГОТОВО: правил на сервере {new_n} "
              f"(было: {old_n if old_n is not None else '?'}). "
              f"chatgpt-кластер: {chatgpt_ip or 'донор'}, "
              f"grok: {grok_ip or 'донор'}, 4pda: {p4}")
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
