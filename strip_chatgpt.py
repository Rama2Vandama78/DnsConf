#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
strip_chatgpt.py — держит redirect_filtered.hosts свежим в этом репозитории.

Что делает: качает RFL combined + malw, вырезает 6 зон (chatgpt.com,
openai.com, oaistatic.com, oaiusercontent.com, grok.com, x.ai — все
поддомены, текущие и будущие), пишет redirect_filtered.hosts.
Запускается workflow'ем strip_chatgpt.yml (каждый день в 04:20 МСК —
за 10 минут до синка DnsConf в 04:30).

Зачем вырезать: воркер DnsConf не трогает реврайты домёнов, которых нет в
списках, поэтому пины apply_pins.py (143.20.64.192 / 181.215.40.49)
живут вечно: их не перезапишет ни хилинг донором RFL, ни синк.
Вырезанные зоны целиком ведёт apply_pins.py (гигиена + откат IP).
Сравнение зон регистронезависимое — воркер сам Lowercase-ит строки.
"""

import time
import urllib.request

COMBINED_URL = "https://raw.githubusercontent.com/Noktomezo/RussiaFancyLists/main/lists/hosts/combined.hosts"
MALW_URL = "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/master/hosts"

# Вырезаем ЗОНЫ целиком (домен == зона или endsWith('.'+зона)):
# новые поддомены OpenAI/X.ai в апстриме тоже вырезаются автоматически, вместо
# того чтобы хилиться на вырезанный Дом.ру IP в лотерее RFL.
# Эти зоны ведёт apply_pins.py (пины: chatgpt -> .192, grok -> .49).
# arkoselabs.com НЕ вырезаем: донор лечит его на живой IP — работает.
ZONES = ["chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com",
         "grok.com", "x.ai"]


def in_strip(d):
    d = d.lower().rstrip(".")
    return any(d == z or d.endswith("." + z) for z in ZONES)

OUT_PATH = "redirect_filtered.hosts"


def fetch(url, tries=3):
    last = None
    for _ in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode("utf-8", errors="replace").splitlines()
        except Exception as e:
            last = e
            time.sleep(3)
    raise last


def process(lines, out):
    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            out.append(line)
            continue
        tokens = line.split()
        if len(tokens) < 2:
            out.append(line)
            continue
        ip, domains = tokens[0], tokens[1:]
        if not (ip.count(".") == 3 and all(p.isdigit() for p in ip.split("."))):
            out.append(line)
            continue
        kept = [d for d in domains if not in_strip(d)]
        if len(kept) == len(domains):
            out.append(line)
        elif kept:
            out.append(ip + " " + " ".join(kept))


def main():
    out = ["# redirect_filtered.hosts — combined + malw минус chatgpt-зоны (SNI-кластер OpenAI)",
           "# генератор: strip_chatgpt.py. НЕ редактировать руками — перезапишется."]
    for url in (COMBINED_URL, MALW_URL):
        process(fetch(url), out)
        out.append("")
    with open(OUT_PATH, "w") as f:
        f.write("\n".join(out) + "\n")
    kept = sum(1 for l in out if l.strip() and not l.startswith("#"))
    print(f"OK: {OUT_PATH}, {kept} строк")


if __name__ == "__main__":
    main()
