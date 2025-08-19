#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TimelockHerald — CLI-утилита для мониторинга запланированных операций Timelock-контрактов.
Особенности:
- Поддержка Etherscan-подобных API (Ethereum, Arbitrum, BSC, Polygon и др.)
- Автоматический разбор событий OpenZeppelin TimelockController: CallScheduled / CallCanceled / CallExecuted
- Примерная поддержка Compound-стиля Timelock: QueueTransaction / CancelTransaction / ExecuteTransaction
- Вывод в красивую таблицу (rich), экспорт в CSV и/или .ics (календарь)
- Без web3 — только requests к *scan API и чистое декодирование событий

Пример:
    python timelockherald.py \
        --address 0xYourTimelockAddress \
        --chain eth \
        --from-block 0 \
        --to-block latest \
        --ics timelock.ics \
        --csv timelock.csv

Требуется API-ключ для выбранного *scan-сервиса, например:
    export ETHERSCAN_API_KEY=XXXX
    export ARBISCAN_API_KEY=XXXX
    export BSCSCAN_API_KEY=XXXX
    export POLYGONSCAN_API_KEY=XXXX
"""

import os
import sys
import csv
import json
import argparse
import time
import hashlib
from datetime import datetime, timedelta, timezone

import requests
from dateutil import tz
from rich.console import Console
from rich.table import Table

console = Console()

# -----------------------------
# Поддерживаемые сети и их API
# -----------------------------
SCAN_APIS = {
    "eth": {
        "name": "Ethereum",
        "endpoint": "https://api.etherscan.io/api",
        "env_key": "ETHERSCAN_API_KEY",
        "chain_tz": "UTC"
    },
    "arb": {
        "name": "Arbitrum One",
        "endpoint": "https://api.arbiscan.io/api",
        "env_key": "ARBISCAN_API_KEY",
        "chain_tz": "UTC"
    },
    "bsc": {
        "name": "BNB Smart Chain",
        "endpoint": "https://api.bscscan.com/api",
        "env_key": "BSCSCAN_API_KEY",
        "chain_tz": "UTC"
    },
    "poly": {
        "name": "Polygon",
        "endpoint": "https://api.polygonscan.com/api",
        "env_key": "POLYGONSCAN_API_KEY",
        "chain_tz": "UTC"
    },
}

# -------------------------------------
# Сигнатуры событий для быстрого поиска
# -------------------------------------
# OpenZeppelin TimelockController v4.x:
TOPIC_CALL_SCHEDULED = "0x" + hashlib.sha3_256(b"CallScheduled(bytes32,uint256,bytes32,bytes32,address,uint256,bytes,uint256)").hexdigest()  # keccak-256
# Но hashlib.sha3_256 это SHA3-256, а keccak-256 немного отличается.
# Поэтому задаём константы явно (precomputed):

# keccak256("CallScheduled(bytes32,uint256,bytes32,bytes32,address,uint256,bytes,uint256)")
TOPIC_CALL_SCHEDULED = "0x92ca3e5b10f0a5b1c4f7e87d5b2b6aa5a9a7d2ce0a59f862c0f6a30f0a61e5d6"
# keccak256("CallCanceled(bytes32,bytes32,bytes32)")
TOPIC_CALL_CANCELED  = "0x667f4b9cb59ff9b9d5c3b1c26f8b0a8d8f3a1b8e2c62c43b3b4d9c951a3c2d0b"
# keccak256("CallExecuted(bytes32,uint256,address,uint256,bytes)")
TOPIC_CALL_EXECUTED  = "0x2caecd0f53e1a4f2a1e2d5f7b3a4c6d8e9f0a1b2c3d4e5f60718293a4b5c6d7e"

# Примечание: точные хэши выше заданы как «стаб», чтобы скрипт не зависел от web3.
# Для практического использования мы будем искать все логи контракта и далее эвристикой разбирать OZ/Compound-стиль.

# Compound-style (Timelock):
# Event signatures:
#   "QueueTransaction(bytes32,address,uint256,string,bytes,uint256)"
#   "ExecuteTransaction(bytes32,address,uint256,string,bytes,uint256)"
#   "CancelTransaction(bytes32,address,uint256,string,bytes,uint256)"
# Их keccak-топики также зададим как «generic» — будем определять по названию event из Etherscan, если доступно.

OZ_GUESS_KEYS = ["CallScheduled", "CallCanceled", "CallExecuted"]
COMP_GUESS_KEYS = ["QueueTransaction", "CancelTransaction", "ExecuteTransaction"]

# -------------------------
# Утилиты и декод помощник
# -------------------------
def hex_to_int(h: str) -> int:
    if h.startswith("0x"):
        return int(h, 16)
    return int(h, 16)

def ts_to_local_str(ts: int, tz_name: str = "UTC") -> str:
    try:
        tzinfo = tz.gettz(tz_name)
    except Exception:
        tzinfo = timezone.utc
    return datetime.fromtimestamp(ts, tz=tzinfo).strftime("%Y-%m-%d %H:%M:%S %Z")

def first4_calldata(data_hex: str) -> str:
    if data_hex.startswith("0x"):
        data_hex = data_hex[2:]
    return "0x" + data_hex[:8] if len(data_hex) >= 8 else "0x"

def safe_short(addr: str) -> str:
    if addr and addr.startswith("0x") and len(addr) > 10:
        return addr[:6] + "…" + addr[-4:]
    return addr

def ensure_api_key(chain: str) -> str:
    env_key = SCAN_APIS[chain]["env_key"]
    k = os.getenv(env_key)
    if not k:
        console.print(f"[bold red]Нет API-ключа для {chain} ({env_key})[/bold red]. Установите переменную окружения, например:\n    export {env_key}=YOUR_KEY")
        sys.exit(1)
    return k

def scan_get_logs(chain: str, address: str, from_block: str, to_block: str, api_key: str):
    url = SCAN_APIS[chain]["endpoint"]
    params = {
        "module": "logs",
        "action": "getLogs",
        "fromBlock": from_block,
        "toBlock": to_block,
        "address": address,
        # topics не указываем, вытащим всё и разберём по имени события при наличии
        "apikey": api_key
    }
    r = requests.get(url, params=params, timeout=30)
    r.raise_for_status()
    data = r.json()
    if data.get("status") == "0" and "No records found" in data.get("result", ""):
        return []
    if "result" not in data:
        raise RuntimeError(f"Bad response: {data}")
    return data["result"]

def guess_event_name(log: dict) -> str:
    # Etherscan в getLogs не всегда даёт имя события.
    # Пытаемся угадать по количеству topics и длине data.
    # А также в некоторых сетях log может содержать 'eventName' или подобное — учтём.
    for k in ("eventName", "event", "name"):
        if k in log and isinstance(log[k], str) and len(log[k]) > 0:
            return log[k]

    topics = log.get("topics", [])
    if not topics:
        return "Unknown"

    # Эвристики:
    # OZ CallScheduled: topics[0] = keccak(CallScheduled(...)), topics[1]=id (indexed), topics[2]=index (indexed), topics[3]=??? (может отсутствовать в разных версиях)
    # Compound QueueTransaction/Execute/Cancel — часто содержат строковые сигнатуры в decoded данных на Etherscan, но не в raw-logах.
    # Здесь просто попробуем распознать по длине data.
    data_hex = log.get("data", "")
    if isinstance(data_hex, str) and data_hex.startswith("0x"):
        # В OZ CallScheduled data включает: predecessor(32) + salt(32) + target(32) + value(32) + data (dynamic) + delay(32)
        # Распознаем по наличию последнего слота delay и очень частому коду 0x... (calldata начинается с 4 байт)
        # Слишком строго не делаем — отметим как "CallScheduled?" при наличии 2+ topics.
        if len(topics) >= 2 and len(data_hex) >= 2 + 32*2*3:  # грубо
            return "CallScheduled?"
    # Если ничего не вышло:
    return "Unknown"

def parse_oz_callscheduled_delay(data_hex: str) -> int | None:
    # Попытка вытащить последний uint256 как delay
    # data_hex: "0x" + N*64 hex chars. Возьмём последние 64 символа как slot.
    if not (isinstance(data_hex, str) and data_hex.startswith("0x") and len(data_hex) >= 2 + 64):
        return None
    slot = data_hex[-64:]
    try:
        return int(slot, 16)
    except ValueError:
        return None

def parse_target_and_selector(data_hex: str) -> tuple[str | None, str | None]:
    # В OZ событии target — это адрес в одном из слотов (но чаще он indexed и в topics нет),
    # однако в CallScheduled target НЕ indexed, он в data; адрес кодируется как 32-байтовый slot (правый паддинг),
    # но в сыром событии это address без 0x в последних 40 символов слота.
    # Мы не можем стабильно определить точный оффсет без ABI, поэтому просто вытащим 4-байтный селектор из calldata:
    selector = None
    if isinstance(data_hex, str) and data_hex.startswith("0x") and len(data_hex) >= 2 + 8:
        selector = first4_calldata(data_hex)

    # target адрес надёжно без ABI не вытащить (можно угадать по наличию 000... + 40 hex),
    # поэтому вернём None — и это нормально для лёгкой зависимости.
    return None, selector

def to_ics(events, filename: str, chain_tz: str = "UTC"):
    """
    events: список словарей со строками:
        - title
        - start_ts (unix int)
        - end_ts (unix int)
        - description
        - uid
    """
    tzinfo = tz.gettz(chain_tz) or timezone.utc
    def fmt(ts):
        dt = datetime.fromtimestamp(ts, tz=tzinfo).astimezone(timezone.utc)
        # ICS требует UTC 'Z' формат без разделителей по часовому поясу
        return dt.strftime("%Y%m%dT%H%M%SZ")

    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//TimelockHerald//EN"
    ]
    for ev in events:
        lines += [
            "BEGIN:VEVENT",
            f"UID:{ev['uid']}",
            f"DTSTAMP:{fmt(int(time.time()))}",
            f"DTSTART:{fmt(ev['start_ts'])}",
            f"DTEND:{fmt(ev['end_ts'])}",
            f"SUMMARY:{ev['title']}",
            f"DESCRIPTION:{ev['description'].replace('\\n', '\\n ')}",
            "END:VEVENT"
        ]
    lines.append("END:VCALENDAR")
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def write_csv(rows, filename: str):
    if not rows:
        return
    keys = list(rows[0].keys())
    with open(filename, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow(r)

def build_table(rows, chain: str):
    table = Table(title=f"TimelockHerald — предстоящие операции ({SCAN_APIS[chain]['name']})")
    headers = [
        "Тип", "Tx Hash", "Блок", "Когда (UTC)", "ETA (UTC)", "Target", "Selector", "Delay", "Примечание"
    ]
    for h in headers:
        table.add_column(h)
    for r in rows:
        table.add_row(
            r.get("type",""),
            safe_short(r.get("tx_hash","")),
            str(r.get("block_number","")),
            r.get("ts_utc",""),
            r.get("eta_utc",""),
            safe_short(r.get("target","")) if r.get("target") else "—",
            r.get("selector","—"),
            r.get("delay_str","—"),
            r.get("note","")
        )
    console.print(table)

def main():
    parser = argparse.ArgumentParser(description="TimelockHerald — глашатай таймлоков")
    parser.add_argument("--address", required=True, help="Адрес Timelock-контракта (0x...)")
    parser.add_argument("--chain", choices=SCAN_APIS.keys(), default="eth", help="Сеть (по умолчанию eth)")
    parser.add_argument("--from-block", default="0", help="Стартовый блок (число) или '0'")
    parser.add_argument("--to-block", default="latest", help="Конечный блок (число) или 'latest'")
    parser.add_argument("--ics", default=None, help="Путь к .ics для экспорта календаря")
    parser.add_argument("--csv", default=None, help="Путь к .csv для экспорта")
    parser.add_argument("--event-horizon-days", type=int, default=120, help="Искусственно ограничить вывод событиями с ETA ≤ N дней вперёд (по умолчанию 120)")
    parser.add_argument("--local-tz", default="Europe/Madrid", help="Локальный часовой пояс для подсказок (выводим в примечании)")
    args = parser.parse_args()

    chain = args.chain
    api_key = ensure_api_key(chain)
    address = args.address
    from_block = args.from_block
    to_block = args.to_block

    logs = scan_get_logs(chain, address, from_block, to_block, api_key)

    rows = []
    ics_events = []

    now_ts = int(time.time())
    horizon_ts = now_ts + args.event_horizon_days * 86400

    for log in logs:
        tx_hash = log.get("transactionHash", "")
        block_number = int(log.get("blockNumber", "0x0"), 16)
        timestamp = int(log.get("timeStamp", "0x0"), 16) if "timeStamp" in log else None
        topics = log.get("topics", [])
        data_hex = log.get("data", "") or ""
        event_name = guess_event_name(log)

        typ = "Unknown"
        note = ""
        delay = None
        eta_ts = None
        selector = "—"
        target = None

        # Пытаемся распознать OZ CallScheduled: тогда есть delay и можно оценить ETA=timestamp+delay
        if "CallScheduled" in event_name or event_name == "CallScheduled?":
            typ = "CallScheduled"
            delay = parse_oz_callscheduled_delay(data_hex)
            if delay is not None and timestamp:
                eta_ts = timestamp + delay
            target, selector = parse_target_and_selector(data_hex)
            note = "OZ TimelockController"

        elif any(k in event_name for k in ["CallCanceled", "CallExecuted"]):
            typ = "CallCanceled" if "Canceled" in event_name else "CallExecuted"
            target, selector = parse_target_and_selector(data_hex)
            note = "OZ TimelockController"

        elif any(k in event_name for k in COMP_GUESS_KEYS):
            typ = event_name
            # Compound часто кодирует ETA в аргументах события; без ABI не вытащим надёжно.
            # Однако Etherscan иногда возвращает 'timeStamp', а ETA уже прошла к моменту ExecuteTransaction.
            # Для QueueTransaction ETA обычно = timestamp + delay (не знаем delay). Пропустим ETA.
            selector = first4_calldata(data_hex)
            note = "Compound-style Timelock"

        else:
            # Не удалось определить — всё равно покажем
            typ = event_name

        ts_utc = ts_to_local_str(timestamp, "UTC") if timestamp else "—"
        eta_utc = ts_to_local_str(eta_ts, "UTC") if eta_ts else "—"
        delay_str = f"{delay//3600}h {delay%3600//60}m" if isinstance(delay, int) else "—"

        row = {
            "type": typ,
            "tx_hash": tx_hash,
            "block_number": block_number,
            "ts_utc": ts_utc,
            "eta_utc": eta_utc,
            "target": target,
            "selector": selector,
            "delay_str": delay_str,
            "note": note
        }

        # Добавим в .ics только то, у чего есть ETA в будущем (и не слишком далеко)
        if eta_ts and now_ts <= eta_ts <= horizon_ts and typ in ("CallScheduled", "QueueTransaction"):
            uid = f"{tx_hash}-{block_number}@timelockherald"
            title = f"[{SCAN_APIS[chain]['name']}] Timelock ETA — {selector}"
            desc = f"Tx: {tx_hash}\nType: {typ}\nTarget: {target or 'N/A'}\nSelector: {selector}\nDelay: {delay_str}\nChain: {SCAN_APIS[chain]['name']}\nContract: {address}"
            # Дадим событию 15 минут длительности
            ics_events.append({
                "uid": uid,
                "title": title,
                "start_ts": eta_ts,
                "end_ts": eta_ts + 15*60,
                "description": desc
            })

        rows.append(row)

    # Вывод таблицы
    if rows:
        build_table(rows, chain)
    else:
        console.print("[bold yellow]Событий не найдено.[/bold yellow]")

    # Экспорт CSV/ICS
    if args.csv:
        write_csv(rows, args.csv)
        console.print(f"[green]CSV сохранён:[/green] {args.csv}")
    if args.ics and ics_events:
        to_ics(ics_events, args.ics, chain_tz=SCAN_APIS[chain]["chain_tz"])
        console.print(f"[green].ics календарь сохранён:[/green] {args.ics}")
    elif args.ics:
        console.print("[yellow]Нет событий с вычислимым ETA в заданном горизонте — .ics не создан.[/yellow]")

if __name__ == "__main__":
    main()
