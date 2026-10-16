#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
浏览器取证 —— 从 Edge / Chrome 的本地数据里还原强制门户（Captive Portal）的登录接口

为什么需要它
------------
Portal 主机通常**只在未认证状态下可达**。如果你已经登录上网了，就抓不到登录请求，
门户地址甚至会直接超时。但浏览器会把访问过的门户页面、以及它引用的 JS，
**留在磁盘缓存里** —— 本项目的 `host_url = '/api'` 和 CSRF 机制就是这么找到的
（当时门户已经完全不可达）。

安全承诺
--------
* 全程**只读**：复制到临时目录再查，绝不修改浏览器的任何数据；
* 不联网、不上传任何东西；
* 输出里可能包含你自己的账号/内网地址，**发到公开渠道前请自行打码**。

用法
----
    python tools/browser_forensics.py --list
    python tools/browser_forensics.py --history
    python tools/browser_forensics.py --history --keyword portal
    python tools/browser_forensics.py --cache --keyword wlanuserip
    python tools/browser_forensics.py --cache --dump out/
"""
from __future__ import annotations

import argparse
import csv
import glob
import io
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

LOCAL = os.environ.get("LOCALAPPDATA", "")
BROWSERS = {
    "edge":   os.path.join(LOCAL, "Microsoft", "Edge", "User Data"),
    "chrome": os.path.join(LOCAL, "Google", "Chrome", "User Data"),
}

# 判断"这条 URL 像门户"的关键词
DEFAULT_KEYWORDS = [
    "wlanuserip", "wlanacname", "nasip", "nasId", "switchip", "ac_ip",
    "portal", "eportal", "srun", "drcom", "captcha",
    "/login", "/auth", "/logout", "csrf-token",
]

# 缓存里值得关注的字节特征
CACHE_ANCHORS = [
    b"wlanuserip", b"nasId", b"switchip", b"host_url", b"csrf",
    b"/account/login", b"csrf_token", b"captchaId",
]


# --------------------------------------------------------------------------
def profiles(browser: str) -> list[Path]:
    root = BROWSERS.get(browser)
    if not root or not os.path.isdir(root):
        return []
    out = [Path(p) for p in glob.glob(os.path.join(root, "*")) if os.path.isdir(p)]
    return [p for p in out if (p / "History").exists() or (p / "Cache").exists()]


def cmd_list(args) -> int:
    found = False
    for b in (args.browser or BROWSERS.keys()):
        for p in profiles(b):
            found = True
            print(f"  [{b}] {p}")
    if not found:
        print("  没有找到任何浏览器数据目录（Edge / Chrome 都没装或没跑过？）")
    return 0


# --------------------------------------------------------------------------
def cmd_history(args) -> int:
    """从 History 数据库按时间线还原门户访问记录。"""
    kws = [args.keyword] if args.keyword else DEFAULT_KEYWORDS
    ts = "datetime(v.visit_time/1000000-11644473600,'unixepoch','localtime')"
    total = 0

    for b in (args.browser or BROWSERS.keys()):
        for prof in profiles(b):
            db = prof / "History"
            if not db.exists():
                continue
            print("=" * 78)
            print(f"[{b}] {db}   ({db.stat().st_size/1024/1024:.1f} MB)")
            print("=" * 78)
            tmp = os.path.join(tempfile.gettempdir(), "_bf_history.sqlite")
            try:
                shutil.copy2(db, tmp)          # 浏览器可能锁着，复制一份再查
            except OSError as e:
                print(f"  复制失败（浏览器占用？）：{e}")
                continue
            try:
                con = sqlite3.connect(tmp)
                where = " OR ".join("u.url LIKE ?" for _ in kws)
                like = [f"%{k}%" for k in kws]
                cur = con.execute(
                    f"SELECT {ts}, u.url, IFNULL(u.title,'') FROM visits v "
                    f"JOIN urls u ON v.url = u.id WHERE {where} "
                    f"ORDER BY v.visit_time DESC LIMIT ?", like + [args.limit])
                rows = cur.fetchall()
                if rows:
                    total += len(rows)
                    for t, url, title in rows:
                        print(f"  {t}  {url[:150]}")
                        if title:
                            print(f"                       标题: {title[:90]}")
                else:
                    print("  （没有匹配的记录）")
                con.close()
            except sqlite3.Error as e:
                print(f"  查询失败：{e}")
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass

    print()
    print(f"共 {total} 条。若看到形如 http://x.x.x.x/api/r/<nasId>?wlanuserip=<你的IP> 的地址，"
          f"那就是 Portal 入口。")
    return 0


# --------------------------------------------------------------------------
def _clean(b: bytes) -> str:
    s = b.decode("utf-8", "replace")
    return "".join(ch if (ch.isprintable() or ch in "\r\n\t") else "." for ch in s)


def cmd_cache(args) -> int:
    """在浏览器缓存里搜门户相关的字节，并打印上下文。"""
    anchor = args.keyword.encode("utf-8") if args.keyword else None
    anchors = [anchor] if anchor else CACHE_ANCHORS
    dump_dir = Path(args.dump) if args.dump else None
    if dump_dir:
        dump_dir.mkdir(parents=True, exist_ok=True)

    hits = 0
    scanned = 0
    for b in (args.browser or BROWSERS.keys()):
        for prof in profiles(b):
            for sub in ("Cache/Cache_Data", "Code Cache/js"):
                d = prof / sub
                if not d.is_dir():
                    continue
                print(f"[扫描] {d}")
                for fp in d.rglob("*"):
                    if not fp.is_file():
                        continue
                    try:
                        if fp.stat().st_size > 25 * 1024 * 1024:
                            continue
                        data = fp.read_bytes()
                    except OSError:
                        continue
                    scanned += 1
                    if not any(a in data for a in anchors):
                        continue
                    hits += 1
                    print("=" * 78)
                    print(f"[命中] {fp}  ({len(data)/1024:.0f} KB)")
                    print("=" * 78)
                    for a in anchors:
                        p = data.find(a)
                        if p < 0:
                            continue
                        lo, hi = max(0, p - 1500), min(len(data), p + 3000)
                        print(f"\n----- 片段 @{a.decode(errors='replace')} -----")
                        print(_clean(data[lo:hi]))
                        break
                    if dump_dir:
                        out = dump_dir / f"{b}_{fp.name}.txt"
                        out.write_text(_clean(data), encoding="utf-8")
                        print(f"\n[已导出] {out}")

    print()
    print(f"扫描 {scanned} 个缓存文件，命中 {hits} 个。")
    if hits == 0:
        print("没找到门户相关内容：可能缓存已被淘汰，或当时用的是隐私模式。")
    return 0


# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description="浏览器取证：还原 Portal 登录接口（只读，不修改浏览器数据）")
    ap.add_argument("--browser", choices=list(BROWSERS), action="append",
                    help="指定浏览器，可重复；默认全部")
    ap.add_argument("--list", action="store_true", help="列出找到的浏览器配置目录")
    ap.add_argument("--history", action="store_true", help="从浏览历史里找门户 URL（带时间线）")
    ap.add_argument("--cache", action="store_true", help="从磁盘缓存里捞门户页面与其 JS")
    ap.add_argument("--keyword", default=None, help="自定义关键词")
    ap.add_argument("--limit", type=int, default=60, help="--history 最多输出多少条")
    ap.add_argument("--dump", default=None, help="--cache 命中时把整块缓存导出到该目录")
    args = ap.parse_args()

    if not any((args.list, args.history, args.cache)):
        ap.print_help()
        print("\n提示：先跑 --list，再 --history 和 --cache")
        return 1
    if args.list:
        return cmd_list(args)
    if args.history:
        cmd_history(args)
    if args.cache:
        cmd_cache(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
