# -*- coding: utf-8 -*-
"""
真实抓包验证工具  tools/capture_live.py
=====================================

用途
----
在**未登录**状态下运行，它会把真实的 Portal 交互全过程打印出来，用来验证
项目里内置的接口/字段是否与实际一致：

  1. 探测链路 -> 打印完整 302 链
  2. 请求 Portal 入口页 -> 保存原始 HTML
  3. 检查前端脚本里是否引用了 CSRF 相关文件（本项目唯一未验证点）
  4. 调用 /account/status 看是否已在线
  5. 【关键】用一个**故意错误的密码**去调 /account/check 与 /account/login，
     借此确认：
       - 接口路径是否存在（404 说明路径不对）
       - 提交字段名是否被接受（返回"参数错误"说明字段名不对）
       - 返回是不是 JSON、code 语义是否与前端一致
     因为是错密码，绝不会真的登录成功，也不会泄露真实密码。

注意
----
本脚本**不读取、也不需要你的真实密码**。它只用 "-ProbeOnly" 模式发一个
一眼假的占位密码，属于安全的自检手段。

用法
----
    python tools/capture_live.py
    python tools/capture_live.py --no-post      # 只做只读探测，连测试 POST 都不发
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests                                   # noqa: E402

from campusnet import config as cfgmod, logkit, netcheck   # noqa: E402
from campusnet.portal import PortalClient          # noqa: E402

OUT_DIR = Path(__file__).resolve().parent.parent / "recon"

# 故意错误的占位密码：只会得到"密码错误"，不可能登录成功
FAKE_PASSWORD = "___wrong_password_probe___"


def section(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def main() -> int:
    ap = argparse.ArgumentParser(description="Portal 真实交互抓包验证（不需要真实密码）")
    ap.add_argument("--no-post", action="store_true", help="完全不发送 POST，只做只读探测")
    ap.add_argument("--username", default=None, help="用于测试 POST 的账号，默认取配置里的")
    args = ap.parse_args()

    cfg = cfgmod.ensure_config()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    timeout = cfg.get_float("policy", "request_timeout", 8.0)

    section("0) 环境")
    print(f"本机 IPv4 : {netcheck.local_ipv4()}")
    print(f"本机 MAC  : {netcheck.local_mac(cfg.get('network', 'interface', 'WLAN'))}")
    print(f"当前 SSID : {netcheck.current_ssid(cfg.get('network', 'interface', 'WLAN'))}")
    print(f"配置账号  : {args.username or cfg.get('account', 'username') or '(未设置)'}")

    section("1) 链路探测（是否已被 Portal 劫持）")
    online, details, suspects = netcheck.check_online(timeout=timeout, cfg=cfg)
    for d in details:
        print(f"  [{'OK  ' if d.ok else 'FAIL'}] {d.name:<20} status={d.status} "
              f"err={d.error} loc={d.location}")
    print(f"\n判定：{'已登录 —— 现在抓不到登录请求，请先注销再跑本脚本' if online else '未登录 —— 适合抓包'}")
    if online:
        print("\n提示：可以先执行下面的命令让 Portal 把你踢下线（前提是 Portal 可达）：")
        print("      python -m campusnet logout")
        return 2

    section("2) 302 重定向链（Portal 入口的真实来源）")
    sess = requests.Session()
    sess.headers.update({"User-Agent": "Mozilla/5.0", "Connection": "close"})
    probe = cfg.get("portal", "probe_url", "http://www.gstatic.com/generate_204")
    try:
        r = sess.get(probe, timeout=timeout, allow_redirects=True)
        hop = 1
        for h in r.history:
            print(f"  {hop}) {h.status_code} {h.url}")
            loc = h.headers.get("Location")
            if loc:
                print(f"      -> Location: {loc}")
            hop += 1
        print(f"  {hop}) {r.status_code} {r.url}   <== 最终落地")
        body = r.text or ""
        if body:
            name = "portal_entry.html"
            (OUT_DIR / name).write_text(body, encoding="utf-8")
            print(f"      正文 {len(body)} 字节，已保存到 recon/{name}")
    except requests.exceptions.RequestException as e:
        print(f"  请求失败：{type(e).__name__}: {e}")

    entry = netcheck.discover_entry(cfg, timeout=timeout)
    if not entry:
        print("\n[!!] 没能发现 Portal 入口，无法继续。请检查 portal.entry_template 配置。")
        return 4

    section("3) Portal 入口上下文")
    print(f"  入口 URL : {entry.entry_url}")
    print(f"  base_url : {entry.base_url}")
    print(f"  参数     : {json.dumps(entry.params, ensure_ascii=False)}")
    print(f"  推导 IP  : {entry.ip}")
    print(f"  推导 NAS : {entry.nas_id}")
    print(f"  IP 参数名: {'wlanuserip' if entry.params.get('wlanuserip') else '缺失'}")

    client = PortalClient(cfg, entry)

    section("4) 入口页 HTML 与前端脚本（查 CSRF / 加密 / 验证码）")
    try:
        pr = client.sess.get(entry.entry_url, timeout=timeout, allow_redirects=True)
        html = pr.text or ""
        (OUT_DIR / "portal_entry_live.html").write_text(html, encoding="utf-8")
        print(f"  HTTP {pr.status_code}，{len(html)} 字节 -> recon/portal_entry_live.html")
        scripts = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html, re.I)
        print(f"  引用的脚本（{len(scripts)} 个）:")
        for s in scripts:
            print(f"    - {urllib.parse.urljoin(pr.url, s)}")
        if any("csrf" in s.lower() for s in scripts):
            print("  [!] 页面引用了 csrf.js —— 说明可能存在 CSRF 校验，"
                  "请把该 js 的内容发我，或先试运行看是否 403。")
        for kw in ("md5", "sha1", "sha256", "rsa", "jsencrypt", "cryptojs", "encrypt"):
            if kw in html.lower():
                print(f"  [!] HTML 里出现加密关键字: {kw}")
        if re.search(r"captcha|verifycode|checkcode", html, re.I):
            print("  [!] HTML 里出现验证码关键字")
        m = re.search(r"""var\s+host_url\s*=\s*["']([^"']*)["']""", html)
        if m:
            print(f"  host_url = {m.group(1)!r}")
    except requests.exceptions.RequestException as e:
        print(f"  拉取入口页失败：{type(e).__name__}: {e}")

    section("5) GET /account/status（只读，判断 Portal 侧是否已在线）")
    try:
        js = client.status()
        print(f"  返回: {json.dumps(js, ensure_ascii=False)[:600]}")
        print(f"  code==0 ？ {'是 —— Portal 认为已在线' if js.get('code') == 0 else '否'}")
    except Exception as e:
        print(f"  失败：{type(e).__name__}: {e}")

    if args.no_post:
        section("6) 已跳过 POST 测试（--no-post）")
        return 0

    username = args.username or cfg.get("account", "username", "").strip()
    if not username:
        section("6) 跳过 POST 测试：配置里没有账号，且未用 --username 指定")
        return 0

    section("6) POST 接口自检（使用故意错误的密码，不会真的登录成功）")
    print(f"  账号     : {username}")
    print(f"  密码     : {FAKE_PASSWORD!r}  <- 故意错误，仅用于探测接口是否存在")
    payload = client.build_payload(username, FAKE_PASSWORD)
    print(f"  将提交字段: {sorted(payload.keys())}")
    print("  （password 的值不在日志里显示）")

    print("\n  --- POST /account/check ---")
    try:
        ck = client.check(payload)
        print(f"  返回: {json.dumps(ck, ensure_ascii=False)[:600]}")
        if ck.get("code") == 1:
            print("  [OK] 接口存在且字段被识别（返回了业务层错误，而不是 404/参数错误）")
        elif ck.get("code") == 0:
            print("  [?] 意外返回成功，请人工核对")
    except Exception as e:
        print(f"  失败：{type(e).__name__}: {e}")
        print("  [!] 若为 404，说明 check_path 配置不对；若为 403，多半是 CSRF 校验")

    print("\n  --- POST /account/login ---")
    try:
        res = client.login(username, FAKE_PASSWORD)
        print(f"  code={res.code}  msg={res.msg!r}  captcha={res.captcha_needed}")
        if res.code == 1:
            print("  [OK] 登录接口路径与字段名**全部正确**——错密码得到了业务层失败响应。")
            print("       这说明用真实密码就能登录成功，项目实现可以直接用。")
        elif res.captcha_needed:
            print("  [!] 服务端直接要求验证码，无法无人值守完成。")
        elif res.code == 0:
            print("  [?] 意外成功，请立刻检查账号状态。")
        else:
            print(f"  [?] 未预期的 code={res.code}，请把原始返回发我：")
            print(f"      {json.dumps(res.raw, ensure_ascii=False)[:600]}")
    except Exception as e:
        print(f"  失败：{type(e).__name__}: {e}")

    section("完成")
    print("请把上面第 2~6 节的输出（含 recon/portal_entry_live.html）反馈，")
    print("即可最终确认实现与学校 Portal 完全一致。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
