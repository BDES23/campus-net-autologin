# -*- coding: utf-8 -*-
"""
校园网 Portal 侦察探针  probe_portal.py
=======================================

用途
----
在「未登录（未认证）」状态下，自动完成抓包里最麻烦的那部分工作：
  1. 判断当前是否被 Portal 劫持；
  2. 记录完整的 302 重定向链，定位真实 Portal 入口 URL；
  3. 拉取 Portal 页面，解析登录表单的 action / method / 全部字段名；
  4. 扫描页面，提示是否存在 JS 加密（RSA/MD5/AES/CryptoJS…）或验证码；
  5. 把原始 HTML 和结构化报告落盘，便于进一步分析。

安全承诺
--------
  * 只用 Python 标准库，不需要 pip 安装任何东西；
  * 只发 GET 探测请求，**绝不提交账号或密码**；
  * 不修改系统设置、不写注册表、不注册开机自启；
  * 输出报告里不含任何凭据（因为脚本压根不碰凭据）。

典型用法
--------
    python probe_portal.py                     # 单次探测 + 出报告
    python probe_portal.py --watch             # 每 3 秒轮询，等 Portal 出现（配合"随机硬件地址"使用）
    python probe_portal.py --out recon\\r.json  # 指定报告路径
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

# Windows 中文控制台编码兜底，避免打印中文时崩掉
try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0")

# 探测点： (URL, 期望状态码, 期望正文正则, 说明)
# 只要有一项不符合期望，就说明链路被劫持 / 未认证。
DETECTORS = [
    ("http://www.gstatic.com/generate_204",        204, None,                  "Google generate_204"),
    ("http://connect.rom.miui.com/generate_204",   204, None,                  "小米 generate_204"),
    ("http://www.msftconnecttest.com/connecttest.txt", 200, r"Microsoft Connect Test", "微软 NCSI 探测"),
    ("http://captive.apple.com/hotspot-detect.html",   200, r"Success",         "Apple Captive 探测"),
    ("http://detectportal.firefox.com/success.txt",    200, r"success",         "Firefox Captive 探测"),
]

# 可选的"额外尝试清单"：某些 Portal 在抓不到重定向时，可以直接试入口模板。
# {ip} 会替换成本机当前 IPv4。留空即可 —— 脚本真正依赖的是重定向链里抓到的真实地址。
# 示例： HINT_PATTERNS = ["http://10.0.0.1/api/r/1?wlanuserip={ip}"]
HINT_PATTERNS = []

CRYPTO_HINTS = [
    "jsencrypt", "JSEncrypt", "setPublicKey", "publicKey", "public_key",
    "crypto-js", "cryptojs", "CryptoJS", "RSA", "rsa",
    "MD5", "md5", "SHA1", "sha1", "SHA256", "sha256",
    "AES", "aes", "Base64", "base64", "encrypt", "Encrypt", "encryptpwd",
]

CAPTCHA_HINTS = [
    "captcha", "Captcha", "CAPTCHA", "verifycode", "verifyCode", "checkcode",
    "checkCode", "vcode", "imgcode", "validate", "验证码",
]


# --------------------------------------------------------------------------
# HTTP 基础
# --------------------------------------------------------------------------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """禁止 urllib 自动跟随 3xx，这样我们才能看到每一跳的 Location。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_get(url, timeout=8.0, follow=False, max_bytes=400_000):
    """发一个 GET，返回一个纯 dict（绝不抛出，方便批量探测）。"""
    handlers = [] if follow else [_NoRedirect()]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Connection": "close",
    })
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(max_bytes)
            return {
                "url": url, "final_url": resp.geturl(), "status": resp.status,
                "headers": {k: v for k, v in resp.headers.items()},
                "body": body.decode("utf-8", "replace"),
                "error": None,
            }
    except urllib.error.HTTPError as e:                       # 含被我们拦下的 3xx
        body = b""
        try:
            body = e.read(max_bytes)
        except Exception:
            pass
        return {
            "url": url, "final_url": url, "status": e.code,
            "headers": {k: v for k, v in (e.headers or {}).items()},
            "body": body.decode("utf-8", "replace"),
            "error": None,
        }
    except Exception as e:                                     # 超时 / DNS / 连接被重置
        return {
            "url": url, "final_url": url, "status": None, "headers": {},
            "body": "", "error": f"{type(e).__name__}: {e}",
        }


def trace_redirects(url, max_hops=6, timeout=8.0):
    """手工跟随重定向，记录每一跳，用来还原 Portal 入口。"""
    hops, seen, cur = [], set(), url
    for _ in range(max_hops):
        if cur in seen:
            break
        seen.add(cur)
        r = http_get(cur, timeout=timeout, follow=False)
        hops.append(r)
        if r["status"] in (301, 302, 303, 307, 308):
            loc = r["headers"].get("Location") or r["headers"].get("location")
            if loc:
                cur = urllib.parse.urljoin(cur, loc)
                continue
        break
    return hops


# --------------------------------------------------------------------------
# HTML 解析
# --------------------------------------------------------------------------
class PageParser(HTMLParser):
    """提取表单、输入框、脚本、图片、iframe、meta refresh —— 够用且零依赖。"""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.forms: list[dict] = []
        self.inputs: list[dict] = []
        self.scripts: list[str] = []
        self.images: list[str] = []
        self.iframes: list[str] = []
        self.meta_refresh: list[str] = []
        self._cur_form = None
        self._in_title = False
        self._in_script = False
        self._script_buf: list[str] = []
        self.inline_js: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "form":
            self._cur_form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(),
                              "name": a.get("name", ""), "id": a.get("id", "")}
            self.forms.append(self._cur_form)
        elif tag == "input":
            item = {"name": a.get("name", ""), "type": (a.get("type") or "text").lower(),
                    "id": a.get("id", ""), "value": a.get("value", ""),
                    "placeholder": a.get("placeholder", "")}
            self.inputs.append(item)
            if self._cur_form is not None:
                self._cur_form.setdefault("fields", []).append(item)
        elif tag == "select":
            if self._cur_form is not None:
                self._cur_form.setdefault("fields", []).append(
                    {"name": a.get("name", ""), "type": "select", "id": a.get("id", "")})
        elif tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:
                self._in_script = True
                self._script_buf = []
        elif tag == "img":
            self.images.append(a.get("src", ""))
        elif tag == "iframe":
            self.iframes.append(a.get("src", ""))
        elif tag == "meta":
            if (a.get("http-equiv", "").lower() == "refresh"):
                self.meta_refresh.append(a.get("content", ""))

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._cur_form = None
        elif tag == "script" and self._in_script:
            self._in_script = False
            self.inline_js.append("".join(self._script_buf))

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._in_script:
            self._script_buf.append(data)


def analyze_page(html: str, base_url: str) -> dict:
    p = PageParser()
    try:
        p.feed(html)
    except Exception:
        pass

    def absu(u):
        return urllib.parse.urljoin(base_url, u) if u else u

    forms = []
    for f in p.forms:
        forms.append({
            "action": absu(f.get("action", "")),
            "action_raw": f.get("action", ""),
            "method": f.get("method", "get"),
            "name": f.get("name", ""),
            "id": f.get("id", ""),
            "fields": [dict(x) for x in f.get("fields", [])],
        })

    haystack = html + "\n" + "\n".join(p.inline_js)
    crypto = sorted({k for k in CRYPTO_HINTS if k in haystack})
    captcha = sorted({k for k in CAPTCHA_HINTS if k in haystack})
    captcha_imgs = [absu(s) for s in p.images
                    if any(t in s.lower() for t in ("captcha", "verify", "code", "vcode", "check"))]

    return {
        "title": p.title.strip(),
        "forms": forms,
        "inputs_all": p.inputs,
        "scripts": [absu(s) for s in p.scripts],
        "iframes": [absu(s) for s in p.iframes],
        "meta_refresh": p.meta_refresh,
        "captcha_images": captcha_imgs,
        "crypto_hints": crypto,
        "captcha_hints": captcha,
        "html_length": len(html),
    }


# --------------------------------------------------------------------------
# 本机网络信息
# --------------------------------------------------------------------------
def local_ipv4(default=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("223.5.5.5", 80))       # 不会真的发包，只为拿到出口网卡地址
        return s.getsockname()[0]
    except Exception:
        return default
    finally:
        s.close()


def ipconfig_summary():
    """从 ipconfig /all 里抠出**承载本机 IP 的那块网卡**的网关/DHCP/DNS。

    注意：不能直接取第一个匹配行 —— 本机常装着 Tailscale / Radmin VPN / 加速器
    等多个虚拟网卡，它们排在前面，会报出错误的网关（曾实测把 Radmin 的 26.0.0.1
    当成默认网关）。这里先按适配器分块，再挑包含本机 IP 的那一块。
    """
    info = {"adapter": None, "gateway": None, "dhcp_server": None, "dns": []}
    try:
        out = subprocess.run(["ipconfig", "/all"], capture_output=True, timeout=15)
        txt = out.stdout.decode("gbk", "replace")

        # 按适配器分块：以非缩进、以冒号结尾的行为块首
        blocks, cur = [], None
        for line in txt.splitlines():
            if line.strip() and not line[0].isspace() and line.rstrip().endswith(":"):
                if cur:
                    blocks.append(cur)
                cur = [line.rstrip()]
            elif cur is not None:
                cur.append(line)
        if cur:
            blocks.append(cur)

        ip = local_ipv4(default=None)
        target = None
        for b in blocks:
            if ip and ip in "\n".join(b):
                target = b
                break
        if target is None:
            for b in blocks:                    # 退一步：找有 IPv4 的块
                if re.search(r"IPv4.*?(\d+\.\d+\.\d+\.\d+)", "\n".join(b)):
                    target = b
                    break
        if target is None and blocks:
            target = blocks[0]

        if target:
            info["adapter"] = target[0].strip().rstrip(":")
            for line in target:
                s = line.strip()
                for key, labels in (("gateway", ("默认网关", "Default Gateway")),
                                    ("dhcp_server", ("DHCP 服务器", "DHCP Server"))):
                    if any(s.startswith(l) for l in labels) and not info[key]:
                        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", s)
                        if m:
                            info[key] = m.group(1)
                if s.startswith(("DNS 服务器", "DNS Servers")):
                    for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)", s):
                        if m.group(1) not in info["dns"]:
                            info["dns"].append(m.group(1))
    except Exception as e:
        info["error"] = str(e)
    return info


def dns_sanity():
    """看一眼公共域名解析结果，用来发现 DNS 劫持。"""
    out = {}
    for host in ("www.baidu.com", "www.gstatic.com"):
        try:
            out[host] = sorted({ai[4][0] for ai in socket.getaddrinfo(host, 80, socket.AF_INET)})
        except Exception as e:
            out[host] = f"ERR {type(e).__name__}"
    return out


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
def detect_once(extra_patterns=None, deep=True):
    ip = local_ipv4()
    result = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "local_ip": ip,
        "ipconfig": ipconfig_summary(),
        "dns": dns_sanity(),
        "detectors": [],
        "portal_suspects": [],
        "portal_page": None,
        "verdict": None,
    }

    hijacked = False
    for url, want_code, want_re, label in DETECTORS:
        fresh = http_get(url, timeout=8.0, follow=False, max_bytes=4096)
        entry = {
            "label": label, "url": url, "want_status": want_code,
            "status": fresh["status"], "error": fresh["error"],
            "location": fresh["headers"].get("Location") or fresh["headers"].get("location"),
            "body_head": (fresh["body"] or "")[:200],
            "ok": None,
        }
        if fresh["status"] == want_code and (want_re is None or re.search(want_re, fresh["body"] or "")):
            entry["ok"] = True
        else:
            entry["ok"] = False
            if fresh["status"] is not None or fresh["error"]:
                hijacked = True
        result["detectors"].append(entry)

        # 被劫持时，追一下这条的重定向链
        if entry["ok"] is False and deep:
            hops = trace_redirects(url, max_hops=6)
            entry["redirect_chain"] = [
                {"status": h["status"], "url": h["url"],
                 "location": h["headers"].get("Location") or h["headers"].get("location"),
                 "error": h["error"], "server": h["headers"].get("Server")}
                for h in hops
            ]
            for h in hops:
                loc = h["headers"].get("Location") or h["headers"].get("location")
                if loc:
                    result["portal_suspects"].append(urllib.parse.urljoin(h["url"], loc))
                if h["status"] == 200 and len(h["body"]) > 400:
                    result["portal_suspects"].append(h["url"])

    # 额外尝试已知入口模式
    for pat in (extra_patterns or []):
        if "{ip}" in pat and not ip:
            continue
        u = pat.replace("{ip}", ip or "")
        h = http_get(u, timeout=8.0, follow=False, max_bytes=2000)
        result["detectors"].append({
            "label": "hint", "url": u, "status": h["status"], "error": h["error"],
            "location": h["headers"].get("Location"), "ok": h["status"] == 200,
            "body_head": (h["body"] or "")[:200],
        })
        if h["status"] == 200 and len(h["body"]) > 200:
            result["portal_suspects"].append(u)

    # 去重，优先取带参数的、非探测点的
    seen, suspects = set(), []
    for s in result["portal_suspects"]:
        if s in seen or any(s.startswith(d[0]) for d in DETECTORS):
            continue
        seen.add(s)
        suspects.append(s)
    result["portal_suspects"] = suspects

    # 拉取第一个可疑入口，解析页面
    if deep and suspects:
        target = suspects[0]
        hops = trace_redirects(target, max_hops=4)
        final = hops[-1]
        result["portal_page"] = {
            "entry": target,
            "chain": [{"status": h["status"], "url": h["url"], "error": h["error"]} for h in hops],
            "final_url": final["url"],
            "final_status": final["status"],
            "analysis": analyze_page(final["body"], final["url"]) if final["body"] else None,
            "html": final["body"][:200_000],
        }

    if hijacked:
        result["verdict"] = "UN_AUTHENTICATED"     # 未登录，链路被 Portal 劫持
    elif all(d.get("ok") for d in result["detectors"] if d["label"] != "hint"):
        result["verdict"] = "ALREADY_ONLINE"       # 已认证，无劫持
    else:
        result["verdict"] = "UNCLEAR"              # 网络不通或其他异常
    return result


def print_report(res, html_saved=None):
    line = "=" * 74
    print(line)
    print(f"校园网 Portal 侦察报告   {res['timestamp']}")
    print(line)
    print(f"本机 IPv4    : {res['local_ip']}")
    ic = res.get("ipconfig") or {}
    print(f"网卡         : {ic.get('adapter')}")
    print(f"默认网关     : {ic.get('gateway')}")
    print(f"DHCP 服务器  : {ic.get('dhcp_server')}")
    print(f"DNS          : {', '.join(ic.get('dns') or []) or '-'}")
    print()
    print("[1] 链路探测")
    for d in res["detectors"]:
        if d["label"] == "hint":
            continue
        flag = "[OK]  " if d.get("ok") else "[FAIL]"
        st = d["status"] if d["status"] is not None else f"ERR({d.get('error')})"
        print(f"  {flag} {d['label']:<22} status={st}")
        if d.get("location"):
            print(f"          -> Location: {d['location']}")
        if d.get("redirect_chain"):
            for h in d["redirect_chain"]:
                loc = f" -> {h['location']}" if h.get("location") else ""
                print(f"          hop {h['status']}: {h['url']}{loc}")
    hints = [d for d in res["detectors"] if d["label"] == "hint"]
    if hints:
        print("\n[1b] 已知入口模式尝试")
        for d in hints:
            st = d["status"] if d["status"] is not None else f"ERR({d.get('error')})"
            print(f"  {'[OK]  ' if d.get('ok') else '[FAIL]'} {d['url']}  status={st}")

    print()
    print("[2] 判定")
    v = res["verdict"]
    print("  " + {
        "UN_AUTHENTICATED": "未登录 —— 链路被 Portal 劫持，可以抓包了！",
        "ALREADY_ONLINE":   "已认证 / 无 Portal 劫持 —— 现在抓不到登录请求。",
        "UNCLEAR":          "不确定 —— 网络可能不通或异常，看上面的探测详情。",
    }.get(v, v))

    print()
    print("[3] Portal 入口候选")
    if res["portal_suspects"]:
        for i, s in enumerate(res["portal_suspects"], 1):
            print(f"  {i}. {s}")
    else:
        print("  （无）")

    pp = res.get("portal_page")
    if pp:
        print()
        print("[4] Portal 页面解析")
        print(f"  入口     : {pp['entry']}")
        print(f"  最终 URL : {pp['final_url']}   status={pp['final_status']}")
        a = pp.get("analysis")
        if a:
            print(f"  标题     : {a['title']}")
            print(f"  表单数   : {len(a['forms'])}")
            for i, f in enumerate(a["forms"], 1):
                print(f"    表单{i}: method={f['method'].upper()}  action={f['action']}")
                for fl in f["fields"]:
                    print(f"        - name={fl.get('name')!r:<28} type={fl.get('type')} id={fl.get('id')!r}")
            if a["scripts"]:
                print(f"  外部 JS  ({len(a['scripts'])}):")
                for s in a["scripts"][:20]:
                    print(f"      {s}")
            if a["iframes"]:
                print(f"  iframe   : {a['iframes']}")
            if a["meta_refresh"]:
                print(f"  meta refresh: {a['meta_refresh']}")
            if a["crypto_hints"]:
                print(f"  [!] 疑似 JS 加密关键字: {', '.join(a['crypto_hints'])}")
                print("      -> 密码很可能是密文提交，需要移植 JS 算法或改用 Playwright")
            else:
                print("  [i] 未命中常见加密关键字（不代表一定明文，仍需看实际 Payload）")
            if a["captcha_hints"] or a["captcha_images"]:
                print(f"  [!] 疑似验证码: {a['captcha_hints']} {a['captcha_images']}")
            else:
                print("  [i] 未发现验证码迹象")
        if html_saved:
            print(f"  原始 HTML 已保存: {html_saved}")

    print()
    print(line)
    if res["verdict"] == "UN_AUTHENTICATED":
        print("下一步：把本报告 + 上面 Portal 页面里那条登录 POST 的 cURL 发给我")
        print("        （记得先把 password 的值替换成 <PASSWORD> 再发）")
    elif res["verdict"] == "ALREADY_ONLINE":
        print("下一步：想办法回到未认证状态，再跑一次本脚本。方法见 README。")
    print(line)


def main():
    ap = argparse.ArgumentParser(description="校园网 Portal 侦察探针（只读、不登录）")
    ap.add_argument("--out", default=None, help="JSON 报告输出路径")
    ap.add_argument("--html-dir", default=None, help="Portal 原始 HTML 保存目录")
    ap.add_argument("--extra", action="append", default=None,
                    help="额外尝试的入口 URL 模式，可用 {ip} 占位，可重复")
    ap.add_argument("--watch", action="store_true", help="每 3 秒轮询，直到检测到未认证状态")
    ap.add_argument("--interval", type=float, default=3.0, help="--watch 的轮询间隔（秒）")
    ap.add_argument("--no-deep", action="store_true", help="只做浅探测，不跟随重定向、不解析页面")
    args = ap.parse_args()

    patterns = list(HINT_PATTERNS)
    if args.extra:
        patterns = args.extra + patterns

    # 本脚本位于 tools/ 下，报告统一写到项目根目录的 recon/
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = os.path.join(base, "recon")
    os.makedirs(out_dir, exist_ok=True)

    try:
        if not args.watch:
            res = detect_once(patterns, deep=not args.no_deep)
            html_path = None
            if res.get("portal_page") and res["portal_page"].get("html"):
                html_path = os.path.join(args.html_dir or out_dir, "portal_page.html")
                os.makedirs(os.path.dirname(html_path), exist_ok=True)
                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(res["portal_page"]["html"])
                res["portal_page"].pop("html", None)
            out_path = args.out or os.path.join(out_dir, "probe_report.json")
            os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(res, f, ensure_ascii=False, indent=2)
            print_report(res, html_path)
            print(f"JSON 报告: {out_path}")
            return 0

        # --watch 模式：等到出现未认证状态就停下并出报告
        print(f"轮询中（每 {args.interval}s），请配合「随机硬件地址」或重新获取 IP 来触发未认证状态…")
        n = 0
        while True:
            n += 1
            res = detect_once(patterns, deep=False)
            ts = time.strftime("%H:%M:%S")
            bad = [d for d in res["detectors"] if d["label"] != "hint" and not d.get("ok")]
            print(f"[{ts}] #{n:<4} ip={res['local_ip']:<16} verdict={res['verdict']:<18} 异常探测点={len(bad)}")
            if res["verdict"] == "UN_AUTHENTICATED":
                print("\n>>> 检测到未认证状态！立刻做深度解析…\n")
                res = detect_once(patterns, deep=True)
                html_path = None
                if res.get("portal_page") and res["portal_page"].get("html"):
                    html_path = os.path.join(out_dir, "portal_page.html")
                    with open(html_path, "w", encoding="utf-8") as f:
                        f.write(res["portal_page"]["html"])
                    res["portal_page"].pop("html", None)
                out_path = os.path.join(out_dir, "probe_report.json")
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump(res, f, ensure_ascii=False, indent=2)
                print_report(res, html_path)
                print(f"JSON 报告: {out_path}")
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n已手动中断。")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
