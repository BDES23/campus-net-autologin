# -*- coding: utf-8 -*-
"""网络状态检测 与 Portal 入口自动发现。

为什么不用单一 URL 判断
-----------------------
校园网 Portal 的实现方式有三种，必须都覆盖：
  1. 302 跳转   —— 请求被重定向到 Portal（本机实测就是这种：
                   /api/r/8?wlanuserip=... → /index_8.html → /tpl/default/login.html）
  2. 200 劫持   —— 直接返回 Portal 的 HTML（含 meta refresh 或 JS location 跳转）
  3. 连接重置   —— https 被阻断（所以探测一律用 http，绝不用 https）

判定"已登录"的标准是：**至少一个探测点完全符合预期**（204 且无跳转 / 200 且正文
是预期内容）。只要有一个不符合，就认为需要认证。
"""
from __future__ import annotations

import re
import socket
import subprocess
import urllib.parse
from dataclasses import dataclass, field

import requests

# (URL, 期望状态码, 期望正文正则, 名称)  —— 全部使用 http
PROBES = [
    ("http://www.gstatic.com/generate_204", 204, None, "Google generate_204"),
    ("http://connect.rom.miui.com/generate_204", 204, None, "小米 generate_204"),
    ("http://www.msftconnecttest.com/connecttest.txt", 200,
     r"Microsoft Connect Test", "微软 NCSI"),
]

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0")

# Portal 入口特征：路径里带这些片段的 URL 很可能是入口
ENTRY_HINTS = ("/api/r/", "index_", "login", "portal", "wlanuserip", "nasId")

# 从 HTML 里兜底提取跳转目标
_HTML_REDIRECT = [
    re.compile(r"""<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["'][^"']*?url=([^"'\s>]+)""", re.I),
    re.compile(r"""(?:location\.href|location\.replace\s*\()\s*=?\s*["']([^"']+)["']""", re.I),
    re.compile(r"""(?:window\.location)\s*=\s*["']([^"']+)["']""", re.I),
]


# --------------------------------------------------------------------------
# 本机信息
# --------------------------------------------------------------------------
def local_ipv4() -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("223.5.5.5", 80))       # 不实际发包，只为选出出口网卡
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")


def local_mac(interface: str = "WLAN") -> str | None:
    """返回指定网卡的 MAC，格式 aa:bb:cc:dd:ee:ff（Portal 的 userMac 字段用这个格式）。

    注意：不能用 uuid.getnode() —— 本机装了 Tailscale / Radmin VPN 等多个虚拟网卡时，
    它常常挑到虚拟网卡并因组播位置位而返回无效值。这里改为按网卡名精确匹配。
    """
    # 1) getmac 按网卡名 / 描述匹配（只读命令）
    try:
        import csv
        import io
        out = subprocess.run(["getmac", "/v", "/fo", "csv", "/nh"],
                             capture_output=True, timeout=15)
        txt = out.stdout.decode("gbk", "replace")
        want = (interface or "").lower()
        for row in csv.reader(io.StringIO(txt)):
            if len(row) < 3:
                continue
            name, desc, mac = row[0], row[1], row[2]
            m = _MAC_RE.search(mac or "")
            if not m:
                continue
            if want and (want in (name or "").lower() or want in (desc or "").lower()):
                return m.group(0).replace("-", ":").lower()
    except Exception:
        pass

    # 2) 退到 uuid.getnode()
    try:
        import uuid
        node = uuid.getnode()
        if not (node >> 40) & 0x01:        # 组播位未置位才是有效 MAC
            parts = [(node >> (8 * i)) & 0xFF for i in range(6)]
            return ":".join(f"{b:02x}" for b in reversed(parts))
    except Exception:
        pass
    return None


def current_ssid(interface: str = "WLAN") -> str | None:
    """通过 netsh 读取当前 SSID。只读操作。"""
    try:
        out = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                             capture_output=True, timeout=15)
        txt = out.stdout.decode("gbk", "replace")
        for line in txt.splitlines():
            m = re.match(r"^\s*SSID\s*:\s*(.+?)\s*$", line)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------
# 结果结构
# --------------------------------------------------------------------------
@dataclass
class ProbeDetail:
    name: str
    url: str
    ok: bool
    status: int | None = None
    error: str | None = None
    location: str | None = None


@dataclass
class PortalEntry:
    """Portal 入口上下文，全部来自真实重定向，不是猜的。"""
    base_url: str
    entry_url: str
    params: dict = field(default_factory=dict)

    @property
    def ip(self) -> str | None:
        return self.params.get("wlanuserip") or self.params.get("ip")

    @property
    def nas_id(self) -> str | None:
        return self.params.get("nasId")


def _extract_params(url: str) -> dict:
    q = urllib.parse.urlsplit(url).query
    return {k: v for k, v in urllib.parse.parse_qsl(q, keep_blank_values=True)}


def _extract_nas_id(url: str, params: dict) -> str | None:
    if params.get("nasId"):
        return params["nasId"]
    path = urllib.parse.urlsplit(url).path
    m = re.search(r"/api/r/(\d+)", path) or re.search(r"index_(\d+)\.html", path)
    return m.group(1) if m else None


# --------------------------------------------------------------------------
# 在线检测
# --------------------------------------------------------------------------
def _eval_probe(sess, spec, timeout):
    """执行单个探测点，返回 (ProbeDetail, body)。"""
    url, want_code, want_re, name, generic = spec
    d = ProbeDetail(name=name, url=url, ok=False)
    body = ""
    try:
        r = sess.get(url, timeout=timeout, allow_redirects=False)
        d.status = r.status_code
        d.location = r.headers.get("Location")
        try:
            body = r.text or ""
        except Exception:
            body = ""

        if generic:
            # 通用规则：状态码 2xx、没有跳转、正文很短且不像 HTML 页面
            looks_like_portal = (bool(d.location)
                                 or "<html" in body.lower()
                                 or len(body) > 1024)
            d.ok = r.status_code in (200, 204) and not looks_like_portal
        else:
            d.ok = (r.status_code == want_code
                    and (want_re is None or re.search(want_re, body)))
    except requests.exceptions.RequestException as e:
        d.error = f"{type(e).__name__}"
    return d, body


def _collect_suspects(spec, d: ProbeDetail, body: str, suspects: list) -> None:
    """把"这一跳很可能就是 Portal 入口"的 URL 收集起来。"""
    if d.ok:
        return
    url = spec[0]
    if d.location:
        suspects.append(urllib.parse.urljoin(url, d.location))
    for pat in _HTML_REDIRECT:
        m = pat.search(body)
        if m:
            suspects.append(urllib.parse.urljoin(url, m.group(1)))
            break
    if d.status == 200 and len(body) > 500 and not d.location:
        suspects.append(url)


def check_online(timeout: float = 8.0, session: requests.Session | None = None,
                 cfg=None, extra_probe: str | None = None):
    """返回 (是否已在线, [ProbeDetail], [可疑 Portal URL])。

    探测点选择规则：
      * 默认用内置的三个探测点（Google / 小米 generate_204 + 微软 NCSI）。
      * 如果 config.ini 的 portal.probe_url 被改成**内置之外的**地址，
        则以它**独占**判定（通用规则：2xx 且无跳转且正文不像 Portal 页面）。
        这样学校屏蔽了内置探测点时，换一个轻量 http 地址即可继续工作。
      * 自定义探测点若完全不可达（连接失败），自动退回内置探测点，
        避免"探测地址写错"被误判成"未登录"。
    """
    sess = session or requests.Session()
    sess.headers.update({"User-Agent": UA, "Connection": "close"})
    details: list[ProbeDetail] = []
    suspects: list[str] = []
    online_votes = 0

    # (url, 期望码, 期望正文正则, 名称, 是否通用规则)
    builtin = [(u, c, rx, n, False) for (u, c, rx, n) in PROBES]

    custom = ""
    if cfg is not None:
        custom = cfg.get("portal", "probe_url", "").strip()
    if extra_probe:
        custom = extra_probe

    if custom and not any(p[0] == custom for p in builtin):
        probes = [(custom, None, None, "配置的探测地址", True)]
        fallback = builtin
    else:
        probes = builtin
        fallback = []

    for spec in probes:
        d, body = _eval_probe(sess, spec, timeout)
        details.append(d)
        if d.ok:
            online_votes += 1
        else:
            _collect_suspects(spec, d, body, suspects)

    # 自定义探测点整体不可达 → 退回内置探测点
    if fallback and details and all(x.error for x in details):
        details.clear()
        online_votes = 0
        for spec in fallback:
            d, body = _eval_probe(sess, spec, timeout)
            details.append(d)
            if d.ok:
                online_votes += 1
            else:
                _collect_suspects(spec, d, body, suspects)

    return online_votes > 0, details, suspects


# --------------------------------------------------------------------------
# Portal 入口发现
# --------------------------------------------------------------------------
def discover_entry(cfg, timeout: float = 8.0,
                   session: requests.Session | None = None) -> PortalEntry | None:
    """跟着真实重定向链找到 Portal 入口，并解析出 wlanuserip / nasId / switchip / mac。"""
    sess = session or requests.Session()
    sess.headers.update({"User-Agent": UA})

    probe_url = cfg.get("portal", "probe_url", PROBES[0][0])
    chain: list[str] = []
    final_url = None

    try:
        r = sess.get(probe_url, timeout=timeout, allow_redirects=True)
        for h in r.history:
            loc = h.headers.get("Location")
            if loc:
                chain.append(urllib.parse.urljoin(h.url, loc))
        final_url = r.url
        if r.status_code == 200 and final_url.rstrip("/") != probe_url.rstrip("/"):
            chain.append(final_url)
    except requests.exceptions.RequestException:
        pass

    # 1) 从重定向链里挑最像 Portal 入口的一条
    candidates = [u for u in chain if any(h.lower() in u.lower() for h in ENTRY_HINTS)]
    entry_url = candidates[0] if candidates else (chain[-1] if chain else None)

    # 2) 兜底：用配置里的入口模板
    if not entry_url:
        tpl = cfg.get("portal", "entry_template", "").strip()
        ip = local_ipv4()
        if tpl and ip:
            entry_url = tpl.replace("{ip}", ip)

    if not entry_url:
        return None

    params = _extract_params(entry_url)
    nas_id = _extract_nas_id(entry_url, params)
    if nas_id and not params.get("nasId"):
        params["nasId"] = nas_id

    ip = local_ipv4()
    if ip and not params.get("wlanuserip"):
        params["wlanuserip"] = ip
    if ip and not params.get("ip"):
        params["ip"] = ip
    mac = local_mac()
    if mac and not params.get("mac"):
        params["mac"] = mac

    # base_url：优先用重定向链里的主机；否则回退配置
    split = urllib.parse.urlsplit(entry_url)
    base_url = f"{split.scheme}://{split.netloc}" if split.netloc else \
        cfg.get("portal", "base_url").rstrip("/")

    return PortalEntry(base_url=base_url.rstrip("/"), entry_url=entry_url, params=params)
