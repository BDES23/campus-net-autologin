# -*- coding: utf-8 -*-
"""
本地模拟 Portal 服务器，用于端到端验证。

协议**完全按 2026-10-17 从真实 Portal 抓到的资源复刻**（见 recon/live/）：

    config.js:  var host_url = '/api'        <-- 所有接口都带 /api 前缀
    csrf.js:    GET {host_url}/csrf-token -> {"csrf_token": "..."}
                $.ajaxPrefilter -> 每个请求带 X-CSRF-Token 头

路由：
    GET  /generate_204                    未认证 -> 302 到 /api/r/{nasId}?wlanuserip=..；已认证 -> 204
    GET  /api/r/{nasId}?wlanuserip=..     302 -> /tpl/default/login.html?ip=..&nasId=..&wlanuserip=..
    GET  /tpl/default/login.html          200 登录页
    GET  /api/csrf-token                  {"csrf_token": "..."}
    GET  /api/account/status?wlanuserip=  {"code":0,...} 已在线 / {"code":1} 未在线
    POST /api/account/check               {"code":0,"isChangePwd":"0","msg":""}
    POST /api/account/login               {"code":0} / {"code":1,"msg":..} / {"code":2,"captcha":{..}}

默认强制校验 X-CSRF-Token —— 这样测试才能真正覆盖客户端的 CSRF 实现。
"""
from __future__ import annotations

import http.server
import json
import threading
import urllib.parse

LOGIN_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>网络准入认证</title>
<script src="static/js/jquery.min.js"></script>
<script src="static/js/config.js"></script>
<script src="static/js/csrf.js"></script>
</head><body>
<form id="my-form">
  <input type="text" name="username" id="username">
  <input type="password" name="password" id="password">
  <input type="text" id="codeNumber"/>
</form></body></html>"""


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "MockPortal/2.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):                     # 静音
        pass

    @property
    def st(self) -> dict:
        return self.server.state                      # type: ignore[attr-defined]

    def _send(self, code: int, body: bytes = b"",
              ctype: str = "text/html; charset=utf-8", extra: dict | None = None):
        self.send_response(code)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        if code != 204:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and code != 204:
            self.wfile.write(body)

    def _json(self, obj: dict, code: int = 200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _check_csrf(self) -> bool:
        """返回 True 表示通过。"""
        st = self.st
        if not st.get("require_csrf"):
            return True
        return self.headers.get("X-CSRF-Token") == st["csrf_token"]

    # ------------------------------------------------------------------
    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        st = self.st
        st["requests"].append(("GET", self.path))
        nas = st["nas_id"]

        if u.path == "/generate_204":
            if st["authenticated"]:
                self._send(204)
            else:
                self._send(302, extra={
                    "Location": f"/api/r/{nas}?wlanuserip={st['client_ip']}"})
            return

        if u.path.startswith("/api/r/"):
            self._send(302, extra={
                "Location": (f"/tpl/default/login.html?ip={q.get('wlanuserip', '')}"
                             f"&nasId={nas}&wlanuserip={q.get('wlanuserip', '')}")})
            return

        if u.path == "/tpl/default/login.html":
            self._send(200, LOGIN_HTML.encode("utf-8"))
            return

        if u.path == "/api/csrf-token":
            # 模拟"取令牌暂时失败"，用于测试自愈
            if st.get("csrf_token_fails_remaining", 0) > 0:
                st["csrf_token_fails_remaining"] -= 1
                self._json({"code": 1, "msg": "服务端暂时不可用"}, 500)
                return
            self._json({"csrf_token": st["csrf_token"]})
            return

        if u.path == "/api/config":
            self._json({"code": 0, "msg": "ok", "data": {"config": {
                "title": "网络准入认证", "auth_methods": "account",
                "err_count_captcha": "3"}}})
            return

        if u.path == "/api/account/status":
            if st["authenticated"]:
                self._json({"code": 0, "msg": "在线", "online": {
                    "Username": st["username"], "Name": "",
                    "UserIpv4": q.get("wlanuserip", ""), "UserMac": st["user_mac"],
                    "BytesIn4": "0", "BytesOut4": "0", "BytesIn6": "0",
                    "BytesOut6": "0", "AddTime": "",
                }})
            else:
                self._json({"code": 1, "msg": "未登录"})
            return

        self._send(404, b"not found")

    # ------------------------------------------------------------------
    def do_POST(self):
        u = urllib.parse.urlsplit(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        form = dict(urllib.parse.parse_qsl(raw))
        st = self.st
        st["posts"].append((u.path, form, dict(self.headers)))

        # 用于测试"403 -> 刷新令牌 -> 重试"链路
        if u.path.startswith("/api/account/") and st.get("fail_first_post_403"):
            st["fail_first_post_403"] = False
            self._json({"code": 1, "msg": "CSRF token 校验失败"}, 403)
            return

        if u.path.startswith("/api/account/") and not self._check_csrf():
            # 与真实服务端一致：令牌**缺失**时返回 400，不是 403
            self._json({"code": 1, "msg": "CSRF token 校验失败"}, 400)
            return

        if u.path == "/api/account/check":
            # 注意 isChangePwd 是字符串 —— 与真实接口一致
            self._json({"code": 0, "isChangePwd": "0", "msg": ""})
            return

        if u.path == "/api/account/login":
            if st.get("force_captcha"):
                self._json({"code": 2, "captcha": {
                    "picPath": "/captcha.png", "captchaId": "cid-123"}})
                return
            if form.get("password") == st["password"]:
                st["authenticated"] = True
                self._json({"code": 0, "msg": "认证成功", "online": {
                    "Username": form.get("username", ""), "Name": "",
                    "UserIpv4": form.get("userIpv4", ""), "UserMac": form.get("userMac", ""),
                    "BytesIn4": "0", "BytesOut4": "0", "BytesIn6": "0",
                    "BytesOut6": "0", "AddTime": "",
                }})
            else:
                msg = st.get("fail_msg") or "认证被拒绝"
                if st.get("echo_password_in_msg"):
                    msg = f"认证被拒绝，收到的密码是 {form.get('password')}"
                self._json({"code": 1, "msg": msg})
            return

        self._send(404, b"not found")


class MockPortalServer:
    """在 127.0.0.1 的随机空闲端口上跑一个模拟 Portal。"""

    def __init__(self, password: str = "correct-pw", username: str = "20230001",
                 nas_id: str = "8", client_ip: str = "127.0.0.1",
                 user_mac: str = "aa:bb:cc:dd:ee:ff", require_csrf: bool = True):
        self.state = {
            "authenticated": False,
            "password": password,
            "username": username,
            "nas_id": nas_id,
            "client_ip": client_ip,
            "user_mac": user_mac,
            "require_csrf": require_csrf,
            "csrf_token": "mock-csrf-token-0123456789",
            "fail_first_post_403": False,
            "csrf_token_fails_remaining": 0,
            "force_captcha": False,
            "fail_msg": None,
            "echo_password_in_msg": False,
            "requests": [],
            "posts": [],
        }
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.state = self.state                    # type: ignore[attr-defined]
        self.httpd.daemon_threads = True
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def url(self, path: str) -> str:
        return self.base_url + path

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:
            pass

    # ---- 断言辅助 ------------------------------------------------------
    def login_posts(self) -> list:
        return [p for p in self.state["posts"] if p[0] == "/api/account/login"]

    def reset_records(self):
        self.state["requests"].clear()
        self.state["posts"].clear()
