# -*- coding: utf-8 -*-
"""Portal 协议客户端。

接口与字段来源：用户本机 Edge 缓存中的真实 Portal 前端 JavaScript
（recon/cache_dump/hit_1_f_01c7d4.txt），并非推测。详见包 __init__ 说明。
"""
from __future__ import annotations

import time
import urllib.parse
from dataclasses import dataclass, field

import requests

from . import logkit
from .netcheck import PortalEntry, local_ipv4, local_mac

log = logkit.get("portal")

# 登录响应的 code 语义（来自前端源码注释）
#   code=0 认证成功   code=1 认证失败   code=2 需要验证码
CODE_OK = 0
CODE_FAIL = 1
CODE_CAPTCHA = 2


@dataclass
class LoginResult:
    ok: bool
    code: int | None = None
    msg: str = ""
    captcha_needed: bool = False
    captcha_pic: str = ""
    captcha_id: str = ""
    online: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    def summary(self) -> str:
        if self.ok:
            name = self.online.get("Name") or self.online.get("Username") or ""
            return f"认证成功（用户 {name}）"
        if self.captcha_needed:
            return "认证需要验证码：服务端下发了验证码，无法无人值守完成"
        return f"认证失败（code={self.code}）：{self.msg}"


class PortalError(RuntimeError):
    pass


class PortalClient:
    """一个 Portal 会话。所有路径都可在 config.ini 里覆盖。"""

    def __init__(self, cfg, entry: PortalEntry, session: requests.Session | None = None):
        self.cfg = cfg
        self.entry = entry
        self.timeout = cfg.get_float("policy", "request_timeout", 8.0)
        self.sess = session or requests.Session()
        headers = {
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"),
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            # 关键：Portal 的入口页在 /tpl/default/ 下，请求头带上同源 Referer
            "Referer": entry.entry_url,
            "Origin": entry.base_url,
        }
        headers.update(cfg.extra_headers)
        self.sess.headers.update(headers)
        self._csrf_token: str | None = None

    # ---- CSRF -----------------------------------------------------------
    def ensure_csrf(self, force: bool = False, attempts: int = 3) -> str | None:
        """取一次 CSRF 令牌并挂到会话请求头上。

        复刻前端 csrf.js 的行为：先 GET {host_url}/csrf-token 拿到
        {"csrf_token": "..."}，再由 $.ajaxPrefilter 给每个请求加
        `X-CSRF-Token` 头。

        重要：校园网关实测**约有一半的连接会超时**，所以这里必须重试——
        否则第一次超时就会"无令牌裸奔"去登录，白白浪费一次机会。
        确实取不到时只警告不阻断（有些部署不启用 CSRF）。
        """
        if self._csrf_token and not force:
            return self._csrf_token
        header = self.cfg.get("portal", "csrf_header", "X-CSRF-Token").strip()
        path = self.cfg.get("portal", "csrf_path", "/api/csrf-token").strip()
        if not header or not path:
            return None
        url = self._url("csrf_path", "/api/csrf-token")
        self._csrf_token = None

        for i in range(1, max(1, attempts) + 1):
            try:
                r = self.sess.get(url, timeout=self.timeout)
                if r.status_code != 200:
                    log.warning("取 CSRF 令牌失败(第 %d/%d 次)：HTTP %s  %s",
                                i, attempts, r.status_code, url)
                else:
                    token = (r.json() or {}).get("csrf_token")
                    if token:
                        self._csrf_token = str(token)
                        self.sess.headers[header] = self._csrf_token
                        log.debug("已获取 CSRF 令牌（%d 字符），随 %s 头发送",
                                  len(self._csrf_token), header)
                        return self._csrf_token
                    # 服务端明确没有这个字段 → 说明该部署不启用 CSRF，重试无意义
                    log.warning("CSRF 接口返回里没有 csrf_token（按未启用处理）：%s",
                                logkit.redact((r.text or "")[:200]))
                    return None
            except Exception as e:
                log.warning("取 CSRF 令牌异常(第 %d/%d 次)：%s",
                            i, attempts, logkit.redact(e))
            if i < attempts:
                time.sleep(0.4 * i)
        log.warning("CSRF 令牌最终未取到，仍将尝试登录（可能返回 403）")
        return None

    def _post(self, url: str, data: dict) -> requests.Response:
        """POST，并在疑似 CSRF 失败时刷新令牌重试一次。

        实测（2026-10-17 生产日志）：令牌**缺失**时服务端返回 **400 Bad Request**，
        令牌过期/错误才返回 403。两者都要能自愈 —— 否则一次取令牌超时就会
        白白烧掉一轮重试。
        """
        r = self.sess.post(url, data=data, timeout=self.timeout)
        if r.status_code in (400, 403):
            log.warning("POST 返回 %s（多半是 CSRF 令牌缺失或过期），刷新令牌后重试一次：%s",
                        r.status_code, url)
            if self.ensure_csrf(force=True):
                r = self.sess.post(url, data=data, timeout=self.timeout)
        return r

    # ---- URL 组装 -------------------------------------------------------
    def _url(self, path_key: str, default_path: str) -> str:
        p = self.cfg.get("portal", path_key, default_path).strip() or default_path
        if p.startswith("http://") or p.startswith("https://"):
            return p
        return self.entry.base_url + (p if p.startswith("/") else "/" + p)

    # ---- 构造提交数据 ---------------------------------------------------
    def build_payload(self, username: str, password: str) -> dict:
        """
        严格复刻前端行为：
          postData.username/password <- 输入框原值（**明文**）
          postData.switchip <- url 参数 switchip
          postData.nasId    <- url 参数 nasId
          postData.userIpv4 <- url 参数 wlanuserip
          postData.userMac  <- url 参数 mac
          最后删除所有空字符串字段（前端就是这么做的）
        """
        p = self.entry.params
        payload = {
            "username": username,
            "password": password,
            "switchip": p.get("switchip", ""),
            "nasId": p.get("nasId", ""),
            "userIpv4": p.get("wlanuserip") or local_ipv4() or "",
            "userMac": p.get("mac") or local_mac(self.cfg.get("network", "interface", "WLAN")) or "",
            "captcha": "",
            "captchaId": "",
            "isp": self.cfg.get("account", "isp", "local"),
            "timeLimit": self.cfg.get("account", "time_limit", ""),
        }
        return {k: v for k, v in payload.items() if v not in (None, "")}

    # ---- 接口 -----------------------------------------------------------
    def status(self, ip: str | None = None) -> dict:
        """GET /api/account/status?wlanuserip=<ip>  —— code==0 表示当前已在线。"""
        url = self._url("status_path", "/api/account/status")
        params = {"wlanuserip": ip or self.entry.ip or local_ipv4() or ""}
        r = self.sess.get(url, params=params, timeout=self.timeout)
        r.raise_for_status()
        return self._json(r)

    def check(self, payload: dict) -> dict:
        """POST /api/account/check —— 登录前检查（是否强制改密等）。失败不阻断登录。"""
        self.ensure_csrf()
        url = self._url("check_path", "/api/account/check")
        r = self._post(url, payload)
        r.raise_for_status()
        return self._json(r)

    def login(self, username: str, password: str) -> LoginResult:
        """POST /api/account/login —— 真正的登录接口。密码明文、form-urlencoded。"""
        self.ensure_csrf()
        url = self._url("login_path", "/api/account/login")
        payload = self.build_payload(username, password)
        # 日志里只出现字段名，绝不出现 password 的值
        log.debug("POST %s 字段=%s", url, sorted(payload.keys()))
        r = self._post(url, payload)
        r.raise_for_status()
        js = self._json(r)
        return self._to_result(js)

    def logout(self, ip: str | None = None) -> dict:
        """GET /api/account/logout?wlanuserip=<ip> —— 注销（仅用于测试与排障）。"""
        url = self._url("logout_path", "/api/account/logout")
        params = {"wlanuserip": ip or self.entry.ip or local_ipv4() or ""}
        r = self.sess.get(url, params=params, timeout=self.timeout)
        r.raise_for_status()
        return self._json(r)

    # ---- 内部 -----------------------------------------------------------
    def _json(self, r: requests.Response) -> dict:
        try:
            return r.json()
        except ValueError:
            body = logkit.redact((r.text or "")[:300])
            raise PortalError(
                f"接口返回的不是 JSON（HTTP {r.status_code}）。"
                f"很可能是链路被拦截或 Portal 已改版。响应片段：{body}"
            )

    def _to_result(self, js: dict) -> LoginResult:
        code = js.get("code")
        res = LoginResult(
            ok=(code == CODE_OK),
            code=code,
            msg=str(js.get("msg") or js.get("extendMsg") or ""),
            online=js.get("online") or {},
            raw=js,
        )
        if code == CODE_CAPTCHA:
            cap = js.get("captcha") or {}
            res.captcha_needed = True
            res.captcha_pic = str(cap.get("picPath") or "")
            res.captcha_id = str(cap.get("captchaId") or "")
        return res
