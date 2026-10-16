# -*- coding: utf-8 -*-
"""登录编排：检测 → 发现入口 → 登录 → 校验，带重试与退避。"""
from __future__ import annotations

import time

import requests

from . import logkit, netcheck, secretstore
from .portal import PortalClient, PortalError

log = logkit.get("runner")

# 退出码约定（供任务计划程序与人工排障使用）
EXIT_OK = 0            # 已在线，或登录成功
EXIT_LOGIN_FAILED = 1  # 登录失败（账号密码错误、被拒等）
EXIT_CAPTCHA = 2       # 需要验证码，无法无人值守完成
EXIT_CONFIG = 3        # 配置缺失（用户名或密码）
EXIT_NETWORK = 4       # 网络不可用 / 找不到 Portal 入口


class Result:
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message

    def __repr__(self) -> str:
        return f"<Result {self.code}: {self.message}>"


def _ssid_allowed(cfg) -> bool:
    allow = cfg.ssid_whitelist
    if not allow:
        return True
    ssid = netcheck.current_ssid(cfg.get("network", "interface", "WLAN"))
    if ssid is None:
        log.warning("读取不到当前 SSID，跳过 SSID 白名单校验")
        return True
    ok = ssid in allow
    if not ok:
        log.info("当前 SSID=%r 不在白名单 %s 内，跳过本次自动登录", ssid, allow)
    return ok


def _verify_online(cfg, timeout: float) -> bool:
    online, details, _ = netcheck.check_online(timeout=timeout, cfg=cfg)
    for d in details:
        log.debug("  校验 %s: ok=%s status=%s err=%s", d.name, d.ok, d.status, d.error)
    return online


def run_once(cfg, force: bool = False, session: requests.Session | None = None) -> Result:
    """执行一次完整的"该不该登录 / 登录"流程。"""
    timeout = cfg.get_float("policy", "request_timeout", 8.0)

    if not _ssid_allowed(cfg):
        return Result(EXIT_OK, "不在目标 SSID 上，跳过")

    # ---- 1. 是否已在线 -------------------------------------------------
    online, details, suspects = netcheck.check_online(timeout=timeout, session=session, cfg=cfg)
    for d in details:
        log.debug("探测 %s -> ok=%s status=%s err=%s", d.name, d.ok, d.status, d.error)

    if online and not force:
        log.info("网络已处于已登录状态，跳过（不重复登录）")
        return Result(EXIT_OK, "已在线")
    if online and force:
        log.info("已在线，但指定了 --force，继续执行登录流程")

    # ---- 2. 账号密码 ---------------------------------------------------
    username = cfg.get("account", "username", "").strip()
    if not username:
        return Result(EXIT_CONFIG, "config.ini 里的 account.username（学号）为空")
    password = secretstore.get_password(username)
    if not password:
        return Result(
            EXIT_CONFIG,
            f"凭据管理器中查不到 {username} 的密码，请先执行：python -m campusnet set-password",
        )
    logkit.register_secret(password)          # 登记脱敏，之后日志里出现它一律变 ***

    retries = max(1, cfg.get_int("policy", "retries", 3))
    backoff = cfg.get_float("policy", "retry_backoff", 2.0)
    last = Result(EXIT_NETWORK, "尚未执行")

    for attempt in range(1, retries + 1):
        try:
            # ---- 3. 发现 Portal 入口 ----------------------------------
            entry = netcheck.discover_entry(cfg, timeout=timeout, session=session)
            if entry is None:
                last = Result(EXIT_NETWORK, "未能发现 Portal 入口（没有跳转，也没有可用入口模板）")
                log.warning("第 %d/%d 次：%s", attempt, retries, last.message)
                raise _Retry()

            log.info(
                "Portal 入口: %s  (base=%s, wlanuserip=%s, nasId=%s)",
                entry.entry_url, entry.base_url, entry.ip, entry.nas_id,
            )

            client = PortalClient(cfg, entry, session=session)

            # ---- 4. 先问一次状态，避免重复登录 -------------------------
            try:
                st = client.status()
                if isinstance(st, dict) and st.get("code") == 0 and not force:
                    log.info("Portal 侧显示已在线，跳过登录")
                    return Result(EXIT_OK, "Portal 侧已在线")
            except (requests.RequestException, PortalError) as e:
                log.debug("状态查询失败（不影响后续登录）：%s", e)

            # ---- 5. 登录前检查（非致命） -------------------------------
            payload = client.build_payload(username, password)
            try:
                ck = client.check(payload)
                if isinstance(ck, dict):
                    if ck.get("code") == 1:
                        msg = str(ck.get("msg") or "登录前检查未通过")
                        log.warning("登录前检查返回失败：%s", msg)
                        # 前端此时会直接 return，我们也照做：这通常是账号层面的问题
                        return Result(EXIT_LOGIN_FAILED, msg)
                    if ck.get("code") == 0 and str(ck.get("isChangePwd") or "0") == "1":
                        return Result(EXIT_LOGIN_FAILED,
                                      "学校要求先修改密码（isChangePwd=1），请手动登录改密后再用")
            except (requests.RequestException, PortalError) as e:
                log.debug("登录前检查不可用，直接登录：%s", e)

            # ---- 6. 登录 -----------------------------------------------
            log.info("第 %d/%d 次尝试登录（账号 %s）…", attempt, retries, username)
            res = client.login(username, password)

            if res.ok:
                log.info("%s", res.summary())
                if cfg.get_bool("network", "verify_after_login", True):
                    time.sleep(1.5)
                    if _verify_online(cfg, timeout):
                        return Result(EXIT_OK, "登录成功并已校验连通")
                    log.warning("登录接口返回成功，但连通性校验未通过（可能 Portal 会话尚未生效）")
                    last = Result(EXIT_NETWORK, "登录返回成功但连通性未通过")
                    raise _Retry()
                return Result(EXIT_OK, "登录成功")

            if res.captcha_needed:
                log.error("服务端要求验证码 (captchaId=%s, pic=%s)",
                          res.captcha_id, res.captcha_pic)
                return Result(EXIT_CAPTCHA, res.summary())

            log.warning("登录失败：%s", res.summary())
            last = Result(EXIT_LOGIN_FAILED, res.summary())

            # 账号密码类错误，重试没有意义
            msg = (res.msg or "").lower()
            if any(k in msg for k in ("密码", "password", "用户名", "账号", "不存在", "锁定")):
                log.error("判定为账号/密码问题，停止重试")
                return last

        except _Retry:
            pass
        except (requests.RequestException, PortalError) as e:
            log.warning("第 %d/%d 次出现异常：%s", attempt, retries, logkit.redact(e))
            last = Result(EXIT_NETWORK, logkit.redact(e))

        if attempt < retries:
            wait = backoff * (2 ** (attempt - 1))
            log.info("等待 %.1f 秒后重试…", wait)
            time.sleep(wait)

    log.error("重试 %d 次后仍未成功：%s", retries, last.message)
    return last


class _Retry(Exception):
    """内部控制流：跳到下一次重试。"""


def guard(cfg, stop_after: int | None = None) -> int:
    """常驻巡检：每 guard_interval 秒检查一次，掉线就重登。"""
    interval = max(30, cfg.get_int("policy", "guard_interval", 300))
    log.info("进入巡检模式，间隔 %d 秒（Ctrl+C 退出）", interval)
    rounds = 0
    while True:
        rounds += 1
        try:
            r = run_once(cfg)
            log.info("第 %d 轮巡检结果：%s", rounds, r.message)
        except KeyboardInterrupt:
            raise
        except Exception as e:                       # 任何异常都不能让巡检挂掉
            log.exception("巡检出现未预期异常：%s", logkit.redact(e))
        if stop_after and rounds >= stop_after:
            return 0
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            log.info("巡检已停止")
            return 0
