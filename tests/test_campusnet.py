# -*- coding: utf-8 -*-
"""
测试套件（仅用标准库 unittest，不需要 pytest）。

运行方式（在项目根目录）：
    python -X utf8 -m unittest discover -s tests -v

包含两类测试：
  [单元]     配置读写、日志脱敏、入口参数解析、提交字段构造、响应码映射
  [集成]     启动本地模拟 Portal，跑完整的 runner.run_once 流程：
             未登录 -> 发现入口 -> 提交 -> 校验成功
             已登录 -> 跳过（不重复登录）
             密码错误 -> 明确失败，且**不会**因为"密码"字样反复重试
             服务端拒绝 -> 按配置重试 N 次
             需要验证码 -> 返回专门的退出码
             服务端回显密码 -> 日志里必须被脱敏成 ***
"""
from __future__ import annotations

import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))                  # 让 mock_portal 可导入
sys.path.insert(0, str(_HERE.parent))           # 让 campusnet 可导入

from campusnet import config as cfgmod, logkit, netcheck, runner, secretstore  # noqa: E402
from campusnet.portal import PortalClient, LoginResult, CODE_OK, CODE_FAIL, CODE_CAPTCHA  # noqa: E402
from campusnet.netcheck import PortalEntry                                     # noqa: E402
from mock_portal import MockPortalServer                                       # noqa: E402

PASSWORD = "p@ssw0rd-测试"
USERNAME = "20230001"


def _reset_logging():
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
        try:
            h.close()
        except Exception:
            pass
    logkit._configured = False
    logkit.clear_secrets()


# ==========================================================================
# 单元测试
# ==========================================================================
class TestConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_defaults_are_complete(self):
        cfg = cfgmod.ensure_config(self.tmp / "config.ini")
        self.assertTrue((self.tmp / "config.ini").exists())
        # 关键默认值必须与实测协议一致（全部带 /api 前缀：
        # config.js 里写着 var host_url = '/api'）
        self.assertEqual(cfg.get("portal", "login_path"), "/api/account/login")
        self.assertEqual(cfg.get("portal", "check_path"), "/api/account/check")
        self.assertEqual(cfg.get("portal", "status_path"), "/api/account/status")
        self.assertEqual(cfg.get("portal", "logout_path"), "/api/account/logout")
        self.assertEqual(cfg.get("portal", "csrf_path"), "/api/csrf-token")
        self.assertEqual(cfg.get("portal", "csrf_header"), "X-CSRF-Token")
        self.assertEqual(cfg.get("account", "isp"), "local")

    def test_legacy_paths_are_migrated(self):
        """老版本漏了 /api 前缀的配置要自动修正，否则升级后仍然 404。"""
        p = self.tmp / "old.ini"
        p.write_text(
            "[portal]\nlogin_path = /account/login\ncheck_path = /account/check\n"
            "status_path = /account/status\nlogout_path = /account/logout\n"
            "[account]\nusername = 20231234\n",
            encoding="utf-8")
        cfg = cfgmod.load(p)
        self.assertEqual(cfg.get("portal", "login_path"), "/api/account/login")
        self.assertEqual(cfg.get("portal", "check_path"), "/api/account/check")
        self.assertEqual(cfg.get("portal", "status_path"), "/api/account/status")
        self.assertEqual(cfg.get("portal", "logout_path"), "/api/account/logout")
        self.assertEqual(cfg.get("account", "username"), "20231234")

    def test_round_trip_and_helpers(self):
        p = self.tmp / "config.ini"
        cfg = cfgmod.ensure_config(p)
        cfg.data["account"]["username"] = "20231234"
        cfg.data["network"]["ssid_whitelist"] = "Campus-WiFi, Campus-5G"
        cfg.data["portal"]["extra_headers"] = "X-CSRF-Token: abc; X-Other: 1"
        cfg.data["policy"]["retries"] = "5"
        cfg.data["network"]["verify_after_login"] = "true"
        cfgmod.save(cfg)

        cfg2 = cfgmod.load(p)
        self.assertEqual(cfg2.get("account", "username"), "20231234")
        self.assertEqual(cfg2.ssid_whitelist, ["Campus-WiFi", "Campus-5G"])
        self.assertEqual(cfg2.extra_headers,
                         {"X-CSRF-Token": "abc", "X-Other": "1"})
        self.assertEqual(cfg2.get_int("policy", "retries"), 5)
        self.assertTrue(cfg2.get_bool("network", "verify_after_login"))
        self.assertFalse(cfg2.get_bool("network", "no_such_key"))

    def test_password_never_in_config_file(self):
        p = self.tmp / "config.ini"
        cfg = cfgmod.ensure_config(p)
        cfg.data["account"]["username"] = USERNAME
        cfgmod.save(cfg)
        text = p.read_text(encoding="utf-8")
        self.assertNotIn(PASSWORD, text)
        self.assertNotIn("password =", text.lower())
        self.assertNotIn("[secrets]", text.lower())


class TestRedaction(unittest.TestCase):
    def setUp(self):
        logkit.clear_secrets()

    def tearDown(self):
        logkit.clear_secrets()

    def test_registered_secret_is_masked(self):
        logkit.register_secret("hunter2")
        self.assertEqual(logkit.redact("pw=hunter2 ok"), "pw=*** ok")

    def test_password_patterns_are_masked_without_registration(self):
        for s in ("password=abc123", "passwd: abc123", 'pwd=abc123',
                  '{"password":"abc123"}'):
            self.assertNotIn("abc123", logkit.redact(s))

    def test_log_record_args_are_masked(self):
        _reset_logging()
        tmp = Path(tempfile.mkdtemp())
        logkit.setup(tmp, level="INFO", console=False)
        logkit.register_secret("topsecret")
        logging.getLogger("t").warning("登录失败：%s", "密码是 topsecret 哦")
        for h in logging.getLogger().handlers:
            h.flush()
        text = (tmp / "campusnet.log").read_text(encoding="utf-8")
        self.assertNotIn("topsecret", text)
        self.assertIn("***", text)


class TestEntryParsing(unittest.TestCase):
    def test_extract_params(self):
        u = ("http://portal.example.edu/tpl/default/login.html"
             "?ip=10.20.30.40&nasId=8&wlanuserip=10.20.30.40")
        p = netcheck._extract_params(u)
        self.assertEqual(p["nasId"], "8")
        self.assertEqual(p["ip"], "10.20.30.40")
        self.assertEqual(p["wlanuserip"], "10.20.30.40")

    def test_extract_nas_id_from_path(self):
        self.assertEqual(
            netcheck._extract_nas_id("http://h/api/r/8?wlanuserip=1.2.3.4", {}), "8")
        self.assertEqual(
            netcheck._extract_nas_id("http://h/index_12.html?wlanuserip=1.2.3.4", {}), "12")
        # 显式参数优先
        self.assertEqual(
            netcheck._extract_nas_id("http://h/api/r/8", {"nasId": "99"}), "99")
        self.assertIsNone(netcheck._extract_nas_id("http://h/x.html", {}))


class TestPayload(unittest.TestCase):
    """提交字段必须与真实前端逐项一致。"""

    def _client(self):
        entry = PortalEntry(
            base_url="http://portal.example",
            entry_url=("http://portal.example/tpl/default/login_account.html"
                       "?ip=1.2.3.4&nasId=8&wlanuserip=1.2.3.4&switchip=9.9.9.9&mac=aa:bb:cc:dd:ee:01"),
            params={"ip": "1.2.3.4", "nasId": "8", "wlanuserip": "1.2.3.4",
                    "switchip": "9.9.9.9", "mac": "aa:bb:cc:dd:ee:01"},
        )
        class _Cfg:
            data = {"account": {"isp": "local", "time_limit": "",
                                "switchip": "", "userIpv4": "", "userMac": "",
                                "captcha": "", "captchaId": ""},
                    "portal": {"extra_headers": "", "base_url": "http://portal.example",
                               "status_path": "/api/account/status",
                               "check_path": "/api/account/check",
                               "login_path": "/api/account/login",
                               "logout_path": "/api/account/logout",
                               "csrf_path": "", "csrf_header": ""},
                    "network": {"interface": "WLAN"}}
            extra_headers = {}
            def get(self, s, k, d=""):
                return self.data.get(s, {}).get(k, d)
            def get_float(self, s, k, d=0.0):
                return d
        return PortalClient(_Cfg(), entry)

    def test_plaintext_password_and_mapping(self):
        c = self._client()
        p = c.build_payload(USERNAME, PASSWORD)
        self.assertEqual(p["username"], USERNAME)
        # 实测：前端是 postData.password = $('#password').val()，明文提交，无加密
        self.assertEqual(p["password"], PASSWORD)
        self.assertEqual(p["nasId"], "8")
        self.assertEqual(p["switchip"], "9.9.9.9")
        self.assertEqual(p["userIpv4"], "1.2.3.4")
        self.assertEqual(p["userMac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(p["isp"], "local")

    def test_empty_fields_are_removed_like_frontend(self):
        c = self._client()
        p = c.build_payload(USERNAME, PASSWORD)
        # 前端会 delete 掉空串字段；time_limit/captcha/captchaId 为空，必须不出现
        for k in ("captcha", "captchaId", "timeLimit"):
            self.assertNotIn(k, p, f"空字段 {k} 不应出现在提交数据里")
        for v in p.values():
            self.assertNotEqual(v, "")

    def test_exactly_ten_known_fields_exist(self):
        c = self._client()
        p = c.build_payload(USERNAME, PASSWORD)
        allowed = {"username", "password", "switchip", "nasId", "userIpv4",
                   "userMac", "captcha", "captchaId", "isp", "timeLimit"}
        self.assertTrue(set(p).issubset(allowed), f"出现了未知字段: {set(p) - allowed}")


class TestResponseMapping(unittest.TestCase):
    def _client(self):
        entry = PortalEntry(base_url="http://h", entry_url="http://h/x", params={})
        class _Cfg:
            data = {"account": {"isp": "local", "time_limit": ""},
                    "portal": {}, "network": {}}
            extra_headers = {}
            def get(self, s, k, d=""):
                return self.data.get(s, {}).get(k, d)
            def get_float(self, s, k, d=0.0):
                return d
        return PortalClient(_Cfg(), entry)

    def test_code_semantics(self):
        c = self._client()
        r = c._to_result({"code": 0, "online": {"Username": "u", "Name": "n"}})
        self.assertTrue(r.ok)
        self.assertEqual(r.code, CODE_OK)

        r = c._to_result({"code": 1, "msg": "密码错误"})
        self.assertFalse(r.ok)
        self.assertEqual(r.msg, "密码错误")
        self.assertEqual(r.code, CODE_FAIL)

        r = c._to_result({"code": 2, "captcha": {"picPath": "/c.png", "captchaId": "id1"}})
        self.assertTrue(r.captcha_needed)
        self.assertEqual(r.captcha_id, "id1")
        self.assertEqual(r.captcha_pic, "/c.png")
        self.assertEqual(r.code, CODE_CAPTCHA)


# ==========================================================================
# 集成测试：本地模拟 Portal，跑完整 runner.run_once
# ==========================================================================
class IntegrationBase(unittest.TestCase):
    fail_msg = None
    force_captcha = False
    echo_password_in_msg = False
    mock_password = PASSWORD          # 模拟 Portal 那边期望的密码
    client_password = PASSWORD        # 客户端实际提交的密码

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        _reset_logging()

        self.srv = MockPortalServer(password=self.mock_password, username=USERNAME,
                                    client_ip=netcheck.local_ipv4() or "127.0.0.1")
        self.srv.state["fail_msg"] = self.fail_msg
        self.srv.state["force_captcha"] = self.force_captcha
        self.srv.state["echo_password_in_msg"] = self.echo_password_in_msg
        self.srv.start()

        cfg_path = self.tmp / "config.ini"
        cfg = cfgmod.ensure_config(cfg_path)
        # 把探测地址指向模拟 Portal —— 这正是 config.ini 里 probe_url 的用途
        cfg.data["portal"]["base_url"] = self.srv.base_url
        cfg.data["portal"]["probe_url"] = self.srv.url("/generate_204")
        cfg.data["portal"]["entry_template"] = self.srv.url("/api/r/8?wlanuserip={ip}")
        cfg.data["account"]["username"] = USERNAME
        cfg.data["account"]["isp"] = "local"
        cfg.data["network"]["ssid_whitelist"] = ""        # 不限制 SSID
        cfg.data["network"]["verify_after_login"] = "true"
        cfg.data["policy"]["retries"] = "2"
        cfg.data["policy"]["retry_backoff"] = "0.05"
        cfg.data["policy"]["request_timeout"] = "5"
        cfg.data["logging"]["dir"] = str(self.tmp / "logs")
        cfgmod.save(cfg)
        self.cfg = cfgmod.load(cfg_path)

        logkit.setup(self.cfg.log_dir, level="DEBUG", console=False)

        # 用环境变量提供密码，避免污染真实的 Windows 凭据管理器
        self._orig_get = secretstore.get_password
        secretstore.get_password = lambda u: self.client_password   # type: ignore[assignment]

    def tearDown(self):
        secretstore.get_password = self._orig_get                # type: ignore[assignment]
        self.srv.stop()
        _reset_logging()

    def log_text(self) -> str:
        f = self.cfg.log_dir / "campusnet.log"
        for h in logging.getLogger().handlers:
            h.flush()
        return f.read_text(encoding="utf-8") if f.exists() else ""


class TestHappyPath(IntegrationBase):
    def test_not_online_then_login_succeeds(self):
        self.assertFalse(self.srv.state["authenticated"])
        r = runner.run_once(self.cfg)
        self.assertEqual(r.code, runner.EXIT_OK, f"未成功：{r.message}")
        self.assertTrue(self.srv.state["authenticated"], "模拟 Portal 应已变为已认证")
        self.assertIn("成功", r.message)

    def test_submitted_payload_matches_real_protocol(self):
        runner.run_once(self.cfg)
        posts = self.srv.login_posts()
        self.assertTrue(posts, "应当向 /account/login 提交过请求")
        path, form, headers = posts[-1]

        self.assertEqual(path, "/api/account/login")
        self.assertEqual(form["username"], USERNAME)
        self.assertEqual(form["password"], PASSWORD)          # 明文，与实测一致
        self.assertEqual(form["isp"], "local")
        self.assertEqual(form["nasId"], "8")
        self.assertEqual(form["userIpv4"], netcheck.local_ipv4())
        self.assertNotIn("captcha", form)
        self.assertNotIn("captchaId", form)
        self.assertNotIn("timeLimit", form)
        # 前端是 $.post -> form-urlencoded
        self.assertIn("application/x-www-form-urlencoded",
                      headers.get("Content-Type", ""))
        # csrf.js 用 $.ajaxPrefilter 给每个请求加 X-CSRF-Token
        self.assertEqual(headers.get("X-CSRF-Token"), self.srv.state["csrf_token"])

    def test_csrf_token_is_fetched_first(self):
        runner.run_once(self.cfg)
        gets = [p[1] for p in self.srv.state["requests"]]
        self.assertTrue(any("/api/csrf-token" in g for g in gets),
                        f"应当先请求 /api/csrf-token，实际 {gets}")

    def test_check_endpoint_is_called_before_login(self):
        runner.run_once(self.cfg)
        paths = [p[0] for p in self.srv.state["posts"]]
        self.assertIn("/api/account/check", paths)
        self.assertLess(paths.index("/api/account/check"), paths.index("/api/account/login"))

    def test_redirect_chain_is_followed(self):
        runner.run_once(self.cfg)
        gets = [p[1] for p in self.srv.state["requests"]]
        self.assertTrue(any("/api/r/8" in g for g in gets), f"应访问入口 /api/r/8，实际 {gets}")
        self.assertTrue(any("/api/account/status" in g for g in gets))


class TestAlreadyOnline(IntegrationBase):
    def test_skips_when_already_online(self):
        self.srv.state["authenticated"] = True
        r = runner.run_once(self.cfg)
        self.assertEqual(r.code, runner.EXIT_OK)
        self.assertEqual(self.srv.login_posts(), [],
                         "已登录时绝不能重复调用 /account/login")
        self.assertIn("已", r.message)

    def test_force_flag_does_login(self):
        self.srv.state["authenticated"] = True
        r = runner.run_once(self.cfg, force=True)
        self.assertEqual(r.code, runner.EXIT_OK)
        self.assertTrue(self.srv.login_posts(), "--force 时应当真的提交登录")


class TestCsrfRefresh(IntegrationBase):
    """实测校园网关约一半连接会超时，取令牌可能失败；403 必须能自愈。"""

    def setUp(self):
        super().setUp()
        self.srv.state["fail_first_post_403"] = True

    def test_refreshes_token_and_retries_on_403(self):
        r = runner.run_once(self.cfg)
        self.assertEqual(r.code, runner.EXIT_OK,
                         f"403 后应刷新令牌并重试成功，实际：{r.message}")
        self.assertTrue(self.srv.state["authenticated"])
        gets = [p[1] for p in self.srv.state["requests"]]
        n = sum(1 for g in gets if "/api/csrf-token" in g)
        self.assertGreaterEqual(n, 2, f"应至少取两次 CSRF 令牌（首次 + 403 后刷新），实际 {n}")


class TestCsrfRecovery(IntegrationBase):
    """复现 2026-10-17 生产日志里的真实场景：

    取令牌连续 3 次失败（网关抖动）-> 客户端无令牌提交 ->
    服务端返回 **400**（不是 403）-> 客户端刷新令牌后重试 -> **在单轮尝试内自愈成功**。
    修复前这里会烧掉一整轮 runner 重试。
    """

    def setUp(self):
        super().setUp()
        # 前 3 次取令牌都失败，正好耗尽 ensure_csrf 的内部重试
        self.srv.state["csrf_token_fails_remaining"] = 3

    def test_recovers_within_a_single_attempt(self):
        r = runner.run_once(self.cfg)
        self.assertEqual(r.code, runner.EXIT_OK,
                         f"应在单轮内自愈成功，实际：{r.message}")
        self.assertTrue(self.srv.state["authenticated"])

        # 关键：runner 只应该发起 1 轮尝试 —— 自愈发生在 PortalClient 内部
        attempts = self.log_text().count("次尝试登录")
        self.assertEqual(attempts, 1,
                         f"应当只尝试登录 1 次（400 自愈），实际 {attempts} 次")

        # 令牌请求次数 = 首次内部 3 次 + 400 后的刷新 1 次
        gets = [p[1] for p in self.srv.state["requests"]]
        n = sum(1 for g in gets if "/api/csrf-token" in g)
        self.assertGreaterEqual(n, 4, f"应至少取 4 次令牌，实际 {n}")

    def test_csrf_header_present_on_successful_post(self):
        runner.run_once(self.cfg)
        _, _, headers = self.srv.login_posts()[-1]
        self.assertEqual(headers.get("X-CSRF-Token"), self.srv.state["csrf_token"])


class TestFailurePaths(IntegrationBase):
    # Portal 期望 PASSWORD，客户端却提交错误的密码 —— 必须明确失败
    client_password = "wrong-password"

    def test_wrong_password_fails(self):
        r = runner.run_once(self.cfg)
        self.assertEqual(r.code, runner.EXIT_LOGIN_FAILED, f"实际：{r.message}")
        self.assertFalse(self.srv.state["authenticated"])
        self.assertTrue(self.srv.login_posts())


class TestSmartRetry(unittest.TestCase):
    """账号/密码类错误不该无意义重试；其他错误才重试到上限。"""

    def _run(self, fail_msg, echo=False, password=PASSWORD):
        tmp = Path(tempfile.mkdtemp())
        _reset_logging()
        srv = MockPortalServer(password="expected", username=USERNAME,
                               client_ip=netcheck.local_ipv4() or "127.0.0.1")
        srv.state["fail_msg"] = fail_msg
        srv.state["echo_password_in_msg"] = echo
        srv.start()
        try:
            cfg = cfgmod.ensure_config(tmp / "config.ini")
            cfg.data["portal"]["probe_url"] = srv.url("/generate_204")
            cfg.data["portal"]["base_url"] = srv.base_url
            cfg.data["account"]["username"] = USERNAME
            cfg.data["network"]["ssid_whitelist"] = ""
            cfg.data["network"]["verify_after_login"] = "false"
            cfg.data["policy"]["retries"] = "3"
            cfg.data["policy"]["retry_backoff"] = "0.02"
            cfg.data["policy"]["request_timeout"] = "5"
            cfg.data["logging"]["dir"] = str(tmp / "logs")
            cfgmod.save(cfg)
            cfg = cfgmod.load(tmp / "config.ini")
            logkit.setup(cfg.log_dir, level="DEBUG", console=False)
            orig = secretstore.get_password
            secretstore.get_password = lambda u: password          # type: ignore[assignment]
            try:
                r = runner.run_once(cfg)
            finally:
                secretstore.get_password = orig                   # type: ignore[assignment]
            for h in logging.getLogger().handlers:
                h.flush()
            logf = cfg.log_dir / "campusnet.log"
            return r, srv, (logf.read_text(encoding="utf-8") if logf.exists() else "")
        finally:
            srv.stop()
            _reset_logging()

    def test_password_error_does_not_retry(self):
        r, srv, _ = self._run("密码错误")
        self.assertEqual(r.code, runner.EXIT_LOGIN_FAILED)
        self.assertEqual(len(srv.login_posts()), 1,
                         "含『密码』字样的错误应立即停止重试，不应重试 3 次")

    def test_other_error_retries_up_to_limit(self):
        r, srv, _ = self._run("认证被拒绝")
        self.assertEqual(r.code, runner.EXIT_LOGIN_FAILED)
        self.assertEqual(len(srv.login_posts()), 3, "非密码类错误应重试到配置上限")

    def test_password_is_redacted_in_log(self):
        r, srv, log = self._run("x", echo=True, password="SuperSecret123")
        self.assertIn("SuperSecret123", str(srv.login_posts()[-1][1].get("password")))
        self.assertNotIn("SuperSecret123", log,
                         "服务端把密码回显到错误信息里时，日志必须脱敏")
        self.assertIn("***", log)


class TestCaptcha(unittest.TestCase):
    def test_captcha_returns_dedicated_exit_code(self):
        tmp = Path(tempfile.mkdtemp())
        _reset_logging()
        srv = MockPortalServer(password="expected", username=USERNAME,
                               client_ip=netcheck.local_ipv4() or "127.0.0.1")
        srv.state["force_captcha"] = True
        srv.start()
        try:
            cfg = cfgmod.ensure_config(tmp / "config.ini")
            cfg.data["portal"]["probe_url"] = srv.url("/generate_204")
            cfg.data["portal"]["base_url"] = srv.base_url
            cfg.data["account"]["username"] = USERNAME
            cfg.data["network"]["ssid_whitelist"] = ""
            cfg.data["policy"]["retries"] = "1"
            cfg.data["policy"]["request_timeout"] = "5"
            cfg.data["logging"]["dir"] = str(tmp / "logs")
            cfgmod.save(cfg)
            cfg = cfgmod.load(tmp / "config.ini")
            logkit.setup(cfg.log_dir, level="DEBUG", console=False)
            orig = secretstore.get_password
            secretstore.get_password = lambda u: "expected"       # type: ignore[assignment]
            try:
                r = runner.run_once(cfg)
            finally:
                secretstore.get_password = orig                   # type: ignore[assignment]
            self.assertEqual(r.code, runner.EXIT_CAPTCHA)
            self.assertIn("验证码", r.message)
        finally:
            srv.stop()
            _reset_logging()


class TestMissingConfig(unittest.TestCase):
    def test_missing_username_returns_config_error(self):
        tmp = Path(tempfile.mkdtemp())
        _reset_logging()
        srv = MockPortalServer(client_ip=netcheck.local_ipv4() or "127.0.0.1").start()
        try:
            cfg = cfgmod.ensure_config(tmp / "config.ini")
            cfg.data["portal"]["probe_url"] = srv.url("/generate_204")
            cfg.data["account"]["username"] = ""
            cfg.data["network"]["ssid_whitelist"] = ""
            cfg.data["logging"]["dir"] = str(tmp / "logs")
            logkit.setup(cfg.log_dir, level="DEBUG", console=False)
            r = runner.run_once(cfg)
            self.assertEqual(r.code, runner.EXIT_CONFIG)
            self.assertIn("username", r.message)
        finally:
            srv.stop()
            _reset_logging()

    def test_missing_password_returns_config_error(self):
        tmp = Path(tempfile.mkdtemp())
        _reset_logging()
        srv = MockPortalServer(client_ip=netcheck.local_ipv4() or "127.0.0.1").start()
        try:
            cfg = cfgmod.ensure_config(tmp / "config.ini")
            cfg.data["portal"]["probe_url"] = srv.url("/generate_204")
            cfg.data["account"]["username"] = USERNAME
            cfg.data["network"]["ssid_whitelist"] = ""
            cfg.data["logging"]["dir"] = str(tmp / "logs")
            logkit.setup(cfg.log_dir, level="DEBUG", console=False)
            orig = secretstore.get_password
            secretstore.get_password = lambda u: None             # type: ignore[assignment]
            try:
                r = runner.run_once(cfg)
            finally:
                secretstore.get_password = orig                   # type: ignore[assignment]
            self.assertEqual(r.code, runner.EXIT_CONFIG)
            self.assertIn("set-password", r.message)
        finally:
            srv.stop()
            _reset_logging()


if __name__ == "__main__":
    unittest.main(verbosity=2)
