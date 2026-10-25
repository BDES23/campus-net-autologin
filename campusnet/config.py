# -*- coding: utf-8 -*-
"""配置读写（INI，零第三方依赖，Python 标准库 configparser 可直接回写）。"""
from __future__ import annotations

import configparser
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

DEFAULTS = {
    "portal": {
        # Portal 主机。**留空即可** —— 默认完全靠 302 重定向自动发现，
        # 这样换校区/换楼栋也不会失效。
        # 若自动发现失败，再手工填上，例如 "http://10.0.0.1"。
        "base_url": "",
        # ⚠ 路径必须带 /api 前缀 —— 这是实测结论，不是猜的：
        #   登录页引用的 static/js/config.js 里写着 `var host_url = '/api'`，
        #   前端实际请求的是 host_url + '/account/login'。
        #   少了 /api 会被 nginx 直接返回 404（本项目踩过这个坑）。
        "login_path": "/api/account/login",
        "check_path": "/api/account/check",
        "status_path": "/api/account/status",
        "logout_path": "/api/account/logout",
        # CSRF：前端用 $.ajaxPrefilter 给每个请求加 X-CSRF-Token，
        # 令牌来自 GET {host_url}/csrf-token 返回的 {"csrf_token": "..."}。
        # 若你的 Portal 没有这个接口，把 csrf_path 留空即可自动跳过。
        "csrf_path": "/api/csrf-token",
        "csrf_header": "X-CSRF-Token",
        # 未认证时会被劫持的探测地址（用 http，不要用 https）
        "probe_url": "http://www.gstatic.com/generate_204",
        # 可选：抓不到重定向时的兜底入口模板，{ip} 会替换为本机 IP。
        # 形如 "http://10.0.0.1/api/r/1?wlanuserip={ip}"
        "entry_template": "",
        # 需要额外请求头时在此添加，形如 "A: b; C: d"
        "extra_headers": "",
    },
    "account": {
        "username": "",          # 学号
        "isp": "local",          # 运营商，校园网一般为 local
        "time_limit": "",        # 上网时长，留空则不下发该字段
    },
    "network": {
        "interface": "WLAN",
        # 只在指定 SSID 上自动登录；留空表示不限制
        "ssid_whitelist": "",
        "verify_after_login": "true",
    },
    "policy": {
        "retries": "3",          # 单次运行内的重试次数
        "retry_backoff": "2.0",  # 退避基数（秒），第 n 次重试等待 backoff * 2^(n-1)
        "request_timeout": "8",  # 单请求超时（秒）
        "guard_interval": "300", # 巡检间隔（秒）
        "on_captcha": "stop",    # stop=记日志并退出 / notify=弹窗提醒
    },
    "logging": {
        "dir": "logs",
        "level": "INFO",
        "max_bytes": "1048576",
        "backup_count": "5",
    },
}

REDACT_FIELDS = ("password", "passwd", "pwd")


@dataclass
class Config:
    path: Path
    data: dict = field(default_factory=dict)

    # ---- 便捷读取 -------------------------------------------------------
    def get(self, section: str, key: str, default: str = "") -> str:
        return self.data.get(section, {}).get(key, default)

    def get_int(self, section: str, key: str, default: int = 0) -> int:
        try:
            return int(str(self.get(section, key, str(default))).strip())
        except (TypeError, ValueError):
            return default

    def get_float(self, section: str, key: str, default: float = 0.0) -> float:
        try:
            return float(str(self.get(section, key, str(default))).strip())
        except (TypeError, ValueError):
            return default

    def get_bool(self, section: str, key: str, default: bool = False) -> bool:
        raw = str(self.get(section, key, str(default))).strip().lower()
        return raw in ("1", "true", "yes", "on", "是")

    # ---- 派生属性 -------------------------------------------------------
    @property
    def base_dir(self) -> Path:
        return self.path.parent

    @property
    def log_dir(self) -> Path:
        d = Path(self.get("logging", "dir", "logs"))
        return d if d.is_absolute() else (self.base_dir / d)

    @property
    def extra_headers(self) -> dict:
        raw = self.get("portal", "extra_headers", "").strip()
        out = {}
        for part in raw.replace(",", ";").split(";"):
            if ":" in part:
                k, v = part.split(":", 1)
                if k.strip():
                    out[k.strip()] = v.strip()
        return out

    @property
    def ssid_whitelist(self) -> list:
        raw = self.get("network", "ssid_whitelist", "")
        return [s.strip() for s in raw.split(",") if s.strip()]


def app_dir() -> Path:
    """程序所在目录（exe 打包后要读写的那个目录）。

    打包成 exe 后**必须**用 exe 自身的位置，不能用 __file__：
    PyInstaller 单文件模式会把代码解压到临时目录（sys._MEIPASS），
    __file__ 指向那里，往里写 config.ini / logs 会在进程退出时被清掉。
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def default_config_path() -> Path:
    env = os.environ.get("CAMPUSNET_CONFIG")
    if env:
        return Path(env)
    return app_dir() / "config.ini"


def load(path: Path | str | None = None) -> Config:
    p = Path(path) if path else default_config_path()
    cp = configparser.ConfigParser()
    # 先灌默认值，保证任何键都存在
    for sec, kv in DEFAULTS.items():
        cp.add_section(sec)
        for k, v in kv.items():
            cp.set(sec, k, v)
    if p.exists():
        cp.read(p, encoding="utf-8")
    data = {sec: dict(cp.items(sec)) for sec in cp.sections()}
    _migrate(data)
    return Config(path=p, data=data)


# 老版本（1.0.0）的接口路径漏了 /api 前缀，会导致登录 404。
# 这里自动迁移，避免升级代码后老 config.ini 继续报 404 让人困惑。
_LEGACY_PATH_KEYS = ("login_path", "check_path", "status_path", "logout_path")


def _migrate(data: dict) -> None:
    portal = data.get("portal")
    if not portal:
        return
    for k in _LEGACY_PATH_KEYS:
        v = str(portal.get(k, ""))
        if v.startswith("/account/"):
            portal[k] = "/api" + v


def save(cfg: Config) -> None:
    cp = configparser.ConfigParser()
    for sec, kv in cfg.data.items():
        cp.add_section(sec)
        for k, v in kv.items():
            cp.set(sec, k, str(v))
    cfg.path.parent.mkdir(parents=True, exist_ok=True)
    with open(cfg.path, "w", encoding="utf-8") as f:
        f.write("# 校园网自动登录配置。密码不在这里，密码存在 Windows 凭据管理器。\n")
        f.write("# 修改后无需重新安装自启任务。\n\n")
        cp.write(f)


def ensure_config(path: Path | str | None = None) -> Config:
    """配置文件不存在则用默认值创建一份。"""
    cfg = load(path)
    if not cfg.path.exists():
        save(cfg)
    return cfg
