# -*- coding: utf-8 -*-
"""日志：滚动文件 + 控制台，并且**强制脱敏**，密码永不落盘。

设计要点
--------
1. 注册一个 Filter，对每条日志消息与 args 做字符串替换，凡是出现已登记的
   敏感值（密码）一律替换为 ***。
2. 另外用正则兜底，拦掉形如 password=xxx / "password":"xxx" 的片段。
3. 网络请求的响应体在写日志前会先经过 redact()，避免服务端回显密码。
"""
from __future__ import annotations

import logging
import logging.handlers
import re
from pathlib import Path

_SECRETS: set[str] = set()

_PATTERNS = [
    re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*([^\s&,;"\']+)'),
    re.compile(r'(?i)"(password|passwd|pwd)"\s*:\s*"[^"]*"'),
]


def register_secret(value: str | None) -> None:
    """登记一个需要脱敏的值（例如密码）。只在内存里，不落盘。"""
    if value and len(value) >= 2:
        _SECRETS.add(value)


def clear_secrets() -> None:
    _SECRETS.clear()


def redact(text) -> str:
    if text is None:
        return ""
    s = str(text)
    for sec in _SECRETS:
        if sec in s:
            s = s.replace(sec, "***")
    for pat in _PATTERNS:
        s = pat.sub(lambda m: f"{m.group(1)}=***", s)
    return s


class _RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = redact(record.msg)
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {k: (redact(v) if isinstance(v, str) else v)
                                   for k, v in record.args.items()}
                elif isinstance(record.args, tuple):
                    record.args = tuple(redact(a) if isinstance(a, str) else a
                                        for a in record.args)
        except Exception:
            pass
        return True


_configured = False


def setup(log_dir: Path, level: str = "INFO", max_bytes: int = 1_048_576,
          backup_count: int = 5, console: bool = True) -> logging.Logger:
    global _configured
    root = logging.getLogger()
    if _configured:
        return root

    root.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    flt = _RedactFilter()

    log_dir.mkdir(parents=True, exist_ok=True)
    fh = logging.handlers.RotatingFileHandler(
        log_dir / "campusnet.log", maxBytes=max_bytes,
        backupCount=backup_count, encoding="utf-8",
    )
    fh.setFormatter(fmt)
    fh.addFilter(flt)
    root.addHandler(fh)

    if console:
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        ch.addFilter(flt)
        root.addHandler(ch)

    _configured = True
    return root


def get(name: str) -> logging.Logger:
    return logging.getLogger(name)
