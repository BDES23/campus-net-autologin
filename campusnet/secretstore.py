# -*- coding: utf-8 -*-
"""凭据存储：Windows 凭据管理器（通过 keyring），密码绝不写入代码或配置文件。

降级链
------
1. keyring（首选）—— Windows 上后端为 Windows Credential Manager。
2. 若 keyring 不可用，则**拒绝静默降级**，明确报错并给出解决方案，
   避免用户以为密码安全存着、实际上被写进了明文文件。
"""
from __future__ import annotations

import os

SERVICE = "campus-net-autologin"
ENV_FALLBACK = "CAMPUSNET_PASSWORD"   # 可选：不落盘的最后手段


class SecretError(RuntimeError):
    pass


def _keyring():
    try:
        import keyring  # type: ignore
        from keyring.backends import Windows  # noqa: F401  触发后端注册
        return keyring
    except Exception:
        return None


def backend_name() -> str:
    kr = _keyring()
    if kr is None:
        return "unavailable"
    try:
        return kr.get_keyring().__class__.__name__
    except Exception:
        return "unavailable"


def available() -> bool:
    return _keyring() is not None and backend_name() != "unavailable"


def set_password(username: str, password: str) -> None:
    kr = _keyring()
    if kr is not None:
        try:
            kr.set_password(SERVICE, username, password)
            return
        except Exception as e:                        # pragma: no cover
            raise SecretError(
                f"写入 Windows 凭据管理器失败：{e}\n"
                "请确认已安装 keyring（pip install keyring），"
                f"或改用环境变量 {ENV_FALLBACK}。"
            ) from e
    raise SecretError(
        "keyring 不可用，拒绝把密码写进明文文件。\n"
        "请执行：pip install keyring\n"
        f"或临时改用环境变量 {ENV_FALLBACK}（不安全，仅测试用）。"
    )


def get_password(username: str) -> str | None:
    kr = _keyring()
    if kr is not None:
        try:
            pw = kr.get_password(SERVICE, username)
            if pw:
                return pw
        except Exception:
            pass
    return os.environ.get(ENV_FALLBACK) or None


def delete_password(username: str) -> bool:
    kr = _keyring()
    if kr is None:
        return False
    try:
        kr.delete_password(SERVICE, username)
        return True
    except Exception:
        return False


def has_password(username: str) -> bool:
    return bool(get_password(username))
