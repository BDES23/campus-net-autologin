# -*- coding: utf-8 -*-
"""命令行入口：python -m campusnet <命令>"""
from __future__ import annotations

import argparse
import getpass
import sys
import time
from pathlib import Path

# 允许 `python -m campusnet` 与直接运行脚本两种方式
if __package__ in (None, ""):                     # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from campusnet import config as cfgmod, logkit, netcheck, runner, secretstore
else:
    from . import config as cfgmod, logkit, netcheck, runner, secretstore

EXIT = runner


def _bootstrap(args):
    cfg = cfgmod.ensure_config(args.config)
    logkit.setup(
        cfg.log_dir,
        level=("DEBUG" if getattr(args, "verbose", False) else cfg.get("logging", "level", "INFO")),
        max_bytes=cfg.get_int("logging", "max_bytes", 1_048_576),
        backup_count=cfg.get_int("logging", "backup_count", 5),
        console=True,
    )
    return cfg


# --------------------------------------------------------------------------
def cmd_setup(args):
    cfg = _bootstrap(args)
    print("=" * 66)
    print("校园网自动登录 —— 初始化")
    print("=" * 66)
    print(f"配置文件: {cfg.path}")
    print()

    cur = cfg.get("account", "username", "").strip()
    username = input(f"学号 / 账号 [{cur}]: ").strip() or cur
    if not username:
        print("学号不能为空。")
        return EXIT.EXIT_CONFIG
    cfg.data["account"]["username"] = username

    base = cfg.get("portal", "base_url", "")
    new_base = input(f"Portal 主机 [{base}]: ").strip()
    if new_base:
        cfg.data["portal"]["base_url"] = new_base

    ssid = cfg.get("network", "ssid_whitelist", "")
    detected = netcheck.current_ssid(cfg.get("network", "interface", "WLAN"))
    hint = f"（当前检测到 SSID: {detected}）" if detected else ""
    new_ssid = input(f"限定 SSID，逗号分隔，留空=不限制 [{ssid}]{hint}: ").strip()
    if new_ssid:
        cfg.data["network"]["ssid_whitelist"] = new_ssid

    cfgmod.save(cfg)
    print(f"\n已保存配置 -> {cfg.path}")

    print("\n现在录入密码（密码只会写进 Windows 凭据管理器，不会存进任何文件）")
    print("提示：输入时屏幕不显示字符，这是正常的。")
    pw1 = getpass.getpass("密码: ")
    pw2 = getpass.getpass("再输一次: ")
    if pw1 != pw2:
        print("两次输入不一致，已取消。")
        return EXIT.EXIT_CONFIG
    if not pw1:
        print("密码为空，已取消。")
        return EXIT.EXIT_CONFIG
    try:
        secretstore.set_password(username, pw1)
    except secretstore.SecretError as e:
        print(f"\n[失败] {e}")
        return EXIT.EXIT_CONFIG
    print(f"已写入凭据管理器（service={secretstore.SERVICE}, 账号={username}）")
    print(f"后端: {secretstore.backend_name()}")
    print("\n下一步：python -m campusnet check")
    return EXIT.EXIT_OK


def cmd_set_password(args):
    cfg = _bootstrap(args)
    username = args.username or cfg.get("account", "username", "").strip()
    if not username:
        print("未指定账号，且配置里 account.username 为空。")
        return EXIT.EXIT_CONFIG
    pw1 = getpass.getpass(f"为 {username} 录入密码: ")
    pw2 = getpass.getpass("再输一次: ")
    if pw1 != pw2 or not pw1:
        print("两次不一致或为空，已取消。")
        return EXIT.EXIT_CONFIG
    try:
        secretstore.set_password(username, pw1)
    except secretstore.SecretError as e:
        print(f"[失败] {e}")
        return EXIT.EXIT_CONFIG
    print("已更新凭据管理器中的密码。")
    return EXIT.EXIT_OK


def cmd_delete_password(args):
    """从凭据管理器删除密码（卸载自启时调用）。"""
    cfg = _bootstrap(args)
    username = args.username or cfg.get("account", "username", "").strip()
    if not username:
        print("配置里没有账号，无需删除。")
        return EXIT.EXIT_OK
    if args.yes:
        ok = secretstore.delete_password(username)
        print(f"删除凭据 {secretstore.SERVICE}/{username}：{'成功' if ok else '失败或不存在'}")
        return EXIT.EXIT_OK
    ans = input(f"确认删除凭据管理器中的 {secretstore.SERVICE}/{username} ？(y/N): ").strip().lower()
    if ans != "y":
        print("已取消。")
        return EXIT.EXIT_OK
    ok = secretstore.delete_password(username)
    print(f"删除结果：{'成功' if ok else '失败或不存在'}")
    return EXIT.EXIT_OK


def cmd_check(args):
    cfg = _bootstrap(args)
    r = runner.run_once(cfg, force=args.force)
    print(f"\n结果：{r.message}")
    print(f"退出码：{r.code}")
    return r.code


def cmd_guard(args):
    cfg = _bootstrap(args)
    return runner.guard(cfg)


def cmd_status(args):
    cfg = _bootstrap(args)
    timeout = cfg.get_float("policy", "request_timeout", 8.0)
    print(f"配置文件 : {cfg.path}")
    print(f"账号     : {cfg.get('account', 'username') or '(未设置)'}")
    print(f"Portal   : {cfg.get('portal', 'base_url')}")
    print(f"凭据后端 : {secretstore.backend_name()}")
    u = cfg.get("account", "username", "").strip()
    print(f"密码已存 : {'是' if u and secretstore.has_password(u) else '否'}")
    print(f"本机 IPv4: {netcheck.local_ipv4()}")
    print(f"本机 MAC : {netcheck.local_mac()}")
    print(f"当前 SSID: {netcheck.current_ssid(cfg.get('network', 'interface', 'WLAN'))}")
    print()
    online, details, suspects = netcheck.check_online(timeout=timeout, cfg=cfg)
    print(f"是否已登录: {'是' if online else '否'}")
    for d in details:
        mark = "OK  " if d.ok else "FAIL"
        print(f"  [{mark}] {d.name:<20} status={d.status} err={d.error or '-'}")
    if suspects:
        print("可疑 Portal 入口：")
        for s in dict.fromkeys(suspects):
            print(f"  - {s}")
    return EXIT.EXIT_OK


def cmd_logout(args):
    cfg = _bootstrap(args)
    online, details, _ = netcheck.check_online(cfg.get_float("policy", "request_timeout", 8.0), cfg=cfg)
    if not online:
        print("当前未登录，无需注销。")
        return EXIT.EXIT_OK
    entry = netcheck.discover_entry(cfg)
    if entry is None:
        print("无法发现 Portal 入口，注销失败。")
        return EXIT.EXIT_NETWORK
    from .portal import PortalClient
    client = PortalClient(cfg, entry)
    try:
        js = client.logout()
        print(f"注销返回：{js}")
        time.sleep(2)
        online2, _, _ = netcheck.check_online(cfg.get_float("policy", "request_timeout", 8.0), cfg=cfg)
        print(f"注销后是否仍在线：{'是' if online2 else '否'}")
    except Exception as e:
        print(f"注销失败：{e}")
        return EXIT.EXIT_LOGIN_FAILED
    return EXIT.EXIT_OK


def cmd_doctor(args):
    """排障：把判断依据全部打出来。"""
    cfg = _bootstrap(args)
    timeout = cfg.get_float("policy", "request_timeout", 8.0)
    print("=" * 70)
    print("环境自检")
    print("=" * 70)
    print(f"Python        : {sys.version.split()[0]}  ({sys.executable})")
    print(f"配置文件      : {cfg.path}  (存在={cfg.path.exists()})")
    print(f"日志目录      : {cfg.log_dir}")
    print(f"凭据后端      : {secretstore.backend_name()}")
    try:
        import requests
        print(f"requests      : {requests.__version__}")
    except Exception as e:
        print(f"requests      : 缺失! {e}")
    print(f"本机 IPv4     : {netcheck.local_ipv4()}")
    print(f"本机 MAC      : {netcheck.local_mac()}")
    print(f"当前 SSID     : {netcheck.current_ssid(cfg.get('network', 'interface', 'WLAN'))}")
    print()
    online, details, suspects = netcheck.check_online(timeout=timeout, cfg=cfg)
    print(f"链路判定      : {'已登录' if online else '未登录 / 需认证'}")
    for d in details:
        print(f"  [{'OK  ' if d.ok else 'FAIL'}] {d.name:<20} url={d.url}")
        print(f"          status={d.status} error={d.error} location={d.location}")
    print()
    entry = netcheck.discover_entry(cfg, timeout=timeout)
    if entry:
        print(f"Portal 入口   : {entry.entry_url}")
        print(f"Portal 主机   : {entry.base_url}")
        print(f"入口参数      : {entry.params}")
    else:
        print("Portal 入口   : 未发现")
    return EXIT.EXIT_OK


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="campusnet",
        description="校园网开机自动登录（Portal 认证）",
    )
    p.add_argument("--config", default=None, help="指定配置文件路径")
    p.add_argument("-v", "--verbose", action="store_true", help="输出 DEBUG 日志")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("setup", help="交互式初始化：写配置 + 把密码存进凭据管理器")
    sp = sub.add_parser("set-password", help="只更新凭据管理器里的密码")
    sp.add_argument("--username", default=None, help="指定账号，默认取配置里的")

    sc = sub.add_parser("check", help="执行一次：检测网络，未登录则登录（开机自启调用这个）")
    sc.add_argument("--force", action="store_true", help="即使已在线也强制走一次登录流程")

    sd = sub.add_parser("delete-password", help="从凭据管理器删除密码")
    sd.add_argument("--username", default=None, help="指定账号，默认取配置里的")
    sd.add_argument("--yes", action="store_true", help="不询问，直接删除")

    sub.add_parser("guard", help="常驻巡检：每 guard_interval 秒检查一次，掉线自动重登")
    sub.add_parser("status", help="查看当前状态，不做任何登录动作")
    sub.add_parser("logout", help="主动注销（仅用于测试）")
    sub.add_parser("doctor", help="环境自检与排障信息")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "setup": cmd_setup,
        "set-password": cmd_set_password,
        "delete-password": cmd_delete_password,
        "check": cmd_check,
        "guard": cmd_guard,
        "status": cmd_status,
        "logout": cmd_logout,
        "doctor": cmd_doctor,
    }
    try:
        return handlers[args.cmd](args)
    except KeyboardInterrupt:
        print("\n已中断。")
        return 130


if __name__ == "__main__":                        # pragma: no cover
    raise SystemExit(main())
