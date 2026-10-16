# -*- coding: utf-8 -*-
"""
开机自启调用的入口：检测网络，未登录就登录。
由 Windows 任务计划程序在"用户登录时"触发，延迟 30 秒执行。

不建议给这个脚本加参数（任务计划程序里改参数比较麻烦）；
需要改行为请改 config.ini。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from campusnet import config as cfgmod, logkit, runner   # noqa: E402


def main() -> int:
    cfg = cfgmod.ensure_config()
    logkit.setup(
        cfg.log_dir,
        level=cfg.get("logging", "level", "INFO"),
        max_bytes=cfg.get_int("logging", "max_bytes", 1_048_576),
        backup_count=cfg.get_int("logging", "backup_count", 5),
        console=False,          # 由任务计划程序拉起时没有控制台，不写 stdout
    )
    log = logkit.get("autostart")
    log.info("=" * 56)
    log.info("开机自动登录任务启动")
    try:
        r = runner.run_once(cfg)
        log.info("结束：%s（退出码 %d）", r.message, r.code)
        return r.code
    except Exception as e:                                   # 绝不能让任务崩掉
        log.exception("未预期异常：%s", logkit.redact(e))
        return runner.EXIT_NETWORK


if __name__ == "__main__":
    raise SystemExit(main())
