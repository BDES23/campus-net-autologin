# -*- coding: utf-8 -*-
"""
巡检入口：常驻后台，每 guard_interval 秒检查一次，掉线自动重新登录。
由第二个任务计划程序任务在开机时启动（无窗口）。
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
        console=False,
    )
    logkit.get("guard").info("巡检守护启动")
    try:
        return runner.guard(cfg)
    except KeyboardInterrupt:
        return 0
    except Exception as e:
        logkit.get("guard").exception("巡检守护异常退出：%s", logkit.redact(e))
        return runner.EXIT_NETWORK


if __name__ == "__main__":
    raise SystemExit(main())
