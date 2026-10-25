# -*- coding: utf-8 -*-
"""
校园网自动登录 —— 图形界面 + 静默工作模式（单文件入口）

为什么要做成"一个 exe 双模式"
------------------------------
要发给"完全不懂电脑"的同学，最理想的是**只发一个文件、双击就有窗口**。
但开机自启需要在后台静默运行，不能每次弹窗口。

所以这里用参数分流：

    CampusNet.exe               → 打开图形界面（双击就是这种）
    CampusNet.exe --login       → 静默执行一次登录（任务计划程序调用）
    CampusNet.exe --guard       → 静默常驻巡检（任务计划程序调用）
    CampusNet.exe --install     → 静默安装开机自启（给高级用户/脚本用）
    CampusNet.exe --uninstall   → 静默卸载开机自启

打包时用 console=False，所以 `--login` / `--guard` 被任务拉起时**不会闪黑框**。

权限说明（重要）
----------------
本程序**不需要管理员权限**，因此打包时**不要**加 --uac-admin：
  * keyring 写的是"当前用户"的凭据管理器，普通权限即可；
  * 任务计划程序用的是 RunLevel=Limited 的用户级任务，普通权限即可；
  * 一旦 exe 带 requireAdministrator 清单，那个 Limited 任务在登录时就**拉不起它**，
    开机自启会直接坏掉。
"""
from __future__ import annotations

import os
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

# 让脚本在源码目录和打包后都能 import 到 campusnet
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from campusnet import config as cfgmod          # noqa: E402
from campusnet import config as _cfgmod_ref     # noqa: F401  (保持引用，便于打包分析)
from campusnet import logkit, netcheck, runner, secretstore   # noqa: E402

TASK_LOGIN = "CampusNetAutoLogin"
TASK_GUARD = "CampusNetGuard"
APP_TITLE = "校园网自动登录"


# ==========================================================================
# 通用：路径与任务计划程序
# ==========================================================================
def app_dir() -> Path:
    """exe（或源码）所在目录。打包后 config.ini / logs 都放在这里。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return _HERE


def _task_parts(arg: str) -> tuple[str, str, str]:
    """返回 (要执行的程序, 参数, 工作目录)。"""
    workdir = str(app_dir())
    if getattr(sys, "frozen", False):
        return sys.executable, arg, workdir
    # 源码运行：用当前解释器 + 本文件
    return sys.executable, f'"{Path(__file__).resolve()}" {arg}', workdir


def _run_ps(script: str, timeout: int = 120) -> tuple[int, str]:
    """把 PowerShell 脚本写到带 BOM 的临时文件再执行。

    走文件而不是 -Command 字符串，可以彻底避开引号嵌套问题；
    带 BOM 是必须的，否则 PowerShell 5.1 会按 GBK 解析中文导致语法错误。
    """
    import subprocess
    import tempfile

    fd, path = tempfile.mkstemp(suffix=".ps1", prefix="campusnet_")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8-sig") as f:
            f.write(script)
        r = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path],
            capture_output=True, timeout=timeout,
        )
        out = (r.stdout + r.stderr).decode("gbk", "replace").strip()
        return r.returncode, out
    except Exception as e:
        return -1, f"{type(e).__name__}: {e}"
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def _ps_task_script(task: str, arg: str) -> str:
    exe, arguments, workdir = _task_parts(arg)
    delay = "PT30S" if task == TASK_LOGIN else "PT90S"
    limit = "PT10M" if task == TASK_LOGIN else "PT0S"
    return f"""
$ErrorActionPreference = 'Stop'
$task = '{task}'
Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction -Execute '{exe}' -Argument '{arguments}' -WorkingDirectory '{workdir}'
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$trigger.Delay = '{delay}'
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 2)
$settings.ExecutionTimeLimit = '{limit}'
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\\$env:USERNAME" -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description '{APP_TITLE}' | Out-Null
Write-Output 'OK'
"""


def install_tasks() -> tuple[bool, str]:
    """安装两个用户级任务（不需要管理员）。返回 (成功, 消息)。"""
    msgs = []
    for task, arg, label in ((TASK_LOGIN, "--login", "开机登录"),
                             (TASK_GUARD, "--guard", "巡检保活")):
        rc, out = _run_ps(_ps_task_script(task, arg))
        if rc != 0 or "OK" not in out:
            return False, f"{label} 任务安装失败：{out[:300]}"
        msgs.append(label)
    return True, "已安装：" + "、".join(msgs)


def remove_tasks() -> tuple[bool, str]:
    script = f"""
$ErrorActionPreference = 'Continue'
foreach ($t in @('{TASK_LOGIN}','{TASK_GUARD}')) {{
    $x = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    if ($x) {{
        Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $t -Confirm:$false
        Write-Output "removed $t"
    }}
}}
Write-Output 'DONE'
"""
    rc, out = _run_ps(script)
    if rc != 0:
        return False, f"卸载失败：{out[:300]}"
    return True, "已移除开机自启任务"


def tasks_installed() -> dict:
    script = f"""
foreach ($t in @('{TASK_LOGIN}','{TASK_GUARD}')) {{
    $x = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    if ($x) {{ Write-Output "$t=$($x.State)" }} else {{ Write-Output "$t=missing" }}
}}
"""
    rc, out = _run_ps(script, timeout=60)
    state = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            state[k.strip()] = v.strip()
    return state


# ==========================================================================
# GUI
# ==========================================================================
class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.cfg = cfgmod.ensure_config()
        logkit.setup(self.cfg.log_dir, level=self.cfg.get("logging", "level", "INFO"),
                     console=False)          # 打包后没有控制台，日志只进文件
        self.log = logkit.get("gui")
        # 这一行很关键：万一同学"双击没反应"，日志里有没有它就能立刻区分
        # 是「窗口没起来」还是「起来了但登录失败」。
        self.log.info("图形界面已启动；程序目录=%s", app_dir())

        root.title(f"{APP_TITLE}  v1.1.0")
        root.geometry("620x520")
        root.minsize(560, 460)
        try:
            root.iconbitmap(default="")
        except Exception:
            pass

        self._build_ui()
        self._refresh_status()
        self.write("欢迎使用。第一次使用请：填好账号和密码 → 点「保存账号和密码」→ 点「安装开机自启」。")
        # 放在最后：这一行出现，说明所有控件都建好了、mainloop 即将开始。
        # 同学"双击没反应"时，日志里缺这一行就说明是界面初始化阶段出的问题。
        self.log.info("界面初始化完成，进入事件循环")

    # ---- UI 搭建 -------------------------------------------------------
    def _build_ui(self):
        pad = {"padx": 12, "pady": 6}

        # 状态区
        box = ttk.LabelFrame(self.root, text=" 当前状态 ")
        box.pack(fill="x", **pad)
        self.lbl_account = ttk.Label(box, text="账号：-")
        self.lbl_password = ttk.Label(box, text="密码：-")
        self.lbl_network = ttk.Label(box, text="网络：-")
        self.lbl_autostart = ttk.Label(box, text="开机自启：-")
        for i, w in enumerate((self.lbl_account, self.lbl_password,
                               self.lbl_network, self.lbl_autostart)):
            w.grid(row=i, column=0, sticky="w", padx=10, pady=2)

        # 输入区
        form = ttk.LabelFrame(self.root, text=" 账号设置 ")
        form.pack(fill="x", **pad)
        ttk.Label(form, text="账号：").grid(row=0, column=0, sticky="e", padx=6, pady=6)
        self.ent_user = ttk.Entry(form, width=32)
        self.ent_user.grid(row=0, column=1, sticky="w", pady=6)
        ttk.Label(form, text="密码：").grid(row=1, column=0, sticky="e", padx=6, pady=6)
        self.ent_pass = ttk.Entry(form, width=32, show="●")
        self.ent_pass.grid(row=1, column=1, sticky="w", pady=6)
        ttk.Label(form, text="（密码只存进 Windows 凭据管理器，不会写进任何文件）",
                  foreground="#666").grid(row=1, column=2, sticky="w", padx=6)

        self.ent_user.insert(0, self.cfg.get("account", "username", ""))

        # 按钮区
        btns = ttk.Frame(self.root)
        btns.pack(fill="x", **pad)
        self.btn_save = ttk.Button(btns, text="① 保存账号和密码", command=self.on_save)
        self.btn_save.pack(side="left", padx=4)
        self.btn_login = ttk.Button(btns, text="② 立即登录一次", command=self.on_login)
        self.btn_login.pack(side="left", padx=4)
        self.btn_install = ttk.Button(btns, text="③ 安装开机自启", command=self.on_install)
        self.btn_install.pack(side="left", padx=4)
        self.btn_remove = ttk.Button(btns, text="卸载自启", command=self.on_remove)
        self.btn_remove.pack(side="left", padx=4)

        btns2 = ttk.Frame(self.root)
        btns2.pack(fill="x", padx=12)
        ttk.Button(btns2, text="刷新状态", command=self._refresh_status).pack(side="left", padx=4)
        ttk.Button(btns2, text="打开日志", command=self.on_open_log).pack(side="left", padx=4)
        ttk.Button(btns2, text="打开程序目录", command=self.on_open_dir).pack(side="left", padx=4)

        # 日志区
        logbox = ttk.LabelFrame(self.root, text=" 运行记录 ")
        logbox.pack(fill="both", expand=True, **pad)
        self.txt = tk.Text(logbox, height=12, wrap="word", state="disabled",
                           background="#1e1e1e", foreground="#d4d4d4",
                           insertbackground="#d4d4d4", font=("Consolas", 9))
        sb = ttk.Scrollbar(logbox, command=self.txt.yview)
        self.txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.txt.pack(side="left", fill="both", expand=True)

    # ---- 工具 ----------------------------------------------------------
    def write(self, msg: str):
        self.txt.configure(state="normal")
        self.txt.insert("end", msg.rstrip() + "\n")
        self.txt.see("end")
        self.txt.configure(state="disabled")

    def busy(self, on: bool):
        state = "disabled" if on else "normal"
        for b in (self.btn_save, self.btn_login, self.btn_install, self.btn_remove):
            b.configure(state=state)
        self.root.configure(cursor="watch" if on else "")

    def run_bg(self, fn, done_msg: str):
        """把耗时的活丢到后台线程，避免界面卡死。"""
        self.busy(True)

        def worker():
            try:
                ok, msg = fn()
                text = (f"[成功] {done_msg}" if ok else f"[失败] {msg}")
                if ok and msg:
                    text += f"：{msg}"
            except Exception as e:                        # 任何异常都要显示给用户
                text = f"[异常] {type(e).__name__}: {e}"
            self.root.after(0, lambda: (self.write(text), self.busy(False),
                                        self._refresh_status()))

        threading.Thread(target=worker, daemon=True).start()

    # ---- 状态 ----------------------------------------------------------
    def _refresh_status(self):
        u = self.cfg.get("account", "username", "").strip()
        self.lbl_account.configure(text=f"账号：{u or '（未设置）'}")
        has_pw = bool(u and secretstore.has_password(u))
        self.lbl_password.configure(text=f"密码：{'已保存' if has_pw else '（未保存）'}")

        def probe():
            try:
                online, _, _ = netcheck.check_online(
                    timeout=self.cfg.get_float("policy", "request_timeout", 8.0),
                    cfg=self.cfg)
                return online
            except Exception:
                return None

        def do():
            online = probe()
            st = tasks_installed()
            def apply():
                if online is None:
                    self.lbl_network.configure(text="网络：检测失败")
                else:
                    self.lbl_network.configure(text=f"网络：{'已登录' if online else '未登录'}")
                inst = (st.get(TASK_LOGIN) not in (None, "missing")
                        and st.get(TASK_GUARD) not in (None, "missing"))
                self.lbl_autostart.configure(text=f"开机自启：{'已安装' if inst else '未安装'}")
            self.root.after(0, apply)

        threading.Thread(target=do, daemon=True).start()

    # ---- 动作 ----------------------------------------------------------
    def on_save(self):
        u = self.ent_user.get().strip()
        p = self.ent_pass.get()
        if not u:
            messagebox.showwarning(APP_TITLE, "请先填写账号（学号或手机号）")
            return
        if not p:
            messagebox.showwarning(APP_TITLE, "请填写密码")
            return
        try:
            secretstore.set_password(u, p)
        except secretstore.SecretError as e:
            messagebox.showerror(APP_TITLE, str(e))
            return
        self.cfg.data["account"]["username"] = u
        cfgmod.save(self.cfg)
        self.ent_pass.delete(0, "end")
        self.write(f"[成功] 账号 {u} 已保存；密码已写入 Windows 凭据管理器。")
        self._refresh_status()

    def on_login(self):
        self.write("开始登录…")
        self.run_bg(lambda: (lambda r: (r.code == 0, r.message))(runner.run_once(self.cfg)),
                    "登录完成")

    def on_install(self):
        if messagebox.askyesno(APP_TITLE,
                               "将为你安装两个开机自启任务（不需要管理员权限）：\n\n"
                               "  • 开机登录：登录进桌面 30 秒后自动认证一次\n"
                               "  • 巡检保活：每 5 分钟检查，掉线自动重登\n\n"
                               "继续吗？"):
            self.write("正在安装开机自启…")
            self.run_bg(install_tasks, "开机自启已安装")

    def on_remove(self):
        if messagebox.askyesno(APP_TITLE, "确定要卸载开机自启吗？\n（不会删除你的账号和密码）"):
            self.write("正在卸载…")
            self.run_bg(remove_tasks, "开机自启已卸载")

    def on_open_log(self):
        p = self.cfg.log_dir / "campusnet.log"
        if not p.exists():
            messagebox.showinfo(APP_TITLE, "还没有日志文件，先登录一次试试。")
            return
        os.startfile(str(p))

    def on_open_dir(self):
        os.startfile(str(app_dir()))


# ==========================================================================
# 入口：按参数分流
# ==========================================================================
def run_headless(mode: str) -> int:
    """--login / --guard 的静默模式（任务计划程序会这样调用）。"""
    cfg = cfgmod.ensure_config()
    logkit.setup(cfg.log_dir, level=cfg.get("logging", "level", "INFO"),
                 max_bytes=cfg.get_int("logging", "max_bytes", 1_048_576),
                 backup_count=cfg.get_int("logging", "backup_count", 5),
                 console=False)
    log = logkit.get("cli-headless")
    log.info("=" * 56)
    log.info("静默模式启动：%s", mode)
    try:
        if mode == "--guard":
            return runner.guard(cfg)
        r = runner.run_once(cfg)
        log.info("结束：%s（退出码 %d）", r.message, r.code)
        return r.code
    except Exception as e:
        log.exception("未预期异常：%s", logkit.redact(e))
        return runner.EXIT_NETWORK


def run_diagnose() -> int:
    """--diagnose：把环境信息全部写进日志，方便远程排障。

    打包版没有控制台，所以诊断结果只进日志文件（点 GUI 上的「打开日志」能看到）。
    重点验证 keyring 后端在 PyInstaller 打包之后是否还能被找到。
    """
    cfg = cfgmod.ensure_config()
    logkit.setup(cfg.log_dir, level="DEBUG", console=False)
    log = logkit.get("diagnose")
    log.info("=" * 56)
    log.info("诊断开始")
    log.info("Python         : %s", sys.version.split()[0])
    log.info("frozen         : %s", getattr(sys, "frozen", False))
    log.info("sys.executable : %s", sys.executable)
    log.info("_MEIPASS       : %s", getattr(sys, "_MEIPASS", "-"))
    log.info("程序目录       : %s", app_dir())
    log.info("配置文件       : %s  (存在=%s)", cfg.path, cfg.path.exists())
    log.info("日志目录       : %s", cfg.log_dir)
    log.info("凭据后端       : %s", secretstore.backend_name())
    u = cfg.get("account", "username", "").strip()
    log.info("账号           : %s", u or "(未设置)")
    log.info("密码已存       : %s", bool(u and secretstore.has_password(u)))
    log.info("Portal 主机    : %s", cfg.get("portal", "base_url") or "(自动发现)")
    try:
        online, details, _ = netcheck.check_online(cfg=cfg)
        log.info("网络           : %s", "已登录" if online else "未登录")
        for d in details:
            log.info("  探测 %-20s ok=%s status=%s err=%s",
                     d.name, d.ok, d.status, d.error)
    except Exception as e:
        log.info("网络探测异常   : %s", e)
    log.info("诊断结束")
    return 0


def _say(msg: str) -> None:
    """安全输出。

    console=False 打包后 sys.stdout 是 None，直接 print() 会抛
    AttributeError: 'NoneType' object has no attribute 'write'。
    """
    try:
        if sys.stdout is not None:
            print(msg)
            sys.stdout.flush()
    except Exception:
        pass
    try:
        logkit.get("cli").info("%s", msg)
    except Exception:
        pass


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    for mode in ("--login", "--guard"):
        if mode in argv:
            return run_headless(mode)
    if "--diagnose" in argv:
        return run_diagnose()

    if "--install" in argv or "--uninstall" in argv:
        cfg = cfgmod.ensure_config()
        logkit.setup(cfg.log_dir, level="INFO", console=False)
        ok, msg = (install_tasks() if "--install" in argv else remove_tasks())
        _say(msg)
        return 0 if ok else 1

    try:
        root = tk.Tk()
        App(root)
        root.mainloop()
        return 0
    except Exception as e:                              # 打包后看不到控制台，用弹窗报错
        try:
            from tkinter import messagebox
            messagebox.showerror(APP_TITLE, f"启动失败：{type(e).__name__}: {e}")
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
