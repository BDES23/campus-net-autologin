# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller 打包定义 —— 把整个程序打成**单个** CampusNet.exe
================================================================

用法（在项目根目录）：

    python -m PyInstaller --noconfirm --clean build.spec

产物：dist\\CampusNet.exe

为什么是"一个 exe 双模式"
-------------------------
`campusnet_gui.py` 会根据命令行参数分流：
    双击（无参数）        → 图形界面
    CampusNet.exe --login → 静默登录一次（任务计划程序调用，不闪黑框）
    CampusNet.exe --guard → 静默常驻巡检

这样只需发一个文件给同学，而开机自启又不会弹窗口。

关键配置说明
------------
console=False
    不显示控制台黑框。注意：打包成 windowed 后 sys.stdout / sys.stderr 为 None，
    代码里任何 print() 都会抛 AttributeError —— 本项目的 _say() 已经做了保护，
    并且日志统一走 logging 写文件。

uac_admin=False（**故意不加 --uac-admin**）
    本程序不需要管理员权限：
      * keyring 写的是"当前用户"的凭据管理器，普通权限即可；
      * 自启任务是 RunLevel=Limited 的用户级任务，普通权限即可（已实测）。
    一旦加上 requireAdministrator 清单，那个 Limited 任务在登录时**拉不起**这个
    exe，开机自启会直接坏掉。
    如果你确实因为别的原因需要（例如把程序装进 C:\\Program Files），
    把下面的 uac_admin=False 改成 True；同时必须把任务改成"最高权限"运行，
    否则自启失效。

config.ini 不打包进 exe
    配置文件与日志都放在 exe 同目录（见 campusnet/config.py 的 app_dir()）。
    打包后 __file__ 指向临时解压目录 _MEIPASS，所以不能靠 __file__ 定位配置文件。
"""

from PyInstaller.utils.hooks import collect_submodules, copy_metadata

# ---------------------------------------------------------------- 隐式依赖
# keyring 的后端是通过包元数据里的 entry points **动态**加载的，
# PyInstaller 的静态分析完全看不到，所以必须显式声明，
# 否则运行时会出现经典的：
#   keyring.errors.NoKeyringError: No recommended backend was available
hiddenimports = [
    # keyring 的各个后端（Windows 上真正生效的是 backends.Windows）
    "keyring.backends.Windows",
    "keyring.backends.fail",
    "keyring.backends.chainer",
    # keyring 的传递依赖，同样容易漏
    "win32ctypes.pywin32",
    "win32ctypes.core",
    "jaraco.classes",
    "jaraco.functools",
    "jaraco.context",
    "more_itertools",
]
# 再兜一层：把 keyring 下所有子模块都收进来
hiddenimports += collect_submodules("keyring")

# keyring / requests 运行时要从 dist-info 里读版本与 entry points
datas = []
try:
    datas += copy_metadata("keyring")
except Exception:
    pass
try:
    datas += copy_metadata("requests")
except Exception:
    pass

# ---------------------------------------------------------------- 分析
a = Analysis(
    ["campusnet_gui.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # 排除用不到的大件，显著减小体积
    excludes=[
        "pytest", "numpy", "pandas", "scipy", "matplotlib",
        "PIL", "PyQt5", "PySide2", "PySide6", "IPython", "notebook",
        "test", "unittest",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="CampusNet",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                 # UPX 压缩容易被杀毒软件误报，关掉
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,             # ← 不显示黑框
    disable_windowed_traceback=False,   # 未捕获异常时弹窗，而不是静默死掉
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=False,           # ← 故意不加 --uac-admin，原因见文件头
    icon=None,                 # 有 .ico 时填 "app.ico"
)
