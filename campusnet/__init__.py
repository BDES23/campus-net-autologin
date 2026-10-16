# -*- coding: utf-8 -*-
"""校园网开机自动登录 —— 核心包。

协议来源说明（重要）
-------------------
本包中所有 Portal 接口路径与字段名，均来自对用户本机 Edge 浏览器磁盘缓存中
真实 Portal 页面 JavaScript 的提取（文件见 recon/cache_dump/），并非推测：

    GET  {base}/account/status?wlanuserip=<ip>   在线状态；code==0 表示已在线
    POST {base}/account/check                    登录前检查（是否强制改密）
    POST {base}/account/login                    真正的登录接口
    GET  {base}/account/logout?wlanuserip=<ip>   注销
    GET  {base}/config, /default/isp, /notice/some

    postData 字段：username, password, switchip, nasId, userIpv4, userMac,
                   captcha, captchaId, isp, timeLimit
    值为空串的字段会被前端删除后再提交 —— 本包同样实现该行为。
    密码为**明文**提交（源码：postData.password = $('#password').val()）。
    响应 code：0=成功，1=失败(读 msg)，2=需要验证码(读 captcha.picPath/captchaId)。

所有路径仍可在 config.ini 中覆盖，以适配学校后续改版。
"""

__version__ = "1.1.0"
__all__ = ["__version__"]
