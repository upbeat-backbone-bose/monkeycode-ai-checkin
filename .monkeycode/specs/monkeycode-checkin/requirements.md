# Monkeycode 自动签到需求文档

## 概述

实现一个 Go 语言编写的自动签到工具，通过 GitHub Actions 每日定时调度，访问 Monkeycode 平台执行签到获取积分。无需前端控制面板，通过 Webhook 通知签到失败情况。

## 需求列表

### R1 - 签到执行
- 工具应能通过 Cookie 认证访问 Monkeycode 平台
- 执行签到操作并获取签到结果（积分、连续签到天数等）
- 签到成功时输出结果到标准输出

### R2 - WAF/Challenge 应对
- 使用 uTLS 库模拟 Chrome TLS 指纹
- 能够检测并通过 JavaScript Challenge 验证
- 请求头应模拟真实 Chrome 浏览器

### R3 - GitHub Actions 调度
- 提供 GitHub Actions 工作流配置文件
- 默认每天执行一次签到
- 支持手动触发（workflow_dispatch）

### R4 - 失败通知
- 签到失败时通过 Webhook 发送通知
- 通知内容包含错误类型、错误详情和建议操作
- 支持钉钉/企业微信/飞书格式的 Markdown 消息

### R5 - Cookie 管理
- Cookie 通过环境变量 MONKEYCODE_COOKIE 传入
- Cookie 由用户手动更新并通过 GitHub Secrets 管理
- 不提供自动登录功能

### R6 - 安全要求
- 不得在日志中输出 Cookie 值
- Webhook URL 通过环境变量传入，不得硬编码
- 依赖库需使用可信来源

## 非功能性需求

### NF1 - 性能
- 单次签到执行时间不超过 60 秒
- GitHub Actions 运行时间控制在 2 分钟内

### NF2 - 可靠性
- 网络请求支持自动重试（最多 3 次，指数退避）
- 连接超时 10 秒，读取超时 30 秒

### NF3 - 可维护性
- 代码结构清晰，模块职责单一
- 提供完整的 README 使用说明
