# Monkeycode 自动签到实施任务列表

## 任务清单

### Task 1: 项目初始化
- [x] 1.1 创建 Go Module，初始化 go.mod
- [x] 1.2 创建项目目录结构 (cmd/, internal/)
- [x] 1.3 添加依赖：utls, otto
- [x] 1.4 编写 main.go 骨架（配置加载、环境变量读取）

### Task 2: HTTP 客户端实现
- [x] 2.1 实现 uTLS 配置，使用 Chrome 120 指纹
- [x] 2.2 实现 CookieJar 管理
- [x] 2.3 实现请求头自动注入（User-Agent, Sec-Fetch-* 等）
- [x] 2.4 实现 GET/POST 方法封装
- [x] 2.5 实现重试逻辑（指数退避，最多 3 次）
- [x] 2.6 编写 HTTP 客户端单元测试

### Task 3: Challenge 处理器实现
- [x] 3.1 实现 challenge 页面检测逻辑
- [x] 3.2 实现 JS 代码提取
- [x] 3.3 使用 otto 执行 challenge JS
- [x] 3.4 实现 challenge token 提取和响应构造
- [x] 3.5 编写 Challenge 处理器测试

### Task 4: 签到服务实现
- [x] 4.1 定义 CheckinResult 和错误类型
- [x] 4.2 实现签到流程编排（访问首页 → challenge → 签到请求）
- [x] 4.3 实现签到响应解析
- [x] 4.4 实现错误分类和映射
- [x] 4.5 编写签到服务测试（使用 mock HTTP server）

### Task 5: Webhook 通知实现
- [x] 5.1 实现钉钉格式 Markdown 消息
- [x] 5.2 实现企业微信格式 Markdown 消息
- [x] 5.3 实现飞书格式消息
- [x] 5.4 实现 Webhook 发送逻辑（带超时和错误处理）
- [x] 5.5 编写 Webhook 测试

### Task 6: GitHub Actions 配置
- [x] 6.1 创建 .github/workflows/checkin.yml
- [x] 6.2 配置定时触发（cron）和手动触发（workflow_dispatch）
- [x] 6.3 配置 Go 环境安装和构建步骤
- [x] 6.4 配置 Secrets 传递（MONKEYCODE_COOKIE, WEBHOOK_URL）

### Task 7: 文档与测试
- [x] 7.1 编写 README.md（安装、配置、使用说明）
- [x] 7.2 确保所有测试通过
- [x] 7.3 验证 GitHub Actions 工作流配置

## 依赖关系

```
Task 1 (项目初始化)
    ↓
Task 2 (HTTP 客户端)
    ↓
Task 3 (Challenge 处理器) ──→ 可并行
Task 4 (签到服务) ────────────→ 依赖 Task 2 和 Task 3
    ↓
Task 5 (Webhook 通知) ────────→ 可并行
    ↓
Task 6 (GitHub Actions) ──────→ 依赖 Task 1-5
    ↓
Task 7 (文档与测试) ──────────→ 最后执行
```

## 执行建议

1. 从 Task 1 开始，完成项目骨架
2. Task 2 是核心依赖，优先完成
3. Task 3 和 Task 5 可并行开发
4. Task 4 是核心业务逻辑，在 Task 2 和 Task 3 完成后实现
5. Task 6 和 Task 7 收尾
