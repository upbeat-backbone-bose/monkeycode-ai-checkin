# Monkeycode Checkin

Monkeycode 平台自动签到工具，通过 GitHub Actions 每日定时执行，自动获取积分。

## 功能特性

- 使用 uTLS 模拟 Chrome 浏览器 TLS 指纹，绕过基础 WAF 检测
- 支持 JavaScript Challenge 自动处理（基于 otto JS 引擎）
- 失败时通过 Webhook 发送通知（支持钉钉、企业微信、飞书）
- 指数退避重试机制，提高签到成功率

## 快速开始

### 1. Fork 本仓库

点击 GitHub 右上角的 **Fork** 按钮，将本仓库 Fork 到你的 GitHub 账号。

### 2. 获取 Cookie

1. 在浏览器中登录 [Monkeycode](https://monkeycode-ai.com)
2. 打开浏览器开发者工具（F12）
3. 进入 **Application** > **Cookies**
4. 复制所有 Cookie 值，格式为：`name1=value1; name2=value2; name3=value3`

### 3. 配置 GitHub Secrets

进入 Fork 后的仓库，点击 **Settings** > **Secrets and variables** > **Actions**，添加以下 Secrets：

| Secret 名称 | 必填 | 说明 |
|-------------|------|------|
| `MONKEYCODE_COOKIE` | 是 | 登录后的 Cookie 字符串 |
| `WEBHOOK_URL` | 否 | 失败通知 Webhook 地址 |

### 4. 启用 GitHub Actions

- 进入 **Actions** 标签页
- 点击 **I understand my workflows, go ahead and enable them**

### 5. 手动触发测试

- 进入 **Actions** > **Monkeycode Checkin**
- 点击 **Run workflow** > **Run workflow**

## Webhook 通知

工具会自动检测 Webhook URL 类型，支持以下平台：

| 平台 | URL 特征 |
|------|----------|
| 钉钉 | 包含 `oapi.dingtalk.com` |
| 企业微信 | 包含 `qyapi.weixin.qq.com` |
| 飞书 | 包含 `open.feishu.cn` |
| 通用 | 其他 URL，发送 JSON 格式 |

## 环境变量

| 变量名 | 必填 | 默认值 | 说明 |
|--------|------|--------|------|
| `MONKEYCODE_COOKIE` | 是 | - | 平台登录 Cookie |
| `WEBHOOK_URL` | 否 | - | 失败通知 Webhook |
| `TARGET_URL` | 否 | `https://monkeycode-ai.com` | 平台地址 |

## 签到调度

- **定时执行**：每天 UTC 00:00（北京时间 08:00）
- **手动执行**：通过 GitHub Actions 页面手动触发

## 本地运行

```bash
# 克隆仓库
git clone https://github.com/your-username/monkeycode-checkin.git
cd monkeycode-checkin

# 设置环境变量
export MONKEYCODE_COOKIE="your-cookie-here"
export WEBHOOK_URL="your-webhook-url"  # 可选

# 构建并运行
go build -o checkin ./cmd/checkin/
./checkin
```

## 项目结构

```
├── cmd/checkin/main.go           # 入口程序
├── internal/
│   ├── httpclient/client.go      # uTLS HTTP 客户端
│   ├── challenge/challenge.go    # JS Challenge 处理器
│   ├── checkin/service.go        # 签到业务逻辑
│   └── notify/webhook.go         # Webhook 通知
├── .github/workflows/checkin.yml # GitHub Actions 配置
├── go.mod
└── README.md
```

## 注意事项

- Cookie 会定期过期，如果收到失败通知，请更新 `MONKEYCODE_COOKIE` Secret
- 不要在日志或代码中暴露 Cookie 值
- 签到失败时会自动发送 Webhook 通知，请及时处理

## License

MIT
