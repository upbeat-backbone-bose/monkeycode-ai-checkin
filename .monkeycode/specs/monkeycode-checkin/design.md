# Monkeycode 自动签到技术设计

## 架构概览

```
GitHub Actions (定时调度)
    │
    ├── 读取 Secrets (MONKEYCODE_COOKIE, WEBHOOK_URL, TARGET_URL)
    │
    ├── Go 二进制 (checkin)
    │   ├── HTTP 客户端 (uTLS Chrome 指纹)
    │   ├── Challenge 处理器 (otto JS 引擎)
    │   ├── 签到服务 (业务逻辑)
    │   └── Webhook 通知
    │
    └── 输出结果 / 发送通知
```

## 项目结构

```
monkeycode-checkin/
├── cmd/
│   └── checkin/
│       └── main.go              # 入口，配置加载，流程编排
├── internal/
│   ├── httpclient/
│   │   └── client.go            # uTLS HTTP 客户端
│   ├── challenge/
│   │   └── challenge.go         # JS Challenge 处理
│   ├── checkin/
│   │   └── service.go           # 签到业务逻辑
│   └── notify/
│       └── webhook.go           # Webhook 通知
├── go.mod
├── go.sum
├── .github/
│   └── workflows/
│       └── checkin.yml          # GitHub Actions 配置
└── README.md
```

## 核心组件

### HTTP 客户端

使用 `refraction-networking/utls` 库配置 Chrome TLS 指纹：

- 使用 `utls.HelloChrome_120` 配置文件
- 自定义 CookieJar 管理会话
- 统一设置浏览器风格请求头
- 支持 gzip/br 解压缩
- 内置重试逻辑（指数退避，最多 3 次）

### Challenge 处理器

- 检测响应 HTML 是否包含 challenge 特征
- 提取 challenge JavaScript 代码
- 使用 `github.com/robertkrimen/otto` 执行 JS
- 获取 challenge token 并构造响应

### 签到服务

流程：
1. 初始化客户端，注入 Cookie
2. 访问 Monkeycode 首页
3. 检测并处理 challenge
4. 调用签到接口
5. 解析响应，返回签到结果

数据结构：

```go
type CheckinResult struct {
    Success      bool
    Message      string
    Points       int
    PointsGained int
    StreakDays   int
}

type ErrorType string

const (
    ErrNetwork      ErrorType = "NETWORK_ERROR"
    ErrTLSFingerprint ErrorType = "TLS_FINGERPRINT"
    ErrChallenge    ErrorType = "CHALLENGE_FAILED"
    ErrAuth         ErrorType = "AUTH_EXPIRED"
    ErrBusiness     ErrorType = "BUSINESS_ERROR"
    ErrWAF          ErrorType = "WAF_BLOCKED"
    ErrAPIChange    ErrorType = "API_CHANGED"
)
```

### Webhook 通知

- 支持钉钉/企业微信/飞书 Markdown 格式
- 包含签到时间、错误类型、详情、建议操作
- 发送失败不阻断主流程

## 环境变量

| 变量名 | 必填 | 说明 |
|--------|------|------|
| MONKEYCODE_COOKIE | 是 | 平台登录后的 Cookie 字符串 |
| WEBHOOK_URL | 否 | 失败通知 Webhook 地址 |
| TARGET_URL | 否 | 平台地址，默认 https://monkeycode-ai.com |

## GitHub Actions 调度

- 定时触发：`cron: '0 0 * * *'` (UTC 00:00，即北京时间 08:00)
- 手动触发：`workflow_dispatch`
- 使用 `actions/setup-go` 设置 Go 环境
- 构建并执行二进制文件

## 错误处理

- 网络错误：重试 3 次，指数退避（2s, 4s, 8s）
- 429 状态码：等待 60s 后重试
- 403 状态码：标记 WAF_BLOCKED，发送通知
- 401 状态码：标记 AUTH_EXPIRED，通知更新 Cookie
- 响应结构异常：标记 API_CHANGED，发送通知

## 依赖

- `refraction-networking/utls` - TLS 指纹模拟
- `github.com/robertkrimen/otto` - Go JS 引擎
- `github.com/go-resty/resty/v2` - HTTP 客户端封装（可选，或直接用 net/http）
