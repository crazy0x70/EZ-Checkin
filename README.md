## M-SEC自动签到

支持多账户同时签到，支持统一推送和分账号推送的自动签到。

## 功能特性

- ✅ 支持多账户并发签到
- ✅ 支持飞书/Lark通知统一推送
- ✅ 定时签到（每天8:00）
- ✅ 飞书/Lark通知支持
- ✅ 支持账号密码登录 + [云码验证码识别](https://console.jfbym.com/register/TG120148)
- ✅ 自动Token管理和更新

## 配置格式

### 账号密码登录配置（推荐）

使用账号密码登录，支持[云码验证码识别](https://console.jfbym.com/register/TG120148)：

```json
{
  "user1": {
    "username": "账号1用户名",
    "password": "账号1密码",
    "Authorization": "留空即可"
  },
  "user2": {
    "username": "账号2用户名",
    "password": "账号2密码",
    "Authorization": ""
  },
  "user3": {
    "username": "账号3用户名",
    "password": "账号3密码",
    "Authorization": ""
  },
  "CAPTCHA_TOKEN": "云码token",
  "LARK_WEBHOOK": "your_global_lark_webhook_token"
}
```

### Token认证配置

使用已有的Authorization Token：

```json
{
  "user1": {
    "username": "账号1",
    "Authorization": "your_jwt_token_here"
  },
  "user2": {
    "username": "账号2",
    "Authorization": "your_jwt_token_here"
  },
  "user3": {
    "username": "账号3", 
    "Authorization": "your_jwt_token_here"
  },
  "LARK_WEBHOOK": "your_global_lark_webhook_token"
}
```

## 使用方法

### 本地运行

1. 配置 `config.json` 文件，按照上述格式添加你的账户信息
2. 运行脚本：

```bash
python main.py
```
#### 命令行参数

- `--config-file`: 指定配置文件路径（默认：./config.json）
- `--lark`: 全局Lark webhook token或完整URL
- `--feishu`: 全局Feishu webhook token或完整URL  
- `--tz`: 时区设置（默认：Asia/Shanghai）

### Docker 运行

```bash
docker run -d \
-v $(pwd)/config.json:/app/config.json \
-e TZ=Asia/Shanghai \
--name ez-checkin crazy0x70/ez-checkin:latest
```

#### docker-compose.yml

```yml
version: "3"

services:
  ez-checkin:
    image: crazy0x70/ez-checkin:latest
    container_name: ez-checkin
    environment:
      - TZ=Asia/Shanghai
    volumes:
      - ./config.json:/app/config.json
    restart: unless-stopped
```

## 推送机制

### 推送时机
- **每日签到完成后**：汇总所有用户的签到结果和积分状态

### 统一推送
- 所有用户的签到结果汇总后发送到一个webhook
- 适用于统一管理多个账户的场景

### 通知格式
- 紧凑排版，包含时间、成功统计和积分概览
- 仅在每日签到完成后推送一次，减少干扰

### 登录方式
- **账号密码登录**：配置用户名、密码和云码Token，自动识别验证码登录
- **Token认证**：使用已有的Authorization Token直接登录
- **智能Token管理**：
  - 登录成功后自动保存Token到配置文件
  - 优先使用保存的Token进行操作
  - 只有在Token失效时才重新登录
  - 自动检测Token失效并刷新，无需手动干预
- **顺序登录机制**：
  - 启动时顺序登录所有需要登录的用户
  - 每个用户登录间隔5秒以上，避免并发登录冲突
  - 防止验证码获取失败，提高登录成功率

## 注意事项

1. Authorization token需要定期更新
2. 建议使用Docker运行以确保稳定性
