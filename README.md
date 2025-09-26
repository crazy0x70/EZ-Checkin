## M-SEC自动签到

支持多账户同时签到，支持统一推送和分账号推送的自动签到。

## 功能特性

- ✅ 支持多账户并发签到
- ✅ 支持统一推送和分账号推送
- ✅ 定时签到（每天8:00）
- ✅ 飞书/Lark通知支持

## 配置格式

### 分账户推送配置

每个用户都有独立的webhook配置：

```json
{
  "user1": {
    "username": "账号1",
    "Authorization": "your_jwt_token_here",
    "LARK_WEBHOOK": "your_lark_webhook_token"
  },
  "user2": {
    "username": "账号2", 
    "Authorization": "your_jwt_token_here",
    "LARK_WEBHOOK": "your_lark_webhook_token"
  },
  "user3": {
    "username": "账号3",
    "Authorization": "your_jwt_token_here", 
    "LARK_WEBHOOK": "your_lark_webhook_token"
  }
}
```

### 统一推送配置

所有用户共享一个webhook配置：

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

### 分账号推送
- 每个用户的签到结果会发送到其独立的webhook
- 适用于需要单独监控每个账户的场景

### 统一推送
- 所有用户的签到结果汇总后发送到一个webhook
- 适用于统一管理多个账户的场景

## 注意事项

1. 建议使用Docker运行以确保稳定性。
