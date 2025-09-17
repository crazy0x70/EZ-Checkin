## 自动签到与积分查询服务
功能：
- 每日 08:00 定时签到；每 10 分钟积分查询；鉴权失效时推送提醒
- Docker 容器化部署
### 准备文件
- `config.json`（支持两种格式，二选一）：
- JSON 对象：
```json
{
"Authorization": "xxxx",
"Cookie": "xxx",
"LARK_WEBHOOK": "xxxxxxxx",
"FEISHU_WEBHOOK": "xxxxxxxx"
}
```
- 文本键值对：
```
Authorization=xxxx
Cookie=xxx
LARK_WEBHOOK=xxxxxxxx
FEISHU_WEBHOOK=xxxxxxxx
```
说明：LARK_WEBHOOK/FEISHU_WEBHOOK 可填写纯 token 或完整 URL，程序会自动规范化为：
- Lark: `https://open.larksuite.com/open-apis/bot/v2/hook/`+token
- 飞书: `https://open.feishu.cn/open-apis/bot/v2/hook/`+token
### 本地运行
```bash
pip3 install -r requirements.txt
python3 main.py --config-file ./config.json

# 如需覆盖机器人 token：
python main.py --config-file ./config.json lark=xxxxxxxx feishu=xxxxxxxx
```
环境变量：可指定 `TZ`（时区）。
### 配置说明
- 默认从 `$PWD/config.json` 读取；可用 `--config-file /path/to/config.json` 指定。
- 命令行传入的 `lark=`、`feishu=` 优先级高于 `config.json`，环境变量仅用于时区。
### Docker 运行
```bash
docker run -d \
-v $(pwd)/config.json:/app/config.json \
-e TZ=Asia/Shanghai \
--name ez-checkin crazy0x70/ez-checkin:latest
```
也可按需求以参数形式覆盖 token（容器会覆盖默认 CMD 参数）：
```bash
docker run -d \
-v $(pwd)/config.json:/app/config.json \
-e TZ=Asia/Shanghai \
--name ez-checkin crazy0x70/ez-checkin:latest \
python main.py lark=xxxxxxxx \
feishu=xxxxxxxx
```
容器启动后会立即执行一次签到并推送结果，后续按计划任务执行。
