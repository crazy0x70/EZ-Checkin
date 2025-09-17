import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

import requests
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from pytz import timezone
from urllib.parse import urlparse

CHECKIN_URL = 'https://msec.nsfocus.com/backend_api/checkin/checkin'
POINTS_URL = 'https://msec.nsfocus.com/backend_api/point/common/get'


def load_cookie(filepath: str) -> Dict[str, str]:
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read().strip()
        try:
            data = json.loads(content)
            auth = data.get('Authorization') or data.get('authorization') or ''
            cookie = data.get('Cookie') or data.get('cookie') or ''
            return {"Authorization": auth, "Cookie": cookie}
        except json.JSONDecodeError:
            headers: Dict[str, str] = {}
            for line in content.splitlines():
                if not line.strip():
                    continue
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()
            return {"Authorization": headers.get('Authorization', ''), "Cookie": headers.get('Cookie', '')}


def load_config(filepath: str) -> Dict[str, str]:
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read().strip()
    try:
        obj = json.loads(content)
        return {
            'Authorization': obj.get('Authorization') or obj.get('authorization') or '',
            'Cookie': obj.get('Cookie') or obj.get('cookie') or '',
            'FEISHU_WEBHOOK': obj.get('FEISHU_WEBHOOK') or obj.get('feishu') or obj.get('feishu_token') or '',
            'LARK_WEBHOOK': obj.get('LARK_WEBHOOK') or obj.get('lark') or obj.get('lark_token') or '',
        }
    except json.JSONDecodeError:
        cfg: Dict[str, str] = {'Authorization': '', 'Cookie': '', 'FEISHU_WEBHOOK': '', 'LARK_WEBHOOK': ''}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                k, v = line.split('=', 1)
                key = k.strip()
                val = v.strip()
                if key in cfg:
                    cfg[key] = val
        return cfg


def build_headers(authorization: str, cookie: str) -> Dict[str, str]:
    headers: Dict[str, str] = {
        'Accept': '*/*',
        'Content-Type': 'application/json',
        'Origin': 'https://msec.nsfocus.com',
        'Referer': 'https://msec.nsfocus.com/',
        'User-Agent': 'Mozilla/5.0',
    }
    if authorization:
        headers['Authorization'] = authorization
    if cookie:
        headers['Cookie'] = cookie
    return headers

DEFAULT_QD = """POST /backend_api/checkin/checkin HTTP/1.1
Host: msec.nsfocus.com
Content-Type: application/json

{}
"""

DEFAULT_CX = """POST /backend_api/point/common/get HTTP/1.1
Host: msec.nsfocus.com
Content-Type: application/json

{}
"""

def load_cookie(filepath: str) -> Dict[str, str]:
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read().strip()
        try:
            data = json.loads(content)
            auth = data.get('Authorization') or data.get('authorization') or ''
            cookie = data.get('Cookie') or data.get('cookie') or ''
            return {"Authorization": auth, "Cookie": cookie}
        except json.JSONDecodeError:
            headers: Dict[str, str] = {}
            for line in content.splitlines():
                if not line.strip():
                    continue
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()
            return {"Authorization": headers.get('Authorization', ''), "Cookie": headers.get('Cookie', '')}


def parse_request_file(filepath: str) -> Tuple[str, str, Dict[str, str], Optional[str]]:
    with open(filepath, 'r', encoding='utf-8') as f:
        text = f.read().strip()
    if not text:
        raise ValueError(f"Empty request file: {filepath}")

    try:
        obj = json.loads(text)
        method = (obj.get('method') or 'GET').upper()
        url = obj['url']
        headers = obj.get('headers') or {}
        body = obj.get('body')
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        return method, url, headers, body
    except Exception:
        pass

    if text.lower().startswith('curl '):
        method = 'GET'
        headers: Dict[str, str] = {}
        body: Optional[str] = None
        url_match = re.search(r"(https?://[^\s'\"]+)", text)
        if url_match:
            url = url_match.group(1)
        else:
            raise ValueError('curl missing URL')
        m = re.search(r"-X\s+([A-Z]+)", text)
        if m:
            method = m.group(1).upper()
        for hk, hv in re.findall(r"-H\s+'([^:]+):\s*([^']*)'", text):
            headers[hk.strip()] = hv.strip()
        for hk, hv in re.findall(r' -H\s+"([^:]+):\s*([^"]*)"', text):
            headers[hk.strip()] = hv.strip()
        d = re.search(r"-d\s+'([^']*)'", text, re.S)
        if not d:
            d = re.search(r'-d\s+"([^"]*)"', text, re.S)
        if d:
            body = d.group(1)
        return method, url, headers, body

    lines = text.splitlines()
    first = lines[0].strip()
    m = re.match(r"([A-Z]+)\s+(https?://\S+)", first)
    if m:
        method = m.group(1).upper()
        url = m.group(2)
        headers: Dict[str, str] = {}
        body_lines: list[str] = []
        in_body = False
        for line in lines[1:]:
            if not in_body and not line.strip():
                in_body = True
                continue
            if not in_body:
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()
            else:
                body_lines.append(line)
        body = '\n'.join(body_lines) if body_lines else None
        return method, url, headers, body

    m2 = re.match(r"([A-Z]+)\s+(/\S+)(?:\s+HTTP/\d\.\d)?", first)
    if m2:
        method = m2.group(1).upper()
        path_only = m2.group(2)
        headers: Dict[str, str] = {}
        body_lines: list[str] = []
        in_body = False
        for line in lines[1:]:
            if not in_body and not line.strip():
                in_body = True
                continue
            if not in_body:
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()
            else:
                body_lines.append(line)
        host = headers.get('Host') or headers.get('host')
        scheme = 'https'
        if not host:
            raise ValueError('Raw HTTP request missing Host header')
        url = f"{scheme}://{host}{path_only}"
        body = '\n'.join(body_lines) if body_lines else None
        return method, url, headers, body

    if first.startswith('http://') or first.startswith('https://'):
        return 'GET', first, {}, None

    raise ValueError(f"Unrecognized request file format: {filepath}")


def parse_request_text(text: str) -> Tuple[str, str, Dict[str, str], Optional[str]]:
    tmp = "/tmp/_req.txt"
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(text)
    return parse_request_file(tmp)


def load_request(path: str, fallback_text: str) -> Tuple[str, str, Dict[str, str], Optional[str]]:
    if path and os.path.exists(path):
        return parse_request_file(path)
    return parse_request_text(fallback_text)


def merge_headers(base: Dict[str, str], auth_headers: Dict[str, str]) -> Dict[str, str]:
    merged = {k.strip(): v.strip() for k, v in base.items()}
    if auth_headers.get('Authorization'):
        merged['Authorization'] = auth_headers['Authorization']
    if auth_headers.get('Cookie'):
        merged['Cookie'] = auth_headers['Cookie']
    for hk in list(merged.keys()):
        lk = hk.lower()
        if lk in ('host', 'content-length'):
            merged.pop(hk, None)
    return merged


def send_webhook(text: str, lark_webhook: Optional[str], feishu_webhook: Optional[str]) -> None:
    payload = {"msg_type": "text", "content": {"text": text[:19000]}}
    headers = {"Content-Type": "application/json"}
    for name, url in [("lark", lark_webhook), ("feishu", feishu_webhook)]:
        if not url:
            continue
        try:
            resp = requests.post(url, headers=headers, data=json.dumps(payload, ensure_ascii=False, separators=(",", ":")), timeout=10)
            if resp.status_code >= 300:
                print(f"Webhook {name} failed: HTTP {resp.status_code} body={resp.text[:200]}")
        except Exception as e:
            print(f"Webhook {name} exception: {e}")


def perform_request(method: str, url: str, headers: Dict[str, str], json_body: Optional[Dict[str, Any]] = None) -> requests.Response:
    method = method.upper()
    resp = requests.request(method, url, headers=headers, json=json_body, timeout=30)
    return resp


def try_json(resp: requests.Response) -> Optional[Dict[str, Any]]:
    try:
        return resp.json()
    except Exception:
        return None


def sign_in(req_headers: Dict[str, str]) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    resp = perform_request('POST', CHECKIN_URL, req_headers, json_body={})
    j = try_json(resp)
    success = False
    msg = f"Sign-in HTTP {resp.status_code}"
    if j:
        status = j.get('status')
        message = j.get('message') or ''
        data = j.get('data')
        msg = f"Sign-in status={status} message={message}"
        success = (status == 200) or ('成功' in str(message))
    return success, msg, j


def confirm_signed(req_headers: Dict[str, str]) -> Tuple[bool, str]:
    delays = [1.5, 3.0, 5.0]
    attempt = 0
    last_msg = ''
    while True:
        resp = perform_request('POST', CHECKIN_URL, req_headers, json_body={})
        j = try_json(resp)
        if j:
            status = j.get('status')
            message = j.get('message') or ''
            data = j.get('data')
            if status == 400 and ('已经签到' in str(data) or '已经签到' in message):
                txt = str(data or message)
                return True, f"已签到：{txt}"
            if status == 429:
                last_msg = f"确认响应 status=429 message={message or '请求过于频繁'}"
            else:
                return False, f"确认响应 status={status} message={message}"
        else:
            if resp.status_code == 429:
                last_msg = f"Confirm HTTP 429"
            else:
                return False, f"Confirm HTTP {resp.status_code}"
        if attempt >= len(delays):
            return False, last_msg or '确认失败'
        time.sleep(delays[attempt])
        attempt += 1


def query_points(req_headers: Dict[str, str]) -> Tuple[Optional[int], Optional[int], str]:
    resp = perform_request('POST', POINTS_URL, req_headers, json_body={})
    j = try_json(resp)
    if j and j.get('status') == 200 and isinstance(j.get('data'), dict):
        accrued = j['data'].get('accrued')
        total = j['data'].get('total')
        return accrued, total, 'OK'
    return None, None, f"Query failed: HTTP {resp.status_code} body={resp.text[:200]}"


def now_str(tz_name: str) -> str:
    tz = timezone(tz_name)
    return datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S %Z')


def main() -> None:
    parser = argparse.ArgumentParser(description='Daily sign-in and points checker with Lark/Feishu notifications')
    parser.add_argument('--config-file', default=os.path.join(os.getcwd(), 'config.json'), help='Path to config.json (default: $PWD/config.json)')
    parser.add_argument('--lark', default='', help='Lark webhook token or full URL (overrides config)')
    parser.add_argument('--feishu', default='', help='Feishu webhook token or full URL (overrides config)')
    parser.add_argument('--tz', default=os.environ.get('TZ', 'Asia/Shanghai'), help='Timezone, default Asia/Shanghai')
    args, unknown = parser.parse_known_args()

    for u in unknown:
        if u.startswith('lark=') and not args.lark:
            args.lark = u.split('=', 1)[1]
        if u.startswith('feishu=') and not args.feishu:
            args.feishu = u.split('=', 1)[1]

    def normalize_webhook(value: str, base: str) -> str:
        if not value:
            return ''
        s = (value or '').strip().strip('"').strip("'")
        if s.startswith('http://') or s.startswith('https://'):
            u = urlparse(s)
            if u.scheme in ('http', 'https') and u.netloc and '.' not in u.netloc and (u.path == '' or u.path == '/'):
                token = u.netloc
                return base + token
            return s
        token = s.lstrip('/').lstrip('\\')
        if re.fullmatch(r'[A-Za-z0-9\-]{8,}', token):
            return base + token
        if '/open-apis/bot/v2/hook/' in token:
            idx = token.rfind('/open-apis/bot/v2/hook/')
            maybe = token[idx + len('/open-apis/bot/v2/hook/') :]
            if maybe:
                return base + maybe
        return base + token

    LARK_BASE = 'https://open.larksuite.com/open-apis/bot/v2/hook/'
    FEISHU_BASE = 'https://open.feishu.cn/open-apis/bot/v2/hook/'

    if os.path.exists(args.config_file):
        cfg = load_config(args.config_file)
    else:
        cfg = {
            'Authorization': os.environ.get('Authorization') or os.environ.get('AUTHORIZATION') or '',
            'Cookie': os.environ.get('Cookie') or os.environ.get('COOKIE') or '',
            'LARK_WEBHOOK': os.environ.get('LARK_WEBHOOK') or '',
            'FEISHU_WEBHOOK': os.environ.get('FEISHU_WEBHOOK') or '',
        }
    authorization = cfg.get('Authorization', '')
    cookie_value = cfg.get('Cookie', '')
    if not args.lark:
        args.lark = cfg.get('LARK_WEBHOOK', '')
    if not args.feishu:
        args.feishu = cfg.get('FEISHU_WEBHOOK', '')
    if not args.lark:
        args.lark = os.environ.get('LARK_WEBHOOK', '')
    if not args.feishu:
        args.feishu = os.environ.get('FEISHU_WEBHOOK', '')
    args.lark = normalize_webhook(args.lark, LARK_BASE)
    args.feishu = normalize_webhook(args.feishu, FEISHU_BASE)
    if not authorization or not cookie_value:
        msg = '未找到有效的 Authorization/Cookie（请提供 config.json 或设置环境变量）'
        print(msg)
        send_webhook(f"[签到服务] 启动失败：{msg}", args.lark, args.feishu)
        sys.exit(1)

    req_headers = build_headers(authorization, cookie_value)

    def do_sign_in_flow(trigger: str) -> None:
        nonlocal req_headers
        try:
            ok, first_msg, first_json = sign_in(req_headers)
            time.sleep(1.2)
            confirmed, confirm_msg = confirm_signed(req_headers)
            accrued, total, qmsg = query_points(req_headers)

            final_ok = bool(confirmed or ok)
            status_emoji = '✅' if final_ok else '❌'
            timestamp = now_str(args.tz)

            result_text = '签到成功' if final_ok else '签到失败'
            if accrued is not None:
                points_text = f"积分情况：当前积分{accrued}, 累计积分{total}"
            else:
                points_text = "积分情况：查询失败"
            note = "\n".join([
                f"状态：{status_emoji} {result_text}",
                points_text,
                f"签到时间：{timestamp}",
            ])

            print(note)
            send_webhook(note, args.lark, args.feishu)
        except requests.RequestException as e:
            err = f"[{trigger}] 网络请求错误: {e} @ {now_str(args.tz)}"
            print(err)
            send_webhook(err, args.lark, args.feishu)
        except Exception as e:
            err = f"[{trigger}] 程序错误: {e} @ {now_str(args.tz)}"
            print(err)
            send_webhook(err, args.lark, args.feishu)

    def do_points_check() -> None:
        nonlocal req_headers
        try:
            accrued, total, qmsg = query_points(req_headers)
            if accrued is None:
                warn = f"[积分检查] 失败，可能 Authorization/Cookie 失效：{qmsg} @ {now_str(args.tz)}"
                print(warn)
                send_webhook(warn, args.lark, args.feishu)
            else:
                print(f"[积分检查] 当前 {accrued}, 累计 {total} @ {now_str(args.tz)}")
        except Exception as e:
            warn = f"[积分检查] 异常：{e} @ {now_str(args.tz)}"
            print(warn)
            send_webhook(warn, args.lark, args.feishu)

    do_sign_in_flow('启动签到')

    sched = BackgroundScheduler(timezone=timezone(args.tz))
    sched.add_job(lambda: do_sign_in_flow('定时签到'), CronTrigger(hour=8, minute=0))
    sched.add_job(do_points_check, IntervalTrigger(minutes=10))
    sched.start()

    print(f"Scheduler started. TZ={args.tz}")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()


