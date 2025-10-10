import argparse
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from threading import Lock

import requests
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from pytz import timezone
from urllib.parse import urlparse

CHECKIN_URL = 'https://msec.nsfocus.com/backend_api/checkin/checkin'
POINTS_URL = 'https://msec.nsfocus.com/backend_api/point/common/get'
CAPTCHA_URL = 'https://msec.nsfocus.com/backend_api/account/captcha'
LOGIN_URL = 'https://msec.nsfocus.com/backend_api/account/login'

# 积分状态存储文件
POINTS_STATE_FILE = 'points_state.json'

# 登录节流锁，确保不同用户的登录间隔至少5秒
_LOGIN_THROTTLE_LOCK = Lock()
_last_login_timestamp: float = 0.0


def load_points_state() -> Dict[str, Dict[str, Any]]:
    """加载积分状态历史"""
    if os.path.exists(POINTS_STATE_FILE):
        try:
            with open(POINTS_STATE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def save_points_state(state: Dict[str, Dict[str, Any]]) -> None:
    """保存积分状态历史"""
    try:
        with open(POINTS_STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
    except IOError as e:
        print(f"保存积分状态失败: {e}")


def check_points_changed(username: str, current_points: int, total_points: int) -> bool:
    """检查积分是否发生变化"""
    state = load_points_state()
    user_state = state.get(username, {})
    
    last_current = user_state.get('current_points')
    last_total = user_state.get('total_points')
    
    # 如果积分发生变化，更新状态
    if last_current != current_points or last_total != total_points:
        state[username] = {
            'current_points': current_points,
            'total_points': total_points,
            'last_update': datetime.now().isoformat()
        }
        save_points_state(state)
        return True
    
    return False


def verify_captcha(token: str, captcha_image: str) -> Optional[str]:
    """使用云码识别验证码"""
    url = "http://api.jfbym.com/api/YmServer/customApi"
    data = {
        "token": token,
        "type": 10103,  # 验证码类型
        "image": captcha_image
    }
    headers = {
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(url, headers=headers, json=data, timeout=10).json()
        if response.get('code') == 10000:
            captcha_result = response['data']['data']
            if captcha_result and len(captcha_result) == 5:
                return captcha_result
        return None
    except Exception as e:
        print(f"验证码识别失败: {e}")
        return None


def get_captcha() -> Tuple[Optional[str], Optional[str]]:
    """获取验证码"""
    try:
        resp = requests.post(CAPTCHA_URL, headers=build_headers(""), json={}, timeout=10)
        data = resp.json().get('data')
        if data:
            captcha_id = data.get('id')
            captcha_img = data.get('captcha', '').split(',')[-1] if ',' in data.get('captcha', '') else data.get('captcha')
            return captcha_id, captcha_img
        return None, None
    except Exception as e:
        print(f"获取验证码失败: {e}")
        return None, None


def login_with_password(username: str, password: str, captcha_token: str) -> Optional[str]:
    """使用账号密码登录"""
    global _last_login_timestamp
    token_result: Optional[str] = None
    
    with _LOGIN_THROTTLE_LOCK:
        now = time.time()
        if _last_login_timestamp:
            wait_seconds = max(0.0, 5.0 - (now - _last_login_timestamp))
            if wait_seconds > 0:
                print(f"[{username}] 等待{wait_seconds:.1f}秒后再登录")
                time.sleep(wait_seconds)
        
        for attempt in range(1, 11):
            print(f"[{username}] 第{attempt}次登录尝试")
            time.sleep(2)
            
            # 获取验证码
            captcha_id, captcha_img = get_captcha()
            if not captcha_id or not captcha_img:
                print(f"[{username}] 获取验证码失败")
                continue
            
            # 识别验证码
            captcha_result = verify_captcha(captcha_token, captcha_img)
            if not captcha_result:
                print(f"[{username}] 验证码识别失败")
                continue
            
            print(f"[{username}] 验证码识别成功: {captcha_result}")
            
            # 尝试登录
            login_data = {
                "captcha_answer": captcha_result,
                "captcha_id": captcha_id,
                "password": password,
                "username": username
            }
            
            try:
                resp = requests.post(LOGIN_URL, headers=build_headers(""), json=login_data, timeout=10)
                auth_data = resp.json()
                
                if auth_data.get('status') == 200:
                    token_result = auth_data['data']['token']
                    print(f"[{username}] 登录成功")
                    break
                else:
                    print(f"[{username}] 登录失败: {auth_data.get('message', '未知错误')}")
                    continue
            except Exception as e:
                print(f"[{username}] 登录请求失败: {e}")
                continue
        
        _last_login_timestamp = time.time()
    
    if not token_result:
        print(f"[{username}] 登录失败，已尝试10次")
    return token_result


def login_users_sequentially(users: List[Dict[str, str]], captcha_token: Optional[str], config_file: str) -> None:
    """顺序登录所有需要登录的用户"""
    if not captcha_token:
        return
    
    users_need_login = []
    for user in users:
        # 需要登录的情况：没有Token但有密码，或者Token为空但有密码
        if user['password'] and (not user['Authorization'] or user['Authorization'].strip() == ''):
            users_need_login.append(user)
    
    if not users_need_login:
        print("所有用户都有有效的Token，无需登录")
        return
    
    print(f"\n=== 开始顺序登录 {len(users_need_login)} 个用户 ===")
    
    for i, user in enumerate(users_need_login):
        username = user['username']
        password = user['password']
        
        print(f"[{i+1}/{len(users_need_login)}] 开始登录用户: {username}")
        new_token = login_with_password(username, password, captcha_token)
        if new_token:
            # 更新配置文件中的token
            update_user_token(config_file, username, new_token)
            # 更新内存中的用户配置
            user['Authorization'] = new_token
            print(f"[{username}] 登录成功，Token已保存")
        else:
            print(f"[{username}] 登录失败")
    
    print(f"=== 用户登录完成 ===\n")


def load_config(filepath: str) -> Tuple[List[Dict[str, str]], Optional[str], Optional[str], Optional[str]]:
    """
    加载配置文件，支持多账户格式
    返回: (用户列表, 全局LARK_WEBHOOK, 全局FEISHU_WEBHOOK, 云码TOKEN)
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read().strip()
    
    try:
        obj = json.loads(content)
        users = []
        global_lark = None
        global_feishu = None
        captcha_token = None
        
        # 检查是否有全局webhook配置和云码token
        if 'LARK_WEBHOOK' in obj:
            global_lark = obj['LARK_WEBHOOK']
        if 'FEISHU_WEBHOOK' in obj:
            global_feishu = obj['FEISHU_WEBHOOK']
        if 'CAPTCHA_TOKEN' in obj:
            captcha_token = obj['CAPTCHA_TOKEN']
        
        # 处理用户配置
        for key, value in obj.items():
            if key.startswith('user') and isinstance(value, dict):
                user_config = {
                    'username': value.get('username', f'用户{len(users)+1}'),
                    'Authorization': value.get('Authorization') or value.get('authorization') or '',
                    'password': value.get('password', ''),
                    'LARK_WEBHOOK': value.get('LARK_WEBHOOK') or global_lark or '',
                    'FEISHU_WEBHOOK': value.get('FEISHU_WEBHOOK') or global_feishu or '',
                }
                users.append(user_config)
        
        return users, global_lark, global_feishu, captcha_token
        
    except json.JSONDecodeError:
        # 兼容旧格式
        cfg: Dict[str, str] = {'Authorization': '', 'FEISHU_WEBHOOK': '', 'LARK_WEBHOOK': ''}
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
        
        # 转换为新格式
        if cfg['Authorization']:
            users = [{
                'username': '默认用户',
                'Authorization': cfg['Authorization'],
                'password': '',
                'LARK_WEBHOOK': cfg['LARK_WEBHOOK'],
                'FEISHU_WEBHOOK': cfg['FEISHU_WEBHOOK'],
            }]
            return users, cfg['LARK_WEBHOOK'], cfg['FEISHU_WEBHOOK'], None
        
        return [], None, None, None


def update_user_token(filepath: str, username: str, new_token: str) -> None:
    """更新用户token到配置文件"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # 查找并更新对应用户的token
        for key, value in config.items():
            if key.startswith('user') and isinstance(value, dict) and value.get('username') == username:
                value['Authorization'] = new_token
                break
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
        
        print(f"[{username}] Token已更新到配置文件")
    except Exception as e:
        print(f"[{username}] 更新Token失败: {e}")


def get_user_authorization(user: Dict[str, str], captcha_token: Optional[str], config_file: str) -> str:
    """获取用户Authorization，优先使用保存的token，失败时尝试登录"""
    username = user['username']
    password = user['password']
    saved_token = user['Authorization']
    
    # 如果有保存的token，先尝试使用
    if saved_token:
        print(f"[{username}] 使用保存的Token进行签到")
        return saved_token
    
    # 如果没有保存的token，尝试使用账号密码登录
    if password and captcha_token:
        print(f"[{username}] 无保存的Token，尝试使用账号密码登录")
        new_token = login_with_password(username, password, captcha_token)
        if new_token:
            # 更新配置文件中的token
            update_user_token(config_file, username, new_token)
            return new_token
        else:
            print(f"[{username}] 登录失败，无法获取Token")
            return ""
    else:
        print(f"[{username}] 缺少密码或云码Token，无法登录")
        return ""


def refresh_user_authorization(user: Dict[str, str], captcha_token: Optional[str], config_file: str) -> str:
    """刷新用户Authorization，使用账号密码重新登录"""
    username = user['username']
    password = user['password']
    
    if password and captcha_token:
        print(f"[{username}] Token失效，尝试重新登录")
        new_token = login_with_password(username, password, captcha_token)
        if new_token:
            # 更新配置文件中的token
            update_user_token(config_file, username, new_token)
            return new_token
        else:
            print(f"[{username}] 重新登录失败")
            return ""
    else:
        print(f"[{username}] 缺少密码或云码Token，无法重新登录")
        return ""


def build_headers(authorization: str) -> Dict[str, str]:
    headers: Dict[str, str] = {
        'Accept': '*/*',
        'Content-Type': 'application/json',
        'Origin': 'https://msec.nsfocus.com',
        'Referer': 'https://msec.nsfocus.com/',
        'User-Agent': 'Mozilla/5.0',
    }
    if authorization:
        headers['Authorization'] = authorization
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


def sign_in(req_headers: Dict[str, str], username: str = "") -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    resp = perform_request('POST', CHECKIN_URL, req_headers, json_body={})
    j = try_json(resp)
    success = False
    msg = f"[{username}] Sign-in HTTP {resp.status_code}" if username else f"Sign-in HTTP {resp.status_code}"
    if j:
        status = j.get('status')
        message = j.get('message') or ''
        data = j.get('data')
        msg = f"[{username}] Sign-in status={status} message={message}" if username else f"Sign-in status={status} message={message}"
        success = (status == 200) or ('成功' in str(message))
    return success, msg, j


def confirm_signed(req_headers: Dict[str, str], username: str = "") -> Tuple[bool, str]:
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
                prefix = f"[{username}] " if username else ""
                return True, f"{prefix}已签到：{txt}"
            if status == 429:
                last_msg = f"[{username}] 确认响应 status=429 message={message or '请求过于频繁'}" if username else f"确认响应 status=429 message={message or '请求过于频繁'}"
            else:
                prefix = f"[{username}] " if username else ""
                return False, f"{prefix}确认响应 status={status} message={message}"
        else:
            if resp.status_code == 429:
                last_msg = f"[{username}] Confirm HTTP 429" if username else f"Confirm HTTP 429"
            else:
                prefix = f"[{username}] " if username else ""
                return False, f"{prefix}Confirm HTTP {resp.status_code}"
        if attempt >= len(delays):
            prefix = f"[{username}] " if username else ""
            return False, last_msg or f'{prefix}确认失败'
        time.sleep(delays[attempt])
        attempt += 1


def query_points(req_headers: Dict[str, str], username: str = "") -> Tuple[Optional[int], Optional[int], str]:
    resp = perform_request('POST', POINTS_URL, req_headers, json_body={})
    j = try_json(resp)
    if j and j.get('status') == 200 and isinstance(j.get('data'), dict):
        accrued = j['data'].get('accrued')
        total = j['data'].get('total')
        return accrued, total, 'OK'
    prefix = f"[{username}] " if username else ""
    return None, None, f"{prefix}Query failed: HTTP {resp.status_code} body={resp.text[:200]}"


def now_str(tz_name: str) -> str:
    tz = timezone(tz_name)
    return datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S %Z')


def do_user_sign_in(user: Dict[str, str], trigger: str, tz_name: str, captcha_token: Optional[str], config_file: str) -> Dict[str, Any]:
    """单个用户的签到流程"""
    username = user['username']
    lark_webhook = user.get('LARK_WEBHOOK', '')
    feishu_webhook = user.get('FEISHU_WEBHOOK', '')
    
    # 获取Authorization（优先使用保存的token）
    authorization = user['Authorization']
    if not authorization:
        error_msg = f"[{username}] 无有效的 Authorization"
        print(error_msg)
        return {
            'username': username,
            'success': False,
            'message': error_msg,
            'points': None,
            'total_points': None,
            'lark_webhook': lark_webhook,
            'feishu_webhook': feishu_webhook
        }
    
    req_headers = build_headers(authorization)
    relogin_attempted = False
    
    try:
        while True:
            ok, first_msg, first_json = sign_in(req_headers, username)
            
            # 检查Authorization是否失效
            if not ok and first_json and first_json.get('status') in [401, 403]:
                if relogin_attempted:
                    error_msg = f"[{username}] Authorization仍然失效，请检查账号"
                    print(error_msg)
                    return {
                        'username': username,
                        'success': False,
                        'message': error_msg,
                        'points': None,
                        'total_points': None,
                        'lark_webhook': lark_webhook,
                        'feishu_webhook': feishu_webhook
                    }
                
                if not captcha_token or not user.get('password'):
                    error_msg = f"[{username}] Authorization失效，但缺少账号密码或云码Token，无法自动重新登录"
                    print(error_msg)
                    return {
                        'username': username,
                        'success': False,
                        'message': error_msg,
                        'points': None,
                        'total_points': None,
                        'lark_webhook': lark_webhook,
                        'feishu_webhook': feishu_webhook
                    }
                
                print(f"[{username}] Authorization失效，尝试自动重新登录")
                new_token = refresh_user_authorization(user, captcha_token, config_file)
                if not new_token:
                    error_msg = f"[{username}] 自动重新登录失败，请检查账号或验证码服务"
                    print(error_msg)
                    return {
                        'username': username,
                        'success': False,
                        'message': error_msg,
                        'points': None,
                        'total_points': None,
                        'lark_webhook': lark_webhook,
                        'feishu_webhook': feishu_webhook
                    }
                
                user['Authorization'] = new_token
                req_headers = build_headers(new_token)
                relogin_attempted = True
                print(f"[{username}] 已重新登录并更新Authorization")
                time.sleep(1.0)
                continue
            break
        
        time.sleep(1.2)
        confirmed, confirm_msg = confirm_signed(req_headers, username)
        accrued, total, qmsg = query_points(req_headers, username)
        
        # 签到完成后强制推送积分状态
        if accrued is not None:
            check_points_changed(username, accrued, total)
        
        final_ok = bool(confirmed or ok)
        status_emoji = '✅' if final_ok else '❌'
        timestamp = now_str(tz_name)
        
        result_text = '签到成功' if final_ok else '签到失败'
        if accrued is not None:
            points_text = f"积分情况：当前积分{total}, 累计积分{accrued}"
        else:
            points_text = "积分情况：查询失败"
        
        message = "\n".join([
            f"用户：{username}",
            f"状态：{status_emoji} {result_text}",
            points_text,
            f"签到时间：{timestamp}",
        ])
        
        print(message)
        
        return {
            'username': username,
            'success': final_ok,
            'message': message,
            'points': accrued,
            'total_points': total,
            'lark_webhook': lark_webhook,
            'feishu_webhook': feishu_webhook
        }
        
    except requests.RequestException as e:
        err = f"[{username}] [{trigger}] 网络请求错误: {e} @ {now_str(tz_name)}"
        print(err)
        return {
            'username': username,
            'success': False,
            'message': err,
            'points': None,
            'total_points': None,
            'lark_webhook': lark_webhook,
            'feishu_webhook': feishu_webhook
        }
    except Exception as e:
        err = f"[{username}] [{trigger}] 程序错误: {e} @ {now_str(tz_name)}"
        print(err)
        return {
            'username': username,
            'success': False,
            'message': err,
            'points': None,
            'total_points': None,
            'lark_webhook': lark_webhook,
            'feishu_webhook': feishu_webhook
        }


def do_user_points_check(user: Dict[str, str], tz_name: str, captcha_token: Optional[str], config_file: str, force_push: bool = False) -> Dict[str, Any]:
    """单个用户的积分检查"""
    username = user['username']
    lark_webhook = user.get('LARK_WEBHOOK', '')
    feishu_webhook = user.get('FEISHU_WEBHOOK', '')
    
    # 获取Authorization（优先使用保存的token）
    authorization = user['Authorization']
    if not authorization:
        return {
            'username': username,
            'success': False,
            'message': f"[{username}] 无有效的 Authorization",
            'points': None,
            'total_points': None,
            'lark_webhook': lark_webhook,
            'feishu_webhook': feishu_webhook,
            'points_changed': False
        }
    
    req_headers = build_headers(authorization)
    relogin_attempted = False
    
    try:
        while True:
            accrued, total, qmsg = query_points(req_headers, username)
            
            # 检查Authorization是否失效（积分查询失败且返回401/403）
            if accrued is None and ('401' in qmsg or '403' in qmsg):
                if relogin_attempted:
                    warn = f"[{username}] [积分检查] Authorization仍然失效，请检查账号：{qmsg} @ {now_str(tz_name)}"
                    print(warn)
                    return {
                        'username': username,
                        'success': False,
                        'message': warn,
                        'points': None,
                        'total_points': None,
                        'lark_webhook': lark_webhook,
                        'feishu_webhook': feishu_webhook,
                        'points_changed': False
                    }
                
                if not captcha_token or not user.get('password'):
                    warn = f"[{username}] [积分检查] Authorization失效，但缺少账号密码或云码Token，无法自动重新登录：{qmsg} @ {now_str(tz_name)}"
                    print(warn)
                    return {
                        'username': username,
                        'success': False,
                        'message': warn,
                        'points': None,
                        'total_points': None,
                        'lark_webhook': lark_webhook,
                        'feishu_webhook': feishu_webhook,
                        'points_changed': False
                    }
                
                print(f"[{username}] [积分检查] Authorization失效，尝试自动重新登录")
                new_token = refresh_user_authorization(user, captcha_token, config_file)
                if not new_token:
                    warn = f"[{username}] [积分检查] 自动重新登录失败，请检查账号或验证码服务：{qmsg} @ {now_str(tz_name)}"
                    print(warn)
                    return {
                        'username': username,
                        'success': False,
                        'message': warn,
                        'points': None,
                        'total_points': None,
                        'lark_webhook': lark_webhook,
                        'feishu_webhook': feishu_webhook,
                        'points_changed': False
                    }
                
                user['Authorization'] = new_token
                req_headers = build_headers(new_token)
                relogin_attempted = True
                print(f"[{username}] [积分检查] 已重新登录并更新Authorization")
                time.sleep(1.0)
                continue
            break
        
        if accrued is None:
            warn = f"[{username}] [积分检查] 失败：{qmsg} @ {now_str(tz_name)}"
            print(warn)
            return {
                'username': username,
                'success': False,
                'message': warn,
                'points': None,
                'total_points': None,
                'lark_webhook': lark_webhook,
                'feishu_webhook': feishu_webhook,
                'points_changed': False
            }
        else:
            # 检查积分是否发生变化
            points_changed = check_points_changed(username, accrued, total)
            
            if points_changed or force_push:
                message = f"[{username}] [积分检查] 当前 {total}, 累计 {accrued} @ {now_str(tz_name)}"
                if points_changed:
                    message += " (积分已更新)"
                print(message)
                return {
                    'username': username,
                    'success': True,
                    'message': message,
                    'points': accrued,
                    'total_points': total,
                    'lark_webhook': lark_webhook,
                    'feishu_webhook': feishu_webhook,
                    'points_changed': points_changed
                }
            else:
                # 积分未变化，只记录日志，不推送
                print(f"[{username}] [积分检查] 积分无变化: 当前 {total}, 累计 {accrued} @ {now_str(tz_name)}")
                return {
                    'username': username,
                    'success': True,
                    'message': f"[{username}] [积分检查] 积分无变化: 当前 {total}, 累计 {accrued}",
                    'points': accrued,
                    'total_points': total,
                    'lark_webhook': lark_webhook,
                    'feishu_webhook': feishu_webhook,
                    'points_changed': False
                }
    except Exception as e:
        warn = f"[{username}] [积分检查] 异常：{e} @ {now_str(tz_name)}"
        print(warn)
        return {
            'username': username,
            'success': False,
            'message': warn,
            'points': None,
            'total_points': None,
            'lark_webhook': lark_webhook,
            'feishu_webhook': feishu_webhook,
            'points_changed': False
        }


def main() -> None:
    parser = argparse.ArgumentParser(description='Multi-user daily sign-in and points checker with Lark/Feishu notifications')
    parser.add_argument('--config-file', default=os.path.join(os.getcwd(), 'config.json'), help='Path to config.json (default: $PWD/config.json)')
    parser.add_argument('--lark', default='', help='Global Lark webhook token or full URL (overrides config)')
    parser.add_argument('--feishu', default='', help='Global Feishu webhook token or full URL (overrides config)')
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
        users, global_lark, global_feishu, captcha_token = load_config(args.config_file)
    else:
        users = []
        global_lark = None
        global_feishu = None
        captcha_token = None

    if not users:
        msg = '未找到有效的用户配置（请提供 config.json 或设置环境变量）'
        print(msg)
        sys.exit(1)

    # 处理全局webhook配置
    if not args.lark:
        args.lark = global_lark or ''
    if not args.feishu:
        args.feishu = global_feishu or ''
    if not args.lark:
        args.lark = os.environ.get('LARK_WEBHOOK', '')
    if not args.feishu:
        args.feishu = os.environ.get('FEISHU_WEBHOOK', '')
    args.lark = normalize_webhook(args.lark, LARK_BASE)
    args.feishu = normalize_webhook(args.feishu, FEISHU_BASE)

    # 启动时先进行顺序登录
    login_users_sequentially(users, captcha_token, args.config_file)

    def do_sign_in_flow(trigger: str) -> None:
        """多用户签到流程"""
        print(f"\n=== {trigger} 开始 ===")
        
        # 使用线程池并发处理所有用户
        with ThreadPoolExecutor(max_workers=min(len(users), 5)) as executor:
            # 提交所有签到任务
            future_to_user = {
                executor.submit(do_user_sign_in, user, trigger, args.tz, captcha_token, args.config_file): user 
                for user in users
            }
            
            # 收集结果
            results = []
            for future in as_completed(future_to_user):
                result = future.result()
                results.append(result)
        
        # 发送统一推送
        if args.lark or args.feishu:
            success_count = sum(1 for r in results if r['success'])
            total_count = len(results)
            
            summary_message = f"签到汇总：{success_count}/{total_count} 成功\n\n"
            
            for result in results:
                status_emoji = '✅' if result['success'] else '❌'
                result_text = '签到成功' if result['success'] else '签到失败'
                summary_message += f"{result['username']}：\n"
                summary_message += f"状态：{status_emoji} {result_text}\n"
                if result['points'] is not None:
                    summary_message += f"积分情况：当前积分{result['total_points']}, 累计积分{result['points']}\n"
                else:
                    summary_message += "积分情况：查询失败\n"
                summary_message += "\n"
            
            summary_message += f"完成时间：{now_str(args.tz)}"
            
            send_webhook(summary_message, args.lark, args.feishu)
        
        print(f"=== {trigger} 完成 ===\n")

    def do_points_check() -> None:
        """多用户积分检查（只在积分变更时推送）"""
        print(f"\n=== 积分检查 开始 ===")
        
        # 使用线程池并发处理所有用户
        with ThreadPoolExecutor(max_workers=min(len(users), 5)) as executor:
            # 提交所有积分检查任务
            future_to_user = {
                executor.submit(do_user_points_check, user, args.tz, captcha_token, args.config_file, False): user 
                for user in users
            }
            
            # 收集结果
            results = []
            changed_results = []
            for future in as_completed(future_to_user):
                result = future.result()
                results.append(result)
                
                # 只在积分变更时收集结果
                if result.get('points_changed', False):
                    changed_results.append(result)
        
        # 只在有积分变更时发送统一推送
        if changed_results and (args.lark or args.feishu):
            success_count = sum(1 for r in changed_results if r['success'])
            total_count = len(changed_results)
            
            summary_message = f"积分变更通知：{success_count}/{total_count} 用户积分已更新\n\n"
            
            for result in changed_results:
                status_emoji = '✅' if result['success'] else '❌'
                result_text = '更新成功' if result['success'] else '更新失败'
                summary_message += f"{result['username']}：\n"
                summary_message += f"状态：{status_emoji} {result_text}\n"
                if result['points'] is not None:
                    summary_message += f"积分情况：当前积分{result['total_points']}, 累计积分{result['points']}\n"
                else:
                    summary_message += "积分情况：查询失败\n"
                summary_message += "\n"
            
            summary_message += f"更新时间：{now_str(args.tz)}"
            
            send_webhook(summary_message, args.lark, args.feishu)
        
        if changed_results:
            print(f"=== 积分检查完成，{len(changed_results)} 个用户积分已更新 ===\n")
        else:
            print(f"=== 积分检查完成，无积分变更 ===\n")

    # 启动时执行一次签到
    do_sign_in_flow('启动签到')

    # 设置定时任务
    sched = BackgroundScheduler(timezone=timezone(args.tz))
    sched.add_job(lambda: do_sign_in_flow('定时签到'), CronTrigger(hour=8, minute=0))
    sched.add_job(do_points_check, IntervalTrigger(minutes=10))
    sched.start()

    print(f"多用户签到服务已启动，共 {len(users)} 个用户")
    print(f"时区: {args.tz}")
    print(f"定时签到: 每天 08:00")
    print(f"积分检查: 每 10 分钟（仅在积分变更时推送通知）")
    print(f"推送策略: 统一推送（每日签到完成后 + 积分变更时）")
    if captcha_token:
        print(f"登录方式: 账号密码 + 云码验证码识别")
    else:
        print(f"登录方式: Token认证")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
