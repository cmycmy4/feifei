# -*- coding: utf-8 -*-
import hashlib
import json
import os
import requests
from http.server import BaseHTTPRequestHandler

def calculate_md5(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def get_tenant_access_token():
    url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal/"
    payload = {
        "app_id": os.environ.get("APP_ID"),
        "app_secret": os.environ.get("APP_SECRET")
    }
    r = requests.post(url, json=payload)
    return r.json().get("tenant_access_token")

def send_reply_message(chat_id, text, token):
    url = "https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=chat_id"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "receive_id": chat_id,
        "msg_type": "text",
        "content": json.dumps({"text": text})
    }
    requests.post(url, headers=headers, json=payload)

def handle_event(body):
    # 飞书验证
    if body.get("type") == "url_verification":
        return {"challenge": body.get("challenge")}
    
    # 处理消息
    if body.get("type") == "event_callback" and body["header"]["event_type"] == "im.message.receive_v1":
        msg_event = body["event"]
        content_obj = json.loads(msg_event["message"].get("content", "{}"))
        raw_text = content_obj.get("text", "").strip()
        chat_id = msg_event["message"]["chat_id"]
        
        # 清理 @ 机器人部分（飞书格式：@_user_xxx 你的内容）
        if raw_text.startswith("@_user_"):
            parts = raw_text.split(" ", 1)
            text_to_hash = parts[1] if len(parts) > 1 else ""
        else:
            text_to_hash = raw_text
        
        if text_to_hash:
            md5_val = calculate_md5(text_to_hash)
            reply_text = f"「{text_to_hash}」的 MD5 是：\n`{md5_val}`"
            
            token = get_tenant_access_token()
            if token:
                send_reply_message(chat_id, reply_text, token)
    
    return {"code": 0, "msg": "success"}

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        body = json.loads(post_data.decode('utf-8'))
        
        result = handle_event(body)
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(result).encode('utf-8'))
