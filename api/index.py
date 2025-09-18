import hashlib
import json
import os
import requests
from http.server import BaseHTTPRequestHandler
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import hmac

# 从环境变量读取（推荐）或直接写死（测试用）
VERIFICATION_TOKEN = os.environ.get("VERIFICATION_TOKEN", "A1Vg1UMuWcKm6WETiPCPCccZvjdreSCx")
ENCRYPT_KEY = os.environ.get("ENCRYPT_KEY", "boottestkey")

def decrypt_feishu_event(encrypt_key: str, encrypted_data: str) -> dict:
    if not encrypt_key or not encrypted_data:
        return {}
    try:
        encrypted_bytes = base64.b64decode(encrypted_data)
        cipher = AES.new(encrypt_key.encode('utf-8'), AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted_bytes)
        unpadded = unpad(decrypted, AES.block_size)
        plain_text = unpadded.decode('utf-8')
        return json.loads(plain_text)
    except Exception as e:
        print("❌ 解密失败:", str(e))
        return {}

def calculate_md5(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def get_tenant_access_token():
    url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal/"
    payload = {
        "app_id": os.environ.get("APP_ID"),
        "app_secret": os.environ.get("APP_SECRET")
    }
    try:
        r = requests.post(url, json=payload, timeout=5)
        return r.json().get("tenant_access_token")
    except Exception as e:
        print("❌ 获取 token 失败:", str(e))
        return None

def send_reply_message(chat_id, text, token):
    url = "https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=chat_id"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "receive_id": chat_id,
        "msg_type": "text",
        "content": json.dumps({"text": text})
    }
    try:
        requests.post(url, headers=headers, json=payload, timeout=5)
    except Exception as e:
        print("❌ 发送消息失败:", str(e))

def handle_event(body, headers):
    # Step 1: 校验 Verification Token
    token_in_header = headers.get("X-Lark-Token", "")
    if token_in_header != VERIFICATION_TOKEN:
        print("❌ Verification Token 校验失败")
        return {"code": 403, "msg": "invalid token"}

    # Step 2: 处理 URL 验证（飞书配置时的 challenge）
    if body.get("type") == "url_verification":
        return {"challenge": body.get("challenge")}

    # Step 3: 解密事件（如果是加密事件）
    if "encrypt" in body:
        print("🔐 收到加密事件，正在解密...")
        original_event = decrypt_feishu_event(ENCRYPT_KEY, body["encrypt"])
        if not original_event:
            return {"code": 400, "msg": "decrypt failed"}
        body = original_event  # 替换为解密后的原始事件

    # Step 4: 处理消息事件
    if body.get("type") == "event_callback" and body["header"]["event_type"] == "im.message.receive_v1":
        try:
            msg_event = body["event"]
            content_obj = json.loads(msg_event["message"].get("content", "{}"))
            raw_text = content_obj.get("text", "").strip()
            chat_id = msg_event["message"]["chat_id"]

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

        except Exception as e:
            print("❌ 处理消息出错:", str(e))

    return {"code": 0, "msg": "success"}

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"code": 0, "msg": "ok"}).encode('utf-8'))

    def do_POST(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            body = json.loads(post_data.decode('utf-8'))

            # 传入 headers 用于校验 token
            headers = {k: v for k, v in self.headers.items()}

            result = handle_event(body, headers)

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
        except Exception as e:
            print("❌ 服务器内部错误:", str(e))
            self.send_response(500)
            self.end_headers()
