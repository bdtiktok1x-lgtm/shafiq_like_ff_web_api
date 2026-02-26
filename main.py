from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import aiohttp
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
import threading
import urllib3
import random
import sqlite3
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
import os
import time
import hashlib
import secrets

# ---------- কনফিগারেশন ----------
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
DATABASE = 'auto_uids.db'
ADMIN_USERNAME = 'SHAFIQ'
ADMIN_PASSWORD = 'shafiq111xx'
TOKEN_GENERATOR_API = "https://mahir-jwt-generator.vercel.app/token"

TOKEN_FILES = {
    'BD': 'token_bd.json',
    'IND': 'token_ind.json',
    'BR': 'token_br.json',
    'US': 'token_us.json',
    'SAC': 'token_sac.json',
    'NA': 'token_na.json'
}

current_batch_indices = {}
batch_indices_lock = threading.Lock()

# ---------- টোকেন ক্যাশ ----------
token_cache = {}
token_cache_lock = threading.Lock()
TOKEN_EXPIRY_SECONDS = 600

# ---------- uid/pass লোডিং ----------
def load_uids(server_name):
    if server_name not in TOKEN_FILES:
        return []
    path = TOKEN_FILES[server_name]
    try:
        with open(path, 'r') as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_uids(server_name, uid_list):
    if server_name not in TOKEN_FILES:
        return False
    path = TOKEN_FILES[server_name]
    try:
        with open(path, 'w') as f:
            json.dump(uid_list, f, indent=2)
        return True
    except:
        return False

def add_uid(server_name, uid, password):
    uids = load_uids(server_name)
    uids = [u for u in uids if u.get('uid') != uid]
    uids.append({'uid': uid, 'pass': password})
    return save_uids(server_name, uids)

def remove_uid(server_name, uid):
    uids = load_uids(server_name)
    uids = [u for u in uids if u.get('uid') != uid]
    return save_uids(server_name, uids)

# ---------- টোকেন জেনারেটর ----------
async def fetch_token(session, uid, password):
    cache_key = (uid, password)
    with token_cache_lock:
        if cache_key in token_cache:
            token, expiry = token_cache[cache_key]
            if expiry > datetime.now():
                return token
            else:
                del token_cache[cache_key]

    url = f"{TOKEN_GENERATOR_API}?uid={uid}&password={password}"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 200:
                data = await resp.json()
                token = data.get('jwt_token') or data.get('jwttoken') or data.get('access_token') or data.get('token') or data.get('jwt')
                if token:
                    with token_cache_lock:
                        token_cache[cache_key] = (token, datetime.now() + timedelta(seconds=TOKEN_EXPIRY_SECONDS))
                    return token
                else:
                    print(f"Token not found for {uid}")
                    return None
            else:
                print(f"Token gen failed for {uid}: HTTP {resp.status}")
                return None
    except Exception as e:
        print(f"Token gen exception for {uid}: {e}")
        return None

async def fetch_all_tokens(session, uid_pass_list):
    tasks = [fetch_token(session, item['uid'], item['pass']) for item in uid_pass_list]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    tokens = []
    for i, res in enumerate(results):
        if isinstance(res, str) and res:
            tokens.append(res)
        else:
            print(f"Failed to get token for {uid_pass_list[i]['uid']}")
    return tokens

def run_fetch_tokens(uid_pass_list):
    async def _run():
        async with aiohttp.ClientSession() as session:
            return await fetch_all_tokens(session, uid_pass_list)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_run())
    finally:
        loop.close()

# ---------- এনক্রিপশন ও প্রোটোবাফ ----------
def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')

def create_protobuf_message(user_id, region):
    message = like_pb2.like()
    message.uid = int(user_id)
    message.region = region
    return message.SerializeToString()

def create_protobuf_for_profile_check(uid):
    message = uid_generator_pb2.uid_generator()
    message.krishna_ = int(uid)
    message.teamXdarks = 1
    return message.SerializeToString()

def enc_profile_check_payload(uid):
    protobuf_data = create_protobuf_for_profile_check(uid)
    return encrypt_message(protobuf_data)

# ---------- লাইক পাঠানো ----------
async def send_single_like_request(session, encrypted_like_payload, token, url):
    if not token:
        return 999
    edata = bytes.fromhex(encrypted_like_payload)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB52"
    }
    try:
        async with session.post(url, data=edata, headers=headers, timeout=10) as response:
            # রেসপন্স বডি পড়ুন ডিবাগিংয়ের জন্য
            response_text = await response.text()
            if response.status == 200:
                # সফলレスপন্সের জন্য লগ
                print(f"Like success: {response.status}")
                return response.status
            else:
                # ব্যর্থレスপন্সের জন্য লগ
                print(f"Like failed: {response.status}, Response: {response_text[:100]}")
                return response.status
    except asyncio.TimeoutError:
        print("Like request timeout")
        return 998
    except Exception as e:
        print(f"Send like exception: {e}")
        return 997

async def send_likes_with_token_list(session, uid, server_region, like_api_url, token_list):
    if not token_list:
        return 0
    like_payload = create_protobuf_message(uid, server_region)
    encrypted = encrypt_message(like_payload)
    tasks = [send_single_like_request(session, encrypted, token, like_api_url) for token in token_list]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    # শুধুমাত্র 200 স্ট্যাটাস কোড গণনা করা হবে
    successful = sum(1 for r in results if isinstance(r, int) and r == 200)
    print(f"Total likes sent: {successful} out of {len(token_list)}")
    return successful

def run_send_likes(uid, server_region, like_api_url, token_list):
    async def _run():
        async with aiohttp.ClientSession() as session:
            return await send_likes_with_token_list(session, uid, server_region, like_api_url, token_list)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_run())
    finally:
        loop.close()

# ---------- প্রোফাইল চেক ----------
async def make_profile_check_request_async(session, encrypted_payload, server_name, token):
    if not token:
        return None
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    edata = bytes.fromhex(encrypted_payload)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB52"
    }
    try:
        async with session.post(url, data=edata, headers=headers, timeout=10) as response:
            if response.status != 200:
                return None
            binary_data = await response.read()
            return decode_protobuf_profile_info(binary_data)
    except Exception as e:
        print(f"Profile check error: {e}")
        return None

def decode_protobuf_profile_info(binary_data):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary_data)
        return items
    except Exception as e:
        print(f"Protobuf decode error: {e}")
        return None

async def get_profile_info_async(session, uid, server_name, token):
    encrypted = enc_profile_check_payload(uid)
    info = await make_profile_check_request_async(session, encrypted, server_name, token)
    if info and hasattr(info, 'AccountInfo'):
        likes = int(info.AccountInfo.Likes)
        nickname = str(info.AccountInfo.PlayerNickname) if info.AccountInfo.PlayerNickname else "N/A"
        uid_from = int(info.AccountInfo.UID) if info.AccountInfo.UID else int(uid)
        return likes, nickname, uid_from
    return None, None, None

def run_profile_check(uid, server_name, token):
    async def _run():
        async with aiohttp.ClientSession() as session:
            return await get_profile_info_async(session, uid, server_name, token)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_run())
    finally:
        loop.close()

# ---------- ডাটাবেস ----------
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS auto_uids
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  uid TEXT NOT NULL,
                  server TEXT NOT NULL,
                  last_like_count INTEGER DEFAULT 0,
                  total_likes_given INTEGER DEFAULT 0,
                  last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    try:
        c.execute("SELECT blocked FROM auto_uids LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE auto_uids ADD COLUMN blocked INTEGER DEFAULT 0")
    
    try:
        c.execute("SELECT total_likes_given FROM auto_uids LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE auto_uids ADD COLUMN total_likes_given INTEGER DEFAULT 0")

    c.execute('''CREATE TABLE IF NOT EXISTS blocked_target_uids
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  uid TEXT NOT NULL UNIQUE,
                  reason TEXT DEFAULT 'Blocked by admin',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS like_history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  target_uid TEXT NOT NULL,
                  server TEXT NOT NULL,
                  likes_sent INTEGER DEFAULT 0,
                  before_likes INTEGER DEFAULT 0,
                  after_likes INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS api_stats
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  date DATE UNIQUE,
                  total_likes_sent INTEGER DEFAULT 0,
                  total_requests INTEGER DEFAULT 0)''')
    conn.commit()
    conn.close()

def add_auto_uid(uid, server):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("INSERT INTO auto_uids (uid, server) VALUES (?,?)", (uid, server))
    conn.commit()
    conn.close()

def get_all_auto_uids(include_blocked=True):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    if include_blocked:
        c.execute("SELECT id, uid, server, last_like_count, blocked, total_likes_given FROM auto_uids")
    else:
        c.execute("SELECT id, uid, server, last_like_count, blocked, total_likes_given FROM auto_uids WHERE blocked=0")
    rows = c.fetchall()
    conn.close()
    return rows

def update_last_like_count(uid, server, count, sent_count=0):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("UPDATE auto_uids SET last_like_count=?, total_likes_given = total_likes_given + ?, last_updated=CURRENT_TIMESTAMP WHERE uid=? AND server=?", 
              (count, sent_count, uid, server))
    conn.commit()
    conn.close()

def delete_auto_uid_by_id(id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("DELETE FROM auto_uids WHERE id=?", (id,))
    conn.commit()
    conn.close()

def toggle_block_auto_uid(id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("UPDATE auto_uids SET blocked = 1 - blocked WHERE id=?", (id,))
    conn.commit()
    conn.close()

def add_like_history(target_uid, server, likes_sent, before, after):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("INSERT INTO like_history (target_uid, server, likes_sent, before_likes, after_likes) VALUES (?,?,?,?,?)",
              (target_uid, server, likes_sent, before, after))
    conn.commit()
    conn.close()

def update_api_stats(likes_sent):
    today = datetime.now().date()
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("INSERT INTO api_stats (date, total_likes_sent, total_requests) VALUES (?, ?, 1) ON CONFLICT(date) DO UPDATE SET total_likes_sent = total_likes_sent + ?, total_requests = total_requests + 1",
              (today, likes_sent, likes_sent))
    conn.commit()
    conn.close()

def get_api_stats():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT SUM(total_likes_sent), SUM(total_requests) FROM api_stats")
    total_likes, total_reqs = c.fetchone()
    c.execute("SELECT total_likes_sent, total_requests FROM api_stats WHERE date = date('now')")
    today_likes, today_reqs = c.fetchone() or (0, 0)
    conn.close()
    return {
        'total_likes': total_likes or 0,
        'total_requests': total_reqs or 0,
        'today_likes': today_likes or 0,
        'today_requests': today_reqs or 0
    }

# ---------- ব্লক করা টার্গেট UID ফাংশন ----------
def is_target_uid_blocked(uid):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT id FROM blocked_target_uids WHERE uid=?", (uid,))
    row = c.fetchone()
    conn.close()
    return row is not None

def add_blocked_target_uid(uid, reason="Blocked by admin"):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO blocked_target_uids (uid, reason) VALUES (?,?)", (uid, reason))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    conn.close()
    return success

def remove_blocked_target_uid(uid):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("DELETE FROM blocked_target_uids WHERE uid=?", (uid,))
    deleted = c.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def get_all_blocked_target_uids():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT id, uid, reason, created_at FROM blocked_target_uids ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def get_like_history(limit=50):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT target_uid, server, likes_sent, before_likes, after_likes, created_at FROM like_history ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

# ---------- অটো লাইক জব ----------
def auto_like_job():
    print(f"[{datetime.now()}] অটো লাইক শুরু")
    auto_list = get_all_auto_uids(include_blocked=False)
    if not auto_list:
        print("কোনো সক্রিয় অটো UID নেই")
        return

    server_uids = {}
    for srv in TOKEN_FILES:
        server_uids[srv] = load_uids(srv)

    for row in auto_list:
        id, uid, server, last_count, blocked, total_given = row
        print(f"প্রসেস: {uid} ({server})")

        uid_pass_list = server_uids.get(server, [])
        if not uid_pass_list:
            print(f"{server} এর জন্য uid/pass নেই")
            continue

        tokens = run_fetch_tokens(uid_pass_list)
        if not tokens:
            print(f"টোকেন পাওয়া যায়নি {uid} এর জন্য")
            continue

        if server == "IND":
            like_api_url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server in {"BR", "US", "SAC", "NA"}:
            like_api_url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            like_api_url = "https://clientbp.ggblueshark.com/LikeProfile"

        success = run_send_likes(uid, server, like_api_url, tokens)

        if tokens:
            after_likes, nickname, _ = run_profile_check(uid, server, tokens[0])
            if after_likes is not None:
                update_last_like_count(uid, server, after_likes, success)
                add_like_history(uid, server, success, last_count, after_likes)
                update_api_stats(success)
                print(f"{uid}: লাইক এখন {after_likes}, পাঠানো হয়েছে {success}টি")
            else:
                print(f"{uid}: প্রোফাইল চেক ব্যর্থ")
    print(f"[{datetime.now()}] অটো লাইক শেষ")

# ---------- HTML টেমপ্লেটসমূহ ----------
INDEX_HTML = """<!DOCTYPE html>
<html lang="bn">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SHAFIQ FF LIKE • নিওন ভার্সন</title>
    <!-- Google Fonts & Font Awesome -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Syncopate:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        :root {
            --primary: #00fff9;
            --secondary: #ff00ff;
            --bg: #0a0a0f;
            --surface: #14141f;
            --text: #ffffff;
            --glow: 0 0 10px var(--primary), 0 0 20px var(--primary), 0 0 30px var(--primary);
            --glow-secondary: 0 0 10px var(--secondary), 0 0 20px var(--secondary);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            min-height: 100vh;
            background: var(--bg);
            font-family: 'Space Grotesk', sans-serif;
            color: var(--text);
            position: relative;
            overflow-x: hidden;
        }

        /* অ্যানিমেটেড ব্যাকগ্রাউন্ড */
        #canvas {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 0;
            pointer-events: none;
        }

        .grid-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: 
                linear-gradient(rgba(0, 255, 249, 0.05) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 255, 249, 0.05) 1px, transparent 1px);
            background-size: 50px 50px;
            pointer-events: none;
            z-index: 1;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            position: relative;
            z-index: 2;
        }

        /* হেডার */
        .header {
            text-align: center;
            margin-bottom: 3rem;
            position: relative;
        }

        .glitch-text {
            font-family: 'Syncopate', sans-serif;
            font-size: 3.5rem;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--primary);
            text-shadow: var(--glow);
            position: relative;
            animation: glitch 3s infinite;
            letter-spacing: 5px;
        }

        @keyframes glitch {
            0%, 100% { transform: skew(0deg, 0deg); opacity: 1; }
            95% { transform: skew(5deg, 2deg); opacity: 0.8; }
            96% { transform: skew(-5deg, -2deg); opacity: 0.9; }
            97% { transform: skew(3deg, 1deg); opacity: 0.85; }
        }

        .glitch-text::before,
        .glitch-text::after {
            content: attr(data-text);
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
        }

        .glitch-text::before {
            animation: glitch-top 3s infinite;
            color: var(--secondary);
            z-index: -1;
        }

        .glitch-text::after {
            animation: glitch-bottom 3s infinite;
            color: var(--primary);
            z-index: -2;
        }

        @keyframes glitch-top {
            0%, 100% { transform: translate(0); }
            95% { transform: translate(-2px, -2px); }
            96% { transform: translate(2px, 2px); }
            97% { transform: translate(-1px, -1px); }
        }

        @keyframes glitch-bottom {
            0%, 100% { transform: translate(0); }
            95% { transform: translate(2px, 2px); }
            96% { transform: translate(-2px, -2px); }
            97% { transform: translate(1px, 1px); }
        }

        .subtitle {
            font-size: 1.1rem;
            color: rgba(255, 255, 255, 0.6);
            margin-top: 0.5rem;
            letter-spacing: 2px;
        }

        /* স্ট্যাটস কার্ড */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 3rem;
        }

        .stat-card {
            background: rgba(20, 20, 31, 0.7);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(0, 255, 249, 0.3);
            border-radius: 20px;
            padding: 1.5rem;
            text-align: center;
            position: relative;
            overflow: hidden;
            transition: all 0.3s;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(0, 255, 249, 0.2), transparent);
            transition: left 0.5s;
        }

        .stat-card:hover::before {
            left: 100%;
        }

        .stat-card:hover {
            border-color: var(--primary);
            box-shadow: var(--glow);
            transform: translateY(-5px);
        }

        .stat-icon {
            font-size: 2rem;
            color: var(--primary);
            margin-bottom: 0.5rem;
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--primary);
            text-shadow: var(--glow);
        }

        .stat-label {
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: rgba(255, 255, 255, 0.7);
        }

        /* মেইন কার্ড */
        .main-card {
            background: rgba(20, 20, 31, 0.9);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(0, 255, 249, 0.3);
            border-radius: 30px;
            padding: 2.5rem;
            margin-bottom: 2rem;
            position: relative;
            overflow: hidden;
            animation: cardAppear 1s ease-out;
        }

        @keyframes cardAppear {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .main-card::after {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(0, 255, 249, 0.1) 0%, transparent 70%);
            animation: rotate 20s linear infinite;
            z-index: -1;
        }

        @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        .input-group {
            margin-bottom: 1.8rem;
            position: relative;
        }

        .input-label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: var(--primary);
            margin-bottom: 0.5rem;
        }

        .input-field {
            width: 100%;
            padding: 1.2rem 1.5rem;
            background: rgba(0, 0, 0, 0.3);
            border: 2px solid rgba(0, 255, 249, 0.3);
            border-radius: 15px;
            font-size: 1rem;
            color: var(--text);
            transition: all 0.3s;
            outline: none;
        }

        .input-field:focus {
            border-color: var(--primary);
            box-shadow: var(--glow);
            transform: scale(1.02);
        }

        .select-field {
            width: 100%;
            padding: 1.2rem 1.5rem;
            background: rgba(0, 0, 0, 0.3);
            border: 2px solid rgba(0, 255, 249, 0.3);
            border-radius: 15px;
            font-size: 1rem;
            color: var(--text);
            cursor: pointer;
            transition: all 0.3s;
            outline: none;
        }

        .select-field option {
            background: var(--surface);
        }

        /* বাটন */
        .neon-btn {
            width: 100%;
            padding: 1.2rem;
            background: transparent;
            border: 2px solid var(--primary);
            border-radius: 15px;
            font-size: 1.2rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 3px;
            color: var(--primary);
            cursor: pointer;
            position: relative;
            overflow: hidden;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 1rem;
        }

        .neon-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(0, 255, 249, 0.2), transparent);
            transition: left 0.5s;
        }

        .neon-btn:hover::before {
            left: 100%;
        }

        .neon-btn:hover {
            background: var(--primary);
            color: var(--bg);
            box-shadow: var(--glow);
            transform: translateY(-2px);
        }

        .neon-btn.loading {
            pointer-events: none;
            opacity: 0.8;
        }

        .neon-btn.loading i {
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* রেজাল্ট কার্ড */
        .result-card {
            background: rgba(20, 20, 31, 0.7);
            backdrop-filter: blur(10px);
            border: 1px solid var(--primary);
            border-radius: 20px;
            padding: 2rem;
            margin-top: 2rem;
            display: none;
            animation: slideUp 0.5s ease-out;
        }

        @keyframes slideUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .result-header {
            display: flex;
            align-items: center;
            gap: 1rem;
            font-size: 1.5rem;
            color: var(--primary);
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid rgba(0, 255, 249, 0.3);
        }

        .result-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
        }

        .result-item {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 12px;
            padding: 1rem;
            border-left: 3px solid var(--primary);
        }

        .result-label {
            font-size: 0.8rem;
            text-transform: uppercase;
            color: rgba(255, 255, 255, 0.5);
            margin-bottom: 0.3rem;
        }

        .result-value {
            font-size: 1.2rem;
            font-weight: 700;
            color: var(--primary);
            word-break: break-word;
        }

        .status-success {
            color: #00ff88;
            text-shadow: 0 0 10px #00ff88;
        }

        .status-failed {
            color: #ff3366;
            text-shadow: 0 0 10px #ff3366;
        }

        /* টাইমলাইন */
        .timeline-section {
            margin-top: 3rem;
        }

        .timeline-title {
            display: flex;
            align-items: center;
            gap: 1rem;
            font-size: 1.5rem;
            color: var(--primary);
            margin-bottom: 1.5rem;
        }

        .timeline-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
        }

        .timeline-card {
            background: rgba(20, 20, 31, 0.5);
            backdrop-filter: blur(5px);
            border: 1px solid rgba(0, 255, 249, 0.2);
            border-radius: 15px;
            padding: 1.2rem;
            transition: all 0.3s;
        }

        .timeline-card:hover {
            border-color: var(--primary);
            transform: translateX(5px);
        }

        .timeline-time {
            font-size: 0.8rem;
            color: rgba(255, 255, 255, 0.5);
        }

        .timeline-uid {
            font-size: 1rem;
            font-weight: 600;
            color: var(--primary);
            margin: 0.3rem 0;
        }

        .timeline-stats {
            display: flex;
            gap: 1rem;
            font-size: 0.9rem;
        }

        /* সোশ্যাল বাটন */
        .social-links {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 1rem;
            margin-top: 2rem;
        }

        .social-link {
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: rgba(20, 20, 31, 0.7);
            border: 1px solid var(--primary);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--primary);
            text-decoration: none;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }

        .social-link::before {
            content: '';
            position: absolute;
            width: 100%;
            height: 100%;
            background: var(--primary);
            border-radius: 50%;
            transform: scale(0);
            transition: transform 0.3s;
            z-index: -1;
        }

        .social-link:hover::before {
            transform: scale(1);
        }

        .social-link:hover {
            color: var(--bg);
            box-shadow: var(--glow);
            transform: translateY(-3px);
        }

        .social-link i {
            font-size: 1.3rem;
            z-index: 1;
        }

        /* ফুটার */
        .footer {
            margin-top: 3rem;
            text-align: center;
            padding: 1.5rem;
            border-top: 1px solid rgba(0, 255, 249, 0.2);
        }

        .footer a {
            color: var(--primary);
            text-decoration: none;
            margin: 0 1rem;
            transition: all 0.3s;
        }

        .footer a:hover {
            text-shadow: var(--glow);
        }

        /* প্রোগ্রেস বার */
        .progress-container {
            width: 100%;
            height: 4px;
            background: rgba(0, 255, 249, 0.1);
            border-radius: 2px;
            margin-top: 1rem;
            overflow: hidden;
            display: none;
        }

        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
            width: 0%;
            transition: width 0.3s;
            animation: progressGlow 2s infinite;
        }

        @keyframes progressGlow {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        /* রেসপনসিভ */
        @media (max-width: 768px) {
            .glitch-text { font-size: 2rem; }
            .container { padding: 1rem; }
            .main-card { padding: 1.5rem; }
        }
    </style>
</head>
<body>
    <canvas id="canvas"></canvas>
    <div class="grid-overlay"></div>
    
    <div class="container">
        <!-- হেডার -->
        <div class="header">
            <h1 class="glitch-text" data-text="SHAFIQ">SHAFIQ</h1>
            <div class="subtitle">
                <i class="fas fa-bolt" style="color: var(--primary);"></i>
                ফ্রি ফায়ার লাইক জেনারেটর
                <i class="fas fa-bolt" style="color: var(--secondary);"></i>
            </div>
        </div>

        <!-- স্ট্যাটস -->
        <div class="stats-grid" id="stats">
            <div class="stat-card">
                <i class="fas fa-heart stat-icon"></i>
                <div class="stat-value" id="totalLikes">0</div>
                <div class="stat-label">মোট লাইক</div>
            </div>
            <div class="stat-card">
                <i class="fas fa-chart-line stat-icon"></i>
                <div class="stat-value" id="todayLikes">0</div>
                <div class="stat-label">আজকের লাইক</div>
            </div>
            <div class="stat-card">
                <i class="fas fa-users stat-icon"></i>
                <div class="stat-value" id="totalRequests">0</div>
                <div class="stat-label">মোট রিকোয়েস্ট</div>
            </div>
            <div class="stat-card">
                <i class="fas fa-clock stat-icon"></i>
                <div class="stat-value" id="serverTime">--:--</div>
                <div class="stat-label">সার্ভার টাইম</div>
            </div>
        </div>

        <!-- মেইন কার্ড -->
        <div class="main-card">
            <form id="likeForm">
                <div class="input-group">
                    <div class="input-label">
                        <i class="fas fa-id-card"></i>
                        টার্গেট ইউআইডি
                    </div>
                    <input type="text" class="input-field" name="uid" 
                           placeholder="যেমন: 3020431227" required 
                           pattern="[0-9]+" title="শুধুমাত্র সংখ্যা">
                </div>

                <div class="input-group">
                    <div class="input-label">
                        <i class="fas fa-globe"></i>
                        সার্ভার
                    </div>
                    <select class="select-field" name="server_name" required>
                        <option value="BD">🇧🇩 বাংলাদেশ (BD)</option>
                        <option value="IND">🇮🇳 ইন্ডিয়া (IND)</option>
                        <option value="BR">🇧🇷 ব্রাজিল (BR)</option>
                        <option value="US">🇺🇸 ইউএসএ (US)</option>
                        <option value="SAC">🌍 স্যাক (SAC)</option>
                        <option value="NA">🌍 নর্থ আমেরিকা (NA)</option>
                    </select>
                </div>

                <button type="submit" class="neon-btn" id="likeBtn">
                    <i class="fas fa-rocket"></i>
                    লাইক পাঠান
                    <i class="fas fa-bolt"></i>
                </button>

                <div class="progress-container" id="progressContainer">
                    <div class="progress-bar" id="progressBar"></div>
                </div>
            </form>

            <!-- রেজাল্ট কার্ড -->
            <div class="result-card" id="result">
                <div class="result-header">
                    <i class="fas fa-crown"></i>
                    অপারেশন রিপোর্ট
                </div>
                <div class="result-grid">
                    <div class="result-item">
                        <div class="result-label">নিকনেম</div>
                        <div class="result-value" id="nickname">---</div>
                    </div>
                    <div class="result-item">
                        <div class="result-label">ইউআইডি</div>
                        <div class="result-value" id="uid">---</div>
                    </div>
                    <div class="result-item">
                        <div class="result-label">পূর্বের লাইক</div>
                        <div class="result-value" id="before">---</div>
                    </div>
                    <div class="result-item">
                        <div class="result-label">বর্তমান লাইক</div>
                        <div class="result-value" id="after">---</div>
                    </div>
                    <div class="result-item">
                        <div class="result-label">পাঠানো হয়েছে</div>
                        <div class="result-value" id="given">---</div>
                    </div>
                    <div class="result-item">
                        <div class="result-label">স্ট্যাটাস</div>
                        <div class="result-value" id="status">⏳ প্রসেসিং...</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- লেটেস্ট অ্যাক্টিভিটি -->
        <div class="timeline-section">
            <div class="timeline-title">
                <i class="fas fa-history"></i>
                লেটেস্ট অ্যাক্টিভিটি
            </div>
            <div class="timeline-grid" id="timeline">
                <!-- ডায়নামিকভাবে লোড হবে -->
            </div>
        </div>

        <!-- সোশ্যাল লিংকস -->
        <div class="social-links">
            <a href="https://youtube.com/------" target="_blank" class="social-link" title="YouTube">
                <i class="fab fa-youtube"></i>
            </a>
            <a href="https://tiktok.com/@emniii_999x" target="_blank" class="social-link" title="TikTok">
                <i class="fab fa-tiktok"></i>
            </a>
            <a href="https://t.me/Emnii_999target="_blank" class="social-link" title="Telegram">
                <i class="fab fa-telegram-plane"></i>
            </a>
            <a href="https://wa.me/8801234567890?text=Hello%20----+" target="_blank" class="social-link" title="WhatsApp">
                <i class="fab fa-whatsapp"></i>
            </a>
            <a href="https://facebook.com/____" target="_blank" class="social-link" title="Facebook">
                <i class="fab fa-facebook-f"></i>
            </a>
            <a href="https://instagram.com/emnii_999" target="_blank" class="social-link" title="Instagram">
                <i class="fab fa-instagram"></i>
            </a>
        </div>

        <!-- ফুটার -->
        <div class="footer">
            <a href="/admin/login">
                <i class="fas fa-lock"></i> অ্যাডমিন প্যানেল
            </a>
            <a href="#">
                <i class="fas fa-shield-alt"></i> টার্মস
            </a>
            <a href="#">
                <i class="fas fa-envelope"></i> সাপোর্ট
            </a>
            <p style="margin-top: 1rem; color: rgba(255,255,255,0.3);">
                © 2024 SHAFIQ FF LIKE | ভার্সন ২.০
            </p>
        </div>
    </div>

    <script>
        // ক্যানভাস অ্যানিমেশন
        const canvas = document.getElementById('canvas');
        const ctx = canvas.getContext('2d');
        
        function resizeCanvas() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        }
        resizeCanvas();
        window.addEventListener('resize', resizeCanvas);

        // পার্টিকেল সিস্টেম
        const particles = [];
        const particleCount = 100;

        for (let i = 0; i < particleCount; i++) {
            particles.push({
                x: Math.random() * canvas.width,
                y: Math.random() * canvas.height,
                size: Math.random() * 2 + 1,
                speedX: (Math.random() - 0.5) * 0.5,
                speedY: (Math.random() - 0.5) * 0.5,
                color: `rgba(0, 255, 249, ${Math.random() * 0.5})`
            });
        }

        function animate() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            particles.forEach(p => {
                p.x += p.speedX;
                p.y += p.speedY;
                
                if (p.x < 0 || p.x > canvas.width) p.speedX *= -1;
                if (p.y < 0 || p.y > canvas.height) p.speedY *= -1;
                
                ctx.beginPath();
                ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
                ctx.fillStyle = p.color;
                ctx.fill();
                
                // কানেকশন লাইন
                particles.forEach(p2 => {
                    const dx = p.x - p2.x;
                    const dy = p.y - p2.y;
                    const distance = Math.sqrt(dx * dx + dy * dy);
                    
                    if (distance < 100) {
                        ctx.beginPath();
                        ctx.strokeStyle = `rgba(0, 255, 249, ${0.1 * (1 - distance/100)})`;
                        ctx.lineWidth = 1;
                        ctx.moveTo(p.x, p.y);
                        ctx.lineTo(p2.x, p2.y);
                        ctx.stroke();
                    }
                });
            });
            
            requestAnimationFrame(animate);
        }
        animate();

        // স্ট্যাটস আপডেট
        async function updateStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                
                document.getElementById('totalLikes').textContent = data.total_likes.toLocaleString();
                document.getElementById('todayLikes').textContent = data.today_likes.toLocaleString();
                document.getElementById('totalRequests').textContent = data.total_requests.toLocaleString();
                
                const now = new Date();
                document.getElementById('serverTime').textContent = 
                    now.toLocaleTimeString('bn-BD', { hour: '2-digit', minute: '2-digit' });
            } catch (e) {
                console.error('Stats update failed:', e);
            }
        }

        // টাইমলাইন আপডেট
        async function updateTimeline() {
            try {
                const res = await fetch('/api/history');
                const data = await res.json();
                
                const timeline = document.getElementById('timeline');
                timeline.innerHTML = '';
                
                data.forEach(item => {
                    const card = document.createElement('div');
                    card.className = 'timeline-card';
                    card.innerHTML = `
                        <div class="timeline-time">${item.time}</div>
                        <div class="timeline-uid">${item.uid}</div>
                        <div class="timeline-stats">
                            <span><i class="fas fa-heart" style="color: #00fff9;"></i> +${item.sent}</span>
                            <span><i class="fas fa-globe" style="color: #ff00ff;"></i> ${item.server}</span>
                        </div>
                    `;
                    timeline.appendChild(card);
                });
            } catch (e) {
                console.error('Timeline update failed:', e);
            }
        }

        // ফর্ম সাবমিট
        document.getElementById('likeForm').onsubmit = async function(e) {
            e.preventDefault();
            
            const btn = document.getElementById('likeBtn');
            const progressContainer = document.getElementById('progressContainer');
            const progressBar = document.getElementById('progressBar');
            const result = document.getElementById('result');
            
            btn.classList.add('loading');
            btn.innerHTML = '<i class="fas fa-spinner"></i> প্রসেসিং...';
            progressContainer.style.display = 'block';
            result.style.display = 'none';
            
            const form = new FormData(this);
            const params = new URLSearchParams(form).toString();
            
            let progress = 0;
            const interval = setInterval(() => {
                progress = Math.min(progress + 5, 90);
                progressBar.style.width = progress + '%';
            }, 100);
            
            try {
                const res = await fetch('/like?' + params);
                const data = await res.json();
                
                clearInterval(interval);
                progressBar.style.width = '100%';
                
                setTimeout(() => {
                    progressContainer.style.display = 'none';
                    progressBar.style.width = '0%';
                }, 500);
                
                document.getElementById('nickname').textContent = data.Nickname || 'N/A';
                document.getElementById('uid').textContent = data.UID || 'N/A';
                document.getElementById('before').textContent = data.Before ?? 'N/A';
                document.getElementById('after').textContent = data.After ?? 'N/A';
                document.getElementById('given').textContent = data.Given ?? 'N/A';
                
                const statusEl = document.getElementById('status');
                if (data.Status == 1) {
                    statusEl.innerHTML = '<i class="fas fa-check-circle"></i> সফল';
                    statusEl.className = 'result-value status-success';
                } else if (data.Status == -1) {
                    statusEl.innerHTML = '<i class="fas fa-ban"></i> ব্লক করা হয়েছে';
                    statusEl.className = 'result-value status-failed';
                } else {
                    statusEl.innerHTML = '<i class="fas fa-times-circle"></i> ব্যর্থ';
                    statusEl.className = 'result-value status-failed';
                }
                
                result.style.display = 'block';
                updateStats();
                updateTimeline();
                
            } catch (error) {
                clearInterval(interval);
                progressContainer.style.display = 'none';
                alert('একটি ত্রুটি ঘটেছে। আবার চেষ্টা করুন।');
            } finally {
                btn.classList.remove('loading');
                btn.innerHTML = '<i class="fas fa-rocket"></i> লাইক পাঠান <i class="fas fa-bolt"></i>';
            }
        };

        // প্রতি ৩০ সেকেন্ডে স্ট্যাটস আপডেট
        updateStats();
        updateTimeline();
        setInterval(() => {
            updateStats();
            updateTimeline();
        }, 30000);
    </script>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="bn">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>𝐀𝐃𝐌𝐈𝐍 𝐋𝐎𝐆𝐈𝐍 | SHAFIQ</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        :root {
            --primary: #00fff9;
            --secondary: #ff00ff;
            --bg: #0a0a0f;
            --surface: #14141f;
            --text: #ffffff;
            --glow: 0 0 10px var(--primary), 0 0 20px var(--primary);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            min-height: 100vh;
            background: var(--bg);
            font-family: 'Space Grotesk', sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
        }
        
        .background {
            position: absolute;
            width: 100%;
            height: 100%;
            background: radial-gradient(circle at 50% 50%, rgba(0,255,249,0.1) 0%, transparent 50%);
            animation: pulse 4s ease-in-out infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 0.5; transform: scale(1); }
            50% { opacity: 1; transform: scale(1.2); }
        }
        
        .login-card {
            background: rgba(20, 20, 31, 0.9);
            backdrop-filter: blur(10px);
            border: 2px solid var(--primary);
            border-radius: 30px;
            padding: 3rem;
            width: 90%;
            max-width: 400px;
            position: relative;
            z-index: 10;
            box-shadow: var(--glow);
            animation: fadeIn 1s ease-out;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .login-card::before {
            content: '';
            position: absolute;
            top: -2px;
            left: -2px;
            right: -2px;
            bottom: -2px;
            background: linear-gradient(45deg, var(--primary), var(--secondary));
            border-radius: 32px;
            z-index: -1;
            opacity: 0.3;
            filter: blur(10px);
        }
        
        h1 {
            text-align: center;
            font-size: 2rem;
            color: var(--primary);
            margin-bottom: 0.5rem;
            text-shadow: var(--glow);
            letter-spacing: 3px;
        }
        
        .subtitle {
            text-align: center;
            color: rgba(255,255,255,0.6);
            margin-bottom: 2rem;
            font-size: 0.9rem;
        }
        
        .input-group {
            margin-bottom: 1.5rem;
        }
        
        .input-label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--primary);
            margin-bottom: 0.5rem;
            font-size: 0.9rem;
            letter-spacing: 1px;
        }
        
        .input-field {
            width: 100%;
            padding: 1rem 1.2rem;
            background: rgba(0,0,0,0.3);
            border: 2px solid rgba(0,255,249,0.3);
            border-radius: 15px;
            color: var(--text);
            font-size: 1rem;
            transition: all 0.3s;
            outline: none;
        }
        
        .input-field:focus {
            border-color: var(--primary);
            box-shadow: var(--glow);
        }
        
        .login-btn {
            width: 100%;
            padding: 1rem;
            background: transparent;
            border: 2px solid var(--primary);
            border-radius: 15px;
            color: var(--primary);
            font-size: 1.1rem;
            font-weight: 600;
            letter-spacing: 2px;
            cursor: pointer;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }
        
        .login-btn:hover {
            background: var(--primary);
            color: var(--bg);
            box-shadow: var(--glow);
            transform: translateY(-2px);
        }
        
        .footer {
            margin-top: 2rem;
            text-align: center;
            color: rgba(255,255,255,0.3);
            font-size: 0.8rem;
        }
        
        .footer a {
            color: var(--primary);
            text-decoration: none;
        }
        
        .error {
            background: rgba(255,0,0,0.2);
            border: 1px solid #ff3366;
            color: #ff3366;
            padding: 0.8rem;
            border-radius: 10px;
            margin-bottom: 1rem;
            text-align: center;
            display: none;
        }
    </style>
</head>
<body>
    <div class="background"></div>
    <div class="login-card">
        <h1>𝐀𝐃𝐌𝐈𝐍</h1>
        <div class="subtitle">
            <i class="fas fa-shield-alt" style="color: var(--primary);"></i>
            অথেনটিকেশন রিকোয়ার্ড
        </div>
        
        <div class="error" id="error">
            <i class="fas fa-exclamation-triangle"></i>
            ভুল ইউজারনেম বা পাসওয়ার্ড
        </div>
        
        <form method="POST" id="loginForm">
            <div class="input-group">
                <div class="input-label">
                    <i class="fas fa-user"></i>
                    ইউজারনেম
                </div>
                <input type="text" name="username" class="input-field" 
                       placeholder="এন্টার ইউজারনেম" required>
            </div>
            
            <div class="input-group">
                <div class="input-label">
                    <i class="fas fa-lock"></i>
                    পাসওয়ার্ড
                </div>
                <input type="password" name="password" class="input-field" 
                       placeholder="••••••••" required>
            </div>
            
            <button type="submit" class="login-btn">
                <i class="fas fa-sign-in-alt"></i>
                লগইন
            </button>
        </form>
        
        <div class="footer">
            <a href="/">
                <i class="fas fa-arrow-left"></i>
                হোম পেজে ফিরে যান
            </a>
        </div>
    </div>
    
    <script>
        // URL parameter থেকে error দেখানো
        if (window.location.search.includes('error')) {
            document.getElementById('error').style.display = 'block';
        }
    </script>
</body>
</html>
"""

ADMIN_HTML = """
<!DOCTYPE html>
<html lang="bn">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>𝐀𝐃𝐌𝐈𝐍 𝐏𝐀𝐍𝐄𝐋 | SHAFIQ</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        :root {
            --primary: #00fff9;
            --secondary: #ff00ff;
            --bg: #0a0a0f;
            --surface: #14141f;
            --text: #ffffff;
            --glow: 0 0 10px var(--primary);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            background: var(--bg);
            font-family: 'Space Grotesk', sans-serif;
            color: var(--text);
            padding: 2rem;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        /* হেডার */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding: 1rem;
            background: rgba(20,20,31,0.5);
            border: 1px solid var(--primary);
            border-radius: 15px;
            backdrop-filter: blur(10px);
        }
        
        .header h1 {
            color: var(--primary);
            text-shadow: var(--glow);
            letter-spacing: 2px;
        }
        
        .logout-btn {
            padding: 0.8rem 1.5rem;
            background: transparent;
            border: 2px solid #ff3366;
            border-radius: 10px;
            color: #ff3366;
            text-decoration: none;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .logout-btn:hover {
            background: #ff3366;
            color: var(--bg);
            box-shadow: 0 0 10px #ff3366;
        }
        
        /* স্ট্যাটস গ্রিড */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: rgba(20,20,31,0.5);
            border: 1px solid var(--primary);
            border-radius: 15px;
            padding: 1.5rem;
            backdrop-filter: blur(5px);
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--primary);
        }
        
        .stat-label {
            color: rgba(255,255,255,0.6);
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }
        
        /* ট্যাব */
        .tabs {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }
        
        .tab-btn {
            padding: 1rem 2rem;
            background: transparent;
            border: 2px solid var(--primary);
            border-radius: 10px;
            color: var(--primary);
            cursor: pointer;
            font-size: 1rem;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .tab-btn.active {
            background: var(--primary);
            color: var(--bg);
            box-shadow: var(--glow);
        }
        
        /* ট্যাব কন্টেন্ট */
        .tab-content {
            display: none;
            background: rgba(20,20,31,0.5);
            border: 1px solid var(--primary);
            border-radius: 20px;
            padding: 2rem;
            backdrop-filter: blur(10px);
        }
        
        .tab-content.active {
            display: block;
        }
        
        /* ফর্ম */
        .form-group {
            background: rgba(0,0,0,0.3);
            border-radius: 15px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .form-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .form-input {
            width: 100%;
            padding: 1rem;
            background: rgba(0,0,0,0.5);
            border: 1px solid rgba(0,255,249,0.3);
            border-radius: 10px;
            color: var(--text);
            font-size: 1rem;
        }
        
        .form-input:focus {
            border-color: var(--primary);
            outline: none;
        }
        
        .form-btn {
            padding: 1rem 2rem;
            background: transparent;
            border: 2px solid var(--primary);
            border-radius: 10px;
            color: var(--primary);
            cursor: pointer;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .form-btn:hover {
            background: var(--primary);
            color: var(--bg);
            box-shadow: var(--glow);
        }
        
        /* টেবিল */
        .table-container {
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            text-align: left;
            padding: 1rem;
            background: rgba(0,255,249,0.1);
            color: var(--primary);
            border-bottom: 2px solid var(--primary);
        }
        
        td {
            padding: 1rem;
            border-bottom: 1px solid rgba(0,255,249,0.2);
        }
        
        .badge {
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        
        .badge.active {
            background: rgba(0,255,0,0.2);
            color: #00ff00;
            border: 1px solid #00ff00;
        }
        
        .badge.blocked {
            background: rgba(255,0,0,0.2);
            color: #ff3366;
            border: 1px solid #ff3366;
        }
        
        .action-btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            margin: 0 0.2rem;
            text-decoration: none;
            display: inline-block;
            font-size: 0.9rem;
        }
        
        .btn-block {
            background: #ff3366;
            color: white;
        }
        
        .btn-unblock {
            background: #00ff00;
            color: black;
        }
        
        .btn-delete {
            background: #ff0000;
            color: white;
        }
        
        .btn-edit {
            background: var(--primary);
            color: black;
        }
        
        /* টাইমস্ট্যাম্প */
        .timestamp {
            color: rgba(255,255,255,0.4);
            font-size: 0.8rem;
            margin-top: 1rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- হেডার -->
        <div class="header">
            <h1>
                <i class="fas fa-crown" style="color: var(--primary);"></i>
                𝐀𝐃𝐌𝐈𝐍 𝐂𝐎𝐍𝐓𝐑𝐎𝐋 𝐏𝐀𝐍𝐄𝐋
            </h1>
            <div style="display: flex; gap: 1rem;">
                <span style="color: var(--primary);">
                    <i class="fas fa-clock"></i> {{ now }}
                </span>
                <a href="/admin/logout" class="logout-btn">
                    <i class="fas fa-sign-out-alt"></i> লগআউট
                </a>
            </div>
        </div>
        
        <!-- স্ট্যাটস -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{ stats.total_likes }}</div>
                <div class="stat-label">মোট লাইক</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.today_likes }}</div>
                <div class="stat-label">আজকের লাইক</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.total_requests }}</div>
                <div class="stat-label">মোট রিকোয়েস্ট</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.today_requests }}</div>
                <div class="stat-label">আজকের রিকোয়েস্ট</div>
            </div>
        </div>
        
        <!-- ট্যাব বাটন -->
        <div class="tabs">
            <button class="tab-btn active" onclick="openTab('auto')">
                <i class="fas fa-robot"></i> অটো লাইক
            </button>
            <button class="tab-btn" onclick="openTab('uidpass')">
                <i class="fas fa-key"></i> ইউআইডি/পাস
            </button>
            <button class="tab-btn" onclick="openTab('blocked')">
                <i class="fas fa-ban"></i> ব্লক করা টার্গেট
            </button>
        </div>
        
        <!-- অটো লাইক ট্যাব -->
        <div id="auto" class="tab-content active">
            <div class="form-group">
                <h3 style="color: var(--primary); margin-bottom: 1rem;">
                    <i class="fas fa-plus-circle"></i> নতুন অটো ইউআইডি যোগ করুন
                </h3>
                <form method="POST" action="/admin/add_auto">
                    <div class="form-row">
                        <input type="text" name="uid" class="form-input" 
                               placeholder="টার্গেট ইউআইডি" required>
                        <select name="server" class="form-input" required>
                            <option value="BD">বাংলাদেশ (BD)</option>
                            <option value="IND">ইন্ডিয়া (IND)</option>
                            <option value="BR">ব্রাজিল (BR)</option>
                            <option value="US">ইউএসএ (US)</option>
                            <option value="SAC">স্যাক (SAC)</option>
                            <option value="NA">নর্থ আমেরিকা (NA)</option>
                        </select>
                        <button type="submit" class="form-btn">
                            <i class="fas fa-save"></i> সংরক্ষণ
                        </button>
                    </div>
                </form>
            </div>
            
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>আইডি</th>
                            <th>ইউআইডি</th>
                            <th>সার্ভার</th>
                            <th>শেষ লাইক</th>
                            <th>মোট দেওয়া</th>
                            <th>স্ট্যাটাস</th>
                            <th>অ্যাকশন</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for item in auto_list %}
                        <tr>
                            <td>{{ item[0] }}</td>
                            <td>{{ item[1] }}</td>
                            <td>{{ item[2] }}</td>
                            <td>{{ item[3] }}</td>
                            <td>{{ item[5] }}</td>
                            <td>
                                {% if item[4] == 0 %}
                                <span class="badge active">সক্রিয়</span>
                                {% else %}
                                <span class="badge blocked">ব্লক করা</span>
                                {% endif %}
                            </td>
                            <td>
                                <a href="/admin/toggle_block/{{ item[0] }}" 
                                   class="action-btn {% if item[4] == 0 %}btn-block{% else %}btn-unblock{% endif %}">
                                    {% if item[4] == 0 %}
                                    <i class="fas fa-ban"></i> ব্লক
                                    {% else %}
                                    <i class="fas fa-check"></i> আনব্লক
                                    {% endif %}
                                </a>
                                <a href="/admin/delete_auto/{{ item[0] }}" 
                                   class="action-btn btn-delete"
                                   onclick="return confirm('নিশ্চিতভাবে মুছে ফেলতে চান?')">
                                    <i class="fas fa-trash"></i> ডিলিট
                                </a>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- ইউআইডি/পাস ট্যাব -->
        <div id="uidpass" class="tab-content">
            <div class="form-group">
                <h3 style="color: var(--primary); margin-bottom: 1rem;">
                    <i class="fas fa-plus-circle"></i> নতুন ইউআইডি/পাস যোগ করুন
                </h3>
                <form method="POST" action="/admin/add_uidpass">
                    <div class="form-row">
                        <input type="text" name="uid" class="form-input" 
                               placeholder="ইউআইডি" required>
                        <input type="text" name="password" class="form-input" 
                               placeholder="পাসওয়ার্ড" required>
                        <select name="server" class="form-input" required>
                            <option value="BD">বাংলাদেশ (BD)</option>
                            <option value="IND">ইন্ডিয়া (IND)</option>
                            <option value="BR">ব্রাজিল (BR)</option>
                            <option value="US">ইউএসএ (US)</option>
                            <option value="SAC">স্যাক (SAC)</option>
                            <option value="NA">নর্থ আমেরিকা (NA)</option>
                        </select>
                        <button type="submit" class="form-btn">
                            <i class="fas fa-save"></i> সংরক্ষণ
                        </button>
                    </div>
                </form>
            </div>
            
            {% for server, uids in uidpass_data.items() %}
            <div style="margin-bottom: 2rem;">
                <h4 style="color: var(--primary); margin-bottom: 1rem;">
                    <i class="fas fa-server"></i> {{ server }} সার্ভার ({{ uids|length }}টি একাউন্ট)
                </h4>
                
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>ইউআইডি</th>
                                <th>পাসওয়ার্ড</th>
                                <th>অ্যাকশন</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for item in uids %}
                            <tr>
                                <td>{{ item.uid }}</td>
                                <td>{{ item.pass }}</td>
                                <td>
                                    <a href="/admin/delete_uidpass/{{ server }}/{{ item.uid }}" 
                                       class="action-btn btn-delete"
                                       onclick="return confirm('নিশ্চিতভাবে মুছে ফেলতে চান?')">
                                        <i class="fas fa-trash"></i> ডিলিট
                                    </a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            {% endfor %}
        </div>
        
        <!-- ব্লক করা টার্গেট ট্যাব -->
        <div id="blocked" class="tab-content">
            <div class="form-group">
                <h3 style="color: var(--primary); margin-bottom: 1rem;">
                    <i class="fas fa-plus-circle"></i> নতুন ব্লক ইউআইডি যোগ করুন
                </h3>
                <form method="POST" action="/admin/add_blocked">
                    <div class="form-row">
                        <input type="text" name="uid" class="form-input" 
                               placeholder="টার্গেট ইউআইডি" required>
                        <input type="text" name="reason" class="form-input" 
                               placeholder="কারণ (ঐচ্ছিক)">
                        <button type="submit" class="form-btn">
                            <i class="fas fa-ban"></i> ব্লক করুন
                        </button>
                    </div>
                </form>
            </div>
            
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>আইডি</th>
                            <th>ইউআইডি</th>
                            <th>কারণ</th>
                            <th>তারিখ</th>
                            <th>অ্যাকশন</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for item in blocked_list %}
                        <tr>
                            <td>{{ item[0] }}</td>
                            <td>{{ item[1] }}</td>
                            <td>{{ item[2] }}</td>
                            <td>{{ item[3] }}</td>
                            <td>
                                <a href="/admin/remove_blocked/{{ item[1] }}" 
                                   class="action-btn btn-unblock"
                                   onclick="return confirm('আনব্লক করবেন?')">
                                    <i class="fas fa-check"></i> আনব্লক
                                </a>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="timestamp">
            <i class="fas fa-database"></i> সর্বশেষ আপডেট: {{ now }}
        </div>
    </div>
    
    <script>
        function openTab(tabName) {
            // সব ট্যাব কন্টেন্ট হাইড
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // সব ট্যাব বাটন ইনঅ্যাক্টিভ
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // সিলেক্টেড ট্যাব শো
            document.getElementById(tabName).classList.add('active');
            
            // সিলেক্টেড বাটন অ্যাক্টিভ
            event.target.classList.add('active');
        }
        
        // URL hash থেকে ট্যাব ওপেন করা
        if (window.location.hash) {
            const tab = window.location.hash.substring(1);
            if (document.getElementById(tab)) {
                openTab(tab);
            }
        }
    </script>
</body>
</html>
"""

# ---------- Flask অ্যাপ ----------
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'

init_db()
scheduler = BackgroundScheduler()
scheduler.add_job(func=auto_like_job, trigger="cron", hour=0, minute=0)
scheduler.add_job(func=auto_like_job, trigger="cron", hour=12, minute=0)  # দিনে দুইবার
scheduler.start()

# ---------- API রাউটসমূহ ----------
@app.route('/')
def index():
    return render_template_string(INDEX_HTML)

@app.route('/like', methods=['GET'])
def handle_like():
    uid = request.args.get("uid")
    server = request.args.get("server_name", "").upper()
    
    if not uid or not server:
        return jsonify({"error": "uid and server_name required"}), 400

    if is_target_uid_blocked(uid):
        return jsonify({
            "Nickname": "N/A",
            "UID": uid,
            "Before": "N/A",
            "After": "N/A",
            "Given": "N/A",
            "Status": -1,
            "Message": "এই UID ব্লক করা আছে"
        })

    uid_pass_list = load_uids(server)
    if not uid_pass_list:
        return jsonify({"error": f"{server} এর জন্য কোনো uid/pass নেই"}), 500

    tokens = run_fetch_tokens(uid_pass_list)
    if not tokens:
        return jsonify({"error": "কোনো টোকেন জেনারেট হয়নি"}), 500

    # প্রথমে প্রোফাইল চেক করে বর্তমান লাইক কাউন্ট নিন
    before_likes, nickname, uid_from = run_profile_check(uid, server, tokens[0])
    if before_likes is None:
        before_likes = 0
        nickname = "N/A"
        uid_from = uid
        before_success = False
    else:
        before_success = True

    # লাইক পাঠানোর URL সেট করুন
    if server == "IND":
        like_api_url = "https://client.ind.freefiremobile.com/LikeProfile"
    elif server in {"BR", "US", "SAC", "NA"}:
        like_api_url = "https://client.us.freefiremobile.com/LikeProfile"
    else:
        like_api_url = "https://clientbp.ggblueshark.com/LikeProfile"

    # লাইক পাঠান
    success_count = run_send_likes(uid, server, like_api_url, tokens)

    # লাইক পাঠানোর পর আবার প্রোফাইল চেক করুন
    after_likes, nickname_after, uid_after = run_profile_check(uid, server, tokens[0])
    if after_likes is None:
        after_likes = 0
        after_success = False
    else:
        after_success = True
        nickname = nickname_after
        uid_from = uid_after

    # প্রকৃত লাইক বৃদ্ধি গণনা করুন
    if before_success and after_success:
        actual_increment = after_likes - before_likes
        # API থেকে পাওয়া success_count এর সাথে মিলিয়ে দেখুন
        # শুধুমাত্র actual_increment পজিটিভ হলেই সফল হিসেবে গণ্য করুন
        if actual_increment > 0:
            status = 1
            given_likes = actual_increment  # প্রকৃত যে লাইক বেড়েছে সেটা দেখান
        else:
            status = 0
            given_likes = 0  # কোনো লাইক না বাড়লে 0 দেখান
    else:
        actual_increment = 0
        status = 0
        given_likes = 0

    # শুধুমাত্র সফল লাইক হলে হিস্টোরিতে সেভ করুন
    if actual_increment > 0:
        add_like_history(uid, server, actual_increment, before_likes, after_likes)
        update_api_stats(actual_increment)

    return jsonify({
        "Nickname": nickname,
        "UID": uid_from,
        "Before": before_likes,
        "After": after_likes,
        "Given": given_likes,  # প্রকৃত বৃদ্ধি দেখান
        "Status": status,
        "APISuccess": success_count,  # ডিবাগিংয়ের জন্য API সাকসেস কাউন্ট
        "Message": "লাইক সফল হয়েছে" if status == 1 else "লাইক ব্যর্থ হয়েছে বা কোন পরিবর্তন হয়নি"
    })

@app.route('/api/stats')
def get_stats():
    return jsonify(get_api_stats())

@app.route('/api/history')
def get_history():
    history = get_like_history(10)
    return jsonify([{
        'uid': h[0],
        'server': h[1],
        'sent': h[2],
        'before': h[3],
        'after': h[4],
        'time': datetime.strptime(h[5], '%Y-%m-%d %H:%M:%S').strftime('%H:%M')
    } for h in history])

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.form['username'] == ADMIN_USERNAME and request.form['password'] == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('admin_panel'))
        return redirect(url_for('admin_login') + '?error=1')
    return render_template_string(LOGIN_HTML)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('index'))

@app.route('/admin')
def admin_panel():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    auto_list = get_all_auto_uids(include_blocked=True)
    uidpass_data = {srv: load_uids(srv) for srv in TOKEN_FILES.keys()}
    blocked_list = get_all_blocked_target_uids()
    stats = get_api_stats()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string(ADMIN_HTML, auto_list=auto_list, uidpass_data=uidpass_data, 
                                 blocked_list=blocked_list, now=now, stats=stats)

@app.route('/admin/add_auto', methods=['POST'])
def admin_add_auto():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    add_auto_uid(request.form['uid'], request.form['server'].upper())
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_auto/<int:id>')
def admin_delete_auto(id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    delete_auto_uid_by_id(id)
    return redirect(url_for('admin_panel'))

@app.route('/admin/toggle_block/<int:id>')
def admin_toggle_block(id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    toggle_block_auto_uid(id)
    return redirect(url_for('admin_panel'))

@app.route('/admin/add_uidpass', methods=['POST'])
def admin_add_uidpass():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    uid = request.form['uid']
    password = request.form['password']
    server = request.form['server'].upper()
    add_uid(server, uid, password)
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_uidpass/<server>/<uid>')
def admin_delete_uidpass(server, uid):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    remove_uid(server, uid)
    return redirect(url_for('admin_panel'))

@app.route('/admin/add_blocked', methods=['POST'])
def admin_add_blocked():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    uid = request.form['uid']
    reason = request.form.get('reason', 'Blocked by admin')
    add_blocked_target_uid(uid, reason)
    return redirect(url_for('admin_panel'))

@app.route('/admin/remove_blocked/<uid>')
def admin_remove_blocked(uid):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    remove_blocked_target_uid(uid)
    return redirect(url_for('admin_panel'))

@app.route('/token_info')
def token_info():
    return jsonify({srv: len(load_uids(srv)) for srv in TOKEN_FILES.keys()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)