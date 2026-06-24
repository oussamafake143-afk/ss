from fastapi import FastAPI, HTTPException, Query, Request, Response, Depends
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import secrets
import json
import os
import hashlib
import hmac
import time
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    print("⚠️ Warning: PyJWT not installed. iOS App authentication will be disabled.")
    print("   Install with: pip install PyJWT")
from collections import defaultdict
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters
from contextlib import asynccontextmanager
from asyncio import Lock
import plistlib
import uuid
import re

# Load environment variables from .env file
try:
    with open('.env', 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip()
except FileNotFoundError:
    pass

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "8603609457:AAFqcgG_lixj4bAJ0KqXHqWODBbwkpDpa18")
ADMIN_CHAT_IDS = [i.strip() for i in os.getenv("ADMIN_CHAT_IDS", "7446601898,7162158003").split(",")]
DB_FILE = "keys.json"
db_lock = Lock()

# --- Rate Limiting (Modified for better UX) ---
RATE_LIMIT_WINDOW = 60
MAX_REQUESTS_PER_WINDOW = 60  # Increased from 30
MAX_FAILED_ATTEMPTS = 15      # Increased from 5 to avoid quick 429
LOCKOUT_DURATION = 60         # Reduced from 300 to 60 seconds

rate_limit_store = defaultdict(list)
failed_attempts_store = defaultdict(list)
locked_out_ips = {}


def check_rate_limit(client_ip: str) -> bool:
    now = time.time()
    if client_ip in locked_out_ips:
        if now < locked_out_ips[client_ip]:
            return False
        del locked_out_ips[client_ip]

    timestamps = rate_limit_store[client_ip]
    rate_limit_store[client_ip] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    if len(rate_limit_store[client_ip]) >= MAX_REQUESTS_PER_WINDOW:
        return False
    rate_limit_store[client_ip].append(now)
    return True


def record_failed_attempt(client_ip: str):
    now = time.time()
    failed_attempts_store[client_ip] = [
        t for t in failed_attempts_store[client_ip] if now - t < RATE_LIMIT_WINDOW
    ]
    failed_attempts_store[client_ip].append(now)
    if len(failed_attempts_store[client_ip]) >= MAX_FAILED_ATTEMPTS:
        locked_out_ips[client_ip] = now + LOCKOUT_DURATION
        failed_attempts_store[client_ip] = []


# --- Input Validation ---
API_KEY_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{1,200}$')
DEVICE_ID_PATTERN = re.compile(r'^[a-zA-Z0-9\-]{1,128}$')

# Package-Key binding storage
PACKAGE_KEY_TOKENS = {}  # {package_name: unique_token}


def validate_api_key_format(key: str) -> bool:
    return bool(API_KEY_PATTERN.match(key))


def validate_device_id_format(device_id: str) -> bool:
    return bool(DEVICE_ID_PATTERN.match(device_id))


def generate_package_token(pkg_name: str) -> str:
    """Generate unique token for package"""
    return hashlib.sha256(f"{pkg_name}:{secrets.token_hex(32)}".encode()).hexdigest()


def validate_key_package_binding(api_key: str, package_identifier: str) -> bool:
    """Validate that the key belongs to the correct package"""
    if api_key not in API_KEYS or api_key in ["packages", "global_banned_devices"]:
        return False
    
    key_data = API_KEYS[api_key]
    expected_package = key_data.get("package")
    
    if not expected_package:
        return False
    
    # Check if package identifier matches
    pkg_data = API_KEYS.get("packages", {}).get(expected_package, {})
    pkg_token = pkg_data.get("token")
    
    return package_identifier == pkg_token


# --- Database ---
def load_keys():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                if "packages" not in data:
                    data["packages"] = {}
                if "global_banned_devices" not in data:
                    data["global_banned_devices"] = []
                if "resellers" not in data:
                    data["resellers"] = {}
                # Fix corrupted reseller entries (list instead of dict)
                for rid in list(data.get("resellers", {}).keys()):
                    if not isinstance(data["resellers"][rid], dict):
                        data["resellers"][rid] = {
                            "quota": 0, "used_quota": 0,
                            "max_devices": 1, "max_keys": 0,
                            "permissions": ["all"], "activity_log": []
                        }
                for key, val in data.items():
                    if key not in ["packages", "global_banned_devices", "resellers"] and isinstance(val, dict):
                        val.setdefault("banned_devices", [])
                        # Fix missing role field — causes KeyError in /validate
                        val.setdefault("role", "user")
                return data
            except Exception:
                return {"packages": {}, "resellers": {}, "global_banned_devices": []}

    default = {
        "packages": {},
        "resellers": {},
        "global_banned_devices": [],
        "skam_admin_key": {
            "role": "admin",
            "duration": None,
            "delta_seconds": None,
            "activation_time": None,
            "expiry": "2099-12-31 23:59:59",
            "bound_devices": [],
            "max_users": 999,
            "package": None,
            "banned_devices": []
        }
    }
    save_keys(default)
    return default


def save_keys(data):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


async def save_keys_safe(data):
    async with db_lock:
        save_keys(data)


API_KEYS = load_keys()


def parse_duration(duration_str: str):
    if not duration_str:
        return None
    unit = duration_str[-1].lower()
    try:
        value = int(duration_str[:-1])
        if value <= 0:
            return None
        if unit == 'm': return timedelta(minutes=value)
        if unit == 'h': return timedelta(hours=value)
        if unit == 'd': return timedelta(hours=value * 24)
        if unit == 'w': return timedelta(hours=value * 24 * 7)
    except (ValueError, IndexError):
        pass
    return None


# --- Default Security Config ---
DEFAULT_SECURITY_CONFIG = {
    "anti_inject": True
}

# Global dylib crash kill-switch (affects ALL packages/users)
GLOBAL_DYLIB_CRASH = {"enabled": False}


def get_package_security(pkg_name: str) -> dict:
    pkg_data = API_KEYS.get("packages", {}).get(pkg_name, {})
    sec = pkg_data.get("security", dict(DEFAULT_SECURITY_CONFIG))
    if "anti_inject" not in sec:
        sec["anti_inject"] = True
    # If anti_inject is disabled, dylib_crash is forced ON so injected dylibs still crash.
    # Global kill-switch can also force dylib_crash ON regardless.
    if not sec.get("anti_inject", True):
        sec["dylib_crash"] = True
    else:
        sec["dylib_crash"] = GLOBAL_DYLIB_CRASH["enabled"]
    return sec


# --- Telegram Bot Handlers ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    is_admin = chat_id in ADMIN_CHAT_IDS
    is_reseller = "resellers" in API_KEYS and chat_id in API_KEYS["resellers"]

    if not is_admin and not is_reseller:
        return

    if is_admin:
        keyboard = [
            [InlineKeyboardButton("📦 Create New Package", callback_data="create_package")],
            [InlineKeyboardButton("🔑 Create New Key", callback_data="create_key")],
            [InlineKeyboardButton("👤 Manage Resellers", callback_data="manage_resellers")],
            [InlineKeyboardButton("🗑️ Delete Package", callback_data="delete_package")],
            [InlineKeyboardButton("📊 Show Status + Manage Devices", callback_data="status")],
            [InlineKeyboardButton("🔒 Block Inject", callback_data="sec_enableinject"),
             InlineKeyboardButton("🔓 Allow Inject", callback_data="sec_disableinject")],
            [InlineKeyboardButton("💥 Crash Dylib (Global)", callback_data="sec_crashdylib"),
             InlineKeyboardButton("✅ Stop Crash (Global)", callback_data="sec_uncrashdylib")],
        ]
        text = "**Welcome to the Admin Panel**\nChoose an option:"
    else:
        keyboard = [
            [InlineKeyboardButton("🔑 Create New Key", callback_data="create_key")],
            [InlineKeyboardButton("📊 Show Status", callback_data="reseller_status")],
        ]
        text = f"**Welcome To OSM API**\nChoose an option:"

    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(text, reply_markup=reply_markup, parse_mode='Markdown')


async def show_packages_for_manage(query, context, edit=True):
    if not API_KEYS.get("packages"):
        text = "No packages exist yet."
        if edit:
            await query.edit_message_text(text)
        return
    keyboard = []
    for pkg_name in sorted(API_KEYS["packages"].keys()):
        keyboard.append([InlineKeyboardButton(pkg_name, callback_data=f"status_pkg_{pkg_name}")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    text = "**Select a package to view its keys:**"
    if edit:
        await query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')
    else:
        await query.message.reply_text(text, reply_markup=reply_markup, parse_mode='Markdown')



async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    chat_id = str(query.from_user.id)
    is_admin = chat_id in ADMIN_CHAT_IDS
    is_reseller = "resellers" in API_KEYS and chat_id in API_KEYS["resellers"]
    
    if not is_admin and not is_reseller:
        await query.edit_message_text("You are not authorized.")
        return

    data = query.data

    if data == "start_menu":
        # Rebuild main menu directly without calling start()
        if is_admin:
            keyboard = [
                [InlineKeyboardButton("📦 Create New Package", callback_data="create_package")],
                [InlineKeyboardButton("🔑 Create New Key", callback_data="create_key")],
                [InlineKeyboardButton("👤 Manage Resellers", callback_data="manage_resellers")],
                [InlineKeyboardButton("🗑️ Delete Package", callback_data="delete_package")],
                [InlineKeyboardButton("📊 Show Status + Manage Devices", callback_data="status")],
                [InlineKeyboardButton("🔒 Block Inject", callback_data="sec_enableinject"),
                 InlineKeyboardButton("🔓 Allow Inject", callback_data="sec_disableinject")],
                [InlineKeyboardButton("💥 Crash Dylib (Global)", callback_data="sec_crashdylib"),
                 InlineKeyboardButton("✅ Stop Crash (Global)", callback_data="sec_uncrashdylib")],
            ]
            menu_text = "**Welcome to the Admin Panel**\nChoose an option:"
        else:
            keyboard = [
                [InlineKeyboardButton("🔑 Create New Key", callback_data="create_key")],
                [InlineKeyboardButton("📊 Show Status", callback_data="reseller_status")],
            ]
            menu_text = "**Welcome To OSM API**\nChoose an option:"
        await query.edit_message_text(menu_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='Markdown')

    elif data == "create_package":
        await query.edit_message_text("Enter the name of the new package:")
        context.user_data["state"] = "awaiting_package_name"

    elif data == "create_key":
        if is_reseller and not is_admin:
            pkg = "death"
            if pkg not in API_KEYS.get("packages", {}):
                await query.edit_message_text(f"Error: Package '{pkg}' does not exist. Please contact Admin.")
                return
            context.user_data["selected_package"] = pkg
            await query.edit_message_text(f"Selected package: **{pkg}**\nEnter duration (e.g. 1h, 1d, 7d):", parse_mode='Markdown')
            context.user_data["state"] = "awaiting_duration"
        else:
            keyboard = [[InlineKeyboardButton(p, callback_data=f"key_pkg_{p}")] for p in API_KEYS.get("packages", {})]
            keyboard.append([InlineKeyboardButton("Back", callback_data="start_menu")])
            await query.edit_message_text("Select package:", reply_markup=InlineKeyboardMarkup(keyboard))

    elif data.startswith("key_pkg_"):
        pkg = data.replace("key_pkg_", "")
        context.user_data["selected_package"] = pkg
        await query.edit_message_text(f"Selected package: **{pkg}**\nEnter duration (e.g. 1h, 1d, 7d):", parse_mode='Markdown')
        context.user_data["state"] = "awaiting_duration"

    elif data == "manage_resellers":
        keyboard = [
            [InlineKeyboardButton("➕ Add Reseller", callback_data="add_reseller")],
            [InlineKeyboardButton("📋 List Resellers", callback_data="list_resellers")],
            [InlineKeyboardButton("Back", callback_data="start_menu")]
        ]
        await query.edit_message_text("Reseller Management:", reply_markup=InlineKeyboardMarkup(keyboard))

    elif data == "add_reseller":
        await query.edit_message_text("Enter Reseller ID (Telegram Chat ID):")
        context.user_data["state"] = "awaiting_reseller_id"

    elif data == "list_resellers":
        resellers_dict = API_KEYS.get("resellers", {})
        if not resellers_dict:
            keyboard = [[InlineKeyboardButton("Back", callback_data="manage_resellers")]]
            await query.edit_message_text("No resellers found.", reply_markup=InlineKeyboardMarkup(keyboard))
            return

        text = "📋 Resellers List:\n\n"
        keyboard = []
        fixed = False
        for rid, rdata in list(resellers_dict.items()):
            rid_str = str(rid)
            # Fix corrupted data: if rdata is not a dict, reset it
            if not isinstance(rdata, dict):
                resellers_dict[rid] = {"quota": 0, "used_quota": 0, "max_devices": 1, "max_keys": 0, "permissions": ["all"], "activity_log": []}
                rdata = resellers_dict[rid]
                fixed = True
            used = rdata.get('used_quota', 0)
            total = rdata.get('quota', 0)
            max_dev = rdata.get('max_devices', 1)
            max_keys = rdata.get('max_keys', total)
            status = "✅" if used < total else "🔴"
            text += (
                f"{status} ID: {rid_str}\n"
                f"   Keys: {used}/{total} | Max Keys: {max_keys} | Devices/Key: {max_dev}\n\n"
            )
            keyboard.append([InlineKeyboardButton(
                f"{status} {rid_str}  ({used}/{total} keys)",
                callback_data=f"adm_res_{rid_str}"
            )])

        if fixed:
            await save_keys_safe(API_KEYS)

        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="manage_resellers")])
        await query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard))

    elif data.startswith("adm_res_"):
        rid = data.replace("adm_res_", "")
        resellers_dict = API_KEYS.get("resellers", {})
        rdata = resellers_dict.get(rid)
        
        if not rdata:
            # Try matching as integer if string fail (telegram IDs can be tricky)
            for k, v in resellers_dict.items():
                if str(k) == rid:
                    rdata = v
                    rid = str(k)
                    break
        
        if not rdata:
            await query.answer("Reseller not found.")
            return
        
        my_keys = [k for k, v in API_KEYS.items() if isinstance(v, dict) and str(v.get("created_by_id")) == rid]
        used = rdata.get('used_quota', 0)
        total = rdata.get('quota', 0)
        max_dev = rdata.get('max_devices', 1)
        max_keys = rdata.get('max_keys', total)
        status_str = "✅ Active" if used < total else "🔴 Quota Full"
        text = (f"**Reseller Management**\n\n"
                f"👤 **ID:** `{rid}`\n"
                f"📊 **Keys Quota:** `{used}/{total}`\n"
                f"📱 **Max Devices per Key:** `{max_dev}`\n"
                f"🔑 **Max Keys Allowed:** `{max_keys}`\n"
                f"🗝️ **Keys Created:** `{len(my_keys)}`\n"
                f"📈 **Status:** {status_str}")
        
        keyboard = [
            [InlineKeyboardButton("➕ Increase Quota", callback_data=f"qta_inc_{rid}"),
             InlineKeyboardButton("➖ Decrease Quota", callback_data=f"qta_dec_{rid}")],
            [InlineKeyboardButton("📱 Set Max Devices", callback_data=f"set_maxdev_{rid}"),
             InlineKeyboardButton("🔑 Set Max Keys", callback_data=f"set_maxkeys_{rid}")],
            [InlineKeyboardButton("📊 View Keys", callback_data=f"view_res_keys_{rid}")],
            [InlineKeyboardButton("🗑️ Delete Reseller", callback_data=f"del_res_{rid}")],
            [InlineKeyboardButton("Back", callback_data="list_resellers")]
        ]
        await query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='Markdown')

    elif data.startswith("qta_inc_"):
        rid = data.replace("qta_inc_", "")
        if rid in API_KEYS.get("resellers", {}):
            API_KEYS["resellers"][rid]["quota"] = API_KEYS["resellers"][rid].get("quota", 0) + 1
            await save_keys_safe(API_KEYS)
            await query.answer(f"Quota increased for {rid}")
            # Refresh view
            class FakeQuery:
                def __init__(self): self.data = f"adm_res_{rid}"; self.from_user = query.from_user; self.answer = query.answer; self.edit_message_text = query.edit_message_text
            await button_handler(type('obj', (object,), {'callback_query': FakeQuery()}), context)

    elif data.startswith("qta_dec_"):
        rid = data.replace("qta_dec_", "")
        if rid in API_KEYS.get("resellers", {}):
            if API_KEYS["resellers"][rid].get("quota", 0) > 0:
                API_KEYS["resellers"][rid]["quota"] -= 1
                await save_keys_safe(API_KEYS)
                await query.answer(f"Quota decreased for {rid}")
            else:
                await query.answer("Quota already at 0.")
            # Refresh view
            class FakeQuery:
                def __init__(self): self.data = f"adm_res_{rid}"; self.from_user = query.from_user; self.answer = query.answer; self.edit_message_text = query.edit_message_text
            await button_handler(type('obj', (object,), {'callback_query': FakeQuery()}), context)

    elif data.startswith("del_res_"):
        rid = data.replace("del_res_", "")
        if rid in API_KEYS.get("resellers", {}):
            del API_KEYS["resellers"][rid]
            await save_keys_safe(API_KEYS)
            await query.answer(f"Reseller {rid} deleted.")
            # Go back to list
            class FakeQuery:
                def __init__(self): self.data = "list_resellers"; self.from_user = query.from_user; self.answer = query.answer; self.edit_message_text = query.edit_message_text
            await button_handler(type('obj', (object,), {'callback_query': FakeQuery()}), context)

    elif data.startswith("set_maxdev_"):
        rid = data.replace("set_maxdev_", "")
        context.user_data["setting_maxdev_for"] = rid
        context.user_data["state"] = "awaiting_maxdev"
        await query.edit_message_text(
            f"👤 Reseller: `{rid}`\n\n"
            f"📱 Enter **Max Devices per Key** (e.g. 1, 2, 3):\n"
            f"_(This controls how many devices can use each key this reseller creates)_",
            parse_mode='Markdown'
        )

    elif data.startswith("set_maxkeys_"):
        rid = data.replace("set_maxkeys_", "")
        context.user_data["setting_maxkeys_for"] = rid
        context.user_data["state"] = "awaiting_maxkeys"
        await query.edit_message_text(
            f"👤 Reseller: `{rid}`\n\n"
            f"🔑 Enter **Max Keys** this reseller can create in total (e.g. 10, 50, 100):",
            parse_mode='Markdown'
        )

    elif data.startswith("view_res_keys_"):
        rid = data.replace("view_res_keys_", "")
        my_keys = [k for k, v in API_KEYS.items() if isinstance(v, dict) and str(v.get("created_by_id")) == rid]
        text = f"Keys created by {rid}:\n\n"
        if not my_keys:
            text += "No keys found."
        else:
            for k in my_keys[:20]:
                v = API_KEYS[k]
                expiry = v.get("expiry", "N/A")
                devices = len(v.get("bound_devices", []))
                max_u = v.get("max_users", 1)
                text += f"• {k} [{devices}/{max_u}] — {expiry}\n"
            if len(my_keys) > 20:
                text += f"\n...and {len(my_keys)-20} more"

        keyboard = [[InlineKeyboardButton("🔙 Back", callback_data=f"adm_res_{rid}")]]
        await query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard))

    elif data == "reseller_status":
        reseller_data = API_KEYS.get("resellers", {}).get(chat_id, {})
        my_keys = [k for k, v in API_KEYS.items() if isinstance(v, dict) and str(v.get("created_by_id")) == chat_id]
        used = reseller_data.get('used_quota', 0)
        total = reseller_data.get('quota', 0)
        max_dev = reseller_data.get('max_devices', 1)
        max_keys = reseller_data.get('max_keys', total)
        remaining = max(0, min(total - used, max_keys - len(my_keys)))
        status_str = "✅ Active" if used < total else "🔴 Quota Full"
        text = (
            f"📊 Your Reseller Status\n\n"
            f"🆔 ID: {chat_id}\n"
            f"📈 Status: {status_str}\n\n"
            f"🔑 Keys quota: {used}/{total}\n"
            f"🗝 Keys created: {len(my_keys)}/{max_keys}\n"
            f"📱 Max devices per key: {max_dev}\n"
            f"➕ Can still create: {remaining} key(s)\n\n"
            f"Your keys (latest 10):"
        )
        keyboard = [[InlineKeyboardButton(k, callback_data=f"manage_key_{k}")] for k in my_keys[-10:]]
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="start_menu")])
        await query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard))

    # Re-using existing manage_key, reset_key, stop_key logic but adding reseller permission checks
    elif data.startswith("manage_key_"):
        key = data.replace("manage_key_", "")
        key_data = API_KEYS.get(key)
        if not key_data: return
        
        # Check ownership if reseller
        if is_reseller and not is_admin and key_data.get("created_by_id") != chat_id:
            await query.answer("Not your key.")
            return

        pkg = key_data.get("package", "")
        devices = key_data.get("bound_devices", [])
        dev_list = "\n".join([f"`{d}`" for d in devices]) or "None"
        expiry = key_data.get("expiry", "N/A")
        max_u = key_data.get("max_users", 1)
        banned_str = "🚫 BANNED" if key_data.get("banned") else "✅ Active"

        text = (
            f"**Key:** `{key}`\n"
            f"**Package:** {pkg}\n"
            f"**Status:** {banned_str}\n"
            f"**Expiry:** {expiry}\n"
            f"**Devices ({len(devices)}/{max_u}):**\n{dev_list}"
        )
        # Back button returns to the package list
        back_cb = f"status_pkg_{pkg}" if pkg else "status"
        keyboard = [
            [InlineKeyboardButton("🔄 Reset Devices", callback_data=f"reset_key_{key}"),
             InlineKeyboardButton("🗑️ Delete Key", callback_data=f"stop_key_{key}")],
            [InlineKeyboardButton("🚫 Ban", callback_data=f"ban_key_{key}"),
             InlineKeyboardButton("✅ Unban", callback_data=f"unban_key_{key}")],
            [InlineKeyboardButton("🔙 Back", callback_data=back_cb)]
        ]
        await query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='Markdown')

    elif data.startswith("reset_key_"):
        key = data.replace("reset_key_", "")
        if key in API_KEYS:
            pkg = API_KEYS[key].get("package", "")
            API_KEYS[key]["bound_devices"] = []
            await save_keys_safe(API_KEYS)
            await query.answer(f"Reset {key}")
            # Refresh manage_key view
            key_data = API_KEYS[key]
            back_cb = f"status_pkg_{pkg}" if pkg else "status"
            text = (
                f"**Key:** `{key}`\n"
                f"**Package:** {pkg}\n"
                f"**Status:** {'🚫 BANNED' if key_data.get('banned') else '✅ Active'}\n"
                f"**Expiry:** {key_data.get('expiry', 'N/A')}\n"
                f"**Devices (0/{key_data.get('max_users', 1)}):**\nNone"
            )
            keyboard = [
                [InlineKeyboardButton("🔄 Reset Devices", callback_data=f"reset_key_{key}"),
                 InlineKeyboardButton("🗑️ Delete Key", callback_data=f"stop_key_{key}")],
                [InlineKeyboardButton("🚫 Ban", callback_data=f"ban_key_{key}"),
                 InlineKeyboardButton("✅ Unban", callback_data=f"unban_key_{key}")],
                [InlineKeyboardButton("🔙 Back", callback_data=back_cb)]
            ]
            await query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='Markdown')

    elif data.startswith("stop_key_"):
        key = data.replace("stop_key_", "")
        if key in API_KEYS:
            pkg = API_KEYS[key].get("package", "")
            del API_KEYS[key]
            await save_keys_safe(API_KEYS)
            await query.answer(f"Deleted {key}")
            back_cb = f"status_pkg_{pkg}" if pkg else "status"
            await query.edit_message_text(
                f"Key `{key}` deleted.",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data=back_cb)]]),
                parse_mode='Markdown'
            )

    elif data.startswith("ban_key_"):
        key = data.replace("ban_key_", "")
        if key in API_KEYS:
            API_KEYS[key]["banned"] = True
            await save_keys_safe(API_KEYS)
            await query.answer(f"Banned {key}")
            await query.edit_message_text(f"Key `{key}` banned.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Back", callback_data="start_menu")]]), parse_mode='Markdown')

    elif data.startswith("unban_key_"):
        key = data.replace("unban_key_", "")
        if key in API_KEYS:
            API_KEYS[key]["banned"] = False
            await save_keys_safe(API_KEYS)
            await query.answer(f"Unbanned {key}")
            await query.edit_message_text(f"Key `{key}` unbanned.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Back", callback_data="start_menu")]]), parse_mode='Markdown')

    elif data == "noop":
        await query.answer()
        return

    elif data == "status":
        await show_packages_for_manage(query, context, edit=True)

    elif data == "delete_package":
        if not API_KEYS.get("packages"):
            await query.edit_message_text("No packages to delete.")
            return
        keyboard = [[InlineKeyboardButton(p, callback_data=f"del_pkg_{p}")] for p in API_KEYS["packages"]]
        keyboard.append([InlineKeyboardButton("Back", callback_data="start_menu")])
        await query.edit_message_text("Select package to delete:", reply_markup=InlineKeyboardMarkup(keyboard))

    elif data.startswith("del_pkg_"):
        pkg_name = data.replace("del_pkg_", "")
        keys_to_delete = [k for k, d in API_KEYS.items()
                          if k not in ["packages", "global_banned_devices", "resellers"]
                          and isinstance(d, dict) and d.get("package") == pkg_name]
        for k in keys_to_delete:
            del API_KEYS[k]
        if pkg_name in API_KEYS.get("packages", {}):
            del API_KEYS["packages"][pkg_name]
        await save_keys_safe(API_KEYS)
        await query.edit_message_text(f"Package {pkg_name} and {len(keys_to_delete)} key(s) deleted.")

    elif data.startswith("status_pkg_"):
        parts = data.split("|")
        pkg = parts[0].replace("status_pkg_", "")
        page = int(parts[1]) if len(parts) > 1 else 0
        page_size = 97

        matching = [k for k, v in API_KEYS.items()
                    if k not in ["packages", "global_banned_devices", "resellers"]
                    and isinstance(v, dict) and v.get("package") == pkg]

        if not matching:
            keyboard = [[InlineKeyboardButton("Back", callback_data="status")]]
            await query.edit_message_text(f"Package: {pkg} (0 keys):", reply_markup=InlineKeyboardMarkup(keyboard))
            return

        total_keys = len(matching)
        total_pages = (total_keys + page_size - 1) // page_size
        start = page * page_size
        end = min(start + page_size, total_keys)
        page_keys = matching[start:end]

        text = f"Package: {pkg} ({total_keys} keys):"

        keyboard = []
        for k in page_keys:
            keyboard.append([InlineKeyboardButton(k, callback_data=f"manage_key_{k}")])

        if total_pages > 1:
            nav = []
            if page > 0:
                nav.append(InlineKeyboardButton("Prev", callback_data=f"status_pkg_{pkg}|{page-1}"))
            nav.append(InlineKeyboardButton(f"{page+1}/{total_pages}", callback_data="noop"))
            if page < total_pages - 1:
                nav.append(InlineKeyboardButton("Next", callback_data=f"status_pkg_{pkg}|{page+1}"))
            keyboard.append(nav)

        keyboard.append([InlineKeyboardButton("Back", callback_data="status")])
        await query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard))



async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    is_admin = chat_id in ADMIN_CHAT_IDS
    is_reseller = "resellers" in API_KEYS and chat_id in API_KEYS["resellers"]
    
    if not is_admin and not is_reseller:
        return
        
    state = context.user_data.get("state")
    text = update.message.text.strip()

    if state == "awaiting_package_name":
        if text not in API_KEYS["packages"]:
            API_KEYS["packages"][text] = {"token": secrets.token_hex(16), "aliases": [], "status": "active"}
            await save_keys_safe(API_KEYS)
            await update.message.reply_text(f"Package {text} created.")
        context.user_data["state"] = None

    elif state == "awaiting_reseller_id":
        context.user_data["new_reseller_id"] = text
        await update.message.reply_text("Enter Quota (number of keys this reseller can create):")
        context.user_data["state"] = "awaiting_reseller_quota"

    elif state == "awaiting_reseller_quota":
        rid = context.user_data.get("new_reseller_id")
        try:
            quota = int(text)
        except ValueError:
            await update.message.reply_text("❌ Invalid number. Enter quota:")
            return
        if "resellers" not in API_KEYS: API_KEYS["resellers"] = {}
        API_KEYS["resellers"][rid] = {
            "quota": quota,
            "used_quota": 0,
            "max_devices": 1,
            "max_keys": quota,
            "permissions": ["all"],
            "activity_log": []
        }
        await save_keys_safe(API_KEYS)
        await update.message.reply_text(
            f"✅ **Reseller Added!**\n\n"
            f"👤 ID: `{rid}`\n"
            f"📊 Quota: `{quota}` keys\n"
            f"📱 Max Devices/Key: `1` (default)\n"
            f"🔑 Max Keys: `{quota}`\n\n"
            f"Use **Manage Resellers** to adjust max devices/keys.",
            parse_mode='Markdown'
        )
        context.user_data["state"] = None

    elif state == "awaiting_maxdev":
        rid = context.user_data.get("setting_maxdev_for")
        try:
            max_dev = int(text)
            if max_dev < 1: raise ValueError
        except ValueError:
            await update.message.reply_text("❌ Invalid. Enter a positive number:")
            return
        if rid and rid in API_KEYS.get("resellers", {}):
            API_KEYS["resellers"][rid]["max_devices"] = max_dev
            await save_keys_safe(API_KEYS)
            await update.message.reply_text(
                f"✅ **Max Devices Updated**\n\n"
                f"👤 Reseller: `{rid}`\n"
                f"📱 Max Devices per Key: `{max_dev}`\n\n"
                f"All new keys this reseller creates will allow `{max_dev}` device(s).",
                parse_mode='Markdown'
            )
        context.user_data["state"] = None
        context.user_data["setting_maxdev_for"] = None

    elif state == "awaiting_maxkeys":
        rid = context.user_data.get("setting_maxkeys_for")
        try:
            max_keys = int(text)
            if max_keys < 1: raise ValueError
        except ValueError:
            await update.message.reply_text("❌ Invalid. Enter a positive number:")
            return
        if rid and rid in API_KEYS.get("resellers", {}):
            API_KEYS["resellers"][rid]["max_keys"] = max_keys
            await save_keys_safe(API_KEYS)
            await update.message.reply_text(
                f"✅ **Max Keys Updated**\n\n"
                f"👤 Reseller: `{rid}`\n"
                f"🔑 Max Keys: `{max_keys}`",
                parse_mode='Markdown'
            )
        context.user_data["state"] = None
        context.user_data["setting_maxkeys_for"] = None

    elif state == "awaiting_duration":
        pkg = context.user_data.get("selected_package")
        alias = context.user_data.get("selected_alias")
        duration = parse_duration(text)

        if not duration:
            await update.message.reply_text("❌ Invalid duration. Use format like: 1h, 2d, 1w")
            return

        context.user_data["pending_duration"] = text
        context.user_data["pending_duration_delta"] = int(duration.total_seconds())

        # Step 2: ask devices per key
        if is_reseller and not is_admin:
            reseller = API_KEYS["resellers"][chat_id]
            max_dev = reseller.get("max_devices", 1)
            await update.message.reply_text(
                f"📱 Enter number of devices per key:\n_(max allowed: **{max_dev}**)_",
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text("📱 Enter number of devices per key (e.g. 1):")

        context.user_data["state"] = "awaiting_key_devices"

    elif state == "awaiting_key_devices":
        pkg = context.user_data.get("selected_package")
        duration_str = context.user_data.get("pending_duration")
        delta = context.user_data.get("pending_duration_delta")

        try:
            max_users = int(text)
            if max_users < 1: raise ValueError
        except ValueError:
            await update.message.reply_text("❌ Invalid number. Enter a positive number:")
            return

        # Enforce max_devices limit for resellers
        if is_reseller and not is_admin:
            reseller = API_KEYS["resellers"][chat_id]
            max_dev = reseller.get("max_devices", 1)
            if max_users > max_dev:
                await update.message.reply_text(f"⚠️ Max allowed is {max_dev}. Setting to {max_dev}.")
                max_users = max_dev

        context.user_data["pending_max_users"] = max_users

        # Step 3: ask how many keys to create
        if is_reseller and not is_admin:
            reseller = API_KEYS["resellers"][chat_id]
            used = reseller.get("used_quota", 0)
            total_q = reseller.get("quota", 0)
            my_keys_count = sum(1 for v in API_KEYS.values() if isinstance(v, dict) and str(v.get("created_by_id")) == chat_id)
            max_k = reseller.get("max_keys", total_q)
            remaining = min(total_q - used, max_k - my_keys_count)
            await update.message.reply_text(
                f"🔑 How many keys to create?\n_(max you can create: **{remaining}**)_",
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text("🔑 How many keys to create? (e.g. 1, 5, 10):")

        context.user_data["state"] = "awaiting_key_count"

    elif state == "awaiting_key_count":
        pkg = context.user_data.get("selected_package")
        duration_str = context.user_data.get("pending_duration")
        delta = context.user_data.get("pending_duration_delta")
        max_users = context.user_data.get("pending_max_users", 1)

        try:
            key_count = int(text)
            if key_count < 1: raise ValueError
        except ValueError:
            await update.message.reply_text("❌ Invalid number. Enter a positive number:")
            return

        # Reseller: check quota + max_keys
        if is_reseller and not is_admin:
            reseller = API_KEYS["resellers"][chat_id]
            used = reseller.get("used_quota", 0)
            total_q = reseller.get("quota", 0)
            my_keys_count = sum(1 for v in API_KEYS.values() if isinstance(v, dict) and str(v.get("created_by_id")) == chat_id)
            max_k = reseller.get("max_keys", total_q)
            remaining = min(total_q - used, max_k - my_keys_count)
            if remaining <= 0:
                await update.message.reply_text("❌ Quota exceeded! Contact admin.")
                context.user_data["state"] = None
                return
            if key_count > remaining:
                await update.message.reply_text(f"⚠️ You can only create {remaining} more key(s). Creating {remaining}.")
                key_count = remaining

        # Create keys
        created_keys = []
        for i in range(key_count):
            # Format: pkg-24h-TOKEN or pkg-7d-TOKEN etc
            duration_label = duration_str.lower()  # e.g. 1d, 7d, 24h
            new_key = f"{pkg}-{duration_label}-{secrets.token_hex(8)}"
            while new_key in API_KEYS:
                new_key = f"{pkg}-{duration_label}-{secrets.token_hex(8)}"

            API_KEYS[new_key] = {
                "role": "user",
                "package": pkg,
                "duration": duration_str,
                "delta_seconds": delta,
                "expiry": "Not Activated",
                "bound_devices": [],
                "banned_devices": [],
                "max_users": max_users,
                "created_by_id": chat_id
            }
            created_keys.append(new_key)

            if is_reseller and not is_admin:
                API_KEYS["resellers"][chat_id]["used_quota"] = API_KEYS["resellers"][chat_id].get("used_quota", 0) + 1

        await save_keys_safe(API_KEYS)

        keys_list = "\n".join([f"`{k}`" for k in created_keys])

        if is_reseller and not is_admin:
            reseller = API_KEYS["resellers"][chat_id]
            used_now = reseller.get("used_quota", 0)
            total_q = reseller.get("quota", 0)
            my_keys_count = sum(1 for v in API_KEYS.values() if isinstance(v, dict) and str(v.get("created_by_id")) == chat_id)
            max_k = reseller.get("max_keys", total_q)
            max_dev = reseller.get("max_devices", 1)
            await update.message.reply_text(
                f"✅ **{len(created_keys)} Key(s) created successfully!**\n"
                f"{keys_list}\n"
                f"Duration: `{duration_str}`\n"
                f"Max devices: `{max_users}` device(s)\n"
                f"Package: `{pkg}`\n\n"
                f"📊 Quota used: `{used_now}/{total_q}`\n"
                f"🔑 Keys created: `{my_keys_count}/{max_k}`\n"
                f"📱 Max devices per key: `{max_dev}`",
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text(
                f"✅ **{len(created_keys)} Key(s) created successfully!**\n"
                f"{keys_list}\n"
                f"Duration: `{duration_str}`\n"
                f"Max devices: `{max_users}` device(s)\n"
                f"Package: `{pkg}`",
                parse_mode='Markdown'
            )

        context.user_data["state"] = None
        context.user_data["pending_duration"] = None
        context.user_data["pending_max_users"] = None


async def status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    await update.message.reply_text("Use the 'Show Status' button from the main menu.")


async def stop_key_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    if not context.args:
        await update.message.reply_text("Usage: `/stop <key>`")
        return
    key = context.args[0].strip()
    if key == "skam_admin_key":
        await update.message.reply_text("Cannot delete admin key.")
        return
    if key in API_KEYS and key not in ["packages", "global_banned_devices"]:
        del API_KEYS[key]
        await save_keys_safe(API_KEYS)
        await update.message.reply_text(f"Key `{key}` deleted.")
    else:
        await update.message.reply_text("Key not found.")


async def ban_device_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    if not context.args:
        await update.message.reply_text("Usage: `/ban <DEVICE_ID>`")
        return
    dev_id = context.args[0].strip()
    if not validate_device_id_format(dev_id):
        await update.message.reply_text("Invalid device ID format.")
        return
    global_banned = API_KEYS.setdefault("global_banned_devices", [])
    if dev_id not in global_banned:
        global_banned.append(dev_id)
        await save_keys_safe(API_KEYS)
    for key_data in API_KEYS.values():
        if isinstance(key_data, dict) and "bound_devices" in key_data:
            if dev_id in key_data.get("bound_devices", []):
                banned = key_data.setdefault("banned_devices", [])
                if dev_id not in banned:
                    banned.append(dev_id)
    await update.message.reply_text(f"Device ID banned: {dev_id}")


async def unban_device_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    if not context.args:
        await update.message.reply_text("Usage: `/unban <DEVICE_ID>`")
        return
    dev_id = context.args[0].strip()
    global_banned = API_KEYS.get("global_banned_devices", [])
    was_banned = dev_id in global_banned
    if was_banned:
        global_banned.remove(dev_id)
        await save_keys_safe(API_KEYS)
    for key_data in API_KEYS.values():
        if isinstance(key_data, dict) and "banned_devices" in key_data:
            if dev_id in key_data["banned_devices"]:
                key_data["banned_devices"].remove(dev_id)
    if was_banned:
        await update.message.reply_text(f"Device ID unbanned: {dev_id}")
    else:
        await update.message.reply_text(f"{dev_id} was not banned")


async def reset_key_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    if not context.args:
        await update.message.reply_text("Usage: `/reset <key>`")
        return
    key = context.args[0].strip()
    if key not in API_KEYS or key in ["packages", "global_banned_devices"]:
        await update.message.reply_text("Key not found or invalid.")
        return
    if not isinstance(API_KEYS[key], dict):
        await update.message.reply_text("Invalid key data.")
        return

    key_data = API_KEYS[key]
    old_devices = len(key_data.get("bound_devices", []))
    key_data["bound_devices"] = []
    await save_keys_safe(API_KEYS)
    await update.message.reply_text(
        f"Key `{key}` reset successfully!\n"
        f"{old_devices} device(s) removed.\n"
        f"Activation time and expiry remain unchanged.\n"
        f"You can activate again now on this device."
    )


async def enableinject_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    if not context.args:
        await update.message.reply_text("Usage: `/enableinject <package>`", parse_mode='Markdown')
        return

    pkg_name = context.args[0].strip()
    if pkg_name not in API_KEYS.get("packages", {}):
        await update.message.reply_text(f"Package `{pkg_name}` not found.")
        return

    pkg_data = API_KEYS["packages"][pkg_name]
    pkg_data["security"] = {"anti_inject": True, "dylib_crash": False}
    await save_keys_safe(API_KEYS)
    await update.message.reply_text(
        f"🛡️ Anti-Inject protection **ENABLED** for **{pkg_name}**\n\n"
        f"✅ Dylib injection — BLOCKED\n"
        f"✅ Deb injection — BLOCKED\n"
        f"✅ Framework injection — BLOCKED\n"
        f"✅ Debugger — BLOCKED\n"
        f"✅ Jailbreak — BLOCKED\n"
        f"✅ Integrity check — ACTIVE\n\n"
        f"Any detected injection will crash the app.",
        parse_mode='Markdown'
    )


async def disabledinject_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    if not context.args:
        await update.message.reply_text("Usage: `/disabledinject <package>`", parse_mode='Markdown')
        return

    pkg_name = context.args[0].strip()
    if pkg_name not in API_KEYS.get("packages", {}):
        await update.message.reply_text(f"Package `{pkg_name}` not found.")
        return

    pkg_data = API_KEYS["packages"][pkg_name]
    pkg_data["security"] = {"anti_inject": False, "dylib_crash": True}
    await save_keys_safe(API_KEYS)
    await update.message.reply_text(
        f"⚠️ Anti-Inject protection **DISABLED** for **{pkg_name}**\n\n"
        f"❌ Dylib injection — ALLOWED (crash on detect)\n"
        f"❌ Deb injection — ALLOWED\n"
        f"❌ Framework injection — ALLOWED\n"
        f"❌ Debugger — ALLOWED\n"
        f"❌ Jailbreak — ALLOWED\n"
        f"❌ Integrity check — OFF\n\n"
        f"⚠️ Dylib crash is still **ACTIVE** — injected dylibs will trigger a crash.",
        parse_mode='Markdown'
    )


async def crashdylib_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    GLOBAL_DYLIB_CRASH["enabled"] = True
    await update.message.reply_text(
        "Dylib CRASH **ENABLED** globally\n"
        "ALL clients will crash immediately.",
        parse_mode='Markdown'
    )


async def uncrashdylib_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    GLOBAL_DYLIB_CRASH["enabled"] = False
    await update.message.reply_text(
        "Dylib CRASH **DISABLED** globally\n"
        "Dylib will work normally again for all clients.",
        parse_mode='Markdown'
    )


async def offsets_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show offsets for a package - Usage: /offsets <package_name> [game_version]"""
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    
    args = context.args
    if not args:
        await update.message.reply_text(
            "**Usage:** `/offsets <package_name> [game_version]`\n\n"
            "**Examples:**\n"
            "`/offsets Lmjhed`\n"
            "`/offsets Lmjhed 1.0.0`\n\n"
            "**Available packages:**\n" + 
            "\n".join([f"• {pkg}" for pkg in API_KEYS.get("packages", {}).keys()]) if API_KEYS.get("packages") else "No packages found",
            parse_mode='Markdown'
        )
        return
    
    package_name = args[0]
    game_version = args[1] if len(args) > 1 else "1.0.0"
    
    if "packages" not in API_KEYS or package_name not in API_KEYS["packages"]:
        await update.message.reply_text(f"❌ Package **{package_name}** not found", parse_mode='Markdown')
        return
    
    pkg_data = API_KEYS["packages"][package_name]
    offsets = pkg_data.get("offsets", {}).get(game_version, {})
    
    if not offsets:
        await update.message.reply_text(
            f"❌ No offsets found for:\n"
            f"Package: **{package_name}**\n"
            f"Version: **{game_version}**\n\n"
            f"Use `/addoffsets` to add offsets",
            parse_mode='Markdown'
        )
        return
    
    # Format offsets message
    offset_list = "\n".join([f"• `{k}`: `{v}`" for k, v in list(offsets.items())[:20]])
    total = len(offsets)
    
    await update.message.reply_text(
        f"**📊 Offsets for {package_name}**\n"
        f"Version: `{game_version}`\n"
        f"Total: **{total}** offsets\n\n"
        f"**First 20 offsets:**\n{offset_list}\n\n"
        f"💡 Use `/addoffsets` to update offsets",
        parse_mode='Markdown'
    )


async def addoffsets_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Instructions to add offsets"""
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    
    await update.message.reply_text(
        "**📤 How to Add/Update Offsets:**\n\n"
        "**Method 1: Using Python Script (Recommended)**\n"
        "```\n"
        "cd Lmjhed\n"
        "python DynamicOffsets/add_offsets.py\n"
        "```\n\n"
        "**Method 2: Using API Endpoint**\n"
        "```\n"
        "POST /admin/set-offsets\n"
        "?package_name=Lmjhed\n"
        "&game_version=1.0.0\n"
        "&admin_key=skam_admin_key\n"
        "\n"
        "Body: {\"offsets\": {...}}\n"
        "```\n\n"
        "**Method 3: Edit add_offsets.py**\n"
        "1. Open `DynamicOffsets/add_offsets.py`\n"
        "2. Update OFFSETS dictionary\n"
        "3. Run: `python add_offsets.py`\n\n"
        "💡 Check offsets: `/offsets <package>`",
        parse_mode='Markdown'
    )


async def deleteoffsets_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Delete offsets for a package - Usage: /deleteoffsets <package_name> [game_version]"""
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    
    args = context.args
    if not args:
        await update.message.reply_text(
            "**Usage:** `/deleteoffsets <package_name> [game_version]`\n\n"
            "**Examples:**\n"
            "`/deleteoffsets Lmjhed` - Delete all versions\n"
            "`/deleteoffsets Lmjhed 1.0.0` - Delete specific version",
            parse_mode='Markdown'
        )
        return
    
    package_name = args[0]
    game_version = args[1] if len(args) > 1 else None
    
    if "packages" not in API_KEYS or package_name not in API_KEYS["packages"]:
        await update.message.reply_text(f"❌ Package **{package_name}** not found", parse_mode='Markdown')
        return
    
    pkg_data = API_KEYS["packages"][package_name]
    
    if game_version:
        # Delete specific version
        if "offsets" in pkg_data and game_version in pkg_data["offsets"]:
            del pkg_data["offsets"][game_version]
            await save_keys_safe(API_KEYS)
            await update.message.reply_text(
                f"✅ Deleted offsets for:\n"
                f"Package: **{package_name}**\n"
                f"Version: **{game_version}**",
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text(
                f"❌ No offsets found for version **{game_version}**",
                parse_mode='Markdown'
            )
    else:
        # Delete all versions
        if "offsets" in pkg_data:
            versions = list(pkg_data["offsets"].keys())
            pkg_data["offsets"] = {}
            await save_keys_safe(API_KEYS)
            await update.message.reply_text(
                f"✅ Deleted all offsets for **{package_name}**\n"
                f"Versions removed: {', '.join(versions)}",
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text(
                f"❌ No offsets found for **{package_name}**",
                parse_mode='Markdown'
            )


async def setoffset_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Set single offset - Usage: /setoffset <package> <version> <offset_name> <offset_value>"""
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    
    args = context.args
    if len(args) < 4:
        await update.message.reply_text(
            "**Usage:** `/setoffset <package> <version> <offset_name> <offset_value>`\n\n"
            "**Examples:**\n"
            "`/setoffset Lmjhed 1.0.0 get_HP 0x4A8478C`\n"
            "`/setoffset Lmjhed 1.0.0 autofire 0x56524D4`\n"
            "`/setoffset Lmjhed 1.0.0 crash_offset 0x0`\n\n"
            "💡 Use `0x0` to disable an offset",
            parse_mode='Markdown'
        )
        return
    
    package_name = args[0]
    game_version = args[1]
    offset_name = args[2]
    offset_value = args[3]
    
    if "packages" not in API_KEYS or package_name not in API_KEYS["packages"]:
        await update.message.reply_text(f"❌ Package **{package_name}** not found", parse_mode='Markdown')
        return
    
    pkg_data = API_KEYS["packages"][package_name]
    
    # Initialize offsets structure if not exists
    if "offsets" not in pkg_data:
        pkg_data["offsets"] = {}
    if game_version not in pkg_data["offsets"]:
        pkg_data["offsets"][game_version] = {}
    
    # Set the offset
    pkg_data["offsets"][game_version][offset_name] = offset_value
    await save_keys_safe(API_KEYS)
    
    await update.message.reply_text(
        f"✅ **Offset Updated!**\n\n"
        f"Package: `{package_name}`\n"
        f"Version: `{game_version}`\n"
        f"Offset: `{offset_name}`\n"
        f"Value: `{offset_value}`\n\n"
        f"💡 Changes will apply on next app launch",
        parse_mode='Markdown'
    )


async def crashoffset_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Set crash offset to trigger crash - Usage: /crashoffset <package> <version> <offset_value>"""
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    
    args = context.args
    if len(args) < 2:
        await update.message.reply_text(
            "**💥 Crash Offset Control**\n\n"
            "**Usage:** `/crashoffset <package> <version> [offset_value]`\n\n"
            "**Examples:**\n"
            "`/crashoffset Lmjhed 1.0.0 0xDEADBEEF` - Enable crash\n"
            "`/crashoffset Lmjhed 1.0.0 0x0` - Disable crash\n"
            "`/crashoffset Lmjhed 1.0.0` - Enable with default\n\n"
            "⚠️ **Warning:** This will crash the app immediately!\n"
            "Use special offset name: `crash_offset`",
            parse_mode='Markdown'
        )
        return
    
    package_name = args[0]
    game_version = args[1]
    offset_value = args[2] if len(args) > 2 else "0xDEADBEEF"
    
    if "packages" not in API_KEYS or package_name not in API_KEYS["packages"]:
        await update.message.reply_text(f"❌ Package **{package_name}** not found", parse_mode='Markdown')
        return
    
    pkg_data = API_KEYS["packages"][package_name]
    
    # Initialize offsets structure if not exists
    if "offsets" not in pkg_data:
        pkg_data["offsets"] = {}
    if game_version not in pkg_data["offsets"]:
        pkg_data["offsets"][game_version] = {}
    
    # Set crash offset
    pkg_data["offsets"][game_version]["crash_offset"] = offset_value
    await save_keys_safe(API_KEYS)
    
    if offset_value == "0x0":
        await update.message.reply_text(
            f"✅ **Crash Disabled**\n\n"
            f"Package: `{package_name}`\n"
            f"Version: `{game_version}`\n"
            f"Crash Offset: `0x0` (Disabled)\n\n"
            f"App will work normally",
            parse_mode='Markdown'
        )
    else:
        await update.message.reply_text(
            f"💥 **Crash Enabled!**\n\n"
            f"Package: `{package_name}`\n"
            f"Version: `{game_version}`\n"
            f"Crash Offset: `{offset_value}`\n\n"
            f"⚠️ **Warning:** App will crash on next launch!\n"
            f"To disable: `/crashoffset {package_name} {game_version} 0x0`",
            parse_mode='Markdown'
        )


async def updateoffsets_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Update multiple offsets at once - Usage: /updateoffsets <package> <version>"""
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    
    args = context.args
    if len(args) < 2:
        await update.message.reply_text(
            "**📝 Update Multiple Offsets**\n\n"
            "**Usage:** `/updateoffsets <package> <version>`\n\n"
            "**Example:**\n"
            "`/updateoffsets Lmjhed 1.0.0`\n\n"
            "Then send offsets in this format:\n"
            "```\n"
            "get_HP=0x4A8478C\n"
            "autofire=0x56524D4\n"
            "get_camera=0x84E7148\n"
            "```\n\n"
            "💡 One offset per line: `name=value`",
            parse_mode='Markdown'
        )
        return
    
    package_name = args[0]
    game_version = args[1]
    
    if "packages" not in API_KEYS or package_name not in API_KEYS["packages"]:
        await update.message.reply_text(f"❌ Package **{package_name}** not found", parse_mode='Markdown')
        return
    
    # Store in context for next message
    context.user_data["update_offsets_package"] = package_name
    context.user_data["update_offsets_version"] = game_version
    context.user_data["state"] = "awaiting_offsets_bulk"
    
    await update.message.reply_text(
        f"**Ready to update offsets for:**\n"
        f"Package: `{package_name}`\n"
        f"Version: `{game_version}`\n\n"
        f"Send offsets in format:\n"
        f"```\n"
        f"offset_name=0xVALUE\n"
        f"another_offset=0xVALUE\n"
        f"```\n\n"
        f"Send `/cancel` to cancel",
        parse_mode='Markdown'
    )


async def loaddefaultoffsets_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Load default Lmjhed offsets - Usage: /loaddefaultoffsets [version]"""
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    
    args = context.args
    game_version = args[0] if args else "1.0.0"
    package_name = "Lmjhed"
    
    # Default Lmjhed offsets (ACTUAL offsets from Hooks.h - cleaned)
    DEFAULT_OFFSETS = {
        # Player & Match
        "GetLocalPlayer": "0x28FC854",
        "Curent_Match": "0x4E355B0",
        "name": "0x4A16D38",
        
        # Health & Status
        "GetHp": "0x4A8478C",
        "get_MaxHP": "0x4A8489C",
        "get_IsDieing": "0x4A02EA8",
        "get_isVisible": "0x4A20AF4",
        "get_IsJumping": "0x57A2C70",
        
        # Camera & Transform
        "get_camera": "0x84E7148",
        "Component_GetTransform": "0x854060C",
        "get_position": "0x8552BAC",
        "Transform_GetPosition": "0x8552C10",
        "Transform_SetPosition": "0x8552CE8",
        "Transform_SetRotation": "0x8553650",
        "WorldToViewpoint": "0x84E6AC8",
        "GetForward": "0x85534CC",
        
        # Body Parts
        "GetHeadPositions": "0x4AA1A28",
        "_GetHeadPositions": "0x4AA1A28",
        "Player_GetHeadCollider": "0x4A1A9D4",
        "_newHipMods": "0x4AA1BD8",
        "_GetLeftAnkleTF": "0x4AA2028",
        "_GetRightAnkleTF": "0x4AA2134",
        "_GetLeftToeTF": "0x4AA2240",
        "_GetRightToeTF": "0x4AA234C",
        "_getLeftHandTF": "0x4A1B9B4",
        "_getRightHandTF": "0x4A1BAB8",
        "_getLeftForeArmTF": "0x4A1BBBC",
        "_getRightForeArmTF": "0x4A1BCC0",
        
        # Combat & Weapons
        "get_IsSighting": "0x4A0FF18",
        "get_IsFiring": "0x4A05634",
        "set_aim": "0x4A1C91C",
        "SwapWeapon_Int": "0x4A8E050",
        "PlayerNetwork_StartFiring": "0x4D2C138",
        "PlayerNetwork_StopFire": "0x4D2CCEC",
        "Physics_Raycast": "0x5580870",
        
        # Camera Settings
        "get_fieldOfView": "0x84E4E8C",
        "set_fieldOfView": "0x84E4EDC",
        
        # Team
        "get_isLocalTeam": "0x4A38D90",
    }
    
    # Check if package exists, if not create it
    if "packages" not in API_KEYS:
        API_KEYS["packages"] = {}
    
    if package_name not in API_KEYS["packages"]:
        # Create package with token
        pkg_token = generate_package_token(package_name)
        API_KEYS["packages"][package_name] = {
            "security": {"anti_inject": True, "dylib_crash": False},
            "token": pkg_token
        }
        await update.message.reply_text(
            f"📦 Package **{package_name}** created automatically\n"
            f"Token: `{pkg_token}`\n\n"
            f"Loading offsets...",
            parse_mode='Markdown'
        )
    
    # Load offsets
    pkg_data = API_KEYS["packages"][package_name]
    if "offsets" not in pkg_data:
        pkg_data["offsets"] = {}
    
    pkg_data["offsets"][game_version] = DEFAULT_OFFSETS
    await save_keys_safe(API_KEYS)
    
    await update.message.reply_text(
        f"✅ **Default Offsets Loaded!**\n\n"
        f"Package: `{package_name}`\n"
        f"Version: `{game_version}`\n"
        f"Total Offsets: **{len(DEFAULT_OFFSETS)}**\n\n"
        f"**Loaded offsets include:**\n"
        f"• Player & Match (3 offsets)\n"
        f"• Health & Status (5 offsets)\n"
        f"• Camera & Transform (8 offsets)\n"
        f"• Body Parts (12 offsets)\n"
        f"• Combat & Weapons (7 offsets)\n"
        f"• Camera Settings (2 offsets)\n"
        f"• Team (1 offset)\n\n"
        f"💡 View offsets: `/offsets {package_name} {game_version}`\n"
        f"💡 Update offset: `/setoffset {package_name} {game_version} <name> <value>`",
        parse_mode='Markdown'
    )


async def loginconfig_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Configure login screen - Usage: /loginconfig <package> <action> [value]"""
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    
    args = context.args
    if len(args) < 2:
        await update.message.reply_text(
            "**🎨 Login Config Commands**\n\n"
            "**Usage:** `/loginconfig <package> <action> [value]`\n\n"
            "**Actions:**\n"
            "`enable` - Enable login screen\n"
            "`disable` - Disable login screen\n"
            "`setname <name>` - Set app name\n"
            "`setwelcome <text>` - Set welcome text\n"
            "`seticon <emoji>` - Set icon\n"
            "`setcolor <type> <hex>` - Set color\n"
            "`autopaste on/off` - Auto paste from clipboard\n"
            "`view` - View current config\n\n"
            "**Examples:**\n"
            "`/loginconfig Lmjhed enable`\n"
            "`/loginconfig Lmjhed setname DEATH Mod`\n"
            "`/loginconfig Lmjhed seticon 🎮`\n"
            "`/loginconfig Lmjhed setcolor primary #ff0000`\n"
            "`/loginconfig Lmjhed autopaste on`",
            parse_mode='Markdown'
        )
        return
    
    package_name = args[0]
    action = args[1].lower()
    
    if "packages" not in API_KEYS or package_name not in API_KEYS["packages"]:
        await update.message.reply_text(f"❌ Package **{package_name}** not found", parse_mode='Markdown')
        return
    
    pkg_data = API_KEYS["packages"][package_name]
    
    # Initialize login_config if not exists
    if "login_config" not in pkg_data:
        pkg_data["login_config"] = {}
    
    login_config = pkg_data["login_config"]
    
    if action == "enable":
        login_config["login_enabled"] = True
        await save_keys_safe(API_KEYS)
        await update.message.reply_text(
            f"✅ **Login Enabled**\n\n"
            f"Package: `{package_name}`\n"
            f"Login screen will be shown to users",
            parse_mode='Markdown'
        )
    
    elif action == "disable":
        login_config["login_enabled"] = False
        await save_keys_safe(API_KEYS)
        await update.message.reply_text(
            f"🚫 **Login Disabled**\n\n"
            f"Package: `{package_name}`\n"
            f"Users will bypass login screen",
            parse_mode='Markdown'
        )
    
    elif action == "setname":
        if len(args) < 3:
            await update.message.reply_text("❌ Usage: `/loginconfig <package> setname <name>`", parse_mode='Markdown')
            return
        app_name = " ".join(args[2:])
        login_config["app_name"] = app_name
        login_config["welcome_text"] = f"Welcome to {app_name}"
        await save_keys_safe(API_KEYS)
        await update.message.reply_text(
            f"✅ **App Name Updated**\n\n"
            f"Package: `{package_name}`\n"
            f"New Name: **{app_name}**",
            parse_mode='Markdown'
        )
    
    elif action == "setwelcome":
        if len(args) < 3:
            await update.message.reply_text("❌ Usage: `/loginconfig <package> setwelcome <text>`", parse_mode='Markdown')
            return
        welcome_text = " ".join(args[2:])
        login_config["welcome_text"] = welcome_text
        await save_keys_safe(API_KEYS)
        await update.message.reply_text(
            f"✅ **Welcome Text Updated**\n\n"
            f"Package: `{package_name}`\n"
            f"New Text: **{welcome_text}**",
            parse_mode='Markdown'
        )
    
    elif action == "seticon":
        if len(args) < 3:
            await update.message.reply_text("❌ Usage: `/loginconfig <package> seticon <emoji>`", parse_mode='Markdown')
            return
        icon = args[2]
        login_config["icon"] = icon
        await save_keys_safe(API_KEYS)
        await update.message.reply_text(
            f"✅ **Icon Updated**\n\n"
            f"Package: `{package_name}`\n"
            f"New Icon: {icon}",
            parse_mode='Markdown'
        )
    
    elif action == "setcolor":
        if len(args) < 4:
            await update.message.reply_text(
                "❌ Usage: `/loginconfig <package> setcolor <type> <hex>`\n\n"
                "Types: primary, success, error, background, container",
                parse_mode='Markdown'
            )
            return
        color_type = args[2].lower()
        color_value = args[3]
        
        if "colors" not in login_config:
            login_config["colors"] = {}
        
        login_config["colors"][color_type] = color_value
        await save_keys_safe(API_KEYS)
        await update.message.reply_text(
            f"✅ **Color Updated**\n\n"
            f"Package: `{package_name}`\n"
            f"Type: **{color_type}**\n"
            f"Color: `{color_value}`",
            parse_mode='Markdown'
        )
    
    elif action == "autopaste":
        if len(args) < 3:
            await update.message.reply_text("❌ Usage: `/loginconfig <package> autopaste on/off`", parse_mode='Markdown')
            return
        value = args[2].lower() == "on"
        login_config["auto_paste"] = value
        await save_keys_safe(API_KEYS)
        await update.message.reply_text(
            f"✅ **Auto Paste {'Enabled' if value else 'Disabled'}**\n\n"
            f"Package: `{package_name}`\n"
            f"Auto paste from clipboard: **{'ON' if value else 'OFF'}**",
            parse_mode='Markdown'
        )
    
    elif action == "view":
        config_text = f"**📱 Login Config for {package_name}**\n\n"
        config_text += f"**Status:** {'✅ Enabled' if login_config.get('login_enabled', True) else '🚫 Disabled'}\n"
        config_text += f"**App Name:** {login_config.get('app_name', package_name)}\n"
        config_text += f"**Welcome:** {login_config.get('welcome_text', f'Welcome to {package_name}')}\n"
        config_text += f"**Icon:** {login_config.get('icon', '🔐')}\n"
        config_text += f"**Auto Paste:** {'ON' if login_config.get('auto_paste', False) else 'OFF'}\n\n"
        
        if "colors" in login_config:
            config_text += "**Colors:**\n"
            for color_type, color_value in login_config["colors"].items():
                config_text += f"• {color_type}: `{color_value}`\n"
        
        await update.message.reply_text(config_text, parse_mode='Markdown')
    
    else:
        await update.message.reply_text(
            f"❌ Unknown action: **{action}**\n\n"
            f"Use `/loginconfig` to see available actions",
            parse_mode='Markdown'
        )


async def loaddefaultoffsets_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Load default Lmjhed offsets - Usage: /loaddefaultoffsets [version]"""
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    
    args = context.args
    game_version = args[0] if args else "1.0.0"
    package_name = "Lmjhed"
    
    # Default Lmjhed offsets (ACTUAL offsets from Hooks.h - cleaned)
    DEFAULT_OFFSETS = {
        # Player & Match
        "GetLocalPlayer": "0x28FC854",
        "Curent_Match": "0x4E355B0",
        "name": "0x4A16D38",
        
        # Health & Status
        "GetHp": "0x4A8478C",
        "get_MaxHP": "0x4A8489C",
        "get_IsDieing": "0x4A02EA8",
        "get_isVisible": "0x4A20AF4",
        "get_IsJumping": "0x57A2C70",
        
        # Camera & Transform
        "get_camera": "0x84E7148",
        "Component_GetTransform": "0x854060C",
        "get_position": "0x8552BAC",
        "Transform_GetPosition": "0x8552C10",
        "Transform_SetPosition": "0x8552CE8",
        "Transform_SetRotation": "0x8553650",
        "WorldToViewpoint": "0x84E6AC8",
        "GetForward": "0x85534CC",
        
        # Body Parts
        "GetHeadPositions": "0x4AA1A28",
        "_GetHeadPositions": "0x4AA1A28",
        "Player_GetHeadCollider": "0x4A1A9D4",
        "_newHipMods": "0x4AA1BD8",
        "_GetLeftAnkleTF": "0x4AA2028",
        "_GetRightAnkleTF": "0x4AA2134",
        "_GetLeftToeTF": "0x4AA2240",
        "_GetRightToeTF": "0x4AA234C",
        "_getLeftHandTF": "0x4A1B9B4",
        "_getRightHandTF": "0x4A1BAB8",
        "_getLeftForeArmTF": "0x4A1BBBC",
        "_getRightForeArmTF": "0x4A1BCC0",
        
        # Combat & Weapons
        "get_IsSighting": "0x4A0FF18",
        "get_IsFiring": "0x4A05634",
        "set_aim": "0x4A1C91C",
        "SwapWeapon_Int": "0x4A8E050",
        "PlayerNetwork_StartFiring": "0x4D2C138",
        "PlayerNetwork_StopFire": "0x4D2CCEC",
        "Physics_Raycast": "0x5580870",
        
        # Camera Settings
        "get_fieldOfView": "0x84E4E8C",
        "set_fieldOfView": "0x84E4EDC",
        
        # Team
        "get_isLocalTeam": "0x4A38D90",
    }
    
    # Check if package exists, if not create it
    if "packages" not in API_KEYS:
        API_KEYS["packages"] = {}
    
    if package_name not in API_KEYS["packages"]:
        # Create package with token
        pkg_token = generate_package_token(package_name)
        API_KEYS["packages"][package_name] = {
            "security": {"anti_inject": True, "dylib_crash": False},
            "token": pkg_token
        }
        await update.message.reply_text(
            f"📦 Package **{package_name}** created automatically\n"
            f"Token: `{pkg_token}`\n\n"
            f"Loading offsets...",
            parse_mode='Markdown'
        )
    
    # Load offsets
    pkg_data = API_KEYS["packages"][package_name]
    if "offsets" not in pkg_data:
        pkg_data["offsets"] = {}
    
    pkg_data["offsets"][game_version] = DEFAULT_OFFSETS
    await save_keys_safe(API_KEYS)
    
    await update.message.reply_text(
        f"✅ **Default Offsets Loaded!**\n\n"
        f"Package: `{package_name}`\n"
        f"Version: `{game_version}`\n"
        f"Total Offsets: **{len(DEFAULT_OFFSETS)}**\n\n"
        f"**Loaded offsets include:**\n"
        f"• Player & Match (3 offsets)\n"
        f"• Health & Status (5 offsets)\n"
        f"• Camera & Transform (8 offsets)\n"
        f"• Body Parts (12 offsets)\n"
        f"• Combat & Weapons (7 offsets)\n"
        f"• Camera Settings (2 offsets)\n"
        f"• Team (1 offset)\n\n"
        f"💡 View offsets: `/offsets {package_name} {game_version}`\n"
        f"💡 Update offset: `/setoffset {package_name} {game_version} <name> <value>`",
        parse_mode='Markdown'
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    application = (
        ApplicationBuilder()
        .token(TELEGRAM_TOKEN)
        .get_updates_read_timeout(30)
        .get_updates_write_timeout(30)
        .get_updates_connect_timeout(30)
        .build()
    )

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("status", status_cmd))
    application.add_handler(CommandHandler("stop", stop_key_cmd))
    application.add_handler(CommandHandler("ban", ban_device_cmd))
    application.add_handler(CommandHandler("unban", unban_device_cmd))
    application.add_handler(CommandHandler("reset", reset_key_cmd))
    application.add_handler(CommandHandler("enableinject", enableinject_cmd))
    application.add_handler(CommandHandler("disabledinject", disabledinject_cmd))
    application.add_handler(CommandHandler("crashdylib", crashdylib_cmd))
    application.add_handler(CommandHandler("uncrashdylib", uncrashdylib_cmd))
    application.add_handler(CommandHandler("offsets", offsets_cmd))
    application.add_handler(CommandHandler("addoffsets", addoffsets_cmd))
    application.add_handler(CommandHandler("deleteoffsets", deleteoffsets_cmd))
    application.add_handler(CommandHandler("setoffset", setoffset_cmd))
    application.add_handler(CommandHandler("crashoffset", crashoffset_cmd))
    application.add_handler(CommandHandler("updateoffsets", updateoffsets_cmd))
    application.add_handler(CommandHandler("loaddefaultoffsets", loaddefaultoffsets_cmd))
    application.add_handler(CommandHandler("loginconfig", loginconfig_cmd))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    await application.initialize()
    await application.start()
    await application.updater.start_polling(
        allowed_updates=Update.ALL_TYPES,
        drop_pending_updates=True,
    )
    print("Telegram bot polling started successfully")

    yield

    await application.updater.stop()
    await application.stop()
    await application.shutdown()


app = FastAPI(title="API Server", lifespan=lifespan)


# --- Security Middleware ---
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"

    if not check_rate_limit(client_ip):
        print(f"[RATE LIMIT] Blocked IP: {client_ip}")
        return Response(
            content=json.dumps({"detail": "Too many requests. Try again later.", "ip": client_ip}),
            status_code=429,
            media_type="application/json"
        )

    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"

    return response


@app.get("/validate")
async def validate(
    request: Request, 
    api_key: str = Query(...), 
    device_id: str = Query(...),
    package_token: str = Query(None)  # Package identifier from app
):
    client_ip = request.client.host if request.client else "unknown"

    if not validate_api_key_format(api_key):
        print(f"[VALIDATE] Invalid format: Key={api_key}, IP={client_ip}")
        record_failed_attempt(client_ip)
        raise HTTPException(403, "Invalid key format (Allowed: a-z, A-Z, 0-9, _, -)")

    if not validate_device_id_format(device_id):
        print(f"[VALIDATE] Invalid Device Format: ID={device_id}, IP={client_ip}")
        record_failed_attempt(client_ip)
        raise HTTPException(403, "Invalid device ID format")

    if api_key not in API_KEYS or api_key in ["packages", "global_banned_devices"]:
        print(f"[VALIDATE] Key Not Found: {api_key}, IP={client_ip}")
        record_failed_attempt(client_ip)
        raise HTTPException(403, f"Key '{api_key}' not found in database")

    key_data = API_KEYS[api_key]
    
    # Validate package binding
    if package_token:
        if not validate_key_package_binding(api_key, package_token):
            print(f"[VALIDATE] Package Mismatch: Key={api_key}, Token={package_token}, IP={client_ip}")
            record_failed_attempt(client_ip)
            raise HTTPException(403, "Key does not belong to this package")
    
    now = datetime.now()

    if key_data.get("activation_time") is None or key_data.get("activation_time") == "Not Activated":
        key_data["activation_time"] = now.strftime("%Y-%m-%d %H:%M:%S")
        delta_sec = key_data.get("delta_seconds")
        if delta_sec is not None:
            expiry_dt = now + timedelta(seconds=delta_sec)
            key_data["expiry"] = expiry_dt.strftime("%Y-%m-%d %H:%M:%S")
        await save_keys_safe(API_KEYS)

    expiry_str = key_data.get("expiry")
    if not expiry_str or expiry_str == "Not Activated":
        print(f"[VALIDATE] Expiry Missing for Key: {api_key}")
        raise HTTPException(500, "Expiry date missing")

    expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
    if now > expiry_date:
        print(f"[VALIDATE] Key Expired: {api_key}, Expired at: {expiry_str}")
        raise HTTPException(403, f"Key expired on {expiry_str}")

    bound_devices = key_data.setdefault("bound_devices", [])
    banned_devices = key_data.get("banned_devices", [])
    global_banned = API_KEYS.get("global_banned_devices", [])
    max_users = key_data.get("max_users", 1)

    if device_id in global_banned or device_id in banned_devices:
        print(f"[VALIDATE] Banned Device: {device_id}, Key: {api_key}")
        raise HTTPException(403, "This device is banned")

    if device_id not in bound_devices:
        if len(bound_devices) >= max_users:
            print(f"[VALIDATE] Max Devices Reached: {api_key}, Devices: {len(bound_devices)}/{max_users}")
            raise HTTPException(403, f"Max devices reached ({max_users}). Please reset key.")
        bound_devices.append(device_id)
        await save_keys_safe(API_KEYS)

    remaining = expiry_date - now
    days = remaining.days
    hours, rem = divmod(remaining.seconds, 3600)
    minutes, _seconds = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    remaining_str = " ".join(parts) or "less than 1 minute"

    pkg_name = key_data.get("package", "Standard")

    nice_message = (
        f"Welcome to {pkg_name}!\n\n"
        f"Package: {pkg_name}\n"
        f"Expires at: {expiry_str}\n"
        f"Time left: {remaining_str}\n"
        f"Devices: {len(bound_devices)} / {max_users}"
    )

    print(f"[VALIDATE] Success: Key={api_key}, Device={device_id}")
    return {
        "status": "valid",
        "role": key_data.get("role", "user"),
        "activated_at": key_data.get("activation_time"),
        "expires_at": expiry_str,
        "remaining": remaining_str,
        "devices": f"{len(bound_devices)} / {max_users}",
        "package": pkg_name,
        "message": nice_message
    }


@app.get("/get-udid.mobileconfig")
async def generate_udid_profile(request: Request, api_key: str = Query(...)):
    if not validate_api_key_format(api_key):
        raise HTTPException(403, "Invalid key format")
    if api_key not in API_KEYS or api_key in ["packages", "global_banned_devices"]:
        raise HTTPException(403, "Invalid or unauthorized key")

    key_data = API_KEYS[api_key]
    pkg_name = key_data.get("package", "App")

    profile_uuid = str(uuid.uuid4()).upper()
    
    # Dynamically get host to avoid hardcoded URLs
    host = request.headers.get("host", "your-server-address")
    protocol = "https" if request.url.scheme == "https" else "http"
    base_url = f"{protocol}://{host}"

    plist_dict = {
        "PayloadContent": {
            "URL": f"{base_url}/receive-udid?api_key={api_key}",
            "DeviceAttributes": ["UDID", "SERIAL", "PRODUCT", "VERSION"]
        },
        "PayloadDescription": f"{pkg_name} Device Registration - Used for device activation",
        "PayloadDisplayName": f"{pkg_name} Device Registration",
        "PayloadIdentifier": f"com.app.udid.{profile_uuid}",
        "PayloadOrganization": pkg_name,
        "PayloadType": "Profile Service",
        "PayloadUUID": profile_uuid,
        "PayloadVersion": 1
    }

    plist_bytes = plistlib.dumps(plist_dict, fmt=plistlib.FMT_XML)

    return Response(
        content=plist_bytes,
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": f'attachment; filename="{pkg_name}-udid.mobileconfig"'}
    )


@app.post("/receive-udid")
async def receive_udid(request: Request, api_key: str = Query(...)):
    if not validate_api_key_format(api_key):
        raise HTTPException(403, "Invalid key format")
    if api_key not in API_KEYS:
        raise HTTPException(403, "Invalid key")

    try:
        body_bytes = await request.body()
        if len(body_bytes) > 10 * 1024:
            raise HTTPException(400, "Request body too large")

        xml_match = re.search(b'(<\\?xml.*?</plist>)', body_bytes, re.DOTALL)
        if not xml_match:
            raise HTTPException(400, "No plist XML found in response")

        xml_bytes = xml_match.group(1)
        received_plist = plistlib.loads(xml_bytes)

        udid = received_plist.get("UDID")
        if not udid:
            raise HTTPException(400, "UDID not found in plist")

        if not re.match(r'^[a-zA-Z0-9\-]{1,128}$', udid):
            raise HTTPException(400, "Invalid UDID format")

        key_data = API_KEYS[api_key]
        bound_devices = key_data.setdefault("bound_devices", [])
        if udid not in bound_devices:
            if len(bound_devices) >= key_data.get("max_users", 1):
                raise HTTPException(403, "Max devices reached for this key")
            bound_devices.append(udid)
            await save_keys_safe(API_KEYS)

        return Response(status_code=200, content=b"")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Processing error: {str(e)}")


@app.get("/security-config")
async def get_security_config(request: Request, api_key: str = Query(...)):
    client_ip = request.client.host if request.client else "unknown"

    if not validate_api_key_format(api_key):
        print(f"[SECURITY] Invalid format: {api_key}, IP={client_ip}")
        record_failed_attempt(client_ip)
        raise HTTPException(403, "Invalid key format")

    if api_key not in API_KEYS or api_key in ["packages", "global_banned_devices"]:
        print(f"[SECURITY] Key Not Found: {api_key}, IP={client_ip}")
        record_failed_attempt(client_ip)
        raise HTTPException(403, f"Key '{api_key}' not found")

    key_data = API_KEYS[api_key]
    pkg_name = key_data.get("package")

    if not pkg_name or pkg_name not in API_KEYS.get("packages", {}):
        base = dict(DEFAULT_SECURITY_CONFIG)
        base["dylib_crash"] = GLOBAL_DYLIB_CRASH["enabled"]
        return {"security": base}

    sec_config = get_package_security(pkg_name)
    print(f"[SECURITY] Success: Key={api_key}, Package={pkg_name}")
    return {"security": sec_config, "package": pkg_name}


@app.get("/login-config")
async def get_login_config(
    request: Request,
    package_token: str = Query(...)
):
    """
    Get dynamic login configuration for package
    Controls login screen appearance and behavior
    """
    client_ip = request.client.host if request.client else "unknown"
    
    # Find package by token
    pkg_name = None
    for name, data in API_KEYS.get("packages", {}).items():
        if data.get("token") == package_token:
            pkg_name = name
            break
    
    if not pkg_name:
        print(f"[LOGIN-CONFIG] Package not found for token, IP={client_ip}")
        raise HTTPException(404, "Package not found")
    
    pkg_data = API_KEYS["packages"][pkg_name]
    
    # Get login config or use defaults
    login_config = pkg_data.get("login_config", {})
    
    default_config = {
        "login_enabled": True,
        "package_name": pkg_name,
        "app_name": pkg_name,
        "welcome_text": f"Welcome to {pkg_name}",
        "subtitle": "Please enter your activation key",
        "button_text": "Activate",
        "paste_button_text": "📋 Paste",
        "colors": {
            "primary": "#3498db",
            "success": "#2ecc71",
            "error": "#e74c3c",
            "background": "#0a0a0a",
            "container": "#1a1a1a",
            "text": "#ffffff",
            "text_secondary": "#b0b0b0"
        },
        "icon": "🔐",
        "force_update": False,
        "min_version": "1.0.0",
        "show_paste_button": True,
        "auto_paste": False
    }
    
    # Merge with custom config
    final_config = {**default_config, **login_config}
    
    print(f"[LOGIN-CONFIG] Success: Package={pkg_name}, Enabled={final_config['login_enabled']}")
    return final_config


@app.get("/offsets")
async def get_offsets(
    request: Request,
    api_key: str = Query(...),
    device_id: str = Query(...),
    package_token: str = Query(...),
    game_version: str = Query(...)
):
    client_ip = request.client.host if request.client else "unknown"

    # Validate inputs
    if not validate_api_key_format(api_key):
        print(f"[OFFSETS] Invalid key format: {api_key}, IP={client_ip}")
        record_failed_attempt(client_ip)
        raise HTTPException(403, "Invalid key format")

    if not validate_device_id_format(device_id):
        print(f"[OFFSETS] Invalid device format: {device_id}, IP={client_ip}")
        record_failed_attempt(client_ip)
        raise HTTPException(403, "Invalid device ID format")

    # Check if key exists
    if api_key not in API_KEYS or api_key in ["packages", "global_banned_devices"]:
        print(f"[OFFSETS] Key not found: {api_key}, IP={client_ip}")
        record_failed_attempt(client_ip)
        raise HTTPException(403, "Key not found")

    key_data = API_KEYS[api_key]

    # Validate package binding
    if not validate_key_package_binding(api_key, package_token):
        print(f"[OFFSETS] Package mismatch: Key={api_key}, Token={package_token}, IP={client_ip}")
        record_failed_attempt(client_ip)
        raise HTTPException(403, "Key does not belong to this package")

    # Check if key is valid (not expired, not banned)
    expiry_str = key_data.get("expiry")
    if expiry_str and expiry_str != "Not Activated":
        try:
            expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
            if datetime.now() > expiry_date:
                print(f"[OFFSETS] Key expired: {api_key}")
                raise HTTPException(403, "Key expired")
        except ValueError:
            pass

    # Check if device is banned
    banned_devices = key_data.get("banned_devices", [])
    global_banned = API_KEYS.get("global_banned_devices", [])
    if device_id in global_banned or device_id in banned_devices:
        print(f"[OFFSETS] Banned device: {device_id}, Key={api_key}")
        raise HTTPException(403, "Device is banned")

    # Get package name
    pkg_name = key_data.get("package", "default")

    # Get offsets for this game version
    offsets_data = get_offsets_for_version(pkg_name, game_version)

    if not offsets_data:
        print(f"[OFFSETS] No offsets for version: {game_version}, Package={pkg_name}")
        raise HTTPException(404, f"No offsets available for game version {game_version}")

    print(f"[OFFSETS] Success: Key={api_key}, Version={game_version}, Package={pkg_name}")
    return {
        "success": True,
        "game_version": game_version,
        "package": pkg_name,
        "offsets": offsets_data
    }


def get_offsets_for_version(package_name: str, game_version: str) -> dict:
    """
    Get offsets for specific game version and package
    Offsets are stored in packages data structure
    """
    pkg_data = API_KEYS.get("packages", {}).get(package_name, {})
    offsets_db = pkg_data.get("offsets", {})
    
    # Try to get offsets for specific version
    if game_version in offsets_db:
        return offsets_db[game_version]
    
    # Try to get default offsets
    if "default" in offsets_db:
        return offsets_db["default"]
    
    # Return empty if no offsets configured
    return {}


@app.post("/admin/set-offsets")
async def set_offsets(
    request: Request,
    package_name: str = Query(...),
    game_version: str = Query(...),
    admin_key: str = Query(...)
):
    """
    Admin endpoint to set offsets for a package and game version
    Usage: POST /admin/set-offsets?package_name=Lmjhed&game_version=1.0.0&admin_key=skam_admin_key
    Body: JSON with offsets
    """
    # Verify admin key
    if admin_key != "skam_admin_key":
        raise HTTPException(403, "Unauthorized")

    # Check if package exists
    if package_name not in API_KEYS.get("packages", {}):
        raise HTTPException(404, f"Package {package_name} not found")

    # Get request body
    try:
        body = await request.json()
        offsets = body.get("offsets", {})
    except Exception as e:
        raise HTTPException(400, f"Invalid JSON: {str(e)}")

    if not offsets or not isinstance(offsets, dict):
        raise HTTPException(400, "Offsets must be a dictionary")

    # Store offsets
    pkg_data = API_KEYS["packages"][package_name]
    if "offsets" not in pkg_data:
        pkg_data["offsets"] = {}
    
    pkg_data["offsets"][game_version] = offsets
    await save_keys_safe(API_KEYS)

    print(f"[ADMIN] Set {len(offsets)} offsets for {package_name} v{game_version}")
    return {
        "success": True,
        "message": f"Set {len(offsets)} offsets for {package_name} version {game_version}",
        "package": package_name,
        "game_version": game_version,
        "offset_count": len(offsets)
    }


@app.get("/health")
async def health_check():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


# ========================================
# iOS APP DASHBOARD API ENDPOINTS
# ========================================

# JWT Configuration for iOS App
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION = 48  # hours

# ── Dashboard Users (admin/reseller/developer) ──────────
# Stored in dashboard_users.json — created on first run
DASHBOARD_USERS_FILE = "dashboard_users.json"
DEV_CONTROL_FILE     = "dev_control.json"

ROLE_LEVEL = {"developer": 4, "admin": 3, "reseller": 2, "user": 1}

def load_dashboard_users() -> dict:
    if os.path.exists(DASHBOARD_USERS_FILE):
        try:
            with open(DASHBOARD_USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    # Default: developer (OSM) + admin
    default = {
        "users": [
            {
                "id": secrets.token_hex(16),
                "username": "osm",
                "password": hashlib.sha256("Dox".encode()).hexdigest(),
                "role": "developer",
                "status": "active",
                "expires_at": None,
                "created_at": datetime.now().isoformat()
            },
            {
                "id": secrets.token_hex(16),
                "username": "admin",
                "password": hashlib.sha256("admin123".encode()).hexdigest(),
                "role": "admin",
                "status": "active",
                "expires_at": None,
                "created_at": datetime.now().isoformat()
            }
        ]
    }
    with open(DASHBOARD_USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(default, f, indent=4)
    print("✅ dashboard_users.json created")
    print("   Developer: osm / osm_dev_2026")
    print("   Admin:     admin / admin123")
    return default

def save_dashboard_users(data: dict):
    with open(DASHBOARD_USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def load_dev_control() -> dict:
    if os.path.exists(DEV_CONTROL_FILE):
        try:
            with open(DEV_CONTROL_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    default = {
        "admin_enabled":    True,
        "reseller_enabled": True,
        "maintenance_msg":  "Service temporarily disabled by developer."
    }
    with open(DEV_CONTROL_FILE, "w", encoding="utf-8") as f:
        json.dump(default, f, indent=4)
    return default

def save_dev_control(data: dict):
    with open(DEV_CONTROL_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def is_role_enabled(role: str) -> bool:
    if role == "developer":
        return True
    ctrl = load_dev_control()
    if role == "admin":
        return ctrl.get("admin_enabled", True)
    if role == "reseller":
        return ctrl.get("reseller_enabled", True)
    return True

# Initialize on startup
DASHBOARD_USERS = load_dashboard_users()

# Simple token storage (if JWT not available)
ACTIVE_TOKENS = {}


def generate_jwt_token(user_id: str, username: str, role: str) -> str:
    """Generate JWT token for iOS app"""
    if JWT_AVAILABLE:
        payload = {
            'user_id':  user_id,
            'username': username,
            'role':     role,
            'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION)
        }
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    else:
        token = secrets.token_hex(32)
        ACTIVE_TOKENS[token] = {
            'user_id':  user_id,
            'username': username,
            'role':     role,
            'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION)
        }
        return token


def verify_jwt_token(token: str) -> dict:
    """Verify JWT token"""
    if JWT_AVAILABLE:
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    else:
        if token in ACTIVE_TOKENS:
            token_data = ACTIVE_TOKENS[token]
            if datetime.utcnow() < token_data['exp']:
                return token_data
            else:
                del ACTIVE_TOKENS[token]
        return None


def get_current_user(request: Request):
    """Get current user from Authorization header"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        raise HTTPException(status_code=401, detail="No token provided")
    token = auth_header[7:]
    payload = verify_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload

def require_role(request: Request, min_role: str):
    """Verify token and require minimum role level"""
    user = get_current_user(request)
    role = user.get("role", "user")
    if ROLE_LEVEL.get(role, 0) < ROLE_LEVEL.get(min_role, 0):
        raise HTTPException(status_code=403, detail=f"Requires {min_role} role or higher")
    return user

def require_developer(request: Request):
    return require_role(request, "developer")

def require_admin(request: Request):
    return require_role(request, "admin")


# --- Authentication Endpoints ---

@app.post("/api/auth/login")
async def ios_login(request: Request):
    """iOS App Login — supports developer/admin/reseller"""
    try:
        data     = await request.json()
        username = (data.get('username') or "").strip()
        password = data.get('password') or ""

        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password required")

        users_db = load_dashboard_users()
        user = next((u for u in users_db["users"] if u["username"] == username), None)

        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        if user["password"] != pw_hash:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        if user.get("status") not in ("active",):
            raise HTTPException(status_code=403, detail="Account is disabled")

        role = user.get("role", "user")

        # ── Check expiry (set by developer) ──
        expires_at = user.get("expires_at")
        if expires_at:
            try:
                exp_dt = datetime.fromisoformat(expires_at[:19])
                if datetime.now() > exp_dt:
                    user["status"] = "inactive"
                    save_dashboard_users(users_db)
                    raise HTTPException(status_code=403, detail="Account has expired. Contact the developer.")
            except HTTPException:
                raise
            except Exception:
                pass

        # ── Developer kill-switch ──
        if role != "developer" and not is_role_enabled(role):
            ctrl = load_dev_control()
            msg  = ctrl.get("maintenance_msg", "Access disabled by developer.")
            raise HTTPException(status_code=403, detail=msg)

        # Update last login
        user["last_login"] = datetime.now().isoformat()
        save_dashboard_users(users_db)

        token = generate_jwt_token(user["id"], username, role)

        return {
            "success": True,
            "token": token,
            "user": {
                "id":       user["id"],
                "username": username,
                "role":     role
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/auth/logout")
async def ios_logout(request: Request):
    get_current_user(request)
    return {"success": True, "message": "Logged out successfully"}


@app.get("/api/auth/verify")
async def ios_verify(request: Request):
    user = get_current_user(request)
    return {"success": True, "user": {"id": user.get("user_id"), "username": user["username"], "role": user.get("role", "user")}}


# --- Users Management (Admin + Developer) ---

@app.get("/api/users")
async def ios_get_users(request: Request):
    require_admin(request)
    users_db = load_dashboard_users()
    safe = [{k: v for k, v in u.items() if k != "password"} for u in users_db["users"]]
    return {"success": True, "users": safe}

@app.post("/api/auth/register")
async def ios_register(request: Request):
    """Create new dashboard user (admin or developer only)"""
    caller = require_admin(request)
    try:
        data     = await request.json()
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        role     = data.get("role", "user")

        if not username or not password:
            raise HTTPException(400, "Username and password required")
        if len(password) < 6:
            raise HTTPException(400, "Password must be at least 6 characters")

        # Role guard: only developer can create admin/reseller
        caller_role = caller.get("role", "user")
        if ROLE_LEVEL.get(role, 0) >= ROLE_LEVEL.get(caller_role, 0) and caller_role != "developer":
            raise HTTPException(403, "Cannot create user with equal or higher role")

        users_db = load_dashboard_users()
        if any(u["username"] == username for u in users_db["users"]):
            raise HTTPException(400, "Username already exists")

        expires_at = data.get("expires_at")  # ISO string set by developer

        new_user = {
            "id":         secrets.token_hex(16),
            "username":   username,
            "password":   hashlib.sha256(password.encode()).hexdigest(),
            "role":       role,
            "status":     "active",
            "expires_at": expires_at,
            "created_at": datetime.now().isoformat(),
            "last_login": None
        }
        users_db["users"].append(new_user)
        save_dashboard_users(users_db)

        return {"success": True, "user_id": new_user["id"]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))

@app.put("/api/users/{uid}")
async def ios_update_user(request: Request, uid: str):
    caller = require_admin(request)
    try:
        data = await request.json()
        users_db = load_dashboard_users()
        user = next((u for u in users_db["users"] if u["id"] == uid), None)
        if not user:
            raise HTTPException(404, "User not found")

        caller_role = caller.get("role", "user")
        if ROLE_LEVEL.get(user.get("role","user"), 0) >= ROLE_LEVEL.get(caller_role, 0) and caller_role != "developer":
            raise HTTPException(403, "Cannot edit user with equal or higher role")

        for field in ("email", "role", "status", "expires_at"):
            if field in data:
                user[field] = data[field]
        if data.get("password"):
            user["password"] = hashlib.sha256(data["password"].encode()).hexdigest()

        save_dashboard_users(users_db)
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))

@app.delete("/api/users/{uid}")
async def ios_delete_user(request: Request, uid: str):
    caller = require_admin(request)
    users_db = load_dashboard_users()
    user = next((u for u in users_db["users"] if u["id"] == uid), None)
    if not user:
        raise HTTPException(404, "User not found")
    if user.get("role") == "developer":
        raise HTTPException(403, "Cannot delete developer account")
    caller_role = caller.get("role", "user")
    if ROLE_LEVEL.get(user.get("role","user"), 0) >= ROLE_LEVEL.get(caller_role, 0) and caller_role != "developer":
        raise HTTPException(403, "Cannot delete user with equal or higher role")
    users_db["users"] = [u for u in users_db["users"] if u["id"] != uid]
    save_dashboard_users(users_db)
    return {"success": True}


# --- Developer Control Endpoints ---

@app.get("/api/developer/dashboard-status")
async def ios_get_dashboard_status(request: Request):
    """Developer only: get role enable/disable status"""
    require_developer(request)
    ctrl = load_dev_control()
    return {
        "success":          True,
        "admin_enabled":    ctrl.get("admin_enabled", True),
        "reseller_enabled": ctrl.get("reseller_enabled", True),
        "maintenance_msg":  ctrl.get("maintenance_msg", "")
    }

@app.post("/api/developer/dashboard-status")
async def ios_set_dashboard_status(request: Request):
    """Developer only: enable/disable a role entirely (blocks login)"""
    require_developer(request)
    try:
        data = await request.json()
        role = (data.get("role") or "").lower()
        if role not in ("admin", "reseller"):
            raise HTTPException(400, "Role must be 'admin' or 'reseller'")

        ctrl    = load_dev_control()
        enabled = bool(data.get("enabled", True))

        if role == "admin":
            ctrl["admin_enabled"] = enabled
        elif role == "reseller":
            ctrl["reseller_enabled"] = enabled

        if "maintenance_msg" in data:
            ctrl["maintenance_msg"] = data["maintenance_msg"]

        save_dev_control(ctrl)
        return {"success": True, "admin_enabled": ctrl["admin_enabled"], "reseller_enabled": ctrl["reseller_enabled"]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/developer/set-message")
async def ios_set_maintenance_message(request: Request):
    """Developer only: set message shown to blocked users"""
    require_developer(request)
    try:
        data = await request.json()
        msg  = (data.get("message") or "").strip()
        if not msg:
            raise HTTPException(400, "Message required")
        ctrl = load_dev_control()
        ctrl["maintenance_msg"] = msg
        save_dev_control(ctrl)
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))



@app.get("/api/stats")
async def ios_get_stats(request: Request):
    """Get system statistics for iOS App"""
    get_current_user(request)  # Verify token

    # Count keys (excluding special keys)
    all_keys = [k for k in API_KEYS.keys() if k not in ["packages", "global_banned_devices"] and isinstance(API_KEYS[k], dict)]
    active_keys = [k for k in all_keys if API_KEYS[k].get("expiry") != "Not Activated"]
    banned_keys = [k for k in all_keys if API_KEYS[k].get("banned") is True]

    total_packages = len(API_KEYS.get("packages", {}))

    total_devices = 0
    for k in all_keys:
        total_devices += len(API_KEYS[k].get("bound_devices", []))

    # Dashboard users stats
    users_db = load_dashboard_users()
    admin_count    = len([u for u in users_db["users"] if u.get("role") == "admin"])
    reseller_count = len([u for u in users_db["users"] if u.get("role") == "reseller"])

    return {
        "success": True,
        "stats": {
            "total_users":    len(users_db["users"]),
            "active_users":   len([u for u in users_db["users"] if u.get("status") == "active"]),
            "admin_users":    admin_count,
            "reseller_users": reseller_count,
            "total_packages": total_packages,
            "total_keys":     len(all_keys),
            "active_keys":    len(active_keys),
            "banned_keys":    len(banned_keys),
            "total_devices":  total_devices,
            "banned_devices": len(API_KEYS.get("global_banned_devices", []))
        }
    }



@app.get("/api/packages")
async def ios_get_packages(request: Request):
    """Get all packages for iOS App"""
    get_current_user(request)  # Verify token
    
    packages = []
    for pkg_name, pkg_data in API_KEYS.get("packages", {}).items():
        packages.append({
            "id": pkg_name,
            "name": pkg_name,
            "token": pkg_data.get("token", ""),
            "security": pkg_data.get("security", {}),
            "login_config": pkg_data.get("login_config", {}),
            "offsets_count": sum(len(v) for v in pkg_data.get("offsets", {}).values())
        })
    
    return {"success": True, "packages": packages}


@app.post("/api/packages")
async def ios_create_package(request: Request):
    """Create new package from iOS App"""
    get_current_user(request)  # Verify token
    
    try:
        data = await request.json()
        name = data.get('name')
        
        if not name:
            raise HTTPException(status_code=400, detail="Package name required")
        
        if name in API_KEYS.get("packages", {}):
            raise HTTPException(status_code=400, detail="Package already exists")
        
        # Generate token
        pkg_token = generate_package_token(name)
        
        # Create package
        if "packages" not in API_KEYS:
            API_KEYS["packages"] = {}
        
        API_KEYS["packages"][name] = {
            "security": {"anti_inject": True, "dylib_crash": False},
            "token": pkg_token,
            "login_config": {
                "login_enabled": data.get('login_enabled', True),
                "app_name": data.get('app_name', name),
                "welcome_text": data.get('welcome_message', f'Welcome to {name}'),
                "icon": data.get('icon_emoji', '🎮'),
                "colors": {
                    "primary": data.get('primary_color', '#2196F3')
                }
            }
        }
        
        await save_keys_safe(API_KEYS)
        
        return {
            "success": True,
            "message": "Package created successfully",
            "package": {
                "id": name,
                "name": name,
                "token": pkg_token,
                "security": API_KEYS["packages"][name]["security"],
                "login_config": API_KEYS["packages"][name]["login_config"]
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/api/packages/{package_id}")
async def ios_update_package(request: Request, package_id: str):
    """Update package from iOS App"""
    get_current_user(request)  # Verify token
    
    if "packages" not in API_KEYS or package_id not in API_KEYS["packages"]:
        raise HTTPException(status_code=404, detail="Package not found")
    
    try:
        data = await request.json()
        pkg_data = API_KEYS["packages"][package_id]
        
        # Update fields
        if 'name' in data and data['name'] != package_id:
            # Rename package
            new_name = data['name']
            API_KEYS["packages"][new_name] = pkg_data
            del API_KEYS["packages"][package_id]
            package_id = new_name
        
        if 'security' in data:
            pkg_data['security'].update(data['security'])
        
        if 'login_config' in data:
            if 'login_config' not in pkg_data:
                pkg_data['login_config'] = {}
            pkg_data['login_config'].update(data['login_config'])
        
        await save_keys_safe(API_KEYS)
        
        return {"success": True, "message": "Package updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/packages/{package_id}")
async def ios_delete_package(request: Request, package_id: str):
    """Delete package from iOS App"""
    get_current_user(request)  # Verify token
    
    if "packages" not in API_KEYS or package_id not in API_KEYS["packages"]:
        raise HTTPException(status_code=404, detail="Package not found")
    
    # Delete all keys for this package
    keys_to_delete = [
        k for k, d in API_KEYS.items()
        if k not in ["packages", "global_banned_devices"]
        and isinstance(d, dict) and d.get("package") == package_id
    ]
    
    for k in keys_to_delete:
        del API_KEYS[k]
    
    del API_KEYS["packages"][package_id]
    await save_keys_safe(API_KEYS)
    
    return {"success": True, "message": "Package deleted successfully"}


@app.post("/api/packages/{package_id}/activate")
async def ios_activate_package(request: Request, package_id: str):
    """Activate package"""
    get_current_user(request)  # Verify token
    
    if "packages" not in API_KEYS or package_id not in API_KEYS["packages"]:
        raise HTTPException(status_code=404, detail="Package not found")
    
    pkg_data = API_KEYS["packages"][package_id]
    pkg_data["status"] = "active"
    await save_keys_safe(API_KEYS)
    
    return {"success": True, "message": "Package activated"}


@app.post("/api/packages/{package_id}/deactivate")
async def ios_deactivate_package(request: Request, package_id: str):
    """Deactivate package"""
    get_current_user(request)  # Verify token
    
    if "packages" not in API_KEYS or package_id not in API_KEYS["packages"]:
        raise HTTPException(status_code=404, detail="Package not found")
    
    pkg_data = API_KEYS["packages"][package_id]
    pkg_data["status"] = "inactive"
    await save_keys_safe(API_KEYS)
    
    return {"success": True, "message": "Package deactivated"}


@app.post("/api/packages/{package_id}/anti-inject")
async def ios_toggle_anti_inject(request: Request, package_id: str):
    """Toggle anti-inject for package"""
    get_current_user(request)  # Verify token
    
    if "packages" not in API_KEYS or package_id not in API_KEYS["packages"]:
        raise HTTPException(status_code=404, detail="Package not found")
    
    try:
        data = await request.json()
        enabled = data.get('enabled', True)
        
        pkg_data = API_KEYS["packages"][package_id]
        if "security" not in pkg_data:
            pkg_data["security"] = {}
        
        pkg_data["security"]["anti_inject"] = enabled
        pkg_data["security"]["dylib_crash"] = not enabled  # If anti_inject off, dylib_crash on
        
        await save_keys_safe(API_KEYS)
        
        return {
            "success": True,
            "message": f"Anti-inject {'enabled' if enabled else 'disabled'}",
            "anti_inject": enabled
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/crash/global")
async def ios_toggle_global_crash(request: Request):
    """Toggle global crash"""
    get_current_user(request)  # Verify token
    
    try:
        data = await request.json()
        enabled = data.get('enabled', False)
        
        GLOBAL_DYLIB_CRASH["enabled"] = enabled
        
        return {
            "success": True,
            "message": f"Global crash {'enabled' if enabled else 'disabled'}",
            "enabled": enabled
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/crash/global")
async def ios_get_global_crash(request: Request):
    """Get global crash status"""
    get_current_user(request)  # Verify token
    
    return {
        "success": True,
        "enabled": GLOBAL_DYLIB_CRASH.get("enabled", False)
    }



# --- Reseller Endpoints ---
@app.post("/api/resellers")
async def create_reseller(request: Request):
    caller = get_current_user(request)
    if caller.get("role") != "admin":
        raise HTTPException(403, "Only admin can create resellers")
    
    data = await request.json()
    reseller_id = data.get("reseller_id")
    quota = data.get("quota", 50)
    permissions = data.get("permissions", ["pkg_death", "reset_key", "delete_key", "ban", "unban"])
    
    if not reseller_id:
        raise HTTPException(400, "reseller_id is required")
        
    if "resellers" not in API_KEYS:
        API_KEYS["resellers"] = {}
        
    if reseller_id in API_KEYS["resellers"]:
        raise HTTPException(400, "Reseller already exists")
        
    API_KEYS["resellers"][reseller_id] = {
        "quota": quota,
        "used_quota": 0,
        "permissions": permissions,
        "activity_log": []
    }
    await save_keys_safe(API_KEYS)
    return {"success": True, "message": "Reseller created"}

@app.get("/api/resellers/{reseller_id}/activity")
async def get_reseller_activity(request: Request, reseller_id: str):
    caller = get_current_user(request)
    if caller.get("role") != "admin" and caller.get("user_id") != reseller_id:
        raise HTTPException(403, "Unauthorized")
        
    if "resellers" not in API_KEYS or reseller_id not in API_KEYS["resellers"]:
        raise HTTPException(404, "Reseller not found")
        
    reseller = API_KEYS["resellers"][reseller_id]
    return {
        "success": True, 
        "quota": reseller.get("quota"),
        "used_quota": reseller.get("used_quota"),
        "activity": reseller.get("activity_log", [])
    }


@app.get("/api/resellers/status")
async def get_my_status(request: Request):
    caller = get_current_user(request)
    reseller_id = caller.get("user_id")
    
    if "resellers" not in API_KEYS or reseller_id not in API_KEYS["resellers"]:
        raise HTTPException(404, "Reseller data not found")
        
    reseller = API_KEYS["resellers"][reseller_id]
    
    # Get keys created by this reseller
    my_keys = []
    for k, d in API_KEYS.items():
        if isinstance(d, dict) and d.get("created_by_id") == reseller_id:
            my_keys.append({
                "key": k,
                "package": d.get("package"),
                "expiry": d.get("expiry"),
                "devices": len(d.get("bound_devices", [])),
                "max_users": d.get("max_users")
            })
            
    return {
        "success": True,
        "reseller_id": reseller_id,
        "quota": reseller.get("quota"),
        "used_quota": reseller.get("used_quota"),
        "remaining_quota": reseller.get("quota", 0) - reseller.get("used_quota", 0),
        "permissions": reseller.get("permissions"),
        "keys_count": len(my_keys),
        "keys": my_keys,
        "activity": reseller.get("activity_log", [])[-20:] # Last 20 activities
    }

# --- Keys Endpoints ---

@app.get("/api/keys")
async def ios_get_keys(request: Request):
    """Get keys — reseller sees only their own keys"""
    caller = get_current_user(request)
    caller_role = caller.get("role", "user")
    caller_id   = caller.get("user_id", "")

    keys = []
    for key_name, key_data in API_KEYS.items():
        if key_name in ["packages", "global_banned_devices"]:
            continue
        if not isinstance(key_data, dict):
            continue

        # Reseller sees only keys they created
        if caller_role == "reseller" and key_data.get("created_by_id") != caller_id:
            continue

        status = "active"
        if key_data.get("banned"):
            status = "banned"
        elif key_data.get("expiry") == "Not Activated":
            status = "inactive"
        elif key_data.get("expiry"):
            try:
                exp = datetime.strptime(key_data["expiry"], "%Y-%m-%d %H:%M:%S")
                if datetime.now() > exp:
                    status = "expired"
            except Exception:
                pass

        keys.append({
            "id":           key_name,
            "key":          key_name,
            "package_name": key_data.get("package", ""),
            "status":       status,
            "expiry_date":  key_data.get("expiry", "Not Activated"),
            "max_users":    key_data.get("max_users", 1),
            "bound_devices":len(key_data.get("bound_devices", [])),
            "duration":     key_data.get("duration", ""),
            "created_by":   key_data.get("created_by", "")
        })

    return {"success": True, "keys": keys}


@app.post("/api/keys")
async def ios_create_key(request: Request):
    """Create new key — reseller and above"""
    caller = get_current_user(request)
    caller_role = caller.get("role", "user")
    if ROLE_LEVEL.get(caller_role, 0) < ROLE_LEVEL.get("reseller", 0):
        raise HTTPException(403, "Requires reseller role or higher")

    try:
        data = await request.json()
        package_name = data.get('package_name')
        duration_days = int(data.get('duration_days', 30))

        if not package_name:
            raise HTTPException(status_code=400, detail="Package name required")
        if "packages" not in API_KEYS or package_name not in API_KEYS["packages"]:
            raise HTTPException(status_code=400, detail="Package not found")

        alias = data.get('alias')
        if alias:
            new_key = f"{package_name.upper()}-{alias}"
            if new_key in API_KEYS:
                raise HTTPException(400, "Alias already exists")
        else:
            new_key = f"{package_name.upper()}-{secrets.token_hex(6).upper()}"
            
        # Check Reseller Quota and Permissions
        if caller_role == "reseller":
            reseller_id = caller.get("user_id")
            if "resellers" in API_KEYS and reseller_id in API_KEYS["resellers"]:
                reseller = API_KEYS["resellers"][reseller_id]
                if reseller.get("used_quota", 0) >= reseller.get("quota", 0):
                    raise HTTPException(403, "Quota exceeded")
                if f"pkg_{package_name}" not in reseller.get("permissions", []):
                    raise HTTPException(403, f"No permission for package {package_name}")
                
                reseller["used_quota"] = reseller.get("used_quota", 0) + 1
                reseller.setdefault("activity_log", []).append({
                    "action": "create_key",
                    "key": new_key,
                    "timestamp": datetime.now().isoformat()
                })

        # Exact time calculation
        duration_str = f"{duration_days}d"
        delta_sec = int(duration_days * 24 * 60 * 60)

        API_KEYS[new_key] = {
            "role":           "user",
            "duration":       duration_str,
            "delta_seconds":  delta_sec,
            "activation_time":None,
            "expiry":         "Not Activated",
            "bound_devices":  [],
            "max_users":      data.get('max_users', 1),
            "package":        package_name,
            "banned_devices": [],
            "created_by":     caller.get("username", ""),
            "created_by_id":  caller.get("user_id", "")
        }

        await save_keys_safe(API_KEYS)

        return {
            "success": True,
            "message": "Key created successfully",
            "key": {
                "id":           new_key,
                "key":          new_key,
                "package_name": package_name,
                "status":       "inactive",
                "expiry_date":  "Not Activated",
                "max_users":    data.get('max_users', 1),
                "duration":     duration_str
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/api/keys/{key_id}")
async def ios_update_key(request: Request, key_id: str):
    """Update key from iOS App"""
    get_current_user(request)  # Verify token
    
    if key_id not in API_KEYS or key_id in ["packages", "global_banned_devices"]:
        raise HTTPException(status_code=404, detail="Key not found")
    
    try:
        data = await request.json()
        key_data = API_KEYS[key_id]
        
        # Update status (ban/unban)
        if 'status' in data:
            if data['status'] == 'banned':
                # Ban all devices
                for device in key_data.get("bound_devices", []):
                    if device not in key_data.get("banned_devices", []):
                        key_data.setdefault("banned_devices", []).append(device)
            elif data['status'] == 'active':
                # Unban all devices
                key_data["banned_devices"] = []
        
        # Update duration
        if 'duration_days' in data:
            duration_days = data['duration_days']
            duration_str = f"{duration_days}d"
            delta_sec = duration_days * 24 * 60 * 60
            key_data["duration"] = duration_str
            key_data["delta_seconds"] = delta_sec
            
            # Recalculate expiry if already activated
            if key_data.get("activation_time"):
                activation_time = datetime.fromisoformat(key_data["activation_time"])
                expiry_time = activation_time + timedelta(seconds=delta_sec)
                key_data["expiry"] = expiry_time.strftime("%Y-%m-%d %H:%M:%S")
        
        await save_keys_safe(API_KEYS)
        
        return {"success": True, "message": "Key updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/keys/{key_id}")
async def ios_delete_key(request: Request, key_id: str):
    """Delete key from iOS App"""
    get_current_user(request)  # Verify token
    
    if key_id not in API_KEYS or key_id in ["packages", "global_banned_devices"]:
        raise HTTPException(status_code=404, detail="Key not found")
    
    if key_id == "skam_admin_key":
        raise HTTPException(status_code=403, detail="Cannot delete admin key")
        
    caller = get_current_user(request)
    if caller.get("role") == "reseller":
        reseller_id = caller.get("user_id")
        if "resellers" in API_KEYS and reseller_id in API_KEYS["resellers"]:
            reseller = API_KEYS["resellers"][reseller_id]
            if "delete_key" not in reseller.get("permissions", []):
                raise HTTPException(403, "No permission to delete keys")
            reseller.setdefault("activity_log", []).append({
                "action": "delete_key",
                "key": key_id,
                "timestamp": datetime.now().isoformat()
            })
    
    del API_KEYS[key_id]
    await save_keys_safe(API_KEYS)
    
    return {"success": True, "message": "Key deleted successfully"}


@app.post("/api/keys/{key_id}/reset")
async def ios_reset_key(request: Request, key_id: str):
    """Reset key devices"""
    get_current_user(request)  # Verify token
    
    if key_id not in API_KEYS or key_id in ["packages", "global_banned_devices"]:
        raise HTTPException(status_code=404, detail="Key not found")
    
    caller = get_current_user(request)
    if caller.get("role") == "reseller":
        reseller_id = caller.get("user_id")
        if "resellers" in API_KEYS and reseller_id in API_KEYS["resellers"]:
            reseller = API_KEYS["resellers"][reseller_id]
            if "reset_key" not in reseller.get("permissions", []):
                raise HTTPException(403, "No permission to reset keys")
            reseller.setdefault("activity_log", []).append({
                "action": "reset_key",
                "key": key_id,
                "timestamp": datetime.now().isoformat()
            })

    key_data = API_KEYS[key_id]
    old_devices = len(key_data.get("bound_devices", []))
    key_data["bound_devices"] = []
    
    await save_keys_safe(API_KEYS)
    
    return {
        "success": True,
        "message": f"Key reset successfully. {old_devices} device(s) removed."
    }


@app.post("/api/keys/{key_id}/ban")
async def ios_ban_key(request: Request, key_id: str):
    """Ban key with custom message"""
    get_current_user(request)  # Verify token
    
    if key_id not in API_KEYS or key_id in ["packages", "global_banned_devices"]:
        raise HTTPException(status_code=404, detail="Key not found")
    
    try:
        data = await request.json()
        ban_message = data.get('message', 'Banned by admin')
        
        caller = get_current_user(request)
        if caller.get("role") == "reseller":
            reseller_id = caller.get("user_id")
            if "resellers" in API_KEYS and reseller_id in API_KEYS["resellers"]:
                reseller = API_KEYS["resellers"][reseller_id]
                if "ban" not in reseller.get("permissions", []):
                    raise HTTPException(403, "No permission to ban keys")
                reseller.setdefault("activity_log", []).append({
                    "action": "ban_key",
                    "key": key_id,
                    "timestamp": datetime.now().isoformat()
                })

        key_data = API_KEYS[key_id]
        key_data["banned"] = True
        key_data["ban_message"] = ban_message
        
        # Ban all devices
        for device in key_data.get("bound_devices", []):
            if device not in key_data.get("banned_devices", []):
                key_data.setdefault("banned_devices", []).append(device)
        
        await save_keys_safe(API_KEYS)
        
        return {
            "success": True,
            "message": "Key banned successfully",
            "ban_message": ban_message
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/keys/{key_id}/unban")
async def ios_unban_key(request: Request, key_id: str):
    """Unban key"""
    get_current_user(request)  # Verify token
    
    if key_id not in API_KEYS or key_id in ["packages", "global_banned_devices"]:
        raise HTTPException(status_code=404, detail="Key not found")
    
    caller = get_current_user(request)
    if caller.get("role") == "reseller":
        reseller_id = caller.get("user_id")
        if "resellers" in API_KEYS and reseller_id in API_KEYS["resellers"]:
            reseller = API_KEYS["resellers"][reseller_id]
            if "unban" not in reseller.get("permissions", []):
                raise HTTPException(403, "No permission to unban keys")
            reseller.setdefault("activity_log", []).append({
                "action": "unban_key",
                "key": key_id,
                "timestamp": datetime.now().isoformat()
            })

    key_data = API_KEYS[key_id]
    key_data["banned"] = False
    key_data["ban_message"] = ""
    key_data["banned_devices"] = []
    
    await save_keys_safe(API_KEYS)
    
    return {"success": True, "message": "Key unbanned successfully"}


@app.post("/api/keys/{key_id}/pause")
async def ios_pause_key(request: Request, key_id: str):
    """Pause / resume a key (freezes expiry countdown)"""
    get_current_user(request)
    if key_id not in API_KEYS or key_id in ["packages", "global_banned_devices"]:
        raise HTTPException(status_code=404, detail="Key not found")
    key_data = API_KEYS[key_id]
    paused = not key_data.get("paused", False)
    key_data["paused"] = paused
    await save_keys_safe(API_KEYS)
    return {"success": True, "paused": paused,
            "message": "Key paused" if paused else "Key resumed"}


@app.post("/api/keys/{key_id}/add-days")
async def ios_add_days(request: Request, key_id: str):
    """Add or remove days from key expiry. Send {days: N} (negative to subtract)"""
    get_current_user(request)
    if key_id not in API_KEYS or key_id in ["packages", "global_banned_devices"]:
        raise HTTPException(status_code=404, detail="Key not found")
    try:
        body = await request.json()
        days = int(body.get("days", 0))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid body — send {days: N}")
    key_data = API_KEYS[key_id]
    expiry_str = key_data.get("expiry", "Not Activated")
    if expiry_str in (None, "Not Activated"):
        raise HTTPException(status_code=400, detail="Key not activated yet")
    expiry_dt = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
    expiry_dt += timedelta(days=days)
    key_data["expiry"] = expiry_dt.strftime("%Y-%m-%d %H:%M:%S")
    await save_keys_safe(API_KEYS)
    action = "Added" if days >= 0 else "Removed"
    return {"success": True,
            "message": f"{action} {abs(days)} day(s)",
            "new_expiry": key_data["expiry"]}


@app.post("/api/keys/{key_id}/add-devices")
async def ios_add_devices(request: Request, key_id: str):
    """Add or remove max device slots. Send {devices: N} (negative to subtract)"""
    get_current_user(request)
    if key_id not in API_KEYS or key_id in ["packages", "global_banned_devices"]:
        raise HTTPException(status_code=404, detail="Key not found")
    try:
        body = await request.json()
        delta = int(body.get("devices", 0))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid body — send {devices: N}")
    key_data = API_KEYS[key_id]
    current = key_data.get("max_users", 1)
    new_val = max(1, current + delta)
    key_data["max_users"] = new_val
    await save_keys_safe(API_KEYS)
    action = "Added" if delta >= 0 else "Removed"
    return {"success": True,
            "message": f"{action} {abs(delta)} device slot(s)",
            "max_devices": new_val}


@app.post("/api/keys/{key_id}/ban-hwid")
async def ios_ban_hwid(request: Request, key_id: str):
    """Ban a specific HWID/UDID from a key"""
    get_current_user(request)
    if key_id not in API_KEYS or key_id in ["packages", "global_banned_devices"]:
        raise HTTPException(status_code=404, detail="Key not found")
    try:
        body = await request.json()
        device_id = (body.get("device_id") or "").strip()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid body — send {device_id: ...}")
    if not device_id:
        raise HTTPException(status_code=400, detail="device_id required")
    key_data = API_KEYS[key_id]
    banned = key_data.setdefault("banned_devices", [])
    if device_id not in banned:
        banned.append(device_id)
    # also remove from bound so they can't reconnect
    bound = key_data.get("bound_devices", [])
    if device_id in bound:
        bound.remove(device_id)
    await save_keys_safe(API_KEYS)
    return {"success": True, "message": f"Device {device_id} banned from key"}


@app.post("/api/keys/{key_id}/unban-hwid")
async def ios_unban_hwid(request: Request, key_id: str):
    """Unban a specific HWID/UDID from a key"""
    get_current_user(request)
    if key_id not in API_KEYS or key_id in ["packages", "global_banned_devices"]:
        raise HTTPException(status_code=404, detail="Key not found")
    try:
        body = await request.json()
        device_id = (body.get("device_id") or "").strip()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid body")
    key_data = API_KEYS[key_id]
    banned = key_data.get("banned_devices", [])
    if device_id in banned:
        banned.remove(device_id)
    await save_keys_safe(API_KEYS)
    return {"success": True, "message": f"Device {device_id} unbanned"}


@app.post("/api/keys/{key_id}/update")
async def ios_update_key_details(request: Request, key_id: str):
    """Full update: change package, duration, max_devices, note"""
    get_current_user(request)
    if key_id not in API_KEYS or key_id in ["packages", "global_banned_devices"]:
        raise HTTPException(status_code=404, detail="Key not found")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    key_data = API_KEYS[key_id]
    if "max_users" in body:
        key_data["max_users"] = max(1, int(body["max_users"]))
    if "note" in body:
        key_data["note"] = str(body["note"])
    if "package" in body:
        key_data["package"] = str(body["package"])
    await save_keys_safe(API_KEYS)
    return {"success": True, "message": "Key updated", "key": key_id}


# --- Offsets Endpoints for iOS App ---

@app.get("/api/offsets/{package_name}/{version}")
async def ios_get_offsets(request: Request, package_name: str, version: str):
    """Get offsets for package and version"""
    get_current_user(request)  # Verify token
    
    if "packages" not in API_KEYS or package_name not in API_KEYS["packages"]:
        raise HTTPException(status_code=404, detail="Package not found")
    
    pkg_data = API_KEYS["packages"][package_name]
    offsets = pkg_data.get("offsets", {}).get(version, {})
    
    return {"success": True, "offsets": offsets}


@app.put("/api/offsets/{package_name}/{version}/{offset_name}")
async def ios_set_offset(request: Request, package_name: str, version: str, offset_name: str):
    """Set offset value from iOS App"""
    get_current_user(request)  # Verify token
    
    if "packages" not in API_KEYS or package_name not in API_KEYS["packages"]:
        raise HTTPException(status_code=404, detail="Package not found")
    
    try:
        data = await request.json()
        value = data.get('value')
        
        if not value:
            raise HTTPException(status_code=400, detail="Value required")
        
        pkg_data = API_KEYS["packages"][package_name]
        
        if "offsets" not in pkg_data:
            pkg_data["offsets"] = {}
        if version not in pkg_data["offsets"]:
            pkg_data["offsets"][version] = {}
        
        pkg_data["offsets"][version][offset_name] = value
        await save_keys_safe(API_KEYS)
        
        return {"success": True, "message": "Offset set successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/offsets/{package_name}/{version}/load-defaults")
async def ios_load_default_offsets(request: Request, package_name: str, version: str):
    """Load default offsets from iOS App"""
    get_current_user(request)  # Verify token
    
    if "packages" not in API_KEYS or package_name not in API_KEYS["packages"]:
        raise HTTPException(status_code=404, detail="Package not found")
    
    # Default offsets
    default_offsets = {
        "GetLocalPlayer": "0x28FC854",
        "Curent_Match": "0x4E355B0",
        "GetHp": "0x4A8478C",
        "get_MaxHP": "0x4A8489C",
        "get_camera": "0x84E7148",
        "crash_offset": "0x0"
    }
    
    pkg_data = API_KEYS["packages"][package_name]
    if "offsets" not in pkg_data:
        pkg_data["offsets"] = {}
    
    pkg_data["offsets"][version] = default_offsets
    await save_keys_safe(API_KEYS)
    
    return {"success": True, "message": "Default offsets loaded"}


# --- Logs Endpoints ---

@app.get("/api/logs")
async def ios_get_logs(request: Request, limit: int = 100):
    """Get system logs for iOS App"""
    get_current_user(request)  # Verify token
    logs = []
    return {"success": True, "logs": logs}


if __name__ == "__main__":
    import uvicorn
    print("Starting API server on port 8000 ...")
    uvicorn.run("main_server:app", host="0.0.0.0", port=8000, reload=False)

