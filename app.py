# -*- coding: utf-8 -*-
import os, io, json, threading, logging, webbrowser, secrets, time, sys
from datetime import datetime, timedelta
from functools import wraps

import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from flask import Flask, request, jsonify, send_file, send_from_directory

# =========================
# 资源定位（PyInstaller --onefile 兼容）
# =========================
def resource_path(rel: str) -> str:
    """
    在开发环境下返回相对当前文件的路径；
    在 PyInstaller --onefile 下从临时解包目录（_MEIPASS）取资源。
    """
    base = getattr(sys, "_MEIPASS", os.path.abspath(os.path.dirname(__file__)))
    return os.path.join(base, rel)



# 稳妥的用户数据目录（Windows: %LOCALAPPDATA%\Museumi\PearlCtl）
APPDATA_BASE = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
APPDIR = os.path.join(APPDATA_BASE, "Museumi", "PearlCtl")
os.makedirs(APPDIR, exist_ok=True)


# =========================
# 基础与静态资源
# =========================
# 默认截图保存目录：<APPDIR>/Captures；可用环境变量 CAPTURE_SAVE_DIR 覆盖
CAPTURE_SAVE_DIR = os.getenv("CAPTURE_SAVE_DIR", os.path.join(APPDIR, "Captures"))
os.makedirs(CAPTURE_SAVE_DIR, exist_ok=True)


# 静态目录指向打包资源目录（根目录），以便直接访问 index.html / login.html / 静态文件
app = Flask(__name__, static_folder=resource_path("."), static_url_path='')
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("pearl")


@app.route('/')
def _root():
    # 直接从资源路径读取，避免 CWD 偏差
    return send_file(resource_path('index.html'))

@app.get('/__ls')
def _ls():
    base = resource_path(".")
    return jsonify({
        "base": base,
        "exists_index_html": os.path.exists(os.path.join(base, 'index.html')),
        "files": sorted(os.listdir(base))
    })





# =========================
# 配置持久化（与 /config 对应）
# =========================
# 默认配置文件：<APPDIR>/pearl_config.json；可用环境变量 PEARL_CONFIG_PATH 覆盖
CONFIG_PATH = os.getenv("PEARL_CONFIG_PATH", os.path.join(APPDIR, "pearl_config.json"))
os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)

DEFAULT_CFG = {
    "scheme": os.getenv("PEARL_SCHEME", "http").strip().lower(),   # http/https
    "host":   os.getenv("PEARL_HOST", "192.168.5.120").strip(),
    "user":   os.getenv("PEARL_USER", "admin"),
    "pass":   os.getenv("PEARL_PASS", ""),
    "verify_ssl": os.getenv("PEARL_VERIFY_SSL", "false").lower() == "true",
    "timeout": float(os.getenv("PEARL_TIMEOUT", "4.0")),
    "channels": [int(x) for x in os.getenv("PEARL_CHANNELS", "1,2,3,4,5,6").split(",")],
    "capture_dir": CAPTURE_SAVE_DIR,
}


def load_cfg():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            # 兼容缺省项
            for k, v in DEFAULT_CFG.items():
                cfg.setdefault(k, v)
            return cfg
        except Exception as e:
            log.warning("load_cfg failed, use default: %s", e)
    return DEFAULT_CFG.copy()

def save_cfg(cfg: dict):
    safe = cfg.copy()
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(safe, f, ensure_ascii=False, indent=2)

CFG = load_cfg()

def _url(path: str) -> str:
    return f"{CFG['scheme']}://{CFG['host']}{path}"

def _chs(v):
    if str(v).lower() == "all":
        return CFG["channels"]
    n = int(v)
    if n not in CFG["channels"]:
        raise ValueError("invalid channel")
    return [n]

# =========================
# Requests 会话
# =========================

session = requests.Session()
retry = Retry(
    total=2,
    backoff_factor=0.3,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET", "POST"]
)
adapter = HTTPAdapter(max_retries=retry)
session.mount("http://", adapter)
session.mount("https://", adapter)

def _auth_tuple():
    u, p = CFG.get("user") or "", CFG.get("pass") or ""
    return (u, p) if (u or p) else None




# =========================
# 鉴权（Bearer Token）
# =========================
SESSIONS = {}  # token -> {"exp": epoch_ts, "user": "..."}
SESSION_TTL = int(os.getenv("AUTH_TTL_SECONDS", "43200"))  # 12h

def _issue_token(user_id: str = "admin") -> dict:
    token = secrets.token_urlsafe(32)
    exp = int(time.time()) + SESSION_TTL
    SESSIONS[token] = {"exp": exp, "user": user_id}
    return {"token": token, "expires_in": SESSION_TTL}

def _current_session():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    s = SESSIONS.get(token)
    if not s:
        return None
    if s["exp"] < int(time.time()):
        SESSIONS.pop(token, None)
        return None
    # 可在此处做“滑动过期”
    return {"token": token, **s}

def auth_required(fn):
    @wraps(fn)
    def _wrap(*args, **kwargs):
        s = _current_session()
        if not s:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        return fn(*args, **kwargs)
    return _wrap




# =========================
# 健康检查
# =========================
@app.get('/health')
def health():
    return jsonify({"ok": True, "pearl": {
        "host": CFG["host"], "scheme": CFG["scheme"], "channels": CFG["channels"]
    }})



# =========================
# 配置接口（登录前可用）
# =========================
@app.get('/config')
def get_config():
    # 返回时对口令做掩码
    masked = CFG.copy()
    if masked.get("pass"):
        masked["pass"] = "******"
    return jsonify({
        "host": masked["host"],
        "user": masked["user"],
        "pass": masked["pass"],
        "capture_dir": masked["capture_dir"],
        "scheme": masked["scheme"],
        "verify_ssl": masked["verify_ssl"],
        "timeout": masked["timeout"],
        "channels": masked["channels"],
    })

@app.put('/config')
def set_config():
    body = request.get_json(silent=True) or {}

    # 仅在传入时覆盖，不传保持原值
    for k in ("scheme", "host", "user", "pass", "capture_dir", "verify_ssl", "timeout", "channels"):
        if k in body and body[k] is not None:
            CFG[k] = body[k]

    # 目录存在性保障
    try:
        os.makedirs(CFG["capture_dir"], exist_ok=True)
    except Exception as e:
        return jsonify({"ok": False, "error": f"Invalid capture_dir: {e}"}), 400

    save_cfg(CFG)
    return jsonify({"ok": True, "saved": {
        "scheme": CFG["scheme"], "host": CFG["host"], "user": CFG["user"],
        "capture_dir": CFG["capture_dir"], "verify_ssl": CFG["verify_ssl"],
        "timeout": CFG["timeout"], "channels": CFG["channels"],
    }})



# =========================
# 登录/会话接口
# =========================
@app.post('/auth/test')
def auth_test():
    """
    前端“Test”按钮调用：验证给定 host/user/pass 是否可连（不保存）
    body: {host, user, pass}
    """
    body = request.get_json(silent=True) or {}
    host = (body.get("host") or "").strip()
    user = body.get("user") or ""
    pwd  = body.get("pass") or ""
    scheme = CFG["scheme"]
    verify = CFG["verify_ssl"]
    timeout = CFG["timeout"]

    if not host:
        return jsonify({"ok": False, "error": "host is required"}), 400

    url = f"{scheme}://{host}/"
    try:
        r = session.get(url, auth=(user, pwd) if (user or pwd) else None,
                        timeout=timeout, verify=verify)
        if r.ok:
            return jsonify({"ok": True, "message": "Connection OK"})
        else:
            return jsonify({"ok": False, "error": f"HTTP {r.status_code}", "detail": {"url": url}}), 502
    except requests.RequestException as ex:
        return jsonify({"ok": False, "error": "Request failed", "detail": {"url": url, "exception": str(ex)}}), 502

@app.post('/auth/login')
def auth_login():
    """
    登录：读取当前保存的 CFG（host/user/pass），做一次轻量探测成功则签发 token
    前端契约：login.html 已经先 PUT /config，再 POST /auth/login（空 body）
    """
    url = _url("/")
    try:
        r = session.get(url, auth=_auth_tuple(), timeout=CFG["timeout"], verify=CFG["verify_ssl"])
        if not r.ok:
            return jsonify({"ok": False, "error": f"PEARL unreachable: HTTP {r.status_code}"}), 502
    except requests.RequestException as ex:
        return jsonify({"ok": False, "error": "PEARL request failed", "detail": str(ex)}), 502

    issued = _issue_token(CFG.get("user") or "admin")
    return jsonify({"ok": True, **issued})

@app.get('/auth/me')
def auth_me():
    s = _current_session()
    if not s:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    return jsonify({"ok": True, "user": s["user"], "exp": s["exp"], "pearl": {
        "host": CFG["host"], "scheme": CFG["scheme"], "channels": CFG["channels"]
    }})

@app.post('/auth/logout')
@auth_required
def auth_logout():
    s = _current_session()
    if s:
        SESSIONS.pop(s["token"], None)
    return jsonify({"ok": True})




# =========================
# 设备控制（需要登录）
# =========================
def _set_params(ch: int, params: dict):
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    url = _url(f"/admin/channel{ch}/set_params.cgi?{qs}")
    log.info("SET ch%s -> %s", ch, url)
    r = session.get(url, auth=_auth_tuple(), timeout=CFG["timeout"], verify=CFG["verify_ssl"])
    r.raise_for_status()
    return True

@app.post('/record')
@auth_required
def record():
    data = request.get_json(silent=True) or {}
    try:
        for c in _chs(data.get("channel")):
            _set_params(c, {"rec_enabled": "on"})
        return jsonify({"ok": True})
    except Exception as e:
        log.exception("record failed")
        return jsonify({"ok": False, "error": str(e)}), 502

@app.post('/stop')
@auth_required
def stop():
    data = request.get_json(silent=True) or {}
    try:
        for c in _chs(data.get("channel")):
            _set_params(c, {"rec_enabled": ""})
        return jsonify({"ok": True})
    except Exception as e:
        log.exception("stop failed")
        return jsonify({"ok": False, "error": str(e)}), 502

@app.get('/captures/<path:filename>')
def serve_capture(filename):
    return send_from_directory(CAPTURE_SAVE_DIR, filename, as_attachment=False)

@app.post('/capture')
@auth_required
def capture():
    """
    从 Pearl REST /api/v2.0/channels/{cid}/preview 拉图并保存到服务器本地
    body: {"cid":1} 或 {"channel":1}
          可选 {"format":"jpg|png","resolution":"auto|1280x720",
                "keep_aspect_ratio":true,"prefix":"custom"}
    """
    data = request.get_json(silent=True) or {}

    cid = data.get("cid")
    if cid is None:
        try:
            [ch] = _chs(data.get("channel", 1))
            cid = ch
        except Exception:
            return jsonify({"ok": False, "error": "Invalid channel/cid"}), 400

    fmt = str(data.get("format", "jpg")).lower()
    if fmt not in ("jpg", "png", "jpeg"): fmt = "jpg"
    if fmt == "jpeg": fmt = "jpg"
    resolution = str(data.get("resolution", "auto"))
    keep = "true" if str(data.get("keep_aspect_ratio", True)).lower() in ("1", "true", "yes", "on") else "false"
    accept = "image/jpeg" if fmt == "jpg" else "image/png"

    url = _url(f"/api/v2.0/channels/{cid}/preview")
    try:
        r = session.get(
            url,
            params={"resolution": resolution, "keep_aspect_ratio": keep, "format": fmt},
            auth=_auth_tuple(),
            timeout=CFG["timeout"],
            verify=CFG["verify_ssl"],
            headers={"Accept": accept},
        )
    except requests.RequestException as ex:
        return jsonify({"ok": False, "error": "Request failed", "detail": {"url": url, "exception": str(ex)}}), 502

    content = r.content or b""
    ct_hdr = r.headers.get("Content-Type", "")

    def _sniff_ct(blob, header_ct):
        if not header_ct: header_ct = ""
        h = header_ct.lower()
        if blob.startswith(b"\xff\xd8\xff"): return "image/jpeg"
        if blob.startswith(b"\x89PNG\r\n\x1a\n"): return "image/png"
        if h.startswith("image/"): return header_ct.split(";", 1)[0].strip()
        return None

    mime = _sniff_ct(content, ct_hdr)
    if not (r.ok and content and mime):
        return jsonify({
            "ok": False,
            "error": "REST preview returned non-image",
            "detail": {"url": r.url, "status": r.status_code, "content_type": ct_hdr, "length": len(content)}
        }), 502

    # 保存到服务器
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
    prefix = str(data.get("prefix") or f"cid{cid}")
    prefix = "".join(ch for ch in prefix if ch.isalnum() or ch in ("-", "_"))
    ext = "jpg" if mime == "image/jpeg" else "png"
    filename = f"{prefix}_{ts}.{ext}"
    abs_path = os.path.join(CFG["capture_dir"], filename)

    with open(abs_path, "wb") as f:
        f.write(content)

    rel_url = f"/captures/{filename}"
    return jsonify({
        "ok": True, "cid": cid, "filename": filename, "path": abs_path,
        "url": rel_url, "bytes": len(content), "content_type": mime
    })



# =========================
# 端口占位（保留）
# =========================
# 原始路由
@app.post('/reboot')
@auth_required
def reboot():
    url = _url("/api/v2.0/system/control/reboot")
    r = session.post(url, auth=_auth_tuple(), timeout=CFG["timeout"],
                     verify=CFG["verify_ssl"], headers={"Accept":"application/json"}, data='')
    if 200 <= r.status_code < 300:
        return jsonify({"ok": True, "status": r.status_code})
    return jsonify({"ok": False, "error": f"HTTP {r.status_code}", "text": (r.text or '')[:300]}), 502

# —— 兼容旧前端的别名路径 —— #
app.add_url_rule('/pearl/reboot', 'reboot_alias', reboot, methods=['POST'])




@app.get('/port/2')
def get_port2():
    return jsonify({"mac": "00:11:22:33:44:55", "ip": "192.168.1.20", "mask": "255.255.255.0"})

@app.put('/port/2')
def set_port2():
    body = request.get_json(silent=True) or {}
    if not body.get("mac") or not body.get("ip"):
        return jsonify({"ok": False, "error": "mac and ip are required"}), 400
    return jsonify({"ok": True, "saved": body})



# =========================
# 启动
# =========================
def _open():
    webbrowser.open(f"http://127.0.0.1:{os.getenv('PORT', '8009')}/")

if __name__ == '__main__':
    if os.getenv("OPEN_BROWSER", "true").lower() == "true":
        threading.Timer(1.0, _open).start()
    # 禁用重载器，避免 PyInstaller 打包后重复进程
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8009")), debug=False, use_reloader=False)
