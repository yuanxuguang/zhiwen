"""One persistent Camoufox process per environment; secrets arrive over stdin."""
import json
import ipaddress
import os
from pathlib import Path
import select
import signal
import socket
import socketserver
import sys
import threading
import traceback
from urllib.parse import quote
from zoneinfo import ZoneInfo

GEO_ENDPOINT = "https://ipwho.is/"


def proxy_url(spec):
    host = spec["proxyHost"]
    if ":" in host:
        host = f"[{host}]"
    auth = ""
    if spec["proxyUsername"]:
        auth = f'{quote(spec["proxyUsername"], safe="")}:{quote(spec["proxyPassword"], safe="")}@'
    # socks5h resolves target domains at the upstream proxy.
    scheme = "socks5h" if spec["proxyType"] == "socks5" else "http"
    return f'{scheme}://{auth}{host}:{spec["proxyPort"]}'


def parse_region(data):
    from camoufox.locales import normalize_locale, get_unicode_info

    if not isinstance(data, dict) or data.get("success") is not True:
        raise ValueError("出口地区服务未返回有效结果，请检查代理或稍后再检测。")
    try:
        ip = str(ipaddress.ip_address(data["ip"]))
        country = data["country_code"]
        if not isinstance(country, str) or len(country) != 2 or not country.isalpha():
            raise ValueError("无效国家代码")
        country = country.upper()
        timezone = data["timezone"]["id"]
        ZoneInfo(timezone)
        # Use the most spoken language in the engine's bundled Unicode CLDR
        # territory data. Deterministic selection keeps multilingual exits stable.
        territory = get_unicode_info().find(f"territory[@type='{country}']")
        if territory is None:
            raise ValueError("国家缺少语言数据")
        languages = territory.findall("languagePopulation")
        primary = max(languages, key=lambda language: float(language.attrib["populationPercent"]))
        locale = primary.attrib["type"].replace("_", "-") + "-" + country
        normalize_locale(locale)
        latitude, longitude = float(data["latitude"]), float(data["longitude"])
        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            raise ValueError("无效位置坐标")
        if not isinstance(data["country"], str) or not data["country"]:
            raise ValueError("无效国家名称")
        return dict(ip=ip, countryCode=country, countryName=data["country"],
                    region=data["region"] or "", city=data["city"] or "", locale=locale,
                    timezone=timezone, latitude=latitude, longitude=longitude)
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise ValueError("出口地区结果缺少有效的 IP、语言、时区或位置，未应用配置。") from error


def detect_region(spec, endpoint=GEO_ENDPOINT):
    import requests

    emit("status", message="正在通过当前线路检测出口 IP 和地区…")
    with requests.Session() as session:
        session.trust_env = False
        if spec["proxyType"] != "direct":
            address = proxy_url(spec)
            session.proxies = {"http": address, "https": address}
        try:
            response = session.get(endpoint, timeout=(12, 18),
                                   headers={"User-Agent": "LocalFingerprintBrowser/0.2"})
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as error:
            # requests errors can contain proxy URLs with credentials.
            raise RuntimeError(f"出口 IP 检测失败（{type(error).__name__}）；请检查代理连接或地区服务。未切换为直连。") from None
    return parse_region(data)


def emit(event, **data):
    print(json.dumps({"event": event, **data}, ensure_ascii=False), flush=True)


def atomic_json(path, value):
    temp = path.with_suffix(".tmp")
    with open(temp, "w", encoding="utf-8", opener=lambda p, flags: os.open(p, flags, 0o600)) as out:
        json.dump(value, out, ensure_ascii=False)
    os.replace(temp, path)


def read_exact(sock, count):
    result = b""
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise EOFError("SOCKS 客户端已断开")
        result += chunk
    return result


class AuthenticatedSocksRelay(socketserver.ThreadingTCPServer):
    """Playwright rejects SOCKS credentials; authenticate upstream on loopback only."""
    daemon_threads = True

    def __init__(self, spec):
        relay = self
        self.stopped = threading.Event()

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                import socks
                client = self.request
                client.settimeout(15)
                try:
                    version, count = read_exact(client, 2)
                    methods = read_exact(client, count)
                    if version != 5 or 0 not in methods:
                        client.sendall(b"\x05\xff")
                        return
                    client.sendall(b"\x05\x00")
                    version, command, reserved, kind = read_exact(client, 4)
                    if version != 5 or command != 1 or kind not in (1, 3, 4):
                        client.sendall(b"\x05\x07\x00\x01" + bytes(6))
                        return
                    if kind == 3:
                        host = read_exact(client, read_exact(client, 1)[0]).decode("ascii")
                    else:
                        host = socket.inet_ntop(socket.AF_INET if kind == 1 else socket.AF_INET6,
                                               read_exact(client, 4 if kind == 1 else 16))
                    port = int.from_bytes(read_exact(client, 2), "big")
                    with socks.socksocket() as upstream:
                        upstream.set_proxy(socks.SOCKS5, spec["proxyHost"], int(spec["proxyPort"]),
                                           rdns=True, username=spec["proxyUsername"],
                                           password=spec["proxyPassword"])
                        upstream.settimeout(15)
                        try:
                            upstream.connect((host, port))
                        except OSError as error:
                            client.sendall(b"\x05\x01\x00\x01" + bytes(6))
                            emit("proxy_error", message=f"SOCKS5 上游连接失败：{error}")
                            return
                        client.sendall(b"\x05\x00\x00\x01" + bytes(6))
                        while not relay.stopped.is_set():
                            readable, _, _ = select.select([client, upstream], [], [], 1)
                            for source in readable:
                                data = source.recv(65536)
                                if not data:
                                    return
                                (upstream if source is client else client).sendall(data)
                except (EOFError, ConnectionResetError, BrokenPipeError):
                    return  # Normal browser cancellation or closed tab.
                except (OSError, UnicodeError) as error:
                    emit("proxy_error", message=f"SOCKS5 本机转发失败：{error}")

        super().__init__(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.stopped.set()
        self.shutdown()
        self.server_close()
        self.thread.join()


def build_options(spec, directory):
    from camoufox.pkgman import launch_path
    from camoufox.utils import launch_options, get_env_vars

    identity = {key: spec[key] for key in ("locale", "timezone", "canvasNoise", "webgl", "blockWebRTC")}
    saved_path = directory / "identity.json"
    if saved_path.exists():
        saved = json.loads(saved_path.read_text())
    else:
        saved = None
    if saved is None or saved["settings"] != identity:
        emit("status", message="正在生成环境指纹…")
        generated = launch_options(
            os="macos", headless=False, canvas_noise=spec["canvasNoise"],
            block_webrtc=spec["blockWebRTC"], block_webgl=not spec["webgl"],
            locale=spec["locale"], config={"timezone": spec["timezone"]},
            window=(1100, 720), enable_cache=True,
        )
        saved = {
            "settings": identity,
            "env": {k: v for k, v in generated["env"].items() if k.startswith("CAMOU_")},
            "prefs": generated["firefox_user_prefs"], "args": generated["args"],
        }
        atomic_json(saved_path, saved)
    options = {
        "executable_path": launch_path(), "headless": False,
        "user_data_dir": str(directory / "browser-data"), "no_viewport": True,
        "args": saved["args"], "env": {**os.environ, **saved["env"]},
        "firefox_user_prefs": saved["prefs"],
    }
    if spec.get("resolvedRegion") is not None:
        region = spec["resolvedRegion"]
        chunks = sorted((int(k.rsplit("_", 1)[1]), v) for k, v in saved["env"].items()
                        if k.startswith("CAMOU_CONFIG_"))
        config = json.loads("".join(value for _, value in chunks))
        config.update({"geolocation:latitude": region["latitude"],
                       "geolocation:longitude": region["longitude"], "geolocation:accuracy": 10000})
        options["env"] = {k: v for k, v in options["env"].items() if not k.startswith("CAMOU_CONFIG_")}
        options["env"].update(get_env_vars(config, "mac"))
        options["firefox_user_prefs"] = {**saved["prefs"], "permissions.default.geo": 1}
    if spec["proxyType"] != "direct":
        host = spec["proxyHost"]
        if ":" in host:
            host = f"[{host}]"
        proxy = {"server": f'{spec["proxyType"]}://{host}:{spec["proxyPort"]}'}
        if spec["proxyUsername"]:
            proxy.update(username=spec["proxyUsername"], password=spec["proxyPassword"])
        options["proxy"] = proxy
    return options


def run():
    from camoufox.sync_api import Camoufox
    from playwright.sync_api import Error as BrowserError

    spec = json.loads(sys.stdin.readline())
    directory = Path(sys.argv[1])
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    def commands():
        for line in sys.stdin:
            if line.strip() == "stop":
                stop.set()
                return
        stop.set()  # The manager exited: close cleanly instead of orphaning the profile.

    threading.Thread(target=commands, daemon=True).start()
    if spec["autoRegion"] or spec["action"] == "detect":
        region = detect_region(spec)
        if stop.is_set():
            emit("closed")
            return
        emit("region", result=region)
        spec.update(locale=region["locale"], timezone=region["timezone"], resolvedRegion=region)
    if spec["action"] == "detect" or stop.is_set():
        emit("closed")
        return
    relay = None
    try:
        options = build_options(spec, directory)
        if spec["proxyType"] == "socks5" and spec["proxyUsername"]:
            relay = AuthenticatedSocksRelay(spec)
            options["proxy"] = {"server": f"socks5://127.0.0.1:{relay.server_address[1]}"}
        emit("status", message="正在启动浏览器…")
        with Camoufox(from_options=options, persistent_context=True) as context:
            context.on("close", lambda *_: stop.set())
            page = context.pages[0] if context.pages else context.new_page()
            emit("ready")
            if spec["startURL"]:
                try:
                    page.goto(spec["startURL"], wait_until="domcontentloaded", timeout=30000)
                except BrowserError as error:
                    emit("navigation_error", message=str(error))
            while not stop.is_set():
                pages = context.pages
                if not pages:
                    break
                try:
                    pages[0].wait_for_timeout(200)
                except BrowserError:
                    if stop.is_set() or not context.pages:
                        break
                    raise
    finally:
        if relay is not None:
            relay.close()
    emit("closed")


if __name__ == "__main__":
    try:
        run()
    except Exception as error:
        emit("error", message=f"{type(error).__name__}: {error}")
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
