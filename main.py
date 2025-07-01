#!/usr/bin/env python3
import subprocess
import os
import json
import asyncio
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
import sys
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
from pathlib import Path
import telegram
from telegram.ext import Application, CommandHandler
import time
import ipaddress
import html
import tldextract
import re
import shutil
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import random
import traceback
import signal
import socket
from dotenv import load_dotenv

# Verificar versión mínima de Python
if sys.version_info < (3, 7):
    raise RuntimeError("Se requiere Python 3.7 o superior.")

init(autoreset=True)

# Definir SEVERITY_COLORS antes del logging
SEVERITY_COLORS = {
    "CRITICAL": Fore.RED,
    "HIGH": Fore.MAGENTA,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.BLUE,
    "INFO": Fore.CYAN,
    "DEBUG": Fore.GREEN,
    "WARNING": Fore.YELLOW,
    "ERROR": Fore.RED
}

# Configuración de logging
class ColoredFormatter(logging.Formatter):
    def format(self, record):
        color = SEVERITY_COLORS.get(record.levelname, Fore.WHITE)
        style = Style.BRIGHT if record.levelname in ("ERROR", "CRITICAL") else Style.NORMAL
        message = record.getMessage()
        record.message = f"{style}{color}{message}{Style.RESET_ALL}"
        return super().format(record)

logging.basicConfig(level=logging.DEBUG, handlers=[])
logger = logging.getLogger()
file_handler = RotatingFileHandler("bot_log.txt", maxBytes=10*1024*1024, backupCount=5)
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(ColoredFormatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

def timestamp_now():
    """Devuelve timestamp en formato YYYYMMDD_HHMMSS."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

# Cargar y validar .env
ENV_FILE = Path(__file__).resolve().parent / ".env"
if not ENV_FILE.is_file():
    logger.critical(f"Archivo .env no encontrado en {ENV_FILE}.")
    raise FileNotFoundError(f"Archivo .env no encontrado en {ENV_FILE}.")
if not os.access(ENV_FILE, os.R_OK):
    logger.critical(f"No se puede leer {ENV_FILE}. Verifica permisos.")
    raise PermissionError(f"No se puede leer {ENV_FILE}.")
load_dotenv(dotenv_path=ENV_FILE)

# Configuración de entorno
DEBUG_MODE = os.getenv("DEBUG_MODE", "true").lower() == "true"
logger.setLevel(logging.DEBUG if DEBUG_MODE else logging.INFO)

os.environ["HTTP_PROXY"] = os.getenv("HTTP_PROXY", "")
os.environ["HTTPS_PROXY"] = os.getenv("HTTPS_PROXY", "")

BASE_DIR = Path(__file__).resolve().parent
NUCLEI_BIN = os.getenv("NUCLEI_BIN", "/usr/local/bin/nuclei")
SUBFINDER_BIN = os.getenv("SUBFINDER_BIN", "/usr/local/bin/subfinder")
HTTPX_BIN = os.getenv("HTTPX_BIN", "/usr/local/bin/httpx")
NMAP_BIN = os.getenv("NMAP_BIN", "/usr/bin/nmap")
SEARCHSPLOIT_BIN = os.getenv("SEARCHSPLOIT_BIN", "/usr/bin/searchsploit")
WHATWEB_BIN = os.getenv("WHATWEB_BIN", "/usr/bin/whatweb")
SUBFINDER_RESOLVERS = os.getenv("SUBFINDER_RESOLVERS", "8.8.8.8,1.1.1.1")
SCOPE_FILE = BASE_DIR / "hubspot_scope_live.txt"
TEMP_SCOPE_FILE = BASE_DIR / "temp_scope.txt"
TARGETS_FILE = BASE_DIR / "target.txt"
HISTORY_FILE = BASE_DIR / "targets_completed.txt"
CVE_LOG_FILE = BASE_DIR / "cve_log.json"
CVE_LOG_BACKUP = BASE_DIR / "cve_log_backup.json"
NMAP_RESULTS_FILE = BASE_DIR / "nmap_results.txt"
SEARCHSPLOIT_RESULTS_FILE = BASE_DIR / "searchsploit_results.txt"
WHATWEB_RESULTS_FILE = BASE_DIR / "whatweb_results.txt"
TAGS = os.getenv("NUCLEI_TAGS", "xss,subdomain-takeover,idor,rce,exposure")
SEVERITY = os.getenv("NUCLEI_SEVERITY", "critical,high,medium")
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TOKEN_REGEX = re.compile(r"^\d+:[A-Za-z0-9_-]{35}$")
if not TELEGRAM_TOKEN or not TOKEN_REGEX.match(TELEGRAM_TOKEN):
    logger.critical("TELEGRAM_TOKEN no configurado o inválido en .env.")
    raise ValueError("TELEGRAM_TOKEN no configurado o inválido.")
ALLOWED_CHAT_IDS = set()
raw_ids = os.getenv("ALLOWED_CHAT_IDS", "")
if raw_ids:
    for x in raw_ids.split(","):
        try:
            chat_id = int(x.strip())
            ALLOWED_CHAT_IDS.add(chat_id)
        except ValueError:
            logger.warning(f"ID de chat inválido: {x}")
if not ALLOWED_CHAT_IDS:
    logger.warning("No se configuraron ALLOWED_CHAT_IDS. El bot no enviará mensajes.")
MAX_WORKERS = int(os.getenv("MAX_WORKERS", 20))
SUBPROCESS_TIMEOUT = int(os.getenv("SUBPROCESS_TIMEOUT", 60))
HTTPX_THREADS = int(os.getenv("HTTPX_THREADS", 50))
HTTPX_TIMEOUT = int(os.getenv("HTTPX_TIMEOUT", 10))
NUCLEI_TIMEOUT = int(os.getenv("NUCLEI_TIMEOUT", 20))
NUCLEI_CONCURRENCY = int(os.getenv("NUCLEI_CONCURRENCY", 50))
NMAP_TIMEOUT = int(os.getenv("NMAP_TIMEOUT", 300))
WHATWEB_TIMEOUT = int(os.getenv("WHATWEB_TIMEOUT", 60))
REPORT_INTERVAL = int(os.getenv("REPORT_INTERVAL", 600))
DOMAIN_REGEX = re.compile(r"^(?:\*?\.)?(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z0-9-]{1,63}$")
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
]
SEVERITY_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": -1}

# Validar variables numéricas
for var_name, var_value in [
    ("MAX_WORKERS", MAX_WORKERS),
    ("SUBPROCESS_TIMEOUT", SUBPROCESS_TIMEOUT),
    ("HTTPX_THREADS", HTTPX_THREADS),
    ("HTTPX_TIMEOUT", HTTPX_TIMEOUT),
    ("NUCLEI_TIMEOUT", NUCLEI_TIMEOUT),
    ("NUCLEI_CONCURRENCY", NUCLEI_CONCURRENCY),
    ("NMAP_TIMEOUT", NMAP_TIMEOUT),
    ("WHATWEB_TIMEOUT", WHATWEB_TIMEOUT),
    ("REPORT_INTERVAL", REPORT_INTERVAL)
]:
    if var_value <= 0:
        logger.critical(f"{var_name} debe ser un número positivo: {var_value}")
        raise ValueError(f"{var_name} debe ser un número positivo")

class VulnSentry:
    """Bot para escanear vulnerabilidades usando subfinder, httpx, nmap, nuclei, searchsploit y whatweb."""
    def __init__(self):
        self.app = Application.builder().token(TELEGRAM_TOKEN).read_timeout(10.0).connect_timeout(10.0).pool_timeout(30).build()
        self.scan_lock = asyncio.Lock()
        self.cve_lock = asyncio.Lock()
        self.scan_task = None
        self.cancel_event = asyncio.Event()
        self.executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        self.start_time = time.time()
        self.latest_results = {}  # Almacenar últimos resultados
        self.scan_progress = {}  # Estado del escaneo
        self.validate_tools()
        self.validate_network()

    def validate_tools(self):
        """Valida que las herramientas estén instaladas y sean ejecutables."""
        for tool, path in [
            ("nuclei", NUCLEI_BIN),
            ("subfinder", SUBFINDER_BIN),
            ("httpx", HTTPX_BIN),
            ("nmap", NMAP_BIN),
            ("searchsploit", SEARCHSPLOIT_BIN),
            ("whatweb", WHATWEB_BIN)
        ]:
            resolved_path = shutil.which(path) if not os.path.isabs(path) else path
            if not resolved_path or not os.path.exists(resolved_path):
                self.log(f"[-] ❌ Herramienta {tool} no encontrada en {path}.", logging.ERROR)
                raise FileNotFoundError(f"{tool} no instalado.")
            if not os.access(resolved_path, os.X_OK):
                self.log(f"[-] ❌ {tool} en {resolved_path} no es ejecutable.", logging.ERROR)
                raise PermissionError(f"{tool} no es ejecutable.")
        # Verificar versión de nuclei
        try:
            result = subprocess.run([NUCLEI_BIN, "-version"], capture_output=True, text=True, timeout=10)
            nuclei_version = (result.stderr or result.stdout).strip()
            if "outdated" in nuclei_version.lower():
                self.log(f"[-] ⚠️ Versión de nuclei desactualizada: {nuclei_version}. Ejecute 'nuclei -update' para actualizar.", logging.WARNING)
        except subprocess.SubprocessError as e:
            self.log(f"[-] Error obteniendo versión de nuclei: {e}", logging.ERROR)

    def validate_network(self):
        """Valida resolución DNS y conectividad a api.telegram.org."""
        try:
            ip = socket.gethostbyname("api.telegram.org")
            self.log(f"[*] ✅ Resolución DNS de api.telegram.org: {ip}", logging.INFO)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5.0)
                s.connect(("api.telegram.org", 443))
            self.log("[*] ✅ Conexión TCP a api.telegram.org:443 exitosa.", logging.INFO)
        except (socket.gaierror, socket.timeout, OSError) as e:
            self.log(f"[-] ❌ Error de red con api.telegram.org: {e}. Verifica DNS o proxy.", logging.ERROR)
            raise

    def handle_signal(self, signum, frame):
        """Maneja señales SIGINT y SIGTERM."""
        self.log(f"[*] Señal {signal.Signals(signum).name} recibida, cancelando tareas...", logging.WARNING)
        self.cancel_event.set()
        loop = asyncio.get_event_loop()
        if self.scan_task and not self.scan_task.done():
            loop.call_soon_threadsafe(self.scan_task.cancel)
        loop.call_soon_threadsafe(loop.stop)

    def done_callback(self, task):
        """Callback para limpiar tarea de escaneo."""
        try:
            self.scan_task = None
            self.log("[*] Tarea de escaneo finalizada y limpiada.", logging.DEBUG)
        except Exception as e:
            self.log(f"[-] Error en done_callback: {e}", logging.ERROR)

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=2, min=4, max=20),
        retry=retry_if_exception_type((telegram.error.TimedOut, telegram.error.NetworkError, telegram.error.BadRequest, telegram.error.RetryAfter))
    )
    async def send_message(self, chat_id, message, parse_mode="HTML"):
        """Envía mensaje a Telegram con reintentos."""
        if chat_id not in ALLOWED_CHAT_IDS:
            self.log(f"[-] Chat ID {chat_id} no permitido.", logging.WARNING)
            error_message = "🚫 Acceso denegado. Usa el comando en el grupo permitido."
            try:
                await self.app.bot.send_message(chat_id=chat_id, text=error_message, parse_mode="HTML")
            except Exception as e:
                self.log(f"[-] Error enviando mensaje de denegación a {chat_id}: {e}", logging.ERROR)
            return
        try:
            message = message[:4096]  # Límite de Telegram
            await self.app.bot.send_message(chat_id=chat_id, text=message, parse_mode=parse_mode)
            self.log(f"[*] Mensaje enviado a chat_id {chat_id}: {message[:50]}...", logging.DEBUG)
        except telegram.error.BadRequest as e:
            self.log(f"[-] Error de parseo HTML en mensaje: {message[:100]}... Error: {e}", logging.ERROR)
            await self.app.bot.send_message(chat_id=chat_id, text=message, parse_mode=None)
            self.log(f"[*] Mensaje enviado sin parse_mode a chat_id {chat_id}: {message[:50]}...", logging.DEBUG)
        except Exception as e:
            self.log(f"[-] Error enviando mensaje: {e}\n{traceback.format_exc()}", logging.ERROR)
            raise

    async def send_message_to_all(self, message):
        """Envía mensaje a todos los chats permitidos."""
        tasks = [self.send_message(chat_id, message) for chat_id in ALLOWED_CHAT_IDS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for chat_id, result in zip(ALLOWED_CHAT_IDS, results):
            if isinstance(result, Exception):
                self.log(f"[-] Error enviando mensaje a {chat_id}: {result}", logging.ERROR)

    async def test_bot(self):
        """Prueba la conexión enviando mensaje inicial."""
        if ALLOWED_CHAT_IDS:
            try:
                await self.send_message(list(ALLOWED_CHAT_IDS)[0], "🛡️ VulnSentry iniciado. Listo para recibir comandos.")
            except Exception as e:
                self.log(f"[-] Error en test_bot: {e}\n{traceback.format_exc()}", logging.ERROR)
        else:
            self.log("[-] No hay ALLOWED_CHAT_IDS configurados para la prueba.", logging.WARNING)

    def log(self, message, level=logging.INFO):
        """Registra mensaje sin exponer datos sensibles."""
        message = html.escape(str(message))[:1000]  # Limitar longitud y sanitizar
        logger.log(level, message)

    async def log_cve(self, vuln_data):
        """Registra vulnerabilidad en CVE_LOG_FILE."""
        async with self.cve_lock:
            cve_log = Path(CVE_LOG_FILE)
            backup = Path(CVE_LOG_BACKUP)
            existing = []
            if cve_log.is_file():
                try:
                    with cve_log.open("r", encoding="utf-8") as f:
                        existing = json.load(f)
                    backup.write_text(cve_log.read_text(encoding="utf-8"), encoding="utf-8")
                except json.JSONDecodeError:
                    self.log("[-] Error: Archivo CVE_LOG corrupto, inicializando nuevo.", logging.WARNING)
            existing.append(vuln_data)
            if len(existing) > 1000:
                existing = existing[-500:]
            try:
                with cve_log.open("w", encoding="utf-8") as f:
                    json.dump(existing, f, indent=2)
            except Exception as e:
                self.log(f"[-] Error escribiendo CVE_LOG: {e}\n{traceback.format_exc()}", logging.ERROR)
                if backup.is_file():
                    cve_log.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8")
                raise

    async def report_cve_progress(self):
        """Reporte periódico de vulnerabilidades."""
        while not self.cancel_event.is_set():
            await asyncio.sleep(REPORT_INTERVAL)
            if not Path(CVE_LOG_FILE).is_file():
                continue
            try:
                with Path(CVE_LOG_FILE).open("r", encoding="utf-8") as f:
                    cves = json.load(f)
                if not cves:
                    continue
                message = (
                    f"🛡️ <b>VulnSentry: Reporte de Vulnerabilidades</b> ({timestamp_now()})\n"
                    f"📊 <b>Total:</b> {len(cves)} vulnerabilidades detectadas\n\n"
                )
                for cve in cves[-5:]:
                    message += (
                        f"🔍 <b>[{html.escape(cve['severity'])}]</b> {html.escape(cve['name'])}\n"
                        f"🌐 <b>Host:</b> {html.escape(cve['host'])}\n"
                        f"ℹ️ <b>Detalles:</b> {html.escape(cve['description'][:100])}...\n\n"
                    )
                await self.send_message_to_all(message)
                self.log(f"[*] Reporte periódico enviado: {len(cves)} vulnerabilidades.", logging.DEBUG)
            except json.JSONDecodeError:
                self.log("[-] Error: Archivo CVE_LOG corrupto, omitiendo reporte.", logging.WARNING)
                continue

    def run_subfinder(self, domain):
        """Ejecuta subfinder para encontrar subdominios."""
        self.log(f"[*] 🔎 Buscando subdominios para {domain}...", logging.INFO)
        self.scan_progress["subfinder"] = "running"
        start_time = time.time()
        cmd = [SUBFINDER_BIN, "-d", domain, "-silent", "-recursive"]
        if SUBFINDER_RESOLVERS:
            cmd.extend(["-r", SUBFINDER_RESOLVERS])
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
                check=True
            )
            subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip() and DOMAIN_REGEX.match(line.strip())]
            Path("subdomains_raw.txt").write_text("\n".join(subdomains), encoding="utf-8")
            elapsed = time.time() - start_time
            message = (
                f"✅ <b>Subfinder:</b> {len(subdomains)} subdominios encontrados para {html.escape(domain)} en {elapsed:.2f}s.\n"
                f"📄 Guardados en subdomains_raw.txt."
            )
            self.scan_progress["subfinder"] = f"completed: {len(subdomains)} subdomains"
            self.log(message, logging.INFO)
            if result.stderr:
                self.log(f"[*] subfinder stderr: {result.stderr[:500]}", logging.DEBUG)
            return subdomains, message
        except subprocess.SubprocessError as e:
            err = getattr(e, "stderr", str(e))
            message = f"❌ <b>Error en subfinder</b> para {html.escape(domain)}: {html.escape(err[:500])}"
            self.scan_progress["subfinder"] = f"failed: {err[:100]}"
            self.log(message, logging.ERROR)
            return [], message

    async def run_httpx(self, subdomains):
        """Ejecuta httpx para validar subdominios activos."""
        self.log("[*] 🌐 Validando subdominios activos con httpx...", logging.INFO)
        self.scan_progress["httpx"] = "running"
        start_time = time.time()
        live = []
        chunks = [subdomains[i:i + 100] for i in range(0, len(subdomains), 100)]
        httpx_version = "unknown"
        try:
            result = subprocess.run([HTTPX_BIN, "-version"], capture_output=True, text=True, timeout=10)
            httpx_version = (result.stdout or result.stderr).strip()
            self.log(f"[*] Versión de httpx: {httpx_version}", logging.DEBUG)
        except subprocess.SubprocessError as e:
            self.log(f"[-] Error obteniendo versión de httpx: {e}", logging.ERROR)
        for chunk in chunks:
            if self.cancel_event.is_set():
                raise asyncio.CancelledError
            try:
                user_agent = re.sub(r'[;"\'\n]', '', random.choice(USER_AGENTS))
                cmd = [
                    HTTPX_BIN, "-silent", "-status-code", "-timeout", str(HTTPX_TIMEOUT),
                    "-threads", str(HTTPX_THREADS), "-header", f"User-Agent: {user_agent}"
                ]
                result = subprocess.run(
                    cmd,
                    input="\n".join(chunk),
                    capture_output=True,
                    text=True,
                    timeout=SUBPROCESS_TIMEOUT
                )
                if result.stderr:
                    self.log(f"[*] httpx stderr: {result.stderr[:500]}", logging.WARNING)
                await asyncio.sleep(random.uniform(0.1, 0.5))
                for line in result.stdout.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[1].startswith(("2", "3")):
                        live.append(parts[0])
                    else:
                        self.log(f"[-] Línea no parseada: {line}", logging.WARNING)
            except subprocess.SubprocessError as e:
                err = getattr(e, "stderr", str(e))
                message = f"❌ <b>Error en httpx</b> para {len(chunk)} subdominios: {html.escape(err[:500])}. Versión de httpx: {httpx_version}"
                self.scan_progress["httpx"] = f"failed: {err[:100]}"
                self.log(message, logging.ERROR)
                await self.send_message_to_all(message)
                continue
        live = list(set(live))
        try:
            Path(TEMP_SCOPE_FILE).write_text("\n".join(live), encoding="utf-8")
        except PermissionError as e:
            message = f"❌ <b>Error escribiendo</b> {TEMP_SCOPE_FILE}: {html.escape(str(e))}"
            self.scan_progress["httpx"] = f"failed: permission error"
            self.log(message, logging.ERROR)
            await self.send_message_to_all(message)
            raise
        elapsed = time.time() - start_time
        message = (
            f"✅ <b>Httpx:</b> {len(live)}/{len(subdomains)} subdominios activos detectados en {elapsed:.2f}s.\n"
            f"📄 Guardados en {TEMP_SCOPE_FILE}."
        )
        if len(live) == 0 and subdomains:
            message += f"\n⚠️ <b>Advertencia:</b> Ningún subdominio respondió con códigos 2xx/3xx. Verifica la conectividad o la configuración de httpx."
        self.scan_progress["httpx"] = f"completed: {len(live)} active subdomains"
        self.log(message, logging.INFO)
        return live, message

    def run_whatweb(self, hosts):
        """Ejecuta whatweb para identificar tecnologías web."""
        self.log("[*] 🕸️ Identificando tecnologías web con whatweb...", logging.INFO)
        self.scan_progress["whatweb"] = "running"
        start_time = time.time()
        technologies = {}
        whatweb_version = "unknown"
        try:
            result = subprocess.run([WHATWEB_BIN, "--version"], capture_output=True, text=True, timeout=10)
            whatweb_version = (result.stdout or result.stderr).strip()
            self.log(f"[*] Versión de whatweb: {whatweb_version}", logging.DEBUG)
        except subprocess.SubprocessError as e:
            self.log(f"[-] Error obteniendo versión de whatweb: {e}", logging.ERROR)
        for host in hosts:
            if self.cancel_event.is_set():
                raise asyncio.CancelledError
            try:
                cmd = [WHATWEB_BIN, "--no-errors", "-a", "3", "--user-agent", random.choice(USER_AGENTS), host]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=WHATWEB_TIMEOUT
                )
                if result.stderr:
                    self.log(f"[*] whatweb stderr para {host}: {result.stderr[:500]}", logging.WARNING)
                tech_list = []
                for line in result.stdout.splitlines():
                    if line.strip():
                        tech_list.append(line.strip())
                technologies[host] = tech_list
            except subprocess.SubprocessError as e:
                err = getattr(e, "stderr", str(e))
                message = f"❌ <b>Error en whatweb</b> para {host}: {html.escape(err[:500])}. Versión de whatweb: {whatweb_version}"
                self.scan_progress["whatweb"] = f"failed: {err[:100]}"
                self.log(message, logging.ERROR)
                return technologies, message
        try:
            with open(WHATWEB_RESULTS_FILE, "w", encoding="utf-8") as f:
                json.dump(technologies, f, indent=2)
        except PermissionError as e:
            message = f"❌ <b>Error escribiendo</b> {WHATWEB_RESULTS_FILE}: {html.escape(str(e))}"
            self.scan_progress["whatweb"] = f"failed: permission error"
            self.log(message, logging.ERROR)
            return technologies, message
        elapsed = time.time() - start_time
        total_techs = sum(len(techs) for techs in technologies.values())
        message = (
            f"✅ <b>Whatweb:</b> Identificadas {total_techs} tecnologías en {len(hosts)} hosts en {elapsed:.2f}s.\n"
            f"📄 Resultados guardados en {WHATWEB_RESULTS_FILE}."
        )
        if total_techs > 0:
            message += "\n<b>Tecnologías detectadas:</b>\n"
            for host, techs in technologies.items():
                for tech in techs[:3]:  # Limitar a 3 por host
                    message += f"🌐 {host}: {html.escape(tech[:100])}\n"
        else:
            message += f"\n⚠️ <b>Advertencia:</b> No se detectaron tecnologías. Verifica la conectividad o ajusta los parámetros de whatweb."
        self.scan_progress["whatweb"] = f"completed: {total_techs} technologies"
        self.log(message, logging.INFO)
        return technologies, message

    def run_nmap(self, hosts):
        """Ejecuta nmap para escanear puertos y servicios en hosts activos."""
        self.log("[*] 🔍 Escaneando puertos con nmap...", logging.INFO)
        self.scan_progress["nmap"] = "running"
        start_time = time.time()
        open_ports = {}
        nmap_version = "unknown"
        try:
            result = subprocess.run([NMAP_BIN, "-version"], capture_output=True, text=True, timeout=10)
            nmap_version = (result.stdout or result.stderr).strip()
            self.log(f"[*] Versión de nmap: {nmap_version}", logging.DEBUG)
        except subprocess.SubprocessError as e:
            self.log(f"[-] Error obteniendo versión de nmap: {e}", logging.ERROR)
        for host in hosts:
            if self.cancel_event.is_set():
                raise asyncio.CancelledError
            try:
                cmd = [NMAP_BIN, "-sV", "--open", "-T4", "-oN", str(NMAP_RESULTS_FILE), host]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=NMAP_TIMEOUT
                )
                if result.stderr:
                    self.log(f"[*] nmap stderr para {host}: {result.stderr[:500]}", logging.WARNING)
                ports = []
                for line in result.stdout.splitlines():
                    if "/tcp" in line and "open" in line:
                        parts = line.split()
                        port = parts[0].split("/")[0]
                        service = parts[2] if len(parts) > 2 else "unknown"
                        version = " ".join(parts[3:]) if len(parts) > 3 else "unknown"
                        ports.append({"port": port, "service": service, "version": version})
                open_ports[host] = ports
            except subprocess.SubprocessError as e:
                err = getattr(e, "stderr", str(e))
                message = f"❌ <b>Error en nmap</b> para {host}: {html.escape(err[:500])}. Versión de nmap: {nmap_version}"
                self.scan_progress["nmap"] = f"failed: {err[:100]}"
                self.log(message, logging.ERROR)
                return open_ports, message
        elapsed = time.time() - start_time
        total_ports = sum(len(ports) for ports in open_ports.values())
        message = (
            f"✅ <b>Nmap:</b> Escaneados {len(hosts)} hosts, {total_ports} puertos abiertos detectados en {elapsed:.2f}s.\n"
            f"📄 Resultados guardados en {NMAP_RESULTS_FILE}."
        )
        if total_ports > 0:
            message += "\n<b>Puertos abiertos:</b>\n"
            for host, ports in open_ports.items():
                for port_info in ports[:3]:
                    message += f"🌐 {host}:{port_info['port']} ({port_info['service']} {port_info['version']})\n"
        else:
            message += f"\n⚠️ <b>Advertencia:</b> No se encontraron puertos abiertos. Verifica la conectividad o ajusta los parámetros de nmap."
        self.scan_progress["nmap"] = f"completed: {total_ports} ports"
        self.log(message, logging.INFO)
        return open_ports, message

    def run_searchsploit(self, keywords):
        """Ejecuta searchsploit para buscar exploits basados en palabras clave."""
        self.log("[*] 🔎 Buscando exploits con searchsploit...", logging.INFO)
        self.scan_progress["searchsploit"] = "running"
        start_time = time.time()
        exploits = []
        searchsploit_version = "unknown"
        try:
            result = subprocess.run([SEARCHSPLOIT_BIN, "--version"], capture_output=True, text=True, timeout=10)
            searchsploit_version = (result.stdout or result.stderr).strip()
            self.log(f"[*] Versión de searchsploit: {searchsploit_version}", logging.DEBUG)
        except subprocess.SubprocessError as e:
            self.log(f"[-] Error obteniendo versión de searchsploit: {e}", logging.ERROR)
        for keyword in keywords:
            if self.cancel_event.is_set():
                raise asyncio.CancelledError
            try:
                cmd = [SEARCHSPLOIT_BIN, "-w", "--json", keyword]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=SUBPROCESS_TIMEOUT
                )
                if result.stderr:
                    self.log(f"[*] searchsploit stderr para {keyword}: {result.stderr[:500]}", logging.WARNING)
                try:
                    data = json.loads(result.stdout)
                    for exploit in data.get("RESULTS_EXPLOIT", []):
                        exploits.append({
                            "title": exploit.get("Title", "N/A"),
                            "url": exploit.get("URL", "N/A"),
                            "keyword": keyword
                        })
                except json.JSONDecodeError:
                    self.log(f"[-] Error parseando salida JSON de searchsploit para {keyword}: {result.stdout[:100]}", logging.WARNING)
            except subprocess.SubprocessError as e:
                err = getattr(e, "stderr", str(e))
                message = f"❌ <b>Error en searchsploit</b> para {keyword}: {html.escape(err[:500])}. Versión de searchsploit: {searchsploit_version}"
                self.scan_progress["searchsploit"] = f"failed: {err[:100]}"
                self.log(message, logging.ERROR)
                return exploits, message
        elapsed = time.time() - start_time
        message = (
            f"✅ <b>Searchsploit:</b> {len(exploits)} posibles exploits encontrados en {elapsed:.2f}s.\n"
            f"📄 Resultados guardados en {SEARCHSPLOIT_RESULTS_FILE}."
        )
        if exploits:
            message += "\n<b>Exploits encontrados:</b>\n"
            for exploit in exploits[:3]:
                message += f"🔍 {html.escape(exploit['title'][:100])}\n🌐 {html.escape(exploit['url'])}\n"
        else:
            message += f"\n⚠️ <b>Advertencia:</b> No se encontraron exploits para las palabras clave proporcionadas."
        try:
            with open(SEARCHSPLOIT_RESULTS_FILE, "w", encoding="utf-8") as f:
                json.dump(exploits, f, indent=2)
        except PermissionError as e:
            message = f"❌ <b>Error escribiendo</b> {SEARCHSPLOIT_RESULTS_FILE}: {html.escape(str(e))}"
            self.scan_progress["searchsploit"] = f"failed: permission error"
            self.log(message, logging.ERROR)
            return exploits, message
        self.scan_progress["searchsploit"] = f"completed: {len(exploits)} exploits"
        self.log(message, logging.INFO)
        return exploits, message

    def merge_targets(self, live_subdomains, root_domain):
        """Fusiona subdominios activos con target.txt."""
        self.log("[*] 🔄 Fusionando dominios de target.txt...", logging.INFO)
        self.scan_progress["merge_targets"] = "running"
        targets = set(live_subdomains)
        targets.add(root_domain)
        if Path(TARGETS_FILE).is_file():
            try:
                targets.update(line.strip() for line in Path(TARGETS_FILE).read_text(encoding="utf-8").splitlines() if line.strip() and DOMAIN_REGEX.match(line.strip()))
            except PermissionError as e:
                message = f"❌ <b>Error leyendo</b> {TARGETS_FILE}: {html.escape(str(e))}"
                self.scan_progress["merge_targets"] = f"failed: permission error"
                self.log(message, logging.ERROR)
                raise
        try:
            Path(SCOPE_FILE).write_text("\n".join(sorted(targets)), encoding="utf-8")
        except PermissionError as e:
            message = f"❌ <b>Error escribiendo</b> {SCOPE_FILE}: {html.escape(str(e))}"
            self.scan_progress["merge_targets"] = f"failed: permission error"
            self.log(message, logging.ERROR)
            raise
        message = (
            f"✅ <b>Scope:</b> {SCOPE_FILE} actualizado con {len(targets)} dominios únicos.\n"
            f"📄 Incluye {len(live_subdomains)} subdominios activos y el dominio raíz."
        )
        self.scan_progress["merge_targets"] = f"completed: {len(targets)} domains"
        self.log(message, logging.INFO)
        return message

    def run_nuclei_scan(self, results_file):
        """Ejecuta nuclei con tags específicos, sin depender de directorio de plantillas."""
        self.log("[*] 🛡️ Iniciando escaneo con nuclei...", logging.INFO)
        self.scan_progress["nuclei"] = "running"
        start_time = time.time()
        if not Path(SCOPE_FILE).is_file() or os.path.getsize(SCOPE_FILE) == 0:
            message = f"❌ <b>Error:</b> El archivo {SCOPE_FILE} está vacío o no existe. No se ejecutará nuclei."
            self.scan_progress["nuclei"] = "failed: empty scope file"
            self.log(message, logging.ERROR)
            return results_file, message
        cmd = [
            NUCLEI_BIN, "-l", str(SCOPE_FILE),
            "-tags", TAGS, "-severity", SEVERITY, "-jsonl",
            "-o", results_file, "-timeout", str(NUCLEI_TIMEOUT),
            "-c", str(NUCLEI_CONCURRENCY), "-retries", "2"
        ]
        self.log(f"[*] Ejecutando comando nuclei: {' '.join(cmd)}", logging.INFO)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT * 2
            )
            if result.stdout:
                self.log(f"[*] Nuclei STDOUT:\n{result.stdout[:500]}", logging.DEBUG)
            if result.stderr:
                self.log(f"[*] Nuclei STDERR:\n{result.stderr[:500]}", logging.WARNING)
            if result.returncode != 0:
                message = f"❌ <b>Error en nuclei</b>: {html.escape(result.stderr[:500])}"
                self.scan_progress["nuclei"] = f"failed: {result.stderr[:100]}"
                self.log(message, logging.ERROR)
                return results_file, message
            if not Path(results_file).is_file() or os.path.getsize(results_file) == 0:
                message = (
                    f"⚠️ <b>Nuclei:</b> No se generaron resultados en {results_file}.\n"
                    f"ℹ️ Posibles causas: ningún host respondió, tags ({TAGS}) no aplicables, o versión de nuclei desactualizada."
                )
                self.scan_progress["nuclei"] = "completed: no results"
                self.log(message, logging.WARNING)
                return results_file, message
            try:
                with open(results_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines, 1):
                        if line.strip():
                            json.loads(line.strip())
            except json.JSONDecodeError as e:
                message = f"❌ <b>Error:</b> Archivo {results_file} contiene JSONL inválido en línea {i}: {html.escape(str(e))}"
                self.scan_progress["nuclei"] = f"failed: invalid JSONL"
                self.log(message, logging.ERROR)
                raise ValueError("Archivo de resultados corrupto")
            elapsed = time.time() - start_time
            message = (
                f"✅ <b>Nuclei:</b> Escaneo completado en {elapsed:.2f}s.\n"
                f"📄 Resultados guardados en {results_file}."
            )
            self.scan_progress["nuclei"] = f"completed: results in {results_file}"
            self.log(message, logging.INFO)
            return results_file, message
        except subprocess.SubprocessError as e:
            err = getattr(e, "stderr", str(e))
            message = f"❌ <b>Error en nuclei</b>: {html.escape(err[:500])}"
            self.scan_progress["nuclei"] = f"failed: {err[:100]}"
            self.log(message, logging.ERROR)
            return results_file, message

    async def parse_results(self, results_file, nmap_results, whatweb_results):
        """Procesa resultados de nuclei, nmap y whatweb para generar palabras clave para searchsploit."""
        if not Path(results_file).is_file():
            message = f"❌ <b>Error:</b> No se encontró {results_file}."
            self.scan_progress["parse_results"] = "failed: results file not found"
            self.log(message, logging.ERROR)
            return None, [], message
        self.log("[*] 📊 Procesando resultados del escaneo...", logging.INFO)
        self.scan_progress["parse_results"] = "running"
        vulnerabilities = []
        keywords = []
        with open(results_file, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line.strip())
                    host = data.get("host", "Desconocido")
                    vuln = data.get("info", {}).get("name", "N/A")
                    severity = data.get("info", {}).get("severity", "N/A").upper()
                    description = data.get("info", {}).get("description", "Sin descripción")
                    vuln_data = {"severity": severity, "name": vuln, "host": host, "description": description}
                    await self.log_cve(vuln_data)
                    vulnerabilities.append(vuln_data)
                    if "CVE-" in vuln:
                        keywords.append(vuln)
                    for word in description.split():
                        if "CVE-" in word or re.match(r"[a-zA-Z0-9-]+\s+\d+\.\d+\.\d+", word):
                            keywords.append(word)
                except json.JSONDecodeError:
                    self.log(f"[-] Línea no parseada en {results_file}: {line[:100]}...", logging.WARNING)
                    continue
        for host, ports in nmap_results.items():
            for port_info in ports:
                service = port_info["service"]
                version = port_info["version"]
                if version != "unknown":
                    keywords.append(f"{service} {version}")
                else:
                    keywords.append(service)
        for host, techs in whatweb_results.items():
            for tech in techs:
                if re.match(r"[a-zA-Z0-9-]+\s+\d+\.\d+\.\d+", tech):
                    keywords.append(tech)
        keywords = list(set(keywords))
        if not vulnerabilities:
            message = (
                f"⚠️ <b>Nuclei:</b> No se encontraron vulnerabilidades.\n"
                f"ℹ️ Verifica si los hosts en {SCOPE_FILE} son accesibles o si los tags ({TAGS}) son adecuados."
            )
            self.scan_progress["parse_results"] = "completed: no vulnerabilities"
            self.log(message, logging.WARNING)
            return None, keywords, message
        vulnerabilities.sort(key=lambda v: SEVERITY_ORDER.get(v["severity"], -1), reverse=True)
        message = (
            f"🛡️ <b>VulnSentry: Resumen del Escaneo</b> ({timestamp_now()})\n"
            f"📊 <b>Total vulnerabilidades:</b> {len(vulnerabilities)}\n\n"
        )
        for vuln in vulnerabilities:
            console_msg = f"[{vuln['severity']}] {vuln['name']} en {vuln['host']}\n  └─ {vuln['description']}"
            self.log(console_msg, logging.INFO)
            message += (
                f"🔍 <b>[{html.escape(vuln['severity'])}]</b> {html.escape(vuln['name'])}\n"
                f"🌐 <b>Host:</b> {html.escape(vuln['host'])}\n"
                f"ℹ️ <b>Detalles:</b> {html.escape(vuln['description'][:100])}...\n\n"
            )
        self.latest_results["vulnerabilities"] = vulnerabilities
        self.latest_results["nmap"] = nmap_results
        self.latest_results["whatweb"] = whatweb_results
        self.scan_progress["parse_results"] = f"completed: {len(vulnerabilities)} vulnerabilities"
        return vulnerabilities, keywords, message

    async def run_scan(self, domain, chat_id):
        """Ejecuta pipeline de escaneo."""
        async with self.scan_lock:
            self.cancel_event.clear()
            self.scan_progress = {"domain": domain, "status": "running"}
            results_file = str(BASE_DIR / f"results_{timestamp_now()}.json")
            try:
                with open(TARGETS_FILE, "w", encoding="utf-8") as f:
                    f.write(f"{domain}\n")
                subdomains, msg = await asyncio.get_running_loop().run_in_executor(self.executor, self.run_subfinder, domain)
                await self.send_message_to_all(msg)
                live_subdomains = []
                if subdomains:
                    live_subdomains, msg = await self.run_httpx(subdomains)
                    await self.send_message_to_all(msg)
                else:
                    self.log(f"[*] No se encontraron subdominios, escaneando solo el dominio raíz: {domain}", logging.INFO)
                    live_subdomains = [domain]
                whatweb_results, msg = await asyncio.get_running_loop().run_in_executor(self.executor, self.run_whatweb, live_subdomains)
                await self.send_message_to_all(msg)
                nmap_results, msg = await asyncio.get_running_loop().run_in_executor(self.executor, self.run_nmap, live_subdomains)
                await self.send_message_to_all(msg)
                msg = await asyncio.get_running_loop().run_in_executor(self.executor, self.merge_targets, live_subdomains, domain)
                await self.send_message_to_all(msg)
                results_file, msg = await asyncio.get_running_loop().run_in_executor(self.executor, self.run_nuclei_scan, results_file)
                await self.send_message_to_all(msg)
                vulnerabilities, keywords, msg = await self.parse_results(results_file, nmap_results, whatweb_results)
                await self.send_message_to_all(msg)
                if keywords:
                    exploits, msg = await asyncio.get_running_loop().run_in_executor(self.executor, self.run_searchsploit, keywords)
                    await self.send_message_to_all(msg)
                existing = set(Path(HISTORY_FILE).read_text(encoding="utf-8").splitlines()) if Path(HISTORY_FILE).is_file() else set()
                if domain not in existing:
                    with open(HISTORY_FILE, "a", encoding="utf-8") as f:
                        f.write(f"{domain}\n")
                try:
                    Path(TARGETS_FILE).unlink(missing_ok=True)
                except PermissionError as e:
                    message = f"❌ <b>Error eliminando</b> {TARGETS_FILE}: {html.escape(str(e))}"
                    self.log(message, logging.ERROR)
                    await self.send_message_to_all(message)
                message = (
                    f"🎉 <b>Escaneo de {html.escape(domain)} finalizado exitosamente!</b>\n"
                    f"ℹ️ <b>Resumen:</b>\n"
                    f"- Subdominios: {len(subdomains)} encontrados, {len(live_subdomains)} activos\n"
                    f"- Tecnologías: {sum(len(techs) for techs in whatweb_results.values())} detectadas\n"
                    f"- Puertos: {sum(len(ports) for ports in nmap_results.values())} abiertos\n"
                    f"- Vulnerabilidades: {len(vulnerabilities or [])}\n"
                    f"- Palabras clave: {len(keywords)}\n"
                    f"- Exploits: {len(exploits or [])} posibles\n"
                    f"📄 Resultados en {results_file}, {WHATWEB_RESULTS_FILE}, {NMAP_RESULTS_FILE}, {SEARCHSPLOIT_RESULTS_FILE}"
                )
                self.scan_progress["status"] = "completed"
                self.log(message, logging.INFO)
                await self.send_message_to_all(message)
            except asyncio.CancelledError:
                message = f"🚫 <b>Escaneo de {html.escape(domain)} cancelado por el usuario.</b>"
                self.scan_progress["status"] = "cancelled"
                self.log(message, logging.WARNING)
                await self.send_message_to_all(message)
            except Exception as e:
                message = f"❌ <b>Error en el pipeline</b> para {html.escape(domain)}: {html.escape(str(e))}"
                self.scan_progress["status"] = f"failed: {str(e)[:100]}"
                self.log(message, logging.ERROR)
                await self.send_message_to_all(message)
            finally:
                for file in [SCOPE_FILE, TEMP_SCOPE_FILE, BASE_DIR / "subdomains_raw.txt", results_file, NMAP_RESULTS_FILE, SEARCHSPLOIT_RESULTS_FILE, WHATWEB_RESULTS_FILE]:
                    try:
                        Path(file).unlink(missing_ok=True)
                    except PermissionError as e:
                        message = f"❌ <b>Error eliminando</b> {file}: {html.escape(str(e))}"
                        self.log(message, logging.ERROR)
                        await self.send_message_to_all(message)
                self.scan_task = None

    async def target(self, update, context):
        """Comando /target para iniciar escaneo."""
        chat_id = update.effective_chat.id
        if chat_id not in ALLOWED_CHAT_IDS:
            await update.message.reply_text("🚫 Acceso denegado. Usa el comando en el grupo permitido.", parse_mode="HTML")
            return
        if not context.args or not context.args[0]:
            await update.message.reply_text("❓ Uso: /target <code>domain</code> (ej. example.com)", parse_mode="HTML")
            return
        domain = context.args[0].strip().rstrip('.').lower()
        if not DOMAIN_REGEX.match(domain):
            await update.message.reply_text("❓ Dominio inválido: caracteres no permitidos o formato incorrecto.", parse_mode="HTML")
            return
        if domain in ("localhost", "127.0.0.1"):
            await update.message.reply_text("❓ Dominio inválido: no se permite localhost.", parse_mode="HTML")
            return
        try:
            ipaddress.ip_network(domain, strict=False)
            await update.message.reply_text("❓ Dominio inválido: no se aceptan IPs ni rangos CIDR.", parse_mode="HTML")
            return
        except ValueError:
            pass
        ext = tldextract.extract(domain.lstrip('*.'))
        if not ext.top_domain_under_public_suffix:
            await update.message.reply_text("❓ Dominio inválido. Usa un dominio válido (ej. example.com).", parse_mode="HTML")
            return
        async with self.scan_lock:
            if self.scan_task and not self.scan_task.done():
                await update.message.reply_text("⏳ Escaneo en curso. Por favor, espera a que termine.", parse_mode="HTML")
                return
            await self.send_message(chat_id, f"🛡️ <b>VulnSentry: Iniciando escaneo para {html.escape(domain)}</b> 🎯")
            self.scan_task = asyncio.create_task(self.run_scan(domain.lstrip('*.'), chat_id))
            self.scan_task.add_done_callback(self.done_callback)

    async def status(self, update, context):
        """Comando /status para verificar estado."""
        chat_id = update.effective_chat.id
        if chat_id not in ALLOWED_CHAT_IDS:
            await update.message.reply_text("🚫 Acceso denegado. Usa el comando en el grupo permitido.", parse_mode="HTML")
            return
        async with self.scan_lock:
            if self.scan_task and not self.scan_task.done():
                await update.message.reply_text("⏳ <b>Estado:</b> Escaneo en curso...", parse_mode="HTML")
            else:
                await update.message.reply_text("✅ <b>Estado:</b> Libre para nuevos escaneos.", parse_mode="HTML")

    async def scanstatus(self, update, context):
        """Comando /scanstatus para mostrar progreso detallado del escaneo."""
        chat_id = update.effective_chat.id
        if chat_id not in ALLOWED_CHAT_IDS:
            await update.message.reply_text("🚫 Acceso denegado. Usa el comando en el grupo permitido.", parse_mode="HTML")
            return
        if not self.scan_progress:
            await update.message.reply_text("ℹ️ <b>ScanStatus:</b> No hay escaneo en curso o finalizado.", parse_mode="HTML")
            return
        message = f"🛡️ <b>VulnSentry: Estado del Escaneo</b>\n🌐 <b>Dominio:</b> {html.escape(self.scan_progress.get('domain', 'N/A'))}\n📊 <b>Estado General:</b> {self.scan_progress.get('status', 'N/A')}\n\n"
        for step, status in self.scan_progress.items():
            if step != "domain" and step != "status":
                message += f"🔧 <b>{step.capitalize()}:</b> {html.escape(status)}\n"
        await update.message.reply_text(message[:4096], parse_mode="HTML")

    async def toolcheck(self, update, context):
        """Comando /toolcheck para verificar herramientas instaladas."""
        chat_id = update.effective_chat.id
        if chat_id not in ALLOWED_CHAT_IDS:
            await update.message.reply_text("🚫 Acceso denegado. Usa el comando en el grupo permitido.", parse_mode="HTML")
            return
        tools = [
            ("nuclei", NUCLEI_BIN),
            ("subfinder", SUBFINDER_BIN),
            ("httpx", HTTPX_BIN),
            ("nmap", NMAP_BIN),
            ("searchsploit", SEARCHSPLOIT_BIN),
            ("whatweb", WHATWEB_BIN)
        ]
        message = "🛠️ <b>VulnSentry: Verificación de Herramientas</b>\n\n"
        for tool, path in tools:
            version = "unknown"
            status = "✅ Installed"
            try:
                result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10)
                version = (result.stdout or result.stderr).strip()
                if "outdated" in version.lower() and tool == "nuclei":
                    status += " (⚠️ Outdated)"
            except (subprocess.SubprocessError, FileNotFoundError, PermissionError):
                status = "❌ Not installed or not executable"
            message += f"🔧 <b>{tool.capitalize()}:</b> {status}\n📍 Path: {path}\n📌 Version: {html.escape(version)}\n\n"
        await update.message.reply_text(message[:4096], parse_mode="HTML")

    async def results(self, update, context):
        """Comando /results para mostrar los últimos resultados."""
        chat_id = update.effective_chat.id
        if chat_id not in ALLOWED_CHAT_IDS:
            await update.message.reply_text("🚫 Acceso denegado. Usa el comando en el grupo permitido.", parse_mode="HTML")
            return
        if not self.latest_results:
            await update.message.reply_text("ℹ️ <b>Resultados:</b> No hay resultados de escaneos recientes.", parse_mode="HTML")
            return
        message = f"🛡️ <b>VulnSentry: Últimos Resultados</b>\n\n"
        if "vulnerabilities" in self.latest_results:
            message += f"📊 <b>Vulnerabilidades ({len(self.latest_results['vulnerabilities'])}):</b>\n"
            for vuln in self.latest_results["vulnerabilities"][:3]:
                message += (
                    f"🔍 <b>[{html.escape(vuln['severity'])}]</b> {html.escape(vuln['name'])}\n"
                    f"🌐 <b>Host:</b> {html.escape(vuln['host'])}\n"
                    f"ℹ️ <b>Detalles:</b> {html.escape(vuln['description'][:100])}...\n\n"
                )
        if "whatweb" in self.latest_results:
            message += f"🕸️ <b>Tecnologías ({sum(len(techs) for techs in self.latest_results['whatweb'].values())}):</b>\n"
            for host, techs in list(self.latest_results["whatweb"].items())[:2]:
                for tech in techs[:2]:
                    message += f"🌐 {host}: {html.escape(tech[:100])}\n"
        if "nmap" in self.latest_results:
            message += f"🔌 <b>Puertos ({sum(len(ports) for ports in self.latest_results['nmap'].values())}):</b>\n"
            for host, ports in list(self.latest_results["nmap"].items())[:2]:
                for port_info in ports[:2]:
                    message += f"🌐 {host}:{port_info['port']} ({port_info['service']} {port_info['version']})\n"
        await update.message.reply_text(message[:4096], parse_mode="HTML")

    async def history(self, update, context):
        """Comando /history para listar escaneos previos."""
        chat_id = update.effective_chat.id
        if chat_id not in ALLOWED_CHAT_IDS:
            await update.message.reply_text("🚫 Acceso denegado. Usa el comando en el grupo permitido.", parse_mode="HTML")
            return
        if not Path(HISTORY_FILE).is_file():
            await update.message.reply_text("📜 <b>Historial:</b> No hay escaneos previos.", parse_mode="HTML")
            return
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                domains = f.read().splitlines()[-10:]
            message = "📜 <b>VulnSentry: Historial de Escaneos</b>\n" + "\n".join(map(html.escape, domains))
            await update.message.reply_text(message[:4096], parse_mode="HTML")
        except PermissionError as e:
            message = f"❌ <b>Error leyendo</b> {HISTORY_FILE}: {html.escape(str(e))}"
            self.log(message, logging.ERROR)
            await update.message.reply_text(message, parse_mode="HTML")

    async def cancel(self, update, context):
        """Comando /cancel para detener escaneo."""
        chat_id = update.effective_chat.id
        if chat_id not in ALLOWED_CHAT_IDS:
            await update.message.reply_text("🚫 Acceso denegado. Usa el comando en el grupo permitido.", parse_mode="HTML")
            return
        async with self.scan_lock:
            if self.scan_task and not self.scan_task.done():
                self.cancel_event.set()
                try:
                    await self.scan_task
                except asyncio.CancelledError:
                    pass
                await update.message.reply_text("🚫 <b>Escaneo cancelado.</b>", parse_mode="HTML")
            else:
                await update.message.reply_text("✅ <b>No hay escaneo en curso.</b>", parse_mode="HTML")

    async def help(self, update, context):
        """Comando /help para mostrar ayuda."""
        chat_id = update.effective_chat.id
        if chat_id not in ALLOWED_CHAT_IDS:
            await update.message.reply_text("🚫 Acceso denegado. Usa el comando en el grupo permitido.", parse_mode="HTML")
            return
        message = (
            "🛡️ <b>VulnSentry: Comandos Disponibles</b>\n\n"
            "🔍 /target <code>domain</code> - Inicia un escaneo para el dominio especificado (ej. example.com).\n"
            "📊 /status - Muestra el estado general del escaneo.\n"
            "🔎 /scanstatus - Muestra el progreso detallado de cada etapa del escaneo.\n"
            "🛠️ /toolcheck - Verifica las herramientas instaladas y sus versiones.\n"
            "📜 /history - Lista los dominios escaneados previamente.\n"
            "📋 /results - Muestra los resultados del último escaneo.\n"
            "🚫 /cancel - Cancela el escaneo en curso.\n"
            "ℹ️ /version - Muestra la versión del bot y herramientas.\n"
            "⚙️ /config - Muestra la configuración actual.\n"
            "⏰ /uptime - Muestra el tiempo en ejecución del bot.\n"
            "❓ /help - Muestra esta ayuda."
        )
        self.log(f"[*] Enviando mensaje de ayuda a chat_id {chat_id}: {message[:50]}...", logging.DEBUG)
        await update.message.reply_text(message, parse_mode="HTML")

    async def version(self, update, context):
        """Comando /version para mostrar versiones."""
        chat_id = update.effective_chat.id
        if chat_id not in ALLOWED_CHAT_IDS:
            await update.message.reply_text("🚫 Acceso denegado. Usa el comando en el grupo permitido.", parse_mode="HTML")
            return
        nuclei_version = subfinder_version = httpx_version = nmap_version = searchsploit_version = whatweb_version = "Error"
        try:
            result = subprocess.run([NUCLEI_BIN, "-version"], capture_output=True, text=True, timeout=10)
            nuclei_version = (result.stderr or result.stdout).strip()
            self.log(f"[*] Nuclei version output: {nuclei_version}", logging.DEBUG)
        except subprocess.SubprocessError as e:
            self.log(f"[-] Error obteniendo versión de nuclei: {e}", logging.ERROR)
        try:
            result = subprocess.run([SUBFINDER_BIN, "-version"], capture_output=True, text=True, timeout=10)
            subfinder_version = (result.stderr or result.stdout).strip()
            self.log(f"[*] Subfinder version output: {subfinder_version}", logging.DEBUG)
        except subprocess.SubprocessError as e:
            self.log(f"[-] Error obteniendo versión de subfinder: {e}", logging.ERROR)
        try:
            result = subprocess.run([HTTPX_BIN, "-version"], capture_output=True, text=True, timeout=10)
            httpx_version = (result.stdout or result.stderr).strip()
            self.log(f"[*] Httpx version output: {httpx_version}", logging.DEBUG)
        except subprocess.SubprocessError as e:
            self.log(f"[-] Error obteniendo versión de httpx: {e}", logging.ERROR)
        try:
            result = subprocess.run([NMAP_BIN, "-version"], capture_output=True, text=True, timeout=10)
            nmap_version = (result.stdout or result.stderr).strip()
            self.log(f"[*] Nmap version output: {nmap_version}", logging.DEBUG)
        except subprocess.SubprocessError as e:
            self.log(f"[-] Error obteniendo versión de nmap: {e}", logging.ERROR)
        try:
            result = subprocess.run([SEARCHSPLOIT_BIN, "--version"], capture_output=True, text=True, timeout=10)
            searchsploit_version = (result.stdout or result.stderr).strip()
            self.log(f"[*] Searchsploit version output: {searchsploit_version}", logging.DEBUG)
        except subprocess.SubprocessError as e:
            self.log(f"[-] Error obteniendo versión de searchsploit: {e}", logging.ERROR)
        try:
            result = subprocess.run([WHATWEB_BIN, "--version"], capture_output=True, text=True, timeout=10)
            whatweb_version = (result.stdout or result.stderr).strip()
            self.log(f"[*] Whatweb version output: {whatweb_version}", logging.DEBUG)
        except subprocess.SubprocessError as e:
            self.log(f"[-] Error obteniendo versión de whatweb: {e}", logging.ERROR)
        version_info = (
            "🛡️ <b>VulnSentry: Versión</b>\n"
            f"ℹ️ Versión del script: 0.0.0.1\n"
            f"ℹ️ Python: {sys.version.split()[0]}\n"
            f"ℹ️ python-telegram-bot: {telegram.__version__}\n"
            f"ℹ️ Nuclei: {nuclei_version}\n"
            f"ℹ️ Subfinder: {subfinder_version}\n"
            f"ℹ️ Httpx: {httpx_version}\n"
            f"ℹ️ Nmap: {nmap_version}\n"
            f"ℹ️ Searchsploit: {searchsploit_version}\n"
            f"ℹ️ Whatweb: {whatweb_version}"
        )
        if "outdated" in nuclei_version.lower():
            version_info += "\n⚠️ <b>Advertencia:</b> La versión de nuclei está desactualizada. Ejecute 'nuclei -update'."
        await update.message.reply_text(version_info, parse_mode="HTML")

    async def config(self, update, context):
        """Comando /config para mostrar configuración."""
        chat_id = update.effective_chat.id
        if chat_id not in ALLOWED_CHAT_IDS:
            await update.message.reply_text("🚫 Acceso denegado. Usa el comando en el grupo permitido.", parse_mode="HTML")
            return
        config_info = (
            "🛡️ <b>VulnSentry: Configuración</b>\n"
            f"ℹ️ NUCLEI_TAGS: {TAGS}\n"
            f"ℹ️ NUCLEI_SEVERITY: {SEVERITY}\n"
            f"ℹ️ HTTPX_TIMEOUT: {HTTPX_TIMEOUT}s\n"
            f"ℹ️ NUCLEI_TIMEOUT: {NUCLEI_TIMEOUT}s\n"
            f"ℹ️ NMAP_TIMEOUT: {NMAP_TIMEOUT}s\n"
            f"ℹ️ WHATWEB_TIMEOUT: {WHATWEB_TIMEOUT}s\n"
            f"ℹ️ ALLOWED_CHAT_IDS: {', '.join(map(str, ALLOWED_CHAT_IDS))}\n"
            f"ℹ️ DEBUG_MODE: {DEBUG_MODE}"
        )
        await update.message.reply_text(config_info, parse_mode="HTML")

    async def uptime(self, update, context):
        """Comando /uptime para mostrar tiempo en ejecución."""
        chat_id = update.effective_chat.id
        if chat_id not in ALLOWED_CHAT_IDS:
            await update.message.reply_text("🚫 Acceso denegado. Usa el comando en el grupo permitido.", parse_mode="HTML")
            return
        uptime_seconds = time.time() - self.start_time
        uptime_str = str(timedelta(seconds=int(uptime_seconds)))
        message = f"🛡️ <b>VulnSentry: Uptime</b>\n⏰ Tiempo en ejecución: {uptime_str}"
        await update.message.reply_text(message, parse_mode="HTML")

    async def error_handler(self, update, context):
        """Maneja errores globales del bot."""
        self.log(f"[-] Error en update: {context.error}\n{traceback.format_exc()}", logging.ERROR)
        if update and update.effective_chat.id in ALLOWED_CHAT_IDS:
            await update.effective_message.reply_text(
                "❌ Ocurrió un error procesando el comando. Intenta de nuevo o contacta al administrador.",
                parse_mode="HTML"
            )

    async def start(self):
        """Inicia el bot y configura comandos."""
        self.app.add_handler(CommandHandler("target", self.target))
        self.app.add_handler(CommandHandler("status", self.status))
        self.app.add_handler(CommandHandler("scanstatus", self.scanstatus))
        self.app.add_handler(CommandHandler("toolcheck", self.toolcheck))
        self.app.add_handler(CommandHandler("results", self.results))
        self.app.add_handler(CommandHandler("history", self.history))
        self.app.add_handler(CommandHandler("cancel", self.cancel))
        self.app.add_handler(CommandHandler("help", self.help))
        self.app.add_handler(CommandHandler("version", self.version))
        self.app.add_handler(CommandHandler("config", self.config))
        self.app.add_handler(CommandHandler("uptime", self.uptime))
        self.app.add_error_handler(self.error_handler)
        try:
            await self.app.initialize()
            await self.app.start()
            asyncio.create_task(self.report_cve_progress())
            await self.app.updater.start_polling(drop_pending_updates=True)
            self.log("[*] Bot iniciado en modo polling.", logging.INFO)
            while not self.cancel_event.is_set():
                await asyncio.sleep(1)
        except telegram.error.InvalidToken as e:
            self.log(f"[-] Token de Telegram inválido: {e}\n{traceback.format_exc()}", logging.CRITICAL)
            raise
        except (telegram.error.TimedOut, telegram.error.NetworkError) as e:
            self.log(f"[-] Error de conexión con Telegram: {e}. Verifica red o proxy.\n{traceback.format_exc()}", logging.ERROR)
            raise
        except Exception as e:
            self.log(f"[-] Error inesperado en start: {e}\n{traceback.format_exc()}", logging.ERROR)
            raise
        finally:
            self.log("[*] Deteniendo aplicación...", logging.INFO)
            try:
                await self.app.stop()
                await self.app.shutdown()
                self.log("[*] Aplicación cerrada correctamente.", logging.INFO)
            except Exception as e:
                self.log(f"[-] Error cerrando aplicación: {e}", logging.ERROR)

async def main():
    """Función principal para iniciar el bot."""
    bot = VulnSentry()
    loop = asyncio.get_event_loop()
    signal.signal(signal.SIGINT, bot.handle_signal)
    signal.signal(signal.SIGTERM, bot.handle_signal)
    try:
        await bot.test_bot()
        await bot.start()
    except Exception as e:
        bot.log(f"[-] Error en main: {e}\n{traceback.format_exc()}", logging.ERROR)
    finally:
        if not loop.is_closed():
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()
            bot.log("[*] Bucle de eventos cerrado.", logging.INFO)

if __name__ == "__main__":
    asyncio.run(main())