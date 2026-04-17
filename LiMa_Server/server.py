# ============================================================================
# LiMa Server – Flask-basierter Authentifizierungsserver für das HSD-System
#
# Dieses Backend verwaltet:
#   - Bridge-Geräte (ESP32-Clients): Registrierung, Token, Heartbeat
#   - Benutzer: E-Mail/Passwort-Login, NFC-UIDs, OTP (TOTP + Mail)
#   - Maschinenfreischaltung: Zeitlich befristet, mit Audit-Log
#   - Bridge-Konfiguration: Maschinenname, Standort, Idle-Erkennung etc.
#   - Admin-Dashboard: Echtzeit-Übersicht über Clients, User, Logs
#
# Datenbanken:
#   - lima_clients.db: Bridge-Tokens, OTP-Status, Konfigurationen
#   - lima_users.db: Benutzer, NFC-UIDs, OTP-Secrets, Unlock-/Mail-Logs
#
# API-Endpunkte (Bridge → Server):
#   POST /api/hsd/setup            - Erstregistrierung (MAC → Token)
#   POST /api/hsd/heartbeat        - Statusbericht + Config-Sync
#   POST /api/hsd/nfc              - NFC-UID-Authentifizierung
#   POST /api/hsd/login            - E-Mail/Passwort-Login
#   POST /api/hsd/pin              - OTP-Verifizierung (TOTP oder Mail)
#   POST /api/hsd/register_card    - NFC-Karte mit Benutzer verknüpfen
#   POST /api/hsd/ping             - Token-Validierung
#
# Admin-Endpunkte (Dashboard):
#   GET/POST /api/admin/users/*          - Benutzerverwaltung
#   GET/POST /api/admin/clients/*        - Client-Verwaltung
#   GET/POST /api/admin/bridge_config/*  - Bridge-Konfiguration
#   GET      /api/admin/unlock_log       - Freischaltungs-Protokoll
#   GET      /                           - Admin-Dashboard (HTML)
# ============================================================================

from flask import Flask, request, jsonify, send_file, Response
import base64
import hashlib
import io
import json
import logging
import os
import secrets
import sqlite3
import urllib.request
from datetime import datetime, timedelta, timezone
from werkzeug.exceptions import BadRequest
from werkzeug.utils import secure_filename

try:
    import pyotp
except ImportError:
    pyotp = None

try:
    import qrcode
except ImportError:
    qrcode = None

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

BASE_DIR = os.path.dirname(__file__)
CLIENTS_DB_PATH = os.path.join(BASE_DIR, 'lima_clients.db')
USERS_DB_PATH = os.path.join(BASE_DIR, 'lima_users.db')
OTA_FIRMWARE_DIR = os.path.join(BASE_DIR, 'ota_firmware')
OTA_VERSION_FILE = os.path.join(OTA_FIRMWARE_DIR, 'version.txt')
OTA_FIRMWARE_FILE = os.path.join(OTA_FIRMWARE_DIR, 'firmware.bin')
TOKEN_BYTES = 24
LOGIN_OTP_TTL_MINUTES = 5
PIN_TTL_MINUTES = 5
OPENID_FORWARD_URL = os.getenv('OPENID_FORWARD_URL', '').strip()

ADMIN_PASSWORD = os.getenv('LIMA_ADMIN_PASSWORD', 'L1Ma')


def _check_admin_auth():
    """Gibt None zurück wenn Auth OK, sonst eine 401-Response."""
    auth = request.authorization
    if auth and auth.password == ADMIN_PASSWORD:
        return None
    return Response(
        'Zugang verweigert',
        401,
        {'WWW-Authenticate': 'Basic realm="LiMa Admin"'}
    )


def admin_required(f):
    """Decorator: schützt Admin-Routen mit HTTP Basic Auth."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        err = _check_admin_auth()
        if err is not None:
            return err
        return f(*args, **kwargs)
    return decorated


def localtime_iso():
# Gibt aktuelle UTC-Zeit als ISO-String mit Z-Suffix zurück (timezone-safe für Browser)
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_iso_datetime(value):
    # Parst ISO-String zu datetime-Objekt, None bei Fehler
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


# ============================================================================
# Datenbank-Initialisierung: Erstellt Tabellen und fügt fehlende Spalten hinzu.
# Beim ersten Start werden Demo-Benutzer angelegt.
# ============================================================================

def clients_db_connect():
    # Öffnet Verbindung zur clients-Datenbank (Row-Factory)
    conn = sqlite3.connect(CLIENTS_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def users_db_connect():
    # Öffnet Verbindung zur users-Datenbank (Row-Factory)
    conn = sqlite3.connect(USERS_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def add_column_if_missing(conn, table_name, column_name, ddl_sql):
    # Fügt Spalte zu Tabelle hinzu, falls sie fehlt
    rows = conn.execute(f'PRAGMA table_info({table_name})').fetchall()
    existing = {row['name'] for row in rows}
    if column_name not in existing:
        conn.execute(ddl_sql)


def init_clients_db():
    # Initialisiert clients- und bridge_config-Tabellen, legt fehlende Spalten an
    with clients_db_connect() as conn:
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS clients (
                token TEXT PRIMARY KEY,
                mac_address TEXT NOT NULL UNIQUE,
                otp_secret TEXT,
                otp_secret_hash TEXT,
                current_pin TEXT,
                pin_expires TEXT,
                last_uid TEXT,
                otp_verified_until TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            )
            '''
        )

        add_column_if_missing(conn, 'clients', 'user_id', 'ALTER TABLE clients ADD COLUMN user_id INTEGER')
        add_column_if_missing(conn, 'clients', 'mail_otp_hash', 'ALTER TABLE clients ADD COLUMN mail_otp_hash TEXT')
        add_column_if_missing(conn, 'clients', 'mail_otp_expires', 'ALTER TABLE clients ADD COLUMN mail_otp_expires TEXT')
        add_column_if_missing(conn, 'clients', 'mail_otp_consumed_at', 'ALTER TABLE clients ADD COLUMN mail_otp_consumed_at TEXT')

        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS bridge_config (
                mac_address TEXT PRIMARY KEY,
                machine_name TEXT NOT NULL DEFAULT '',
                location TEXT NOT NULL DEFAULT '',
                idle_current REAL NOT NULL DEFAULT 0.0,
                sound_enabled INTEGER NOT NULL DEFAULT 0,
                idle_detection_enabled INTEGER NOT NULL DEFAULT 0,
                otp_required INTEGER NOT NULL DEFAULT 1,
                info_url TEXT NOT NULL DEFAULT '',
                unlock_duration INTEGER NOT NULL DEFAULT 30,
                config_version INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL,
                last_heartbeat_at TEXT
            )
            '''
        )
        add_column_if_missing(conn, 'bridge_config', 'last_heartbeat_at',
                              'ALTER TABLE bridge_config ADD COLUMN last_heartbeat_at TEXT')
        add_column_if_missing(conn, 'bridge_config', 'otp_required',
                              'ALTER TABLE bridge_config ADD COLUMN otp_required INTEGER NOT NULL DEFAULT 1')
        add_column_if_missing(conn, 'bridge_config', 'info_url',
                              "ALTER TABLE bridge_config ADD COLUMN info_url TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(conn, 'bridge_config', 'unlock_duration',
                              'ALTER TABLE bridge_config ADD COLUMN unlock_duration INTEGER NOT NULL DEFAULT 30')
        add_column_if_missing(conn, 'bridge_config', 'unlock_status',
                              "ALTER TABLE bridge_config ADD COLUMN unlock_status TEXT NOT NULL DEFAULT 'locked'")
        add_column_if_missing(conn, 'bridge_config', 'unlock_remaining_min',
                              'ALTER TABLE bridge_config ADD COLUMN unlock_remaining_min INTEGER NOT NULL DEFAULT 0')
        add_column_if_missing(conn, 'bridge_config', 'fw_version',
                              "ALTER TABLE bridge_config ADD COLUMN fw_version TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(conn, 'bridge_config', 'auto_ota',
                              'ALTER TABLE bridge_config ADD COLUMN auto_ota INTEGER NOT NULL DEFAULT 0')
        add_column_if_missing(conn, 'bridge_config', 'ads0',
                              'ALTER TABLE bridge_config ADD COLUMN ads0 INTEGER NOT NULL DEFAULT 0')
        add_column_if_missing(conn, 'bridge_config', 'ads1',
                              'ALTER TABLE bridge_config ADD COLUMN ads1 INTEGER NOT NULL DEFAULT 0')
        add_column_if_missing(conn, 'bridge_config', 'ads2',
                              'ALTER TABLE bridge_config ADD COLUMN ads2 INTEGER NOT NULL DEFAULT 0')
        add_column_if_missing(conn, 'bridge_config', 'ads3',
                              'ALTER TABLE bridge_config ADD COLUMN ads3 INTEGER NOT NULL DEFAULT 0')
        add_column_if_missing(conn, 'bridge_config', 'pcf_input',
                              'ALTER TABLE bridge_config ADD COLUMN pcf_input INTEGER NOT NULL DEFAULT 255')

        conn.commit()


# ============================================================================
# Authentifizierung: Passwort-Hashing (PBKDF2-SHA256), OpenID-Forward, lokale
# Benutzerprüfung und OTP-Verwaltung (TOTP + Mail-basiert)
# ============================================================================

def hash_password(password, salt_hex=None):
    # Erstellt PBKDF2-SHA256 Passwort-Hash mit Salt
    if salt_hex is None:
        salt_hex = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt_hex), 120000)
    return f'pbkdf2_sha256${salt_hex}${dk.hex()}'


def verify_password(password, stored_hash):
    # Prüft Passwort gegen gespeicherten PBKDF2-Hash
    if not stored_hash or '$' not in stored_hash:
        return False
    try:
        algo, salt_hex, digest_hex = stored_hash.split('$', 2)
    except ValueError:
        return False

    if algo != 'pbkdf2_sha256':
        return False

    check = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt_hex), 120000).hex()
    return secrets.compare_digest(check, digest_hex)


def init_users_db():
    # Initialisiert users-, mail_otp_log- und unlock_log-Tabellen, legt Demo-User an
    with users_db_connect() as conn:
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                nfc_uid TEXT UNIQUE,
                otp_secret TEXT,
                otp_secret_hash TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                unlock_duration INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            '''
        )
        add_column_if_missing(conn, 'users', 'unlock_duration',
                              'ALTER TABLE users ADD COLUMN unlock_duration INTEGER')
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS mail_otp_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL,
                email TEXT NOT NULL,
                otp_code TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            '''
        )
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS unlock_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                display_name TEXT NOT NULL,
                email TEXT NOT NULL,
                nfc_uid TEXT,
                machine_name TEXT NOT NULL DEFAULT '',
                mac_address TEXT NOT NULL DEFAULT '',
                method TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            '''
        )

        user_count = conn.execute('SELECT COUNT(*) AS c FROM users').fetchone()['c']
        if user_count == 0:
            now = localtime_iso()
            demo_users = [
                ('anna@example.org', 'Anna Demo', hash_password('Demo1234!'), 'A1B2C3D4', None, None, 1, now, now),
                ('ben@example.org', 'Ben Demo', hash_password('Demo1234!'), '11223344', None, None, 1, now, now),
                ('clara@example.org', 'Clara Demo', hash_password('Demo1234!'), 'AABBCCDDEEFF11', None, None, 1, now, now),
            ]
            conn.executemany(
                '''
                INSERT INTO users (
                    email, display_name, password_hash, nfc_uid, otp_secret, otp_secret_hash, is_active, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                demo_users,
            )

        conn.commit()


init_clients_db()
init_users_db()


# ============================================================================
# Hilfsfunktionen: JSON-Parsing, MAC/UID-Normierung, Token-Verwaltung,
# Client-Lookup, Benutzersuche und Bridge-Konfiguration
# ============================================================================

def get_json_with_logging(endpoint_name):
    # Liest und parsed JSON-Body, loggt Rohdaten und Fehler
    raw_body = request.get_data(as_text=True)
    app.logger.info('[%s] raw body: %s', endpoint_name, raw_body)
    try:
        data = request.get_json(force=False, silent=False)
        app.logger.info('[%s] parsed json: %s', endpoint_name, data)
        return data, None
    except BadRequest as err:
        app.logger.warning('[%s] JSON syntax error: %s | raw body: %s', endpoint_name, err.description, raw_body)
        return None, (jsonify({'valid': False, 'error': 'invalid_json'}), 400)


def normalize_mac(mac_raw):
    # Normalisiert MAC-Adresse zu XX:XX:XX:XX:XX:XX
    if not isinstance(mac_raw, str):
        return None
    hex_chars = ''.join(char for char in mac_raw if char.isalnum())
    if len(hex_chars) != 12:
        return None
    if not all(char in '0123456789abcdefABCDEF' for char in hex_chars):
        return None
    hex_chars = hex_chars.upper()
    return ':'.join(hex_chars[index:index + 2] for index in range(0, 12, 2))


def normalize_uid(uid_raw):
    # Normalisiert UID (NFC) zu Großbuchstaben, prüft Länge
    if not isinstance(uid_raw, str):
        return None
    uid = ''.join(ch for ch in uid_raw.strip().upper() if ch in '0123456789ABCDEF')
    if len(uid) not in (8, 14):
        return None
    return uid


def generate_pin():
    # Erzeugt zufälligen 6-stelligen PIN-Code als String
    return str(secrets.randbelow(1000000)).zfill(6)


def issue_token():
    # Erzeugt zufälligen Token für Bridge-Client
    return secrets.token_urlsafe(TOKEN_BYTES)


def generate_mail_otp_code():
    # Erzeugt zufälligen 6-stelligen OTP-Code für Mail-Login
    return str(secrets.randbelow(1000000)).zfill(6)


def hash_otp_code(code):
    # Hash eines OTP-Codes (SHA256, für Vergleich)
    return hashlib.sha256(code.encode('utf-8')).hexdigest()


def get_client_by_token(token):
    # Holt Client-Datensatz anhand Token
    with clients_db_connect() as conn:
        row = conn.execute('SELECT * FROM clients WHERE token = ?', (token,)).fetchone()
    return row


def get_client_by_mac(mac_address):
    # Holt Client-Datensatz anhand MAC-Adresse
    with clients_db_connect() as conn:
        row = conn.execute('SELECT * FROM clients WHERE mac_address = ?', (mac_address,)).fetchone()
    return row


def get_latest_client():
    # Gibt zuletzt gesehenen Client zurück
    with clients_db_connect() as conn:
        row = conn.execute('SELECT * FROM clients ORDER BY last_seen_at DESC, created_at DESC LIMIT 1').fetchone()
    return row


def update_client(token, **fields):
    # Aktualisiert Felder eines Clients anhand Token
    if not fields:
        return

    fields['updated_at'] = localtime_iso()
    assignments = ', '.join(f'{key} = ?' for key in fields.keys())
    values = list(fields.values())
    values.append(token)

    with clients_db_connect() as conn:
        conn.execute(f'UPDATE clients SET {assignments} WHERE token = ?', values)
        conn.commit()


def register_client(mac_address):
    # Registriert neuen Client anhand MAC, gibt Datensatz zurück
    now = localtime_iso()
    existing = get_client_by_mac(mac_address)
    if existing:
        update_client(existing['token'], last_seen_at=now)
        return get_client_by_token(existing['token'])

    token = issue_token()
    with clients_db_connect() as conn:
        conn.execute(
            '''
            INSERT INTO clients (
                token, mac_address, otp_secret, otp_secret_hash, current_pin, pin_expires,
                last_uid, otp_verified_until, created_at, updated_at, last_seen_at,
                user_id, mail_otp_hash, mail_otp_expires, mail_otp_consumed_at
            ) VALUES (?, ?, NULL, NULL, NULL, NULL, NULL, NULL, ?, ?, ?, NULL, NULL, NULL, NULL)
            ''',
            (token, mac_address, now, now, now),
        )
        conn.commit()
    return get_client_by_token(token)


def get_bridge_config(mac_address):
    # Holt Bridge-Konfiguration anhand MAC-Adresse
    with clients_db_connect() as conn:
        row = conn.execute('SELECT * FROM bridge_config WHERE mac_address = ?', (mac_address,)).fetchone()
    return row


def ensure_bridge_config(mac_address):
    # Stellt sicher, dass Bridge-Konfiguration existiert (legt ggf. an)
    cfg = get_bridge_config(mac_address)
    if cfg is not None:
        return cfg
    now = localtime_iso()
    with clients_db_connect() as conn:
        conn.execute(
            '''
            INSERT OR IGNORE INTO bridge_config (mac_address, machine_name, location, idle_current,
                sound_enabled, idle_detection_enabled, otp_required, info_url, unlock_duration, config_version, updated_at)
            VALUES (?, '', '', 0.0, 0, 0, 1, '', 30, 0, ?)
            ''',
            (mac_address, now),
        )
        conn.commit()
    return get_bridge_config(mac_address)


def bridge_config_to_dict(cfg):
    # Wandelt Bridge-Konfigurations-Row in dict für JSON um
    if cfg is None:
        return {
            'machine_name': '',
            'location': '',
            'idle_current': 0.0,
            'sound_enabled': False,
            'idle_detection_enabled': False,
            'otp_required': True,
            'info_url': '',
            'unlock_duration': 30,
            'config_version': 0,
            'auto_ota': False,
            'ads0': 0, 'ads1': 0, 'ads2': 0, 'ads3': 0,
            'pcf_input': 255,
        }
    return {
        'machine_name': cfg['machine_name'],
        'location': cfg['location'],
        'idle_current': cfg['idle_current'],
        'sound_enabled': bool(cfg['sound_enabled']),
        'idle_detection_enabled': bool(cfg['idle_detection_enabled']),
        'otp_required': bool(cfg['otp_required']),
        'info_url': cfg['info_url'],
        'unlock_duration': max(1, min(1440, int(cfg['unlock_duration'] or 30))),
        'config_version': cfg['config_version'],
        'auto_ota': bool(cfg['auto_ota']),
        'ads0': int(cfg['ads0'] or 0),
        'ads1': int(cfg['ads1'] or 0),
        'ads2': int(cfg['ads2'] or 0),
        'ads3': int(cfg['ads3'] or 0),
        'pcf_input': int(cfg['pcf_input'] if cfg['pcf_input'] is not None else 255),
    }


def list_bridge_configs():
    # Gibt alle Bridge-Konfigurationen als Liste zurück
    with clients_db_connect() as conn:
        return conn.execute('SELECT * FROM bridge_config ORDER BY mac_address ASC').fetchall()


def get_client_from_token_value(token_value, endpoint_name):
    # Holt Client anhand Token (aus Payload/Query), prüft und loggt Fehler
    token = token_value.strip() if isinstance(token_value, str) else ''
    if not token:
        app.logger.warning('[%s] missing token', endpoint_name)
        return None, (jsonify({'valid': False, 'error': 'missing_token'}), 400)

    client = get_client_by_token(token)
    if client is None:
        app.logger.warning('[%s] invalid token=%s', endpoint_name, token)
        return None, (jsonify({'valid': False, 'error': 'invalid_token'}), 404)

    update_client(token, last_seen_at=localtime_iso())
    return get_client_by_token(token), None


def get_client_from_payload(endpoint_name, data):
    # Holt Client anhand Token aus JSON-Payload
    if not isinstance(data, dict):
        app.logger.warning('[%s] invalid json payload for token lookup: %r', endpoint_name, data)
        return None, (jsonify({'valid': False, 'error': 'invalid_payload'}), 400)
    return get_client_from_token_value(data.get('token', ''), endpoint_name)


def get_client_from_query(endpoint_name):
    # Holt Client anhand Token aus Query-Parameter
    return get_client_from_token_value(request.args.get('token', ''), endpoint_name)


def get_user_by_id(user_id):
    # Holt User anhand ID
    with users_db_connect() as conn:
        return conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()


def get_user_by_email(email):
    # Holt User anhand E-Mail (case-insensitive)
    with users_db_connect() as conn:
        return conn.execute('SELECT * FROM users WHERE lower(email) = lower(?)', (email,)).fetchone()


def get_user_by_nfc_uid(uid):
    # Holt User anhand NFC-UID
    with users_db_connect() as conn:
        return conn.execute('SELECT * FROM users WHERE nfc_uid = ?', (uid,)).fetchone()


def list_users():
    # Gibt alle User als Liste zurück
    with users_db_connect() as conn:
        return conn.execute('SELECT * FROM users ORDER BY id ASC').fetchall()


def list_clients():
    # Gibt alle Clients als Liste zurück
    with clients_db_connect() as conn:
        return conn.execute('SELECT * FROM clients ORDER BY updated_at DESC, created_at DESC').fetchall()


def list_mail_otp_log(limit=50):
    # Gibt die letzten Mail-OTP-Logeinträge zurück
    with users_db_connect() as conn:
        return conn.execute(
            '''
            SELECT m.id, m.user_id, m.token, m.email, m.otp_code, m.expires_at, m.created_at, u.display_name
            FROM mail_otp_log m
            LEFT JOIN users u ON u.id = m.user_id
            ORDER BY m.id DESC LIMIT ?
            ''',
            (limit,),
        ).fetchall()


def log_mail_otp(user, token, code, expires_at_iso):
    # Loggt generierten Mail-OTP-Code für User
    with users_db_connect() as conn:
        conn.execute(
            '''
            INSERT INTO mail_otp_log (user_id, token, email, otp_code, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (user['id'], token, user['email'], code, expires_at_iso, localtime_iso()),
        )
        conn.commit()


# ============================================================================
# Freischaltungslogik: Dauer wird aus User → Bridge → Default (30min) bestimmt.
# Jede Freischaltung wird im unlock_log protokolliert.
# ============================================================================

def resolve_unlock_duration(user, client):
    # Bestimmt Freischaltdauer: User → Bridge → Default (30min)
    if user and user['unlock_duration']:
        return user['unlock_duration']
    cfg = get_bridge_config(client['mac_address']) if client else None
    if cfg and cfg['unlock_duration']:
        return cfg['unlock_duration']
    return 30


def log_unlock(user, client, method):
    # Schreibt Freischaltung in unlock_log (mit User, Methode, Zeit)
    cfg = get_bridge_config(client['mac_address']) if client else None
    machine_name = cfg['machine_name'] if cfg else ''
    mac = client['mac_address'] if client else ''
    user_id = user['id'] if user else None
    display_name = user['display_name'] if user else ''
    email = user['email'] if user else ''
    nfc_uid = (user['nfc_uid'] if 'nfc_uid' in user.keys() else None) if user else None
    with users_db_connect() as conn:
        conn.execute(
            '''
            INSERT INTO unlock_log (user_id, display_name, email, nfc_uid, machine_name, mac_address, method, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (user_id, display_name, email, nfc_uid, machine_name, mac, method, localtime_iso()),
        )
        conn.commit()
    app.logger.info('[UNLOCK] user=%s method=%s machine=%s', email or '?', method, machine_name)


def list_unlock_log(limit=100):
    # Gibt die letzten Unlock-Logeinträge zurück
    with users_db_connect() as conn:
        return conn.execute(
            'SELECT * FROM unlock_log ORDER BY id DESC LIMIT ?', (limit,),
        ).fetchall()


def ensure_user_totp_secret(user_id):
    # Stellt sicher, dass User ein TOTP-Secret hat (legt ggf. an)
    if pyotp is None:
        return None

    user = get_user_by_id(user_id)
    if user is None:
        return None

    if user['otp_secret']:
        return user['otp_secret']

    secret = pyotp.random_base32()
    secret_hash = hashlib.sha256(secret.encode('utf-8')).hexdigest()

    with users_db_connect() as conn:
        conn.execute(
            'UPDATE users SET otp_secret = ?, otp_secret_hash = ?, updated_at = ? WHERE id = ?',
            (secret, secret_hash, localtime_iso(), user_id),
        )
        conn.commit()

    return secret


def build_otp_qr_data_uri(otp_uri):
    # Baut Data-URI für OTP-QR-Code (SVG/PNG, base64)
    if qrcode is None:
        return None

    try:
        from qrcode.image import svg as qrcode_svg

        svg_img = qrcode.make(otp_uri, image_factory=qrcode_svg.SvgImage)
        svg_buf = io.BytesIO()
        svg_img.save(svg_buf)
        svg_payload = base64.b64encode(svg_buf.getvalue()).decode('ascii')
        app.logger.info('[OTP] QR generated as SVG')
        return f'data:image/svg+xml;base64,{svg_payload}'
    except Exception as err:
        app.logger.warning('[OTP] SVG QR generation failed: %s', err)

    try:
        png_img = qrcode.make(otp_uri)
        png_buf = io.BytesIO()
        png_img.save(png_buf, format='PNG')
        png_payload = base64.b64encode(png_buf.getvalue()).decode('ascii')
        app.logger.info('[OTP] QR generated as PNG')
        return f'data:image/png;base64,{png_payload}'
    except Exception as err:
        app.logger.warning('[OTP] PNG QR generation failed: %s', err)

    return None


_pending_totp = {}


def is_pin_valid(client, pin):
    # Prüft, ob PIN für Client noch gültig ist
    expires_at = parse_iso_datetime(client['pin_expires'])
    now = datetime.now()
    if client['current_pin'] is None or expires_at is None or now > expires_at:
        return False
    return client['current_pin'] == pin


def authenticate_via_openid_if_configured(email, password):
    # Prüft Login gegen externen OpenID-Provider (falls konfiguriert)
    if not OPENID_FORWARD_URL:
        return None

    payload = json.dumps({'email': email, 'password': password}).encode('utf-8')
    req = urllib.request.Request(
        OPENID_FORWARD_URL,
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode('utf-8')
            data = json.loads(body)
            valid = bool(data.get('valid'))
            app.logger.info('[LOGIN] OpenID forward result valid=%s', valid)
            return valid
    except Exception as err:
        app.logger.warning('[LOGIN] OpenID forward failed (%s), fallback to local auth', err)
        return None


def authenticate_local_user(email, password):
    # Prüft Login gegen lokale Userdatenbank
    user = get_user_by_email(email)
    if user is None:
        return None
    if not user['is_active']:
        return None
    if not verify_password(password, user['password_hash']):
        return None
    return user


def bind_client_to_user(client_token, user):
    # Verknüpft Client mit User (user_id, OTP-Hash)
    update_client(
        client_token,
        user_id=user['id'],
        otp_secret_hash=user['otp_secret_hash'],
        otp_secret=None,
    )


def trigger_mail_otp_for_client(client, user):
    # Generiert Mail-OTP für Client/User, loggt und speichert Ablaufzeit
    code = generate_mail_otp_code()
    expires = datetime.now() + timedelta(minutes=LOGIN_OTP_TTL_MINUTES)
    expires_iso = expires.isoformat(timespec='seconds')
    update_client(
        client['token'],
        mail_otp_hash=hash_otp_code(code),
        mail_otp_expires=expires_iso,
        mail_otp_consumed_at=None,
    )
    log_mail_otp(user, client['token'], code, expires_iso)
    app.logger.info('[LOGIN] mail OTP generated token=%s user=%s code=%s', client['token'], user['email'], code)
    return code, expires_iso


def mark_otp_verified(client):
    # Markiert OTP als verifiziert (setzt Zeitstempel)
    update_client(
        client['token'],
        otp_verified_until=(datetime.now() + timedelta(minutes=5)).isoformat(timespec='seconds'),
        mail_otp_consumed_at=localtime_iso(),
        mail_otp_hash=None,
        mail_otp_expires=None,
    )


# ============================================================================
# Bridge-API-Endpunkte: Werden von der ESP32-Firmware aufgerufen.
# Jeder Endpunkt validiert den Token und gibt JSON zurück.
# ============================================================================

    # Setup-Endpoint: Registriert Bridge, gibt Token und Config zurück
@app.route('/api/hsd/setup', methods=['POST'])
def handle_setup():
    try:
        data, error_response = get_json_with_logging('SETUP')
        if error_response is not None:
            return error_response

        if not data or 'mac' not in data:
            return jsonify({'valid': False, 'error': 'missing_mac'}), 400

        mac_address = normalize_mac(data['mac'])
        if mac_address is None:
            return jsonify({'valid': False, 'error': 'invalid_mac'}), 400

        client = register_client(mac_address)
        cfg = ensure_bridge_config(mac_address)
        fw_version = (data.get('fw_version') or '').strip()[:32]
        if fw_version:
            with clients_db_connect() as conn:
                conn.execute('UPDATE bridge_config SET fw_version = ? WHERE mac_address = ?',
                             (fw_version, mac_address))
                conn.commit()
            cfg = get_bridge_config(mac_address)
        is_configured = bool(cfg['machine_name'] or cfg['location'])
        resp_data = {
            'valid': True,
            'token': client['token'],
            'mac': client['mac_address'],
            'configured': is_configured,
        }
        if is_configured:
            resp_data['config'] = bridge_config_to_dict(cfg)
        resp = jsonify(resp_data)
        resp.headers['X-Bridge-Token'] = client['token']
        return resp
    except Exception:
        app.logger.exception('[SETUP] unexpected server error')
        return jsonify({'valid': False}), 500


    # NFC-Endpoint: Prüft UID, bindet User, prüft OTP-Anforderung
@app.route('/api/hsd/nfc', methods=['POST'])
def handle_nfc():
    try:
        data, error_response = get_json_with_logging('NFC')
        if error_response is not None:
            return error_response

        client, token_error = get_client_from_payload('NFC', data)
        if token_error is not None:
            return token_error

        uid = normalize_uid(data.get('uid'))
        if uid is None:
            return jsonify({'valid': False, 'error': 'invalid_uid'}), 400

        user = get_user_by_nfc_uid(uid)
        if user is None or not user['is_active']:
            log_unlock(None, client, 'nfc_uid_unknown')
            return jsonify({'valid': False, 'error': 'uid_not_assigned'})

        cfg = get_bridge_config(client['mac_address'])
        pin_required = bool(cfg and cfg['otp_required'])

        bind_client_to_user(client['token'], user)
        update_client(client['token'], last_uid=uid)

        if not pin_required:
            log_unlock(user, client, 'nfc')
            app.logger.info('[NFC] token=%s uid accepted for user=%s otp_not_required',
                            client['token'], user['email'])
            return jsonify({'valid': True, 'pin_required': False, 'user_email': user['email'],
                            'unlock_duration': resolve_unlock_duration(user, client)})

        if user['otp_secret']:
            app.logger.info('[NFC] token=%s uid accepted for user=%s otp_required=totp',
                            client['token'], user['email'])
            return jsonify({
                'valid': True,
                'pin_required': True,
                'otp_required': 'totp',
                'user_email': user['email'],
            })

        _, expires_iso = trigger_mail_otp_for_client(client, user)
        app.logger.info('[NFC] token=%s uid accepted for user=%s otp_required=mail',
                        client['token'], user['email'])
        return jsonify({
            'valid': True,
            'pin_required': True,
            'otp_required': 'mail',
            'mail_simulated': True,
            'mail_expires': expires_iso,
            'user_email': user['email'],
        })
    except Exception:
        app.logger.exception('[NFC] unexpected server error')
        return jsonify({'valid': False}), 500


    # PIN-Endpoint: Prüft OTP (TOTP/Mail) für User/Client
@app.route('/api/hsd/pin', methods=['POST'])
def handle_pin():
    try:
        data, error_response = get_json_with_logging('PIN')
        if error_response is not None:
            return error_response

        client, token_error = get_client_from_payload('PIN', data)
        if token_error is not None:
            return token_error

        pin_raw = data.get('pin')
        if not isinstance(pin_raw, str):
            return jsonify({'valid': False}), 400

        otp = pin_raw.strip()
        if len(otp) != 6 or not otp.isdigit():
            return jsonify({'valid': False})

        user = get_user_by_id(client['user_id']) if client['user_id'] else None
        if user is None:
            return jsonify({'valid': False, 'error': 'user_not_bound'}), 400

        if user['otp_secret']:
            if pyotp is None:
                return jsonify({'valid': False, 'error': 'otp_dependency_missing'}), 503
            valid = pyotp.TOTP(user['otp_secret']).verify(otp, valid_window=2)
            if valid:
                mark_otp_verified(client)
                log_unlock(user, client, 'nfc_totp')
            else:
                log_unlock(user, client, 'nfc_totp_fail')
            resp = {'valid': valid, 'otp_mode': 'totp'}
            if valid:
                resp['unlock_duration'] = resolve_unlock_duration(user, client)
            return jsonify(resp)

        expires = parse_iso_datetime(client['mail_otp_expires'])
        if not client['mail_otp_hash'] or not expires or datetime.now() > expires:
            log_unlock(user, client, 'nfc_mail_expired')
            return jsonify({'valid': False, 'error': 'otp_expired'})
        if client['mail_otp_consumed_at']:
            log_unlock(user, client, 'nfc_mail_reused')
            return jsonify({'valid': False, 'error': 'otp_already_used'})

        if not secrets.compare_digest(client['mail_otp_hash'], hash_otp_code(otp)):
            log_unlock(user, client, 'nfc_mail_fail')
            return jsonify({'valid': False})

        mark_otp_verified(client)
        log_unlock(user, client, 'nfc_mail')
        return jsonify({'valid': True, 'otp_mode': 'mail',
                        'unlock_duration': resolve_unlock_duration(user, client)})
    except Exception:
        app.logger.exception('[PIN] unexpected server error')
        return jsonify({'valid': False}), 500


    # Ping-Endpoint: Prüft Token, gibt ihn zurück (Debug/Status)
@app.route('/api/hsd/ping', methods=['POST'])
def handle_ping():
    try:
        data, error_response = get_json_with_logging('PING')
        if error_response is not None:
            return error_response

        client, token_error = get_client_from_payload('PING', data)
        if token_error is not None:
            return token_error

        return jsonify({'valid': True, 'bridge_token': client['token']})
    except Exception:
        app.logger.exception('[PING] unexpected server error')
        return jsonify({'valid': False}), 500


    # Karten-Registrierung: Verknüpft UID mit User (nach Login)
@app.route('/api/hsd/register_card', methods=['POST'])
def handle_register_card():
    try:
        data, error_response = get_json_with_logging('REGISTER_CARD')
        if error_response is not None:
            return error_response

        client, token_error = get_client_from_payload('REGISTER_CARD', data)
        if token_error is not None:
            return token_error

        uid = normalize_uid(data.get('uid'))
        if uid is None:
            return jsonify({'valid': False, 'error': 'invalid_uid'}), 400

        user_id = client['user_id']
        if not user_id:
            return jsonify({'valid': False, 'error': 'no_user_bound'}), 400

        user = get_user_by_id(user_id)
        if user is None or not user['is_active']:
            return jsonify({'valid': False, 'error': 'user_not_found'}), 404

        # Check if UID is already assigned to another user
        existing = get_user_by_nfc_uid(uid)
        if existing and existing['id'] != user['id']:
            app.logger.warning('[REGISTER_CARD] UID %s already assigned to user %s', uid, existing['email'])
            return jsonify({'valid': False, 'error': 'uid_already_assigned', 'assigned_to': existing['email']})

        with users_db_connect() as conn:
            conn.execute('UPDATE users SET nfc_uid = ?, updated_at = ? WHERE id = ?',
                         (uid, localtime_iso(), user['id']))
            conn.commit()

        app.logger.info('[REGISTER_CARD] UID %s registered for user %s', uid, user['email'])
        return jsonify({'valid': True, 'user': user['email'], 'uid': uid})
    except Exception:
        app.logger.exception('[REGISTER_CARD] unexpected server error')
        return jsonify({'valid': False}), 500


    # Heartbeat: Aktualisiert Bridge-Status, prüft Config-Änderung
@app.route('/api/hsd/heartbeat', methods=['POST'])
def handle_heartbeat():
    try:
        data, error_response = get_json_with_logging('HEARTBEAT')
        if error_response is not None:
            return error_response

        client, token_error = get_client_from_payload('HEARTBEAT', data)
        if token_error is not None:
            return token_error

        client_config_version = int(data.get('config_version', 0))
        cfg = get_bridge_config(client['mac_address'])
        is_configured = bool(cfg and (cfg['machine_name'] or cfg['location']))
        server_version = cfg['config_version'] if cfg else 0
        config_changed = is_configured and (server_version != client_config_version)

        unlock_status = data.get('unlock_status', 'locked')
        unlock_remaining_min = int(data.get('unlock_remaining_min', 0))

        fw_version = (data.get('fw_version') or '').strip()[:32]
        ads_raw = data.get('ads', [])
        ads = [int(v) for v in ads_raw[:4]] if isinstance(ads_raw, list) else [0, 0, 0, 0]
        while len(ads) < 4:
            ads.append(0)
        pcf_input = int(data.get('pcf', 255)) & 0xFF
        idle_current_mV_raw = data.get('idle_current_mV')
        idle_current_mV = float(idle_current_mV_raw) if idle_current_mV_raw is not None else None
        now = localtime_iso()
        with clients_db_connect() as conn:
            if fw_version and idle_current_mV is not None:
                conn.execute(
                    'UPDATE bridge_config SET last_heartbeat_at=?, unlock_status=?, unlock_remaining_min=?,'
                    ' fw_version=?, ads0=?, ads1=?, ads2=?, ads3=?, pcf_input=?, idle_current=? WHERE mac_address=?',
                    (now, unlock_status, unlock_remaining_min, fw_version,
                     ads[0], ads[1], ads[2], ads[3], pcf_input, idle_current_mV, client['mac_address']))
            elif fw_version:
                conn.execute(
                    'UPDATE bridge_config SET last_heartbeat_at=?, unlock_status=?, unlock_remaining_min=?,'
                    ' fw_version=?, ads0=?, ads1=?, ads2=?, ads3=?, pcf_input=? WHERE mac_address=?',
                    (now, unlock_status, unlock_remaining_min, fw_version,
                     ads[0], ads[1], ads[2], ads[3], pcf_input, client['mac_address']))
            elif idle_current_mV is not None:
                conn.execute(
                    'UPDATE bridge_config SET last_heartbeat_at=?, unlock_status=?, unlock_remaining_min=?,'
                    ' ads0=?, ads1=?, ads2=?, ads3=?, pcf_input=?, idle_current=? WHERE mac_address=?',
                    (now, unlock_status, unlock_remaining_min,
                     ads[0], ads[1], ads[2], ads[3], pcf_input, idle_current_mV, client['mac_address']))
            else:
                conn.execute(
                    'UPDATE bridge_config SET last_heartbeat_at=?, unlock_status=?, unlock_remaining_min=?,'
                    ' ads0=?, ads1=?, ads2=?, ads3=?, pcf_input=? WHERE mac_address=?',
                    (now, unlock_status, unlock_remaining_min,
                     ads[0], ads[1], ads[2], ads[3], pcf_input, client['mac_address']))
            conn.commit()
        if idle_current_mV is not None:
            app.logger.info('[HEARTBEAT] idle_current_mV=%.3f saved for mac=%s', idle_current_mV, client['mac_address'])

        resp = {
            'valid': True,
            'configured': is_configured,
            'config_changed': config_changed,
            'config_version': server_version,
        }

        if config_changed and cfg:
            resp['config'] = bridge_config_to_dict(cfg)

        return jsonify(resp)
    except Exception:
        app.logger.exception('[HEARTBEAT] unexpected server error')
        return jsonify({'valid': False}), 500


    # Login-Endpoint: Prüft User/Passwort (lokal oder OpenID), bindet Client
@app.route('/api/hsd/login', methods=['POST'])
def handle_login():
    try:
        data, error_response = get_json_with_logging('LOGIN')
        if error_response is not None:
            return error_response

        client, token_error = get_client_from_payload('LOGIN', data)
        if token_error is not None:
            return token_error

        email = data.get('email', '')
        password = data.get('password', '')
        if not isinstance(email, str) or not isinstance(password, str) or not email or not password:
            return jsonify({'valid': False, 'error': 'missing_credentials'}), 400

        openid_result = authenticate_via_openid_if_configured(email, password)
        user = get_user_by_email(email)

        if openid_result is True:
            if user is None:
                return jsonify({'valid': False, 'error': 'user_not_provisioned'}), 404
            if not user['is_active']:
                return jsonify({'valid': False, 'error': 'user_inactive'}), 403
        elif openid_result is False:
            log_unlock(None, client, 'login_fail')
            return jsonify({'valid': False, 'error': 'invalid_credentials'}), 401
        else:
            user = authenticate_local_user(email, password)
            if user is None:
                log_unlock(None, client, 'login_fail')
                return jsonify({'valid': False, 'error': 'invalid_credentials'}), 401

        bind_client_to_user(client['token'], user)

        cfg = get_bridge_config(client['mac_address'])
        pin_required = bool(cfg and cfg['otp_required'])

        if not pin_required:
            log_unlock(user, client, 'login')
            return jsonify({'valid': True, 'pin_required': False, 'user': user['email'],
                            'unlock_duration': resolve_unlock_duration(user, client)})

        if user['otp_secret']:
            return jsonify({
                'valid': True,
                'pin_required': True,
                'otp_required': 'totp',
                'token': client['token'],
                'user': user['email'],
            })

        _, expires_iso = trigger_mail_otp_for_client(client, user)
        return jsonify({
            'valid': True,
            'pin_required': True,
            'otp_required': 'mail',
            'mail_simulated': True,
            'mail_expires': expires_iso,
            'token': client['token'],
            'user': user['email'],
        })
    except Exception:
        app.logger.exception('[LOGIN] unexpected server error')
        return jsonify({'valid': False}), 500


    # Login-OTP-Endpoint: Prüft OTP nach Login (Mail/TOTP)
@app.route('/api/hsd/login/otp', methods=['POST'])
def verify_login_otp():
    try:
        data, error_response = get_json_with_logging('LOGIN_OTP')
        if error_response is not None:
            return error_response

        client, token_error = get_client_from_payload('LOGIN_OTP', data)
        if token_error is not None:
            return token_error

        otp = data.get('otp', '')
        if not isinstance(otp, str) or len(otp.strip()) != 6 or not otp.strip().isdigit():
            return jsonify({'valid': False, 'error': 'invalid_otp_format'}), 400

        otp = otp.strip()
        user = get_user_by_id(client['user_id']) if client['user_id'] else None
        if user is None:
            return jsonify({'valid': False, 'error': 'user_not_bound'}), 400

        if user['otp_secret']:
            if pyotp is None:
                return jsonify({'valid': False, 'error': 'otp_dependency_missing'}), 503
            valid = pyotp.TOTP(user['otp_secret']).verify(otp, valid_window=2)
            if not valid:
                log_unlock(user, client, 'login_totp_fail')
                return jsonify({'valid': False})
            mark_otp_verified(client)
            log_unlock(user, client, 'login_totp')
            return jsonify({'valid': True, 'otp_mode': 'totp',
                            'unlock_duration': resolve_unlock_duration(user, client)})

        expires = parse_iso_datetime(client['mail_otp_expires'])
        if not client['mail_otp_hash'] or not expires or datetime.now() > expires:
            log_unlock(user, client, 'login_mail_expired')
            return jsonify({'valid': False, 'error': 'otp_expired'})
        if client['mail_otp_consumed_at']:
            log_unlock(user, client, 'login_mail_reused')
            return jsonify({'valid': False, 'error': 'otp_already_used'})

        if not secrets.compare_digest(client['mail_otp_hash'], hash_otp_code(otp)):
            log_unlock(user, client, 'login_mail_fail')
            return jsonify({'valid': False})

        mark_otp_verified(client)
        log_unlock(user, client, 'login_mail')
        return jsonify({'valid': True, 'otp_mode': 'mail',
                        'unlock_duration': resolve_unlock_duration(user, client)})
    except Exception:
        app.logger.exception('[LOGIN_OTP] unexpected server error')
        return jsonify({'valid': False}), 500


    # OTP-Setup: Gibt neues TOTP-Secret und QR-Code für User zurück
@app.route('/api/hsd/otp/setup', methods=['GET'])
def otp_setup():
    if pyotp is None:
        return jsonify({'valid': False, 'error': 'otp_dependency_missing', 'missing': 'pyotp'}), 503

    client, token_error = get_client_from_query('OTP_SETUP')
    if token_error is not None:
        return token_error

    user_id = client['user_id']
    if not user_id:
        return jsonify({'valid': False, 'error': 'user_not_bound'}), 400

    user = get_user_by_id(user_id)
    if user is None:
        return jsonify({'valid': False, 'error': 'user_not_found'}), 404

    secret = ensure_user_totp_secret(user_id)
    user = get_user_by_id(user_id)
    update_client(client['token'], otp_secret_hash=user['otp_secret_hash'])

    account_name = user['email']
    otp_uri = pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name='LiMa Bridge')
    qr_data_uri = build_otp_qr_data_uri(otp_uri)

    return jsonify({
        'valid': True,
        'issuer': 'LiMa Bridge',
        'account': account_name,
        'otp_uri': otp_uri,
        'secret': secret,
        'qr_data_uri': qr_data_uri,
        'qr_available': qr_data_uri is not None,
        'otp_secret_hash': user['otp_secret_hash'],
        'token': client['token'],
    })


    # OTP-Verify: Prüft TOTP-Code für User
@app.route('/api/hsd/otp/verify', methods=['POST'])
def otp_verify():
    try:
        if pyotp is None:
            return jsonify({'valid': False, 'error': 'otp_dependency_missing', 'missing': 'pyotp'}), 503

        data, error_response = get_json_with_logging('OTP')
        if error_response is not None:
            return error_response

        client, token_error = get_client_from_payload('OTP', data)
        if token_error is not None:
            return token_error

        otp_raw = data.get('otp', '')
        if not isinstance(otp_raw, str):
            return jsonify({'valid': False}), 400
        otp_code = otp_raw.strip()

        if len(otp_code) != 6 or not otp_code.isdigit():
            return jsonify({'valid': False})

        user = get_user_by_id(client['user_id']) if client['user_id'] else None
        if user is None or not user['otp_secret']:
            return jsonify({'valid': False, 'error': 'otp_not_initialized'}), 400

        valid = pyotp.TOTP(user['otp_secret']).verify(otp_code, valid_window=2)
        if valid:
            mark_otp_verified(client)

        return jsonify({'valid': valid})
    except Exception:
        app.logger.exception('[OTP] unexpected server error')
        return jsonify({'valid': False}), 500


# ============================================================================
# Admin-API-Endpunkte: Werden vom Dashboard (HTML-Frontend) aufgerufen.
# Benutzerverwaltung, Client-Verwaltung, Bridge-Konfiguration, OTP-Setup.
# ============================================================================

    # Admin: Gibt alle User zurück (ohne Passwort-Hash)
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    rows = [dict(row) for row in list_users()]
    for row in rows:
        row.pop('password_hash', None)
        row['has_otp'] = bool(row.get('otp_secret'))
        row.pop('otp_secret', None)
    return jsonify({'valid': True, 'users': rows})


    # Admin: Speichert User (neu oder Update), prüft UID-Konflikte
@app.route('/api/admin/users/save', methods=['POST'])
@admin_required
def admin_save_user():
    data, error_response = get_json_with_logging('ADMIN_USER_SAVE')
    if error_response is not None:
        return error_response

    user_id = data.get('id')
    email = (data.get('email') or '').strip().lower()
    display_name = (data.get('display_name') or '').strip()
    password = data.get('password') or ''
    nfc_uid = normalize_uid(data.get('nfc_uid')) if data.get('nfc_uid') else None
    otp_secret = (data.get('otp_secret') or '').strip().upper() or None
    is_active = 1 if bool(data.get('is_active', True)) else 0
    unlock_dur_raw = data.get('unlock_duration')
    unlock_duration = max(1, min(1440, int(unlock_dur_raw))) if unlock_dur_raw not in (None, '', 0) else None

    if not email or not display_name:
        return jsonify({'valid': False, 'error': 'missing_fields'}), 400

    otp_hash = hashlib.sha256(otp_secret.encode('utf-8')).hexdigest() if otp_secret else None

    with users_db_connect() as conn:
        if user_id:
            existing = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            if existing is None:
                return jsonify({'valid': False, 'error': 'user_not_found'}), 404

            # Check for NFC UID conflict with another user
            if nfc_uid:
                conflict = conn.execute('SELECT id, email FROM users WHERE nfc_uid = ? AND id != ?', (nfc_uid, user_id)).fetchone()
                if conflict:
                    return jsonify({'valid': False, 'error': 'uid_already_assigned', 'assigned_to': conflict['email']}), 409

            password_hash = existing['password_hash']
            if password:
                password_hash = hash_password(password)

            # Preserve existing OTP secret if not explicitly provided
            if otp_secret:
                final_otp_secret = otp_secret
                final_otp_hash = otp_hash
            else:
                final_otp_secret = existing['otp_secret']
                final_otp_hash = existing['otp_secret_hash']

            conn.execute(
                '''
                UPDATE users
                SET email = ?, display_name = ?, password_hash = ?, nfc_uid = ?, otp_secret = ?, otp_secret_hash = ?, is_active = ?, unlock_duration = ?, updated_at = ?
                WHERE id = ?
                ''',
                (email, display_name, password_hash, nfc_uid, final_otp_secret, final_otp_hash, is_active, unlock_duration, localtime_iso(), user_id),
            )
        else:
            if not password:
                return jsonify({'valid': False, 'error': 'password_required_for_new_user'}), 400

            # Check for NFC UID conflict for new user
            if nfc_uid:
                conflict = conn.execute('SELECT id, email FROM users WHERE nfc_uid = ?', (nfc_uid,)).fetchone()
                if conflict:
                    return jsonify({'valid': False, 'error': 'uid_already_assigned', 'assigned_to': conflict['email']}), 409

            now = localtime_iso()
            conn.execute(
                '''
                INSERT INTO users (email, display_name, password_hash, nfc_uid, otp_secret, otp_secret_hash, is_active, unlock_duration, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (email, display_name, hash_password(password), nfc_uid, otp_secret, otp_hash, is_active, unlock_duration, now, now),
            )
        conn.commit()

    return jsonify({'valid': True})


    # Admin: Löscht User und entfernt Zuordnung in Clients
@app.route('/api/admin/users/delete', methods=['POST'])
@admin_required
def admin_delete_user():
    data, error_response = get_json_with_logging('ADMIN_USER_DELETE')
    if error_response is not None:
        return error_response

    user_id = data.get('id')
    if not user_id:
        return jsonify({'valid': False, 'error': 'missing_id'}), 400

    with users_db_connect() as conn:
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()

    with clients_db_connect() as conn:
        conn.execute('UPDATE clients SET user_id = NULL WHERE user_id = ?', (user_id,))
        conn.commit()

    return jsonify({'valid': True})


    # Admin: Gibt alle Clients/Bridges zurück
@app.route('/api/admin/clients', methods=['GET'])
@app.route('/api/admin/bridges', methods=['GET'])
@admin_required
def admin_get_clients():
    rows = [dict(row) for row in list_clients()]
    return jsonify({'valid': True, 'clients': rows})


    # Admin: Speichert Client/Bridge (neu oder Update)
@app.route('/api/admin/clients/save', methods=['POST'])
@app.route('/api/admin/bridges/save', methods=['POST'])
@admin_required
def admin_save_client():
    data, error_response = get_json_with_logging('ADMIN_CLIENT_SAVE')
    if error_response is not None:
        return error_response

    token = (data.get('token') or '').strip()
    mac = normalize_mac(data.get('mac_address') or '')
    user_id = data.get('user_id')
    last_uid = normalize_uid(data.get('last_uid')) if data.get('last_uid') else None

    if not token or not mac:
        return jsonify({'valid': False, 'error': 'missing_fields'}), 400

    if user_id == '':
        user_id = None

    now = localtime_iso()
    with clients_db_connect() as conn:
        existing = conn.execute('SELECT token FROM clients WHERE token = ?', (token,)).fetchone()
        if existing:
            conn.execute(
                '''
                UPDATE clients SET mac_address = ?, user_id = ?, last_uid = ?, updated_at = ?, last_seen_at = ?
                WHERE token = ?
                ''',
                (mac, user_id, last_uid, now, now, token),
            )
        else:
            conn.execute(
                '''
                INSERT INTO clients (
                    token, mac_address, otp_secret, otp_secret_hash, current_pin, pin_expires,
                    last_uid, otp_verified_until, created_at, updated_at, last_seen_at,
                    user_id, mail_otp_hash, mail_otp_expires, mail_otp_consumed_at
                ) VALUES (?, ?, NULL, NULL, NULL, NULL, ?, NULL, ?, ?, ?, ?, NULL, NULL, NULL)
                ''',
                (token, mac, last_uid, now, now, now, user_id),
            )
        conn.commit()

    return jsonify({'valid': True})


    # Admin: Löscht Client/Bridge
@app.route('/api/admin/clients/delete', methods=['POST'])
@app.route('/api/admin/bridges/delete', methods=['POST'])
@admin_required
def admin_delete_client():
    data, error_response = get_json_with_logging('ADMIN_CLIENT_DELETE')
    if error_response is not None:
        return error_response

    token = (data.get('token') or '').strip()
    if not token:
        return jsonify({'valid': False, 'error': 'missing_token'}), 400

    with clients_db_connect() as conn:
        conn.execute('DELETE FROM clients WHERE token = ?', (token,))
        conn.commit()

    return jsonify({'valid': True})


    # Admin: Gibt alle Bridge-Konfigurationen zurück
@app.route('/api/admin/bridge_config', methods=['GET'])
@admin_required
def admin_get_bridge_configs():
    configs = [dict(row) for row in list_bridge_configs()]
    return jsonify({'valid': True, 'configs': configs})


    # Admin: Speichert Bridge-Konfiguration (neu oder Update)
@app.route('/api/admin/bridge_config/save', methods=['POST'])
@admin_required
def admin_save_bridge_config():
    data, error_response = get_json_with_logging('ADMIN_BRIDGE_CONFIG_SAVE')
    if error_response is not None:
        return error_response

    mac = (data.get('mac_address') or '').strip().upper()
    if not mac:
        return jsonify({'valid': False, 'error': 'missing_mac_address'}), 400

    machine_name = (data.get('machine_name') or '').strip()[:63]
    location = (data.get('location') or '').strip()[:63]
    idle_current = float(data.get('idle_current', 0.0))
    sound_enabled = 1 if data.get('sound_enabled') else 0
    idle_detection_enabled = 1 if data.get('idle_detection_enabled') else 0
    otp_required = 1 if data.get('otp_required', True) else 0
    info_url = (data.get('info_url') or '').strip()[:127]
    unlock_duration = max(1, min(1440, int(data.get('unlock_duration', 30))))
    auto_ota = 1 if data.get('auto_ota') else 0

    now = localtime_iso()
    with clients_db_connect() as conn:
        existing = conn.execute('SELECT config_version FROM bridge_config WHERE mac_address = ?', (mac,)).fetchone()
        if existing:
            new_version = existing['config_version'] + 1
            conn.execute(
                '''UPDATE bridge_config SET machine_name=?, location=?, idle_current=?,
                   sound_enabled=?, idle_detection_enabled=?, otp_required=?, info_url=?, unlock_duration=?, auto_ota=?, config_version=?, updated_at=?
                   WHERE mac_address=?''',
                (machine_name, location, idle_current, sound_enabled, idle_detection_enabled, otp_required, info_url, unlock_duration, auto_ota, new_version, now, mac),
            )
        else:
            conn.execute(
                '''INSERT INTO bridge_config (mac_address, machine_name, location, idle_current,
                   sound_enabled, idle_detection_enabled, otp_required, info_url, unlock_duration, auto_ota, config_version, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)''',
                (mac, machine_name, location, idle_current, sound_enabled, idle_detection_enabled, otp_required, info_url, unlock_duration, auto_ota, now),
            )
        conn.commit()

    cfg = get_bridge_config(mac)
    return jsonify({'valid': True, 'config': dict(cfg)})


    # Admin: Löscht Bridge-Konfiguration
@app.route('/api/admin/bridge_config/delete', methods=['POST'])
@admin_required
def admin_delete_bridge_config():
    data, error_response = get_json_with_logging('ADMIN_BRIDGE_CONFIG_DELETE')
    if error_response is not None:
        return error_response

    mac = (data.get('mac_address') or '').strip().upper()
    if not mac:
        return jsonify({'valid': False, 'error': 'missing_mac_address'}), 400

    with clients_db_connect() as conn:
        conn.execute('DELETE FROM bridge_config WHERE mac_address = ?', (mac,))
        conn.commit()

    return jsonify({'valid': True})


    # Admin: Simuliert Mail-OTP-Versand für User/Client
@app.route('/api/admin/mail/send', methods=['POST'])
@admin_required
def admin_simulate_mail_send():
    data, error_response = get_json_with_logging('ADMIN_MAIL_SEND')
    if error_response is not None:
        return error_response

    token = (data.get('token') or '').strip()
    user_email = (data.get('email') or '').strip().lower()

    client = get_client_by_token(token)
    if client is None:
        return jsonify({'valid': False, 'error': 'invalid_token'}), 404

    user = get_user_by_email(user_email)
    if user is None:
        return jsonify({'valid': False, 'error': 'user_not_found'}), 404

    bind_client_to_user(client['token'], user)
    code, expires_iso = trigger_mail_otp_for_client(client, user)
    return jsonify({'valid': True, 'otp_code': code, 'expires': expires_iso, 'token': token, 'email': user_email})


    # Admin: Gibt Mail-OTP-Log zurück
@app.route('/api/admin/mail', methods=['GET'])
@admin_required
def admin_get_mail_log():
    rows = [dict(row) for row in list_mail_otp_log(limit=100)]
    return jsonify({'valid': True, 'mail_otps': rows})


    # Admin: Startet TOTP-Setup für User (gibt Secret und QR zurück)
@app.route('/api/admin/totp/setup', methods=['POST'])
@admin_required
def admin_totp_setup():
    if pyotp is None:
        return jsonify({'valid': False, 'error': 'pyotp nicht installiert'}), 503

    data, error_response = get_json_with_logging('ADMIN_TOTP_SETUP')
    if error_response is not None:
        return error_response

    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'valid': False, 'error': 'missing_user_id'}), 400

    user = get_user_by_id(int(user_id))
    if user is None:
        return jsonify({'valid': False, 'error': 'user_not_found'}), 404

    secret = pyotp.random_base32()
    _pending_totp[int(user_id)] = secret

    otp_uri = pyotp.TOTP(secret).provisioning_uri(name=user['email'], issuer_name='LiMa Bridge')
    qr_data_uri = build_otp_qr_data_uri(otp_uri)

    return jsonify({
        'valid': True,
        'secret': secret,
        'otp_uri': otp_uri,
        'qr_data_uri': qr_data_uri,
        'qr_available': qr_data_uri is not None,
    })


    # Admin: Bestätigt TOTP-Setup mit Code, speichert Secret
@app.route('/api/admin/totp/confirm', methods=['POST'])
@admin_required
def admin_totp_confirm():
    if pyotp is None:
        return jsonify({'valid': False, 'error': 'pyotp nicht installiert'}), 503

    data, error_response = get_json_with_logging('ADMIN_TOTP_CONFIRM')
    if error_response is not None:
        return error_response

    user_id = data.get('user_id')
    otp_code = (data.get('otp_code') or '').strip()

    if not user_id:
        return jsonify({'valid': False, 'error': 'missing_user_id'}), 400

    uid = int(user_id)
    pending_secret = _pending_totp.get(uid)
    if not pending_secret:
        return jsonify({'valid': False, 'error': 'no_pending_setup'}), 400

    if len(otp_code) != 6 or not otp_code.isdigit():
        return jsonify({'valid': False, 'error': 'invalid_otp_format'}), 400

    valid = pyotp.TOTP(pending_secret).verify(otp_code, valid_window=2)
    if not valid:
        return jsonify({'valid': False, 'error': 'invalid_otp'})

    secret_hash = hashlib.sha256(pending_secret.encode('utf-8')).hexdigest()
    with users_db_connect() as conn:
        conn.execute(
            'UPDATE users SET otp_secret = ?, otp_secret_hash = ?, updated_at = ? WHERE id = ?',
            (pending_secret, secret_hash, localtime_iso(), uid),
        )
        conn.commit()

    del _pending_totp[uid]
    return jsonify({'valid': True})


    # Admin: Entfernt TOTP-Secret für User
@app.route('/api/admin/totp/remove', methods=['POST'])
@admin_required
def admin_totp_remove():
    data, error_response = get_json_with_logging('ADMIN_TOTP_REMOVE')
    if error_response is not None:
        return error_response

    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'valid': False, 'error': 'missing_user_id'}), 400

    uid = int(user_id)
    with users_db_connect() as conn:
        conn.execute(
            'UPDATE users SET otp_secret = NULL, otp_secret_hash = NULL, updated_at = ? WHERE id = ?',
            (localtime_iso(), uid),
        )
        conn.commit()

    _pending_totp.pop(uid, None)
    return jsonify({'valid': True})


    # Admin: Gibt Unlock-Log zurück (letzte Freischaltungen)
@app.route('/api/admin/unlock_log', methods=['GET'])
@admin_required
def admin_unlock_log():
    rows = list_unlock_log()
    return jsonify([dict(r) for r in rows])


# ============================================================================
# OTA Firmware Update Endpunkte
# Bridge: GET /api/hsd/ota/check, GET /api/hsd/ota/firmware
# Admin:  POST /api/admin/ota/upload, GET /api/admin/ota/info
# ============================================================================

def parse_fw_version_from_bin(filepath):
    """Liest version-String aus ESP32-Firmware-Binary (esp_app_desc_t).
    Layout: esp_image_header_t (24 Bytes) + esp_image_segment_header_t (8 Bytes)
    => esp_app_desc_t ab Byte 32:
      +0:  magic_word (uint32, 0xABCD5AA5)
      +4:  secure_version (uint32)
      +8:  reserv1[2] (2x uint32)
      +16: version[32] (char[])
    => version liegt bei Datei-Offset 48."""
    import struct
    try:
        with open(filepath, 'rb') as f:
            header = f.read(80)
        if len(header) < 80:
            return None
        if header[0] != 0xE9:
            return None
        magic = struct.unpack_from('<I', header, 32)[0]
        if magic != 0xABCD5432:  # ESP_APP_DESC_MAGIC_WORD (ESP-IDF 5.x)
            return None
        version_bytes = header[48:80]
        version = version_bytes.split(b'\x00')[0].decode('ascii', errors='replace').strip()
        return version if version else None
    except Exception:
        return None

@app.route('/api/hsd/ota/check', methods=['GET'])
def hsd_ota_check():
    # Bridge prüft ob neue Firmware verfügbar (Token aus Query)
    client, error = get_client_from_query('OTA_CHECK')
    if error is not None:
        return error

    current_version = request.args.get('version', '').strip()

    if not os.path.exists(OTA_VERSION_FILE) or not os.path.exists(OTA_FIRMWARE_FILE):
        return jsonify({'valid': True, 'available': False, 'version': ''})

    with open(OTA_VERSION_FILE, 'r') as f:
        server_version = f.read().strip()

    available = bool(server_version and server_version != current_version)
    app.logger.info('[OTA_CHECK] client=%s current=%s server=%s available=%s',
                    client['mac_address'], current_version, server_version, available)
    return jsonify({'valid': True, 'available': available, 'version': server_version})


@app.route('/api/hsd/ota/firmware', methods=['GET'])
def hsd_ota_firmware():
    # Bridge lädt Firmware-Binary herunter (Token aus Query)
    client, error = get_client_from_query('OTA_FIRMWARE')
    if error is not None:
        return error

    if not os.path.exists(OTA_FIRMWARE_FILE):
        return jsonify({'valid': False, 'error': 'no_firmware'}), 404

    app.logger.info('[OTA_FIRMWARE] serving firmware to client=%s', client['mac_address'])
    return send_file(OTA_FIRMWARE_FILE, mimetype='application/octet-stream',
                     as_attachment=True, download_name='firmware.bin')


@app.route('/api/admin/ota/upload', methods=['POST'])
@admin_required
def admin_ota_upload():
    # Admin lädt neue Firmware hoch (.bin, Versionsnummer optional – wird aus Binary gelesen)
    if 'firmware' not in request.files:
        return jsonify({'valid': False, 'error': 'no_file'}), 400

    file = request.files['firmware']
    version_input = (request.form.get('version') or '').strip()

    if not file or not file.filename:
        return jsonify({'valid': False, 'error': 'empty_file'}), 400

    filename = secure_filename(file.filename)
    if not filename.lower().endswith('.bin'):
        return jsonify({'valid': False, 'error': 'invalid_file_type'}), 400

    os.makedirs(OTA_FIRMWARE_DIR, exist_ok=True)
    file.save(OTA_FIRMWARE_FILE)

    # Version aus Binary auslesen
    detected_version = parse_fw_version_from_bin(OTA_FIRMWARE_FILE)

    # Manuelle Eingabe hat Vorrang; fehlt sie, nehmen wir die erkannte Version
    version = version_input or detected_version or ''
    if not version:
        os.remove(OTA_FIRMWARE_FILE)
        return jsonify({'valid': False, 'error': 'version_not_found',
                        'hint': 'Version konnte nicht aus Binary gelesen werden. Bitte manuell angeben.'}), 400

    with open(OTA_VERSION_FILE, 'w') as f:
        f.write(version)

    app.logger.info('[OTA_UPLOAD] firmware uploaded version=%s detected=%s size=%d',
                    version, detected_version or '-', os.path.getsize(OTA_FIRMWARE_FILE))
    return jsonify({'valid': True, 'version': version, 'detected_version': detected_version or ''})


@app.route('/api/admin/ota/info', methods=['GET'])
@admin_required
def admin_ota_info():
    # Gibt Info über aktuell gespeicherte Firmware zurück
    if os.path.exists(OTA_VERSION_FILE) and os.path.exists(OTA_FIRMWARE_FILE):
        with open(OTA_VERSION_FILE, 'r') as f:
            version = f.read().strip()
        size = os.path.getsize(OTA_FIRMWARE_FILE)
        mtime = datetime.fromtimestamp(os.path.getmtime(OTA_FIRMWARE_FILE)).isoformat(timespec='seconds')
        detected_version = parse_fw_version_from_bin(OTA_FIRMWARE_FILE)
        return jsonify({'valid': True, 'available': True, 'version': version,
                        'detected_version': detected_version or '',
                        'size': size, 'uploaded_at': mtime})
    return jsonify({'valid': True, 'available': False, 'version': '', 'detected_version': '',
                    'size': 0, 'uploaded_at': ''})



# Zeigt Clients, User, Bridge-Config, Unlock-Log, Mail-OTP-Log.
# ============================================================================

    # Dashboard: HTML-Frontend für Status und Verwaltung
@app.route('/')
@admin_required
def dashboard():
    openid_value = OPENID_FORWARD_URL or '(nicht gesetzt - lokale Auth)'

    html = '''
    <html>
    <head>
        <meta charset="utf-8" />
        <title>LiMa Bridge Admin</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 1600px; margin: 20px auto; padding: 20px; background: #f3f4f6; }
            .card { background: white; border: 1px solid #ddd; border-radius: 10px; padding: 16px; margin-top: 14px; }
            .menu button { margin-right: 8px; margin-bottom: 8px; }
            .section { display: none; }
            .section.active { display: block; }
            table { width: 100%; border-collapse: collapse; font-size: 13px; }
            th, td { border: 1px solid #ddd; padding: 6px; text-align: left; }
            input { padding: 6px; margin: 3px; }
            .mono { font-family: monospace; word-break: break-all; }
            .ok { color: #166534; }
            .err { color: #b91c1c; }
        </style>
    </head>
    <body>
        <h1>LiMa Bridge Server GUI</h1>
        <div class="card">
            <h2>Live Status <span id="liveStatusAge" style="font-size:12px; color:#9ca3af; font-weight:normal; margin-left:10px;"></span></h2>
            <div id="liveStatusCards" style="display:flex; flex-wrap:wrap; gap:12px;">Lade...</div>
            <div class="mono" style="margin-top:10px; font-size:12px; color:#6b7280;">OpenID Forward URL: __OPENID_VALUE__</div>
        </div>

        <div class="menu card">
            <button onclick="showSection('users')">Users DB</button>
            <button onclick="showSection('clients')">Bridges DB</button>
            <button onclick="showSection('bridgecfg')">Bridge Konfiguration</button>
            <button onclick="showSection('mail')">Mail OTP Simulation</button>
            <button onclick="showSection('unlocklog')">Freischaltungen</button>
            <button onclick="showSection('ota')">Firmware OTA</button>
            <button onclick="loadAll()">Reload</button>
        </div>

        <div id="users" class="section card active">
            <h2>Users DB</h2>
            <div>
                <input id="u_id" placeholder="id (leer=neu)" maxlength="10" />
                <input id="u_email" placeholder="email" maxlength="254" />
                <input id="u_name" placeholder="display name" maxlength="64" />
                <input id="u_password" placeholder="password (nur bei Neu oder Aenderung)" maxlength="128" />
                <input id="u_uid" placeholder="nfc uid (hex)" maxlength="14" />
                <input id="u_unlock_dur" placeholder="Freischaltzeit (Min, leer=Bridge-Standard)" style="width:250px" type="number" step="1" min="1" max="1440" />
                <label><input type="checkbox" id="u_active" checked /> aktiv</label>
                <button onclick="saveUser()">Speichern</button>
                <button onclick="clearUserForm()">Form leeren</button>
            </div>
            <div id="usersMsg"></div>
            <div id="usersTable"></div>
            <div id="totpSetup" style="display:none; margin-top:14px; padding:14px; border:2px solid #6366f1; border-radius:8px; background:#eef2ff;">
                <h3 style="margin-top:0;">TOTP Authenticator einrichten</h3>
                <p id="totpUser" style="font-weight:600;"></p>
                <div id="totpQr" style="text-align:center;"></div>
                <div style="margin-top:8px;"><strong>Secret:</strong> <span id="totpSecret" class="mono" style="user-select:all;"></span></div>
                <div style="margin-top:10px;">
                    <input id="totpCode" placeholder="6-stelliger Code" maxlength="6" style="width:140px; font-size:18px; letter-spacing:4px; text-align:center;" />
                    <button onclick="confirmTotp()">Bestätigen</button>
                    <button onclick="cancelTotp()">Abbrechen</button>
                </div>
                <div id="totpMsg" style="margin-top:6px;"></div>
            </div>
        </div>

        <div id="clients" class="section card">
            <h2>Bridges DB</h2>
            <div>
                <input id="c_token" placeholder="token" style="width:360px" maxlength="95" />
                <input id="c_mac" placeholder="mac_address" maxlength="17" />
                <input id="c_user_id" placeholder="user_id (optional)" maxlength="10" />
                <input id="c_uid" placeholder="last_uid (optional)" />
                <button onclick="saveClient()">Speichern</button>
                <button onclick="clearClientForm()">Form leeren</button>
            </div>
            <div id="clientsMsg"></div>
            <div id="clientsTable"></div>
        </div>

        <div id="bridgecfg" class="section card">
            <h2>Bridge Konfiguration</h2>
            <div id="bridgecfgForm" style="display:none;">
                <input id="bc_mac" placeholder="MAC-Adresse" style="width:200px" maxlength="17" readonly />
                <input id="bc_name" placeholder="Maschinenname" maxlength="63" />
                <input id="bc_location" placeholder="Standort" maxlength="63" />
                <input id="bc_idle" placeholder="Idle Strom (A)" style="width:120px" type="number" step="0.01" min="0" />
                <label><input type="checkbox" id="bc_sound" /> Sound</label>
                <label><input type="checkbox" id="bc_idle_det" /> Idle-Erkennung</label>
                <label><input type="checkbox" id="bc_otp" checked /> OTP erforderlich</label>
                <label><input type="checkbox" id="bc_auto_ota" /> Auto-Update (OTA)</label>
                <input id="bc_info_url" placeholder="Info URL" style="width:300px" maxlength="127" />
                <input id="bc_unlock_dur" placeholder="Freischaltzeit (Min)" style="width:150px" type="number" step="1" min="1" max="1440" value="30" />
                <button onclick="saveBridgeCfg()">Speichern</button>
                <button onclick="clearBridgeCfgForm()">Abbrechen</button>
            </div>
            <div id="bridgecfgMsg"></div>
            <div id="bridgecfgTable"></div>
        </div>

        <div id="mail" class="section card">
            <h2>Mail OTP Simulation</h2>
            <div>
                <input id="m_token" placeholder="token" style="width:360px" />
                <input id="m_email" placeholder="user email" />
                <button onclick="sendMailOtp()">OTP Mail simulieren</button>
            </div>
            <div id="mailMsg"></div>
            <div id="mailTable"></div>
        </div>

        <div id="unlocklog" class="section card">
            <h2>Freischaltungen</h2>
            <div id="unlocklogTable"></div>
        </div>

        <div id="ota" class="section card">
            <h2>Firmware OTA Update</h2>
            <div id="otaInfo" style="margin-bottom:14px; padding:10px; background:#f0fdf4; border:1px solid #86efac; border-radius:6px;">
                Lade Firmware-Info...
            </div>
            <form id="otaUploadForm" onsubmit="uploadFirmware(event)" style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                <input type="file" id="ota_file" accept=".bin" required style="padding:4px;" onchange="onFirmwareFileSelected(this)" />
                <input type="text" id="ota_version" placeholder="Version (optional, wird aus Binary gelesen)" style="width:260px;" />
                <button type="submit">Firmware hochladen</button>
            </form>
            <div id="otaDetectedVersion" style="margin-top:6px; font-size:13px; color:#6b7280;"></div>
            <div id="otaMsg" style="margin-top:8px;"></div>
        </div>

        <script>
            function showSection(name) {
                for (const el of document.querySelectorAll('.section')) {
                    el.classList.remove('active');
                }
                document.getElementById(name).classList.add('active');
            }

            function esc(s) {
                if (s === null || s === undefined) return '';
                return String(s).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
            }

            async function api(url, method='GET', body=null) {
                const opts = { method: method, headers: { 'Content-Type': 'application/json' } };
                if (body) opts.body = JSON.stringify(body);
                const res = await fetch(url, opts);
                const data = await res.json();
                if (!res.ok || data.valid === false) {
                    throw new Error(JSON.stringify(data));
                }
                return data;
            }

            function clearUserForm() {
                document.getElementById('u_id').value = '';
                document.getElementById('u_email').value = '';
                document.getElementById('u_name').value = '';
                document.getElementById('u_password').value = '';
                document.getElementById('u_uid').value = '';
                document.getElementById('u_unlock_dur').value = '';
                document.getElementById('u_active').checked = true;
            }

            function fillUserForm(u) {
                document.getElementById('u_id').value = u.id || '';
                document.getElementById('u_email').value = u.email || '';
                document.getElementById('u_name').value = u.display_name || '';
                document.getElementById('u_password').value = '';
                document.getElementById('u_uid').value = u.nfc_uid || '';
                document.getElementById('u_otp').value = '';
                document.getElementById('u_unlock_dur').value = u.unlock_duration != null ? u.unlock_duration : '';
                document.getElementById('u_active').checked = !!u.is_active;
            }

            async function loadUsers() {
                const data = await api('/api/admin/users');
                const rows = data.users.map(u => `
                    <tr>
                        <td>${esc(u.id)}</td>
                        <td>${esc(u.email)}</td>
                        <td>${esc(u.display_name)}</td>
                        <td>${esc(u.nfc_uid || '-')}</td>
                        <td>${u.unlock_duration != null ? u.unlock_duration + ' min' : '<span style="color:#9ca3af;">Bridge</span>'}</td>
                        <td>${u.has_otp ? '<span style="color:#166534;">&#10003; aktiv</span> <button onclick="removeTotp(' + u.id + ')">Entfernen</button>' : '<button onclick="setupTotp(' + u.id + ',\\'' + esc(u.display_name) + '\\')">Einrichten</button>'}</td>
                        <td>${u.is_active ? 'ja' : 'nein'}</td>
                        <td>
                            <button onclick='fillUserForm(${JSON.stringify(u)})'>Bearbeiten</button>
                            <button onclick='deleteUser(${u.id})'>Loeschen</button>
                        </td>
                    </tr>
                `).join('');
                document.getElementById('usersTable').innerHTML = `<table><tr><th>ID</th><th>Email</th><th>Name</th><th>NFC UID</th><th>Freischaltzeit</th><th>OTP</th><th>Aktiv</th><th>Aktion</th></tr>${rows}</table>`;
            }

            async function saveUser() {
                const msg = document.getElementById('usersMsg');
                try {
                    await api('/api/admin/users/save', 'POST', {
                        id: document.getElementById('u_id').value || null,
                        email: document.getElementById('u_email').value,
                        display_name: document.getElementById('u_name').value,
                        password: document.getElementById('u_password').value,
                        nfc_uid: document.getElementById('u_uid').value,
                        unlock_duration: document.getElementById('u_unlock_dur').value ? parseInt(document.getElementById('u_unlock_dur').value) : null,
                        is_active: document.getElementById('u_active').checked,
                    });
                    msg.className = 'ok';
                    msg.textContent = 'User gespeichert';
                    clearUserForm();
                    await loadUsers();
                } catch (e) {
                    msg.className = 'err';
                    msg.textContent = 'Fehler: ' + e;
                }
            }

            async function deleteUser(id) {
                const msg = document.getElementById('usersMsg');
                try {
                    await api('/api/admin/users/delete', 'POST', { id: id });
                    msg.className = 'ok';
                    msg.textContent = 'User geloescht';
                    await loadUsers();
                    await loadClients();
                } catch (e) {
                    msg.className = 'err';
                    msg.textContent = 'Fehler: ' + e;
                }
            }

            function clearClientForm() {
                document.getElementById('c_token').value = '';
                document.getElementById('c_mac').value = '';
                document.getElementById('c_user_id').value = '';
                document.getElementById('c_uid').value = '';
            }

            function fillClientForm(c) {
                document.getElementById('c_token').value = c.token || '';
                document.getElementById('c_mac').value = c.mac_address || '';
                document.getElementById('c_user_id').value = c.user_id || '';
                document.getElementById('c_uid').value = c.last_uid || '';
            }

            async function loadClients() {
                const data = await api('/api/admin/bridges');
                const rows = data.clients.map(c => `
                    <tr>
                        <td class='mono'>${esc(c.token)}</td>
                        <td>${esc(c.mac_address)}</td>
                        <td>${esc(c.user_id || '-')}</td>
                        <td>${esc(c.last_uid || '-')}</td>
                        <td>${esc(c.otp_secret_hash || '-')}</td>
                        <td>${esc(c.updated_at)}</td>
                        <td>
                            <button onclick='fillClientForm(${JSON.stringify(c)})'>Bearbeiten</button>
                            <button onclick='deleteClient("${esc(c.token)}")'>Loeschen</button>
                        </td>
                    </tr>
                `).join('');
                document.getElementById('clientsTable').innerHTML = `<table><tr><th>Bridge Token</th><th>MAC</th><th>User ID</th><th>Last UID</th><th>OTP Hash</th><th>Updated</th><th>Aktion</th></tr>${rows}</table>`;
            }

            async function saveClient() {
                const msg = document.getElementById('clientsMsg');
                try {
                    await api('/api/admin/bridges/save', 'POST', {
                        token: document.getElementById('c_token').value,
                        mac_address: document.getElementById('c_mac').value,
                        user_id: document.getElementById('c_user_id').value,
                        last_uid: document.getElementById('c_uid').value,
                    });
                    msg.className = 'ok';
                    msg.textContent = 'Bridge gespeichert';
                    clearClientForm();
                    await loadClients();
                } catch (e) {
                    msg.className = 'err';
                    msg.textContent = 'Fehler: ' + e;
                }
            }

            async function deleteClient(token) {
                const msg = document.getElementById('clientsMsg');
                try {
                    await api('/api/admin/bridges/delete', 'POST', { token: token });
                    msg.className = 'ok';
                    msg.textContent = 'Bridge geloescht';
                    await loadClients();
                } catch (e) {
                    msg.className = 'err';
                    msg.textContent = 'Fehler: ' + e;
                }
            }

            async function loadMail() {
                const data = await api('/api/admin/mail');
                const rows = data.mail_otps.map(m => `
                    <tr>
                        <td>${esc(m.id)}</td>
                        <td>${esc(m.display_name || '-')}</td>
                        <td>${esc(m.email)}</td>
                        <td class='mono'>${esc(m.token)}</td>
                        <td>${esc(m.otp_code)}</td>
                        <td>${esc(m.expires_at)}</td>
                        <td>${esc(m.created_at)}</td>
                    </tr>
                `).join('');
                document.getElementById('mailTable').innerHTML = `<table><tr><th>ID</th><th>User</th><th>Email</th><th>Token</th><th>OTP Code</th><th>Expires</th><th>Created</th></tr>${rows}</table>`;
            }

            async function sendMailOtp() {
                const msg = document.getElementById('mailMsg');
                try {
                    const data = await api('/api/admin/mail/send', 'POST', {
                        token: document.getElementById('m_token').value,
                        email: document.getElementById('m_email').value,
                    });
                    msg.className = 'ok';
                    msg.textContent = 'Mail OTP simuliert: ' + data.otp_code + ' (bis ' + data.expires + ')';
                    await loadMail();
                    await loadClients();
                } catch (e) {
                    msg.className = 'err';
                    msg.textContent = 'Fehler: ' + e;
                }
            }

            async function loadUnlockLog() {
                const data = await api('/api/admin/unlock_log');
                const isFail = m => m.includes('fail') || m.includes('expired') || m.includes('reused') || m.includes('unknown');
                const rows = data.map(r => {
                    const fail = isFail(r.method || '');
                    const color = fail ? '#FCA5A5' : '#6EE7A0';
                    return `
                    <tr style="color:${color}">
                        <td>${esc(r.id)}</td>
                        <td>${esc(r.display_name || '-')}</td>
                        <td>${esc(r.email || '-')}</td>
                        <td class='mono'>${esc(r.nfc_uid || '-')}</td>
                        <td>${esc(r.machine_name || '-')}</td>
                        <td class='mono'>${esc(r.mac_address || '-')}</td>
                        <td>${esc(r.method)}</td>
                        <td>${esc(r.created_at)}</td>
                    </tr>`;
                }).join('');
                document.getElementById('unlocklogTable').innerHTML = `<table><tr><th>ID</th><th>User</th><th>Email</th><th>NFC UID</th><th>Maschine</th><th>MAC</th><th>Methode</th><th>Zeitpunkt</th></tr>${rows}</table>`;
            }

            let _totpUserId = null;

            async function setupTotp(userId, userName) {
                const msg = document.getElementById('totpMsg');
                msg.textContent = '';
                try {
                    const data = await api('/api/admin/totp/setup', 'POST', { user_id: userId });
                    _totpUserId = userId;
                    document.getElementById('totpUser').textContent = 'User: ' + userName;
                    document.getElementById('totpSecret').textContent = data.secret;
                    if (data.qr_available) {
                        document.getElementById('totpQr').innerHTML = '<img src="' + data.qr_data_uri + '" style="width:200px;height:200px;" />';
                    } else {
                        document.getElementById('totpQr').innerHTML = '<em>QR nicht verfuegbar. Secret manuell eingeben.</em>';
                    }
                    document.getElementById('totpCode').value = '';
                    document.getElementById('totpSetup').style.display = 'block';
                    document.getElementById('totpCode').focus();
                } catch(e) {
                    alert('Fehler: ' + e);
                }
            }

            async function confirmTotp() {
                const msg = document.getElementById('totpMsg');
                try {
                    await api('/api/admin/totp/confirm', 'POST', {
                        user_id: _totpUserId,
                        otp_code: document.getElementById('totpCode').value,
                    });
                    msg.className = 'ok';
                    msg.textContent = 'TOTP erfolgreich konfiguriert!';
                    _totpUserId = null;
                    setTimeout(function() {
                        document.getElementById('totpSetup').style.display = 'none';
                    }, 1500);
                    await loadUsers();
                } catch(e) {
                    msg.className = 'err';
                    msg.textContent = 'Code ungueltig oder Fehler: ' + e;
                }
            }

            function cancelTotp() {
                _totpUserId = null;
                document.getElementById('totpSetup').style.display = 'none';
            }

            async function removeTotp(userId) {
                if (!confirm('TOTP fuer diesen User wirklich entfernen?')) return;
                const msg = document.getElementById('usersMsg');
                try {
                    await api('/api/admin/totp/remove', 'POST', { user_id: userId });
                    msg.className = 'ok';
                    msg.textContent = 'TOTP entfernt';
                    await loadUsers();
                } catch(e) {
                    msg.className = 'err';
                    msg.textContent = 'Fehler: ' + e;
                }
            }

            async function loadAll() {
                await loadUsers();
                await loadClients();
                await loadBridgeCfg();
                await loadMail();
                await loadUnlockLog();
                await loadOtaInfo();
            }

            function clearBridgeCfgForm() {
                document.getElementById('bc_mac').value = '';
                document.getElementById('bc_mac').readOnly = true;
                document.getElementById('bc_name').value = '';
                document.getElementById('bc_location').value = '';
                document.getElementById('bc_idle').value = '';
                document.getElementById('bc_sound').checked = false;
                document.getElementById('bc_idle_det').checked = false;
                document.getElementById('bc_info_url').value = '';
                document.getElementById('bc_unlock_dur').value = 30;
                document.getElementById('bc_auto_ota').checked = false;
                document.getElementById('bridgecfgForm').style.display = 'none';
            }

            function fillBridgeCfgForm(cfg) {
                document.getElementById('bc_mac').value = cfg.mac_address || '';
                document.getElementById('bc_mac').readOnly = true;
                document.getElementById('bc_name').value = cfg.machine_name || '';
                document.getElementById('bc_location').value = cfg.location || '';
                document.getElementById('bc_idle').value = cfg.idle_current || 0;
                document.getElementById('bc_sound').checked = !!cfg.sound_enabled;
                document.getElementById('bc_idle_det').checked = !!cfg.idle_detection_enabled;
                document.getElementById('bc_otp').checked = cfg.otp_required !== false && cfg.otp_required !== 0;
                document.getElementById('bc_info_url').value = cfg.info_url || '';
                document.getElementById('bc_unlock_dur').value = cfg.unlock_duration != null ? cfg.unlock_duration : 30;
                document.getElementById('bc_auto_ota').checked = !!cfg.auto_ota;
                document.getElementById('bridgecfgForm').style.display = 'block';
            }

            async function loadBridgeCfg() {
                const data = await api('/api/admin/bridge_config');
                const now = Date.now();
                function hbBadge(ts) {
                    if (!ts) return '<span style="color:#9ca3af;">nie</span>';
                    // Timestamp ohne Zeitzoneninfo als UTC behandeln (Server speichert UTC)
                    const tsUtc = (ts.endsWith('Z') || /[+\-]\d{2}:/.test(ts)) ? ts : ts + 'Z';
                    const d = new Date(tsUtc);
                    const diffMs = now - d.getTime();
                    const diffMin = diffMs / 60000;
                    let color = '#22c55e';
                    let label = '';
                    if (diffMin > 1440) {
                        color = '#9ca3af';
                        const days = Math.floor(diffMin / 1440);
                        label = days + 'd';
                    } else if (diffMin > 10) {
                        color = '#ef4444';
                        const mins = Math.floor(diffMin);
                        label = mins < 60 ? mins + 'min' : Math.floor(mins/60) + 'h ' + (mins%60) + 'min';
                    } else {
                        const mins = Math.floor(diffMin);
                        label = mins < 1 ? '<1min' : mins + 'min';
                    }
                    return '<span title="' + d.toLocaleString() + '" style="color:' + color + '; font-weight:600; cursor:help;">' + label + '</span>';
                }
                const rows = data.configs.map(cfg => {
                    const unconfigured = !cfg.machine_name && !cfg.location;
                    if (unconfigured) {
                        return `<tr>
                            <td>${esc(cfg.mac_address)}</td>
                            <td colspan="13" style="color:#b91c1c; font-style:italic;">unkonfiguriert</td>
                            <td>${hbBadge(cfg.last_heartbeat_at)}</td>
                            <td>${esc(cfg.updated_at)}</td>
                            <td>
                                <button onclick='fillBridgeCfgForm(${JSON.stringify(cfg)})'>Konfigurieren</button>
                                <button onclick='deleteBridgeCfg("${esc(cfg.mac_address)}")'>Loeschen</button>
                            </td>
                        </tr>`;
                    }
                    const ulStatus = cfg.unlock_status === 'unlocked';
                    const ulBadge = ulStatus
                        ? '<span style="color:#22c55e; font-weight:600;">' + esc(cfg.unlock_remaining_min) + ' min</span>'
                        : '<span style="color:#ef4444; font-weight:600;">Gesperrt</span>';
                    // ADS1115: raw → mV (PGA ±2.048V: 1 LSB = 62.5 µV)
                    const adsMv = i => ((cfg['ads' + i] || 0) * 2048 / 32768).toFixed(1);
                    // PCF8574: Bitmaske P7..P0 als farbiger Binärstring
                    const pcfBits = () => {
                        const v = cfg.pcf_input !== undefined ? cfg.pcf_input : 255;
                        let s = '';
                        for (let b = 7; b >= 0; b--) {
                            const bit = (v >> b) & 1;
                            s += `<span style="color:${bit ? '#22c55e' : '#ef4444'};font-family:monospace;">${bit}</span>`;
                            if (b === 4) s += ' ';
                        }
                        return s;
                    };
                    return `<tr>
                        <td>${esc(cfg.mac_address)}</td>
                        <td>${esc(cfg.machine_name)}</td>
                        <td>${esc(cfg.location)}</td>
                        <td>${esc(cfg.idle_current)}</td>
                        <td>${cfg.sound_enabled ? 'ja' : 'nein'}</td>
                        <td>${cfg.idle_detection_enabled ? 'ja' : 'nein'}</td>
                        <td>${cfg.otp_required ? 'ja' : 'nein'}</td>
                        <td>${esc(cfg.unlock_duration)} min</td>
                        <td>${ulBadge}</td>
                        <td>${esc(cfg.config_version)}</td>
                        <td>${esc(cfg.fw_version || '-')}</td>
                        <td>${cfg.auto_ota ? '<span style="color:#22c55e;">&#10003;</span>' : '-'}</td>
                        <td style="font-family:monospace; white-space:nowrap;">${adsMv(0)} / ${adsMv(1)} / ${adsMv(2)} / ${adsMv(3)} mV</td>
                        <td title="P7..P0: ${cfg.pcf_input !== undefined ? cfg.pcf_input.toString(2).padStart(8,'0') : '--------'}" style="cursor:help;">${pcfBits()}</td>
                        <td>${hbBadge(cfg.last_heartbeat_at)}</td>
                        <td>${esc(cfg.updated_at)}</td>
                        <td>
                            <button onclick='fillBridgeCfgForm(${JSON.stringify(cfg)})'>Bearbeiten</button>
                            <button onclick='deleteBridgeCfg("${esc(cfg.mac_address)}")'>Loeschen</button>
                        </td>
                    </tr>`;
                }).join('');
                document.getElementById('bridgecfgTable').innerHTML = `<table><tr><th>MAC</th><th>Maschinenname</th><th>Standort</th><th>Idle Strom</th><th>Sound</th><th>Idle-Erkennung</th><th>OTP</th><th>Freischaltzeit</th><th>Freigabe</th><th>Version</th><th>Firmware</th><th>Auto-Update</th><th>ADS1115 (AIN0-3)</th><th>PCF8574 P7..P0</th><th>Heartbeat</th><th>Updated</th><th>Aktion</th></tr>${rows}</table>`;
            }

            async function deleteBridgeCfg(mac) {
                const msg = document.getElementById('bridgecfgMsg');
                try {
                    await api('/api/admin/bridge_config/delete', 'POST', { mac_address: mac });
                    msg.className = 'ok';
                    msg.textContent = 'Bridge Konfiguration geloescht';
                    clearBridgeCfgForm();
                    await loadBridgeCfg();
                } catch (e) {
                    msg.className = 'err';
                    msg.textContent = 'Fehler: ' + e;
                }
            }

            async function saveBridgeCfg() {
                const msg = document.getElementById('bridgecfgMsg');
                try {
                    await api('/api/admin/bridge_config/save', 'POST', {
                        mac_address: document.getElementById('bc_mac').value,
                        machine_name: document.getElementById('bc_name').value,
                        location: document.getElementById('bc_location').value,
                        idle_current: parseFloat(document.getElementById('bc_idle').value) || 0,
                        sound_enabled: document.getElementById('bc_sound').checked,
                        idle_detection_enabled: document.getElementById('bc_idle_det').checked,
                        otp_required: document.getElementById('bc_otp').checked,
                        info_url: document.getElementById('bc_info_url').value,
                        unlock_duration: parseInt(document.getElementById('bc_unlock_dur').value) || 30,
                        auto_ota: document.getElementById('bc_auto_ota').checked,
                    });
                    msg.className = 'ok';
                    msg.textContent = 'Bridge Konfiguration gespeichert';
                    clearBridgeCfgForm();
                    await loadBridgeCfg();
                } catch (e) {
                    msg.className = 'err';
                    msg.textContent = 'Fehler: ' + e;
                }
            }

            async function loadOtaInfo() {
                const el = document.getElementById('otaInfo');
                try {
                    const data = await api('/api/admin/ota/info');
                    if (data.available) {
                        let info = `<strong>Aktuelle Firmware auf Server:</strong> v${esc(data.version)}`;
                        if (data.detected_version && data.detected_version !== data.version) {
                            info += ` <span style="color:#6b7280;">(Binary: v${esc(data.detected_version)})</span>`;
                        } else if (data.detected_version) {
                            info += ` <span style="color:#16a34a;">&#10003; aus Binary bestätigt</span>`;
                        }
                        info += ` &nbsp;|&nbsp; ${(data.size / 1024).toFixed(1)} KB &nbsp;|&nbsp; hochgeladen: ${esc(data.uploaded_at)}`;
                        el.innerHTML = info;
                        el.style.background = '#f0fdf4';
                        el.style.borderColor = '#86efac';
                    } else {
                        el.textContent = 'Keine Firmware auf dem Server gespeichert.';
                        el.style.background = '#fef9c3';
                        el.style.borderColor = '#fde047';
                    }
                } catch (e) {
                    el.textContent = 'Fehler beim Laden der OTA-Info: ' + e;
                    el.style.background = '#fef2f2';
                    el.style.borderColor = '#fca5a5';
                }
            }

            async function uploadFirmware(evt) {
                evt.preventDefault();
                const msg = document.getElementById('otaMsg');
                msg.className = '';
                msg.textContent = 'Lade hoch...';
                const file = document.getElementById('ota_file').files[0];
                const version = document.getElementById('ota_version').value.trim();
                if (!file) {
                    msg.className = 'err';
                    msg.textContent = 'Bitte eine .bin-Datei auswaehlen.';
                    return;
                }
                const formData = new FormData();
                formData.append('firmware', file);
                if (version) formData.append('version', version);
                try {
                    const res = await fetch('/api/admin/ota/upload', { method: 'POST', body: formData });
                    const data = await res.json();
                    if (res.ok && data.valid) {
                        let text = `Firmware v${data.version} erfolgreich hochgeladen.`;
                        if (data.detected_version) {
                            text += ` (Erkannte Version aus Binary: v${data.detected_version})`;
                        }
                        msg.className = 'ok';
                        msg.textContent = text;
                        document.getElementById('otaUploadForm').reset();
                        document.getElementById('otaDetectedVersion').textContent = '';
                        await loadOtaInfo();
                    } else {
                        throw new Error(data.hint || JSON.stringify(data));
                    }
                } catch (e) {
                    msg.className = 'err';
                    msg.textContent = 'Upload fehlgeschlagen: ' + e;
                }
            }

            function onFirmwareFileSelected(input) {
                const hint = document.getElementById('otaDetectedVersion');
                const versionField = document.getElementById('ota_version');
                if (!input.files || !input.files[0]) { hint.textContent = ''; return; }
                const file = input.files[0];
                const reader = new FileReader();
                reader.onload = function(e) {
                    const buf = new Uint8Array(e.target.result);
                    if (buf.length < 80 || buf[0] !== 0xE9) {
                        hint.textContent = 'Kein gueltiges ESP32-Binary.';
                        hint.style.color = '#ef4444';
                        return;
                    }
                    // Check app desc magic at offset 32 (little-endian 0xABCD5432, ESP-IDF 5.x)
                    // >>> 0 konvertiert zu unsigned 32-bit (nötig weil bit 31 gesetzt ist)
                    const magic = (buf[32] | (buf[33] << 8) | (buf[34] << 16) | (buf[35] << 24)) >>> 0;
                    if (magic !== 0xABCD5432) {
                        hint.textContent = 'App-Deskriptor nicht gefunden.';
                        hint.style.color = '#f59e0b';
                        return;
                    }
                    // Version string at offset 48, max 32 bytes, null-terminated
                    let ver = '';
                    for (let i = 48; i < 80 && buf[i] !== 0; i++) {
                        ver += String.fromCharCode(buf[i]);
                    }
                    if (ver) {
                        hint.textContent = '\u2714 Erkannte Version im Binary: v' + ver;
                        hint.style.color = '#16a34a';
                        if (!versionField.value) versionField.value = ver;
                    } else {
                        hint.textContent = 'Version nicht lesbar.';
                        hint.style.color = '#f59e0b';
                    }
                };
                reader.readAsArrayBuffer(file.slice(0, 80));
            }

            // ── Live Status: auto-refresh alle 15s ──────────────────────────────
            async function loadLiveStatus() {
                const container = document.getElementById('liveStatusCards');
                const ageEl    = document.getElementById('liveStatusAge');
                try {
                    const data = await api('/api/admin/bridge_config');
                    const now  = Date.now();

                    if (!data.configs || data.configs.length === 0) {
                        container.innerHTML = '<span style="color:#9ca3af;">Keine Bridges registriert.</span>';
                        return;
                    }

                    container.innerHTML = data.configs.map(cfg => {
                        const unlocked = cfg.unlock_status === 'unlocked';
                        const cardBorder = unlocked ? '#22c55e' : '#e5e7eb';
                        const cardBg    = unlocked ? '#f0fdf4' : '#ffffff';

                        // Heartbeat-Alter
                        let hbText = 'nie';
                        let hbColor = '#9ca3af';
                        if (cfg.last_heartbeat_at) {
                            const ts = cfg.last_heartbeat_at.endsWith('Z') ? cfg.last_heartbeat_at : cfg.last_heartbeat_at + 'Z';
                            const diffMin = (now - new Date(ts).getTime()) / 60000;
                            if (diffMin < 10) { hbColor = '#22c55e'; }
                            else if (diffMin < 1440) { hbColor = '#ef4444'; }
                            else { hbColor = '#9ca3af'; }
                            hbText = diffMin < 1 ? '<1min' :
                                     diffMin < 60 ? Math.floor(diffMin) + 'min' :
                                     diffMin < 1440 ? Math.floor(diffMin/60) + 'h ' + (Math.floor(diffMin)%60) + 'min' :
                                     Math.floor(diffMin/1440) + 'd';
                        }

                        // Freischalt-Badge
                        const ulBadge = unlocked
                            ? `<span style="background:#dcfce7;color:#166534;padding:2px 8px;border-radius:999px;font-weight:700;">&#128275; Frei&nbsp;${esc(cfg.unlock_remaining_min)}&nbsp;min</span>`
                            : `<span style="background:#fee2e2;color:#b91c1c;padding:2px 8px;border-radius:999px;font-weight:700;">&#128274; Gesperrt</span>`;

                        const name     = cfg.machine_name || cfg.mac_address;
                        const location = cfg.location ? `<div style="color:#6b7280;font-size:12px;">${esc(cfg.location)}</div>` : '';
                        const fw       = cfg.fw_version ? `<div style="color:#6b7280;font-size:12px;">FW: v${esc(cfg.fw_version)}</div>` : '';
                        const lastUid  = cfg.last_uid ? `<div style="color:#6b7280;font-size:12px;">UID: ${esc(cfg.last_uid)}</div>` : '';

                        return `<div style="border:2px solid ${cardBorder};background:${cardBg};border-radius:10px;padding:14px;min-width:220px;max-width:280px;">
                            <div style="font-weight:700;font-size:15px;margin-bottom:4px;">${esc(name)}</div>
                            ${location}
                            <div style="margin:8px 0;">${ulBadge}</div>
                            ${fw}${lastUid}
                            <div style="color:${hbColor};font-size:12px;margin-top:6px;">&#9679; Heartbeat: ${hbText}</div>
                            <div style="color:#9ca3af;font-size:11px;margin-top:2px;font-family:monospace;">${esc(cfg.mac_address)}</div>
                        </div>`;
                    }).join('');

                    ageEl.textContent = 'aktualisiert ' + new Date().toLocaleTimeString();
                } catch(e) {
                    container.innerHTML = '<span style="color:#b91c1c;">Fehler: ' + e + '</span>';
                }
            }

            loadAll();
            loadLiveStatus();
            setInterval(loadLiveStatus, 15000);
        </script>
    </body>
    </html>
    '''

    html = html.replace('__OPENID_VALUE__', openid_value)
    return html


@app.route('/favicon.ico')
@app.route('/robots.txt')
@app.route('/sitemap.xml')
def suppress_browser_noise():
    return '', 204


if __name__ == '__main__':
    os.makedirs(OTA_FIRMWARE_DIR, exist_ok=True)
    #if not os.path.exists('server.crt'):
        #os.system('openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"')

    print('http://localhost:5555')
    #app.run(host='0.0.0.0', port=5555, ssl_context=('server.crt', 'server.key'))
    app.run(host='127.0.0.1', port=5555)
