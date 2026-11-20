#!/usr/bin/env python3
"""
ChainTrace teamserver.

Levert de ChainTrace-webapp en een kleine JSON-API voor samenwerken:
accounts, gedeelde zaken (onderzoeken), deellinks, opmerkingen, activiteitenlog en teamlabels.
Alleen de Python-standaardbibliotheek; opslag in SQLite.

Configuratie via omgevingsvariabelen:
  CT_PORT            poort (standaard 8080)
  CT_DATA            map voor de database (standaard ./data)
  CT_WEB             map met de webapp (standaard ../web naast dit bestand)
  CT_ADMIN_USER      optioneel: maak bij de eerste start deze beheerder aan ...
  CT_ADMIN_PASSWORD  ... met dit wachtwoord (anders: eenmalige setup-code in de log)
  CT_CORS_ORIGINS    extra toegestane origins (komma-gescheiden), bijv. voor de Android-app
  CT_MAX_BODY_MB     maximale grootte van een verzoek (standaard 25)
  CT_SESSION_DAYS    geldigheid van een sessie in dagen (standaard 30)
  CT_TRUST_PROXY     1 = vertrouw X-Forwarded-For (alleen achter een eigen reverse proxy)
"""
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

VERSION = '1.0.0'
HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get('CT_PORT', '8080'))
DATA = os.environ.get('CT_DATA', os.path.join(HERE, 'data'))
WEB = os.path.abspath(os.environ.get('CT_WEB', os.path.join(HERE, '..', 'web')))
MAX_BODY = int(float(os.environ.get('CT_MAX_BODY_MB', '25')) * 1024 * 1024)
TRUST_PROXY = os.environ.get('CT_TRUST_PROXY', '') == '1'
SESSION_DAYS = int(os.environ.get('CT_SESSION_DAYS', '30'))
CORS = {o.strip().rstrip('/') for o in ('https://appassets.androidplatform.net,' + os.environ.get('CT_CORS_ORIGINS', '')).split(',') if o.strip()}
DB_PATH = os.path.join(DATA, 'chaintrace.db')
USER_RE = re.compile(r'^[A-Za-z0-9._@-]{2,40}$')
ROLES = ('view', 'edit')

os.makedirs(DATA, exist_ok=True)
_db_lock = threading.Lock()
SETUP_CODE = None  # eenmalige code voor de eerste beheerder


def now_ms():
    return int(time.time() * 1000)


def db():
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys = ON')
    return con


SCHEMA = """
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE, pw_hash TEXT NOT NULL,
  pw_salt TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, name TEXT NOT NULL, owner_id INTEGER NOT NULL REFERENCES users(id),
  created INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS members (case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, role TEXT NOT NULL, PRIMARY KEY (case_id, user_id));
CREATE TABLE IF NOT EXISTS items (case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE, seed_key TEXT NOT NULL,
  meta TEXT NOT NULL, dossier TEXT NOT NULL, updated INTEGER NOT NULL, updated_by INTEGER, PRIMARY KEY (case_id, seed_key));
CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, seed_key TEXT, text TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS links (token_hash TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  role TEXT NOT NULL, created_by INTEGER, created INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, hint TEXT);
CREATE TABLE IF NOT EXISTS labels (chain TEXT NOT NULL, address TEXT NOT NULL, label TEXT NOT NULL,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, updated INTEGER NOT NULL, PRIMARY KEY (chain, address));
CREATE TABLE IF NOT EXISTS activity (id INTEGER PRIMARY KEY, case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, action TEXT NOT NULL, detail TEXT, created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_activity_case ON activity(case_id, created);
CREATE INDEX IF NOT EXISTS idx_comments_case ON comments(case_id, created);
"""


def hash_pw(password, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 310_000).hex()
    return h, salt


def sha(token):
    return hashlib.sha256(token.encode()).hexdigest()


def init_db():
    global SETUP_CODE
    with db() as con:
        con.executescript(SCHEMA)
        n = con.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        if n == 0:
            u, p = os.environ.get('CT_ADMIN_USER'), os.environ.get('CT_ADMIN_PASSWORD')
            if u and p:
                h, s = hash_pw(p)
                con.execute('INSERT INTO users(username,pw_hash,pw_salt,is_admin,created) VALUES(?,?,?,1,?)', (u, h, s, now_ms()))
                print(f'[chaintrace] beheerder "{u}" aangemaakt vanuit omgevingsvariabelen', flush=True)
            else:
                SETUP_CODE = secrets.token_hex(4).upper()
                print(f'[chaintrace] Eerste start: maak de beheerder aan in de app met setup-code {SETUP_CODE}', flush=True)


# --- eenvoudige bescherming tegen raden van wachtwoorden ---
_fails = {}
_fails_lock = threading.Lock()


def login_blocked(key):
    with _fails_lock:
        n, until = _fails.get(key, (0, 0))
        return until > time.time()


def login_failed(key):
    with _fails_lock:
        n, _ = _fails.get(key, (0, 0))
        n += 1
        wait = 0 if n < 5 else min(900, 2 ** (n - 4))
        _fails[key] = (n, time.time() + wait)


def login_ok(key):
    with _fails_lock:
        _fails.pop(key, None)


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


def log(con, case_id, user_id, action, detail=''):
    con.execute('INSERT INTO activity(case_id,user_id,action,detail,created) VALUES(?,?,?,?,?)', (case_id, user_id, action, detail[:300], now_ms()))


def touch(con, case_id):
    con.execute('UPDATE cases SET updated=? WHERE id=?', (now_ms(), case_id))


def role_of(con, case_id, user_id):
    r = con.execute('SELECT role FROM members WHERE case_id=? AND user_id=?', (case_id, user_id)).fetchone()
    return r['role'] if r else None


def need_role(con, case_id, user, write=False):
    if not con.execute('SELECT 1 FROM cases WHERE id=?', (case_id,)).fetchone():
        raise ApiError(404, 'Zaak niet gevonden')
    r = role_of(con, case_id, user['id'])
    if not r:
        raise ApiError(403, 'Geen toegang tot deze zaak')
    if write and r == 'view':
        raise ApiError(403, 'Alleen-lezen toegang')
    return r


def case_json(con, c, user_id=None):
    members = [dict(username=m['username'], role=m['role']) for m in con.execute(
        "SELECT u.username, m.role FROM members m JOIN users u ON u.id=m.user_id WHERE m.case_id=? ORDER BY m.role != 'owner', m.role, u.username", (c['id'],))]
    items = [dict(seedKey=i['seed_key'], updated=i['updated'], updatedBy=i['ub'], **json.loads(i['meta'])) for i in con.execute(
        'SELECT i.seed_key, i.meta, i.updated, u.username AS ub FROM items i LEFT JOIN users u ON u.id=i.updated_by WHERE i.case_id=? ORDER BY i.updated DESC', (c['id'],))]
    owner = con.execute('SELECT username FROM users WHERE id=?', (c['owner_id'],)).fetchone()
    out = dict(id=c['id'], name=c['name'], created=c['created'], updated=c['updated'], owner=owner['username'] if owner else None,
               members=members, items=items)
    if user_id is not None:
        out['role'] = role_of(con, c['id'], user_id)
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = 'ChainTraceServer/' + VERSION
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):  # beknopte log zonder gevoelige gegevens
        sys.stderr.write('[%s] %s %s\n' % (self.log_date_time_string(), self.command, self.path.split('?')[0][:120]))

    # --- hulpfuncties ---
    def cors(self):
        origin = (self.headers.get('Origin') or '').rstrip('/')
        if origin and origin in CORS:
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin')
            self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
            self.send_header('Access-Control-Max-Age', '600')

    def security_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')

    def send_json(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.cors()
        self.security_headers()
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n > MAX_BODY:
            raise ApiError(413, 'Verzoek te groot')
        if n == 0:
            return {}
        try:
            return json.loads(self.rfile.read(n))
        except Exception:
            raise ApiError(400, 'Ongeldige JSON')

    def client_key(self):
        if TRUST_PROXY and self.headers.get('X-Forwarded-For'):
            return self.headers['X-Forwarded-For'].split(',')[-1].strip()
        return self.client_address[0]

    def current_user(self, con, required=True):
        auth = self.headers.get('Authorization') or ''
        tok = auth[7:] if auth.startswith('Bearer ') else ''
        if tok:
            r = con.execute('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>?', (sha(tok), now_ms())).fetchone()
            if r:
                return r
        if required:
            raise ApiError(401, 'Niet ingelogd')
        return None

    # --- HTTP-methodes ---
    def do_OPTIONS(self):
        self.send_response(204)
        self.cors()
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        self.route('GET')

    def do_POST(self):
        self.route('POST')

    def do_PUT(self):
        self.route('PUT')

    def do_PATCH(self):
        self.route('PATCH')

    def do_DELETE(self):
        self.route('DELETE')

    def route(self, method):
        url = urlparse(self.path)
        path = url.path
        if not path.startswith('/api/'):
            if method != 'GET':
                return self.send_json(405, {'error': 'Methode niet toegestaan'})
            return self.static(path)
        try:
            parts = [unquote(p) for p in path[5:].split('/') if p]
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            with _db_lock, db() as con:
                status, obj = self.api(con, method, parts, q)
            self.send_json(status, obj)
        except ApiError as e:
            self.send_json(e.status, {'error': e.message})
        except Exception as e:  # pragma: no cover
            sys.stderr.write('fout: %r\n' % e)
            self.send_json(500, {'error': 'Interne fout'})

    def static(self, path):
        if path in ('', '/'):
            path = '/index.html'
        full = os.path.abspath(os.path.join(WEB, path.lstrip('/')))
        if not full.startswith(WEB + os.sep) or not os.path.isfile(full) or os.path.basename(full).startswith(('selftest', 'qrtest')):
            return self.send_json(404, {'error': 'Niet gevonden'})
        with open(full, 'rb') as f:
            body = f.read()
        ctype = mimetypes.guess_type(full)[0] or 'application/octet-stream'
        if ctype.startswith('text/') or ctype in ('application/javascript', 'application/json'):
            ctype += '; charset=utf-8'
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'public, max-age=86400' if '/vendor/' in path else 'no-cache')
        self.security_headers()
        self.end_headers()
        self.wfile.write(body)

    # --- API ---
    def api(self, con, method, p, q):
        global SETUP_CODE
        if p == ['info'] and method == 'GET':
            n = con.execute('SELECT COUNT(*) FROM users').fetchone()[0]
            return 200, {'server': 'chaintrace', 'version': VERSION, 'setupNeeded': n == 0}

        if p == ['setup'] and method == 'POST':
            b = self.read_json()
            if con.execute('SELECT COUNT(*) FROM users').fetchone()[0] > 0 or not SETUP_CODE:
                raise ApiError(409, 'De server is al ingericht')
            if not hmac.compare_digest(str(b.get('code', '')).upper(), SETUP_CODE):
                login_failed('setup')
                raise ApiError(403, 'Onjuiste setup-code (zie de serverlog)')
            u, pw = str(b.get('username', '')), str(b.get('password', ''))
            if not USER_RE.match(u) or len(pw) < 8:
                raise ApiError(400, 'Gebruikersnaam 2-40 tekens, wachtwoord minstens 8 tekens')
            h, s = hash_pw(pw)
            con.execute('INSERT INTO users(username,pw_hash,pw_salt,is_admin,created) VALUES(?,?,?,1,?)', (u, h, s, now_ms()))
            SETUP_CODE = None
            return 200, self.new_session(con, u)

        if p == ['login'] and method == 'POST':
            b = self.read_json()
            u, pw = str(b.get('username', '')), str(b.get('password', ''))
            key = self.client_key() + '|' + u.lower()
            if login_blocked(key):
                raise ApiError(429, 'Te veel pogingen, probeer het later opnieuw')
            r = con.execute('SELECT * FROM users WHERE username=?', (u,)).fetchone()
            if not r or not hmac.compare_digest(hash_pw(pw, r['pw_salt'])[0], r['pw_hash']):
                login_failed(key)
                raise ApiError(401, 'Onjuiste gebruikersnaam of wachtwoord')
            login_ok(key)
            return 200, self.new_session(con, r['username'])

        # Alleen-lezen deellink: werkt zonder account.
        if p and p[0] == 'shared' and method == 'GET' and len(p) >= 2:
            link = con.execute('SELECT * FROM links WHERE token_hash=? AND revoked=0', (sha(p[1]),)).fetchone()
            if not link:
                raise ApiError(404, 'Deellink ongeldig of ingetrokken')
            c = con.execute('SELECT * FROM cases WHERE id=?', (link['case_id'],)).fetchone()
            if len(p) == 2:
                cj = case_json(con, c)
                cj['members'] = []
                return 200, {'case': cj, 'role': link['role']}
            if len(p) == 4 and p[2] == 'items':
                it = con.execute('SELECT dossier FROM items WHERE case_id=? AND seed_key=?', (c['id'], p[3])).fetchone()
                if not it:
                    raise ApiError(404, 'Onderzoek niet gevonden')
                return 200, {'dossier': json.loads(it['dossier'])}
            raise ApiError(404, 'Niet gevonden')

        user = self.current_user(con)

        if p == ['logout'] and method == 'POST':
            auth = self.headers.get('Authorization') or ''
            con.execute('DELETE FROM sessions WHERE token_hash=?', (sha(auth[7:]),))
            return 200, {'ok': True}
        if p == ['me'] and method == 'GET':
            return 200, {'username': user['username'], 'admin': bool(user['is_admin'])}
        if p == ['me', 'password'] and method == 'POST':
            b = self.read_json()
            if not hmac.compare_digest(hash_pw(str(b.get('old', '')), user['pw_salt'])[0], user['pw_hash']):
                raise ApiError(403, 'Huidig wachtwoord klopt niet')
            if len(str(b.get('new', ''))) < 8:
                raise ApiError(400, 'Nieuw wachtwoord minstens 8 tekens')
            h, s = hash_pw(str(b['new']))
            con.execute('UPDATE users SET pw_hash=?, pw_salt=? WHERE id=?', (h, s, user['id']))
            con.execute('DELETE FROM sessions WHERE user_id=?', (user['id'],))
            return 200, self.new_session(con, user['username'])

        # --- gebruikers (beheerder) ---
        if p and p[0] == 'users':
            if method == 'GET' and len(p) == 1:
                return 200, {'users': [dict(username=r['username'], admin=bool(r['is_admin'])) for r in con.execute('SELECT * FROM users ORDER BY username')]}
            if not user['is_admin']:
                raise ApiError(403, 'Alleen voor beheerders')
            if method == 'POST' and len(p) == 1:
                b = self.read_json()
                u, pw = str(b.get('username', '')), str(b.get('password', ''))
                if not USER_RE.match(u) or len(pw) < 8:
                    raise ApiError(400, 'Gebruikersnaam 2-40 tekens (letters, cijfers, . _ - @), wachtwoord minstens 8 tekens')
                if con.execute('SELECT 1 FROM users WHERE username=?', (u,)).fetchone():
                    raise ApiError(409, 'Gebruiker bestaat al')
                h, s = hash_pw(pw)
                con.execute('INSERT INTO users(username,pw_hash,pw_salt,is_admin,created) VALUES(?,?,?,?,?)', (u, h, s, 1 if b.get('admin') else 0, now_ms()))
                return 200, {'ok': True}
            if method == 'DELETE' and len(p) == 2:
                if p[1].lower() == user['username'].lower():
                    raise ApiError(400, 'Je kunt jezelf niet verwijderen')
                r = con.execute('SELECT id FROM users WHERE username=?', (p[1],)).fetchone()
                if not r:
                    raise ApiError(404, 'Gebruiker niet gevonden')
                if con.execute('SELECT 1 FROM cases WHERE owner_id=?', (r['id'],)).fetchone():
                    con.execute('UPDATE cases SET owner_id=? WHERE owner_id=?', (user['id'], r['id']))
                    con.execute("INSERT OR REPLACE INTO members(case_id,user_id,role) SELECT id, ?, 'owner' FROM cases WHERE owner_id=?", (user['id'], user['id']))
                con.execute('DELETE FROM users WHERE id=?', (r['id'],))
                return 200, {'ok': True}

        # --- teamlabels ---
        if p == ['labels']:
            if method == 'GET':
                rows = con.execute('SELECT l.*, u.username FROM labels l LEFT JOIN users u ON u.id=l.user_id').fetchall()
                return 200, {'labels': [dict(chain=r['chain'], address=r['address'], label=r['label'], by=r['username'], updated=r['updated']) for r in rows]}
            if method == 'PUT':
                b = self.read_json()
                chain, addr, label = str(b.get('chain', ''))[:12], str(b.get('address', ''))[:120], str(b.get('label', '')).strip()[:120]
                if not chain or not addr:
                    raise ApiError(400, 'Keten en adres verplicht')
                if label:
                    con.execute('INSERT OR REPLACE INTO labels(chain,address,label,user_id,updated) VALUES(?,?,?,?,?)', (chain, addr, label, user['id'], now_ms()))
                else:
                    con.execute('DELETE FROM labels WHERE chain=? AND address=?', (chain, addr))
                return 200, {'ok': True}

        # --- wijzigingen sinds (voor live bijwerken) ---
        if p == ['changes'] and method == 'GET':
            since = int(q.get('since', '0') or 0)
            rows = con.execute('SELECT c.id, c.updated FROM cases c JOIN members m ON m.case_id=c.id WHERE m.user_id=? AND c.updated>?', (user['id'], since)).fetchall()
            lab = con.execute('SELECT MAX(updated) FROM labels').fetchone()[0] or 0
            return 200, {'now': now_ms(), 'cases': [dict(id=r['id'], updated=r['updated']) for r in rows], 'labelsUpdated': lab}

        # --- uitnodiging via deellink (met account) ---
        if p == ['join'] and method == 'POST':
            b = self.read_json()
            link = con.execute('SELECT * FROM links WHERE token_hash=? AND revoked=0', (sha(str(b.get('token', ''))),)).fetchone()
            if not link:
                raise ApiError(404, 'Deellink ongeldig of ingetrokken')
            cur = role_of(con, link['case_id'], user['id'])
            rank = {'view': 1, 'edit': 2, 'owner': 3}
            if not cur or rank[link['role']] > rank[cur]:
                con.execute('INSERT OR REPLACE INTO members(case_id,user_id,role) VALUES(?,?,?)', (link['case_id'], user['id'], link['role']))
                log(con, link['case_id'], user['id'], 'join', link['role'])
                touch(con, link['case_id'])
            return 200, {'caseId': link['case_id']}

        # --- zaken ---
        if p and p[0] == 'cases':
            if len(p) == 1:
                if method == 'GET':
                    rows = con.execute('SELECT c.* FROM cases c JOIN members m ON m.case_id=c.id WHERE m.user_id=? ORDER BY c.updated DESC', (user['id'],)).fetchall()
                    return 200, {'cases': [case_json(con, c, user['id']) for c in rows]}
                if method == 'POST':
                    b = self.read_json()
                    name = str(b.get('name', '')).strip()[:120] or 'Nieuwe zaak'
                    cid = secrets.token_urlsafe(9)
                    t = now_ms()
                    con.execute('INSERT INTO cases(id,name,owner_id,created,updated) VALUES(?,?,?,?,?)', (cid, name, user['id'], t, t))
                    con.execute("INSERT INTO members(case_id,user_id,role) VALUES(?,?,'owner')", (cid, user['id']))
                    log(con, cid, user['id'], 'create', name)
                    c = con.execute('SELECT * FROM cases WHERE id=?', (cid,)).fetchone()
                    return 200, {'case': case_json(con, c, user['id'])}
            cid = p[1]
            if len(p) == 2:
                if method == 'GET':
                    need_role(con, cid, user)
                    c = con.execute('SELECT * FROM cases WHERE id=?', (cid,)).fetchone()
                    return 200, {'case': case_json(con, c, user['id'])}
                if method == 'PATCH':
                    need_role(con, cid, user, write=True)
                    name = str(self.read_json().get('name', '')).strip()[:120]
                    if name:
                        con.execute('UPDATE cases SET name=? WHERE id=?', (name, cid))
                        log(con, cid, user['id'], 'rename', name)
                        touch(con, cid)
                    return 200, {'ok': True}
                if method == 'DELETE':
                    if need_role(con, cid, user) != 'owner' and not user['is_admin']:
                        raise ApiError(403, 'Alleen de eigenaar kan de zaak verwijderen')
                    con.execute('DELETE FROM cases WHERE id=?', (cid,))
                    return 200, {'ok': True}
            sub = p[2]
            if sub == 'items':
                if len(p) == 4:
                    sk = p[3]
                    if method == 'GET':
                        need_role(con, cid, user)
                        it = con.execute('SELECT i.dossier, i.updated, u.username FROM items i LEFT JOIN users u ON u.id=i.updated_by WHERE case_id=? AND seed_key=?', (cid, sk)).fetchone()
                        if not it:
                            raise ApiError(404, 'Onderzoek niet gevonden')
                        return 200, {'dossier': json.loads(it['dossier']), 'updated': it['updated'], 'updatedBy': it['username']}
                    if method == 'PUT':
                        need_role(con, cid, user, write=True)
                        b = self.read_json()
                        if not isinstance(b.get('dossier'), dict) or b['dossier'].get('tool') != 'ChainTrace':
                            raise ApiError(400, 'Geen ChainTrace-dossier')
                        meta = {k: b.get('meta', {}).get(k) for k in ('chain', 'addr', 'role', 'pattern', 'title', 'size')}
                        existed = con.execute('SELECT updated FROM items WHERE case_id=? AND seed_key=?', (cid, sk)).fetchone()
                        base = b.get('base')
                        if existed and isinstance(base, (int, float)) and existed['updated'] > base:
                            # Iemand anders heeft intussen opgeslagen: de app voegt eerst samen.
                            raise ApiError(409, 'Intussen door iemand anders bijgewerkt')
                        t = max(now_ms(), (existed['updated'] + 1) if existed else 0)
                        con.execute('INSERT OR REPLACE INTO items(case_id,seed_key,meta,dossier,updated,updated_by) VALUES(?,?,?,?,?,?)',
                                    (cid, sk, json.dumps(meta), json.dumps(b['dossier']), t, user['id']))
                        log(con, cid, user['id'], 'update' if existed else 'add', meta.get('title') or sk)
                        touch(con, cid)
                        return 200, {'ok': True, 'updated': t}
                    if method == 'DELETE':
                        need_role(con, cid, user, write=True)
                        con.execute('DELETE FROM items WHERE case_id=? AND seed_key=?', (cid, sk))
                        log(con, cid, user['id'], 'remove', sk)
                        touch(con, cid)
                        return 200, {'ok': True}
            if sub == 'members':
                r = need_role(con, cid, user)
                if r != 'owner':
                    raise ApiError(403, 'Alleen de eigenaar beheert leden')
                if method == 'POST' and len(p) == 3:
                    b = self.read_json()
                    role = b.get('role') if b.get('role') in ROLES else 'edit'
                    t = con.execute('SELECT id, username FROM users WHERE username=?', (str(b.get('username', '')),)).fetchone()
                    if not t:
                        raise ApiError(404, 'Gebruiker niet gevonden')
                    if role_of(con, cid, t['id']) == 'owner':
                        raise ApiError(400, 'De eigenaar heeft al volledige toegang')
                    con.execute('INSERT OR REPLACE INTO members(case_id,user_id,role) VALUES(?,?,?)', (cid, t['id'], role))
                    log(con, cid, user['id'], 'member', f"{t['username']}: {role}")
                    touch(con, cid)
                    return 200, {'ok': True}
                if method == 'DELETE' and len(p) == 4:
                    t = con.execute('SELECT id FROM users WHERE username=?', (p[3],)).fetchone()
                    if t and role_of(con, cid, t['id']) != 'owner':
                        con.execute('DELETE FROM members WHERE case_id=? AND user_id=?', (cid, t['id']))
                        log(con, cid, user['id'], 'member-removed', p[3])
                        touch(con, cid)
                    return 200, {'ok': True}
            if sub == 'links':
                if need_role(con, cid, user) != 'owner':
                    raise ApiError(403, 'Alleen de eigenaar maakt deellinks')
                if method == 'GET':
                    rows = con.execute('SELECT l.*, u.username FROM links l LEFT JOIN users u ON u.id=l.created_by WHERE case_id=? AND revoked=0 ORDER BY created DESC', (cid,)).fetchall()
                    return 200, {'links': [dict(id=r['token_hash'][:12], role=r['role'], created=r['created'], by=r['username'], hint=r['hint']) for r in rows]}
                if method == 'POST':
                    role = self.read_json().get('role')
                    role = role if role in ROLES else 'view'
                    tok = secrets.token_urlsafe(24)
                    con.execute('INSERT INTO links(token_hash,case_id,role,created_by,created,hint) VALUES(?,?,?,?,?,?)', (sha(tok), cid, role, user['id'], now_ms(), tok[:4] + '…'))
                    log(con, cid, user['id'], 'link', role)
                    return 200, {'token': tok, 'role': role}
                if method == 'DELETE' and len(p) == 4:
                    con.execute('UPDATE links SET revoked=1 WHERE case_id=? AND token_hash LIKE ?', (cid, p[3] + '%'))
                    log(con, cid, user['id'], 'link-revoked', p[3][:6])
                    return 200, {'ok': True}
            if sub == 'comments':
                need_role(con, cid, user, write=(method == 'POST'))
                if method == 'GET':
                    rows = con.execute('SELECT c.*, u.username FROM comments c LEFT JOIN users u ON u.id=c.user_id WHERE case_id=? ORDER BY created', (cid,)).fetchall()
                    return 200, {'comments': [dict(id=r['id'], by=r['username'], text=r['text'], seedKey=r['seed_key'], created=r['created']) for r in rows]}
                if method == 'POST':
                    b = self.read_json()
                    text = str(b.get('text', '')).strip()[:4000]
                    if not text:
                        raise ApiError(400, 'Lege opmerking')
                    con.execute('INSERT INTO comments(case_id,user_id,seed_key,text,created) VALUES(?,?,?,?,?)', (cid, user['id'], b.get('seedKey'), text, now_ms()))
                    log(con, cid, user['id'], 'comment', text[:80])
                    touch(con, cid)
                    return 200, {'ok': True}
            if sub == 'activity' and method == 'GET':
                need_role(con, cid, user)
                rows = con.execute('SELECT a.*, u.username FROM activity a LEFT JOIN users u ON u.id=a.user_id WHERE case_id=? ORDER BY created DESC LIMIT 200', (cid,)).fetchall()
                return 200, {'activity': [dict(by=r['username'], action=r['action'], detail=r['detail'], created=r['created']) for r in rows]}

        raise ApiError(404, 'Onbekende API-route')

    def new_session(self, con, username):
        r = con.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        tok = secrets.token_urlsafe(32)
        t = now_ms()
        con.execute('INSERT INTO sessions(token_hash,user_id,created,expires) VALUES(?,?,?,?)', (sha(tok), r['id'], t, t + SESSION_DAYS * 86400000))
        con.execute('DELETE FROM sessions WHERE expires<?', (t,))
        return {'token': tok, 'username': r['username'], 'admin': bool(r['is_admin'])}


def make_server(port=PORT):
    init_db()
    srv = ThreadingHTTPServer(('0.0.0.0', port), Handler)
    srv.daemon_threads = True
    return srv


def main():
    srv = make_server()
    print(f'[chaintrace] teamserver {VERSION} op poort {PORT}, webapp uit {WEB}, data in {DATA}', flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
