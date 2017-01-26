from changeme.scanners.http_get import HTTPGetScanner
from lxml import html
from netaddr import *
import re
import requests


class HttpFingerprint:
    def __init__(self, target, url, port, ssl, headers, cookies, config, creds):
        self.target = target
        self.url = url
        self.port = port
        self.ssl = ssl
        self.headers = headers
        self.cookies = cookies
        self.config = config
        self.creds = creds

    def __hash__(self):
        return hash(str(self.target) + str(self.url) + str(self.port) + str(self.ssl) + str(self.headers) + str(self.cookies))

    def __eq__(self, other):
        if self.target == other.target and self.url == other.url and self.port == other.port and self.ssl == other.ssl and self.headers == other.headers and self.cookies == other.cookies:
            return True

    def full_URL(self):
        proto = 'https' if self.ssl else 'http'
        return '%s://%s:%s%s' % (proto, self.target, self.port, self.url)

    def fingerprint(self, logger):
        scanners = list()
        s = requests.Session()
        url = self.full_URL()

        try:
            res = s.get(
                url,
                timeout=self.config.timeout,
                verify=False,
                proxies=self.config.proxy,
                headers=self.headers,
                cookies=self.cookies
            )
        except Exception as e:
            logger.debug('Failed to connect to %s' % url)
            return

        for cred in self.creds:
            if self.ismatch(cred, res, logger):

                csrf = self._get_csrf_token(res, cred, logger)
                if cred['auth'].get('csrf', False) and not csrf:
                    logger.error('Missing required CSRF token')
                    return

                sessionid = self._get_session_id(res, cred, logger)
                if cred['auth'].get('sessionid') and not sessionid:
                    logger.error("Missing session cookie %s for %s" % (cred['auth'].auth('sessionid'), res.url))
                    return

                for c in cred['auth']['credentials']:
                    for u in cred['auth']['url']:  # pass in the auth url
                        u = '%s%s' % (HTTPGetScanner.get_base_url(res.url), u)
                        scanners.append({'cred': cred, 'pair': c, 'url': u, 'cookies': s.cookies, 'csrf':csrf})

        return scanners

    def _get_csrf_token(self, res, cred, logger):
        name = cred['auth'].get('csrf', False)
        if name:
            tree = html.fromstring(res.content)
            try:
                csrf = tree.xpath('//input[@name="%s"]/@value' % name)[0]
            except:
                logger.error(
                    'Failed to get CSRF token %s in %s' % (str(name), str(res.url)))
                return False
            logger.debug('Got CSRF token %s: %s' % (name, csrf))
        else:
            csrf = False

        return csrf

    def _get_session_id(self, res, cred, logger):
        cookie = cred['auth'].get('sessionid', False)

        if cookie:
            try:
                value = res.cookies[cookie]
                logger.debug('Got session cookie value: %s' % value)
            except:
                logger.error(
                    'Failed to get %s cookie from %s' % (cookie, res.url))
                return False
            return {cookie: value}
        else:
            logger.debug('No cookie')
            return False

    @staticmethod
    def ismatch(cred, response, logger):
        match = False
        fp = cred['fingerprint']
        basic_auth = fp.get('basic_auth_realm', None)
        if basic_auth and basic_auth in response.headers.get('WWW-Authenticate', list()):
            logger.info('%s basic auth matched: %s' % (cred['name'], basic_auth))
            match = True

        server = response.headers.get('Server', None)
        fp_server = fp.get('server_header', None)
        if fp_server and server and fp_server in server:
            logger.debug('%s server header matched: %s' % (cred['name'], fp_server))
            match = True

        body = fp.get('body')
        if body and re.search(body, response.text):
            match = True
            logger.info('%s body matched: %s' % (cred['name'], body))
        elif body:
            logger.debug('%s body not matched' % cred['name'])
            match = False

        return match

    @staticmethod
    def build_fingerprints(targets, creds, config):
        fingerprints = list()
        # Build a set of unique fingerprints
        for target in targets:
            for c in creds:
                fp = c['fingerprint']
                for url in fp.get('url'):
                    if not isinstance(target, IPAddress) and ":" in target and not int(target.split(":")[1]) == int(c.get('default_port')):
                        # Only scan open ports from an nmap file
                        continue
                    elif not isinstance(target, IPAddress) and ":" in target:
                        # strip port from nmap target
                        target = target.split(":")[0]

                    hfp = HttpFingerprint(
                        target,
                        url,
                        c.get('default_port', 80),
                        c.get('ssl'),
                        fp.get('headers', None),
                        fp.get('cookie', None),
                        config,
                        creds,
                    )
                    fingerprints.append(hfp)

        return fingerprints
