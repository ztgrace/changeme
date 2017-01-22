import re


class HttpFingerprint:
    def __init__(self, target, url, port, ssl, headers, cookies):
        self.target = target
        self.url = url
        self.port = port
        self.ssl = ssl
        self.headers = headers
        self.cookies = cookies

    def __hash__(self):
        return hash(str(self.target) + str(self.url) + str(self.port) + str(self.ssl) + str(self.headers) + str(self.cookies))

    def __eq__(self, other):
        if self.target == other.target and self.url == other.url and self.port == other.port and self.ssl == other.ssl and self.headers == other.headers and self.cookies == other.cookies:
            return True

    def full_URL(self):
        proto = 'https' if self.ssl else 'http'
        return '%s://%s:%s%s' % (proto, self.target, self.port, self.url)

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


class OldHttpFingerprint:
    def __init__(self, name, fp, config):
        self.logger = config.logger
        self.name = name
        self.urls = set(fp.get('url'))
        self.http_status = fp.get('status')
        self.body_text = fp.get('body')
        self.basic_auth_realm = fp.get('basic_auth_realm', None)
        self.cookies = None
        cookies = fp.get('cookie')
        if cookies:
            self.cookies = cookies[0]
        self.headers = None
        headers = fp.get('headers', None)
        if headers:
            self.headers = headers[0]
            self.logger.debug("self.headers: %s" % self.headers)

        self.server_header = fp.get('server_header', None)

    def __hash__(self):
        return hash(self.name + ' '.join(self.urls))

    def __eq__(self, other):
        self.logger.debug("self.name: %s, other.name: %s" % (self.name, other.name))
        self.logger.debug("self.urls: %s, other.urls: %s" %
                     (','.join(self.urls), ','.join(other.urls)))
        # quick check
        if self.name == other.name:
            return True

        if (self.urls == other.urls and self.cookies == other.cookies and
                    self.headers == other.headers):
            return True

        return False

    def __str__(self):
        return self.name

    def match(self, res):
        match = False

        if (self.basic_auth_realm and
                    self.basic_auth_realm in res.headers.get('WWW-Authenticate', list())):
            self.logger.debug(
                '[Fingerprint.match] basic auth matched: %s' % self.body_text)
            match = True

        server = res.headers.get('Server', None)
        if self.server_header and server and self.server_header in server:
            self.logger.debug(
                '[Fingerprint.match] server header matched: %s' % self.body_text)
            match = True

        if self.body_text and re.search(self.body_text, res.text):
            match = True
            self.logger.debug('[Fingerprint.match] matched body: %s' %
                         self.body_text)
        elif self.body_text:
            self.logger.debug('[Fingerprint.match] body not matched')
            match = False

        return match