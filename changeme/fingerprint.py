import re

class Fingerprint:

    def __init__(self, name, config, fp=dict()):
        self.name = name
        self.config = config
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
            self.config.logger.debug("self.headers: %s" % self.headers)

        self.server_header = fp.get('server_header', None)

    def __hash__(self):
        return hash(self.name + ' '.join(self.urls))

    def __eq__(self, other):
        self.config.logger.debug("self.name: %s, other.name: %s" % (self.name, other.name))
        self.config.logger.debug("self.urls: %s, other.urls: %s" % (','.join(self.urls), ','.join(other.urls)))
        # quick check
        if self.name == other.name:
            return True

        if (self.urls == other.urls and self.cookies == other.cookies and self.headers == other.headers):
            return True

        return False

    def __str__(self):
        return self.name

    def match(self, res):
        match = False

        if (self.basic_auth_realm and self.basic_auth_realm in res.headers.get('WWW-Authenticate', list())):
            self.config.logger.debug('[Fingerprint.match] basic auth matched: %s' % self.body_text)
            match = True

        server = res.headers.get('Server', None)
        if self.server_header and server and self.server_header in server:
            self.config.logger.debug('[Fingerprint.match] server header matched: %s' % self.body_text)
            match = True

        if self.body_text and re.search(self.body_text, res.text):
            self.config.logger.debug('[Fingerprint.match] matched body: %s' % self.body_text)
            match = True
        elif self.body_text:
            self.config.logger.debug('[Fingerprint.match] body not matched')
            match = False

        return match