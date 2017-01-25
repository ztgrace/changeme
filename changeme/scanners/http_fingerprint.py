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
