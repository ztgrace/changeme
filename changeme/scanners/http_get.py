import base64
from http_fingerprint import HttpFingerprint
import requests
from scanner import Scanner
import re


class HTTPGetScanner(Scanner):

    def __init__(self, cred, target, config, session):
        super(HTTPGetScanner, self).__init__(cred, target, config)
        self.cred = cred
        self.config = config
        #self.fingerprint = HttpFingerprint(cred['name'], cred['fingerprint'], config)
        self.request = session
        self.response = None
        self.url = target

    def scan(self):
        self.debug("scan")
        self._build_request()
        self._make_request()
        return self.check_success()

        return False

    def check_success(self):
        self.debug("check_success")
        match = False
        success = self.cred['auth']['success']
        print self.cred
        if self.cred['auth'].get('base64', None):
            username = base64.b64decode(self.cred.username)
            password = base64.b64decode(self.cred.password)

        if success.get('status') == self.response.status_code:
            if success.get('body'):
                for string in success.get('body'):
                    if re.search(string, self.response.text, re.IGNORECASE):
                        match = True
                        break
            else:
                match = True

        if match:
            self.config.logger.critical('[+] Found %s default cred %s:%s at %s' %
                            (self.cred.name, self.cred.username, self.cred.password, self.request))
            return (self.cred.name, self.cred.username, self.cred.password, self.request)
        else:
            self.config.logger.info( '[check_success] Invalid %s default cred %s:%s at %s' %
                         (self.cred['name'], self.cred['username'], self.cred['password'], self.request))
            return False

    def _check_fingerprint(self):
        self.debug("_check_fingerprint")
        self.response = self.request.get(self.url,
                                         timeout=self.config.timeout,
                                         verify=False,
                                         proxies=self.config.proxy,
                                         cookies=self.fingerprint.cookies,
                                         headers=self.fingerprint.headers)
        self.debug('_check_fingerprint', '%s - %i' % (self.url, self.response.status_code))
        return self.fingerprint.match(self.response)

    def _make_request(self):
        self.debug("_make_request")
        self.request.get()

    def _build_headers(self):
        self.cred['']
