from changeme.scanners.http_post import HTTPPostScanner


class HTTPRawPostScanner(HTTPPostScanner):

    def __init__(self, cred, target, username, password, config, cookies, csrf, raw):
        super(HTTPRawPostScanner, self).__init__(cred, target, username, password, config, cookies, csrf)
        self.raw = raw

    def __reduce__(self):
        return (self.__class__, (self.cred, self.target, self.username, self.password, self.config, self.cookies, self.csrf, self.raw))

    def _make_request(self):
        self.logger.debug('_make_request')
        self.logger.debug("target: %s" % self.target)
        self.response = self.request.post(self.target,
                                          self.raw,
                                          verify=False,
                                          proxies=self.config.proxy,
                                          timeout=self.config.timeout,
                                          headers=self.headers,
                                          cookies=self.cookies)
