from changeme.scanners.http_get import HTTPGetScanner


class HTTPPostScanner(HTTPGetScanner):

    def __init__(self, cred, target, username, password, config, cookies, csrf):
        super(HTTPPostScanner, self).__init__(cred, target, username, password, config, cookies)
        self.csrf = csrf

    def __reduce__(self):
        return (self.__class__, (self.cred, self.target, self.username, self.password, self.config, self.cookies, self.csrf))

    def _make_request(self):
        self.logger.debug('_make_request')
        self.logger.debug("target: %s" % self.target)
        data = self.render_creds(self.cred, self.csrf)
        self.response = self.request.post(self.target,
                                          data,
                                          verify=False,
                                          proxies=self.config.proxy,
                                          timeout=self.config.timeout,
                                          headers=self.headers,
                                          cookies=self.cookies)
