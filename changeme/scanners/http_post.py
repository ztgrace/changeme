from changeme.scanners.http_get import HTTPGetScanner


class HTTPPostScanner(HTTPGetScanner):

    def __init__(self, cred,target, username, password, config, session, csrf):
        super(HTTPPostScanner, self).__init__(cred, target, username, password, config, session)
        self.csrf = csrf

    def _make_request(self):
        self.debug('_make_request')
        data = self.render_creds(self.cred, self.csrf)
        self.response = self.request.post(self.url,
                                          data,
                                          verify=False,
                                          proxies=self.config.proxy,
                                          timeout=self.config.timeout,
                                          headers=self.config.useragent,)



