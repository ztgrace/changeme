from scanner import Scanner


class HTTPGetScanner(Scanner):

    def __init__(self, creds, target, config):
        super(HTTPGetScanner, self).__init__(creds, target, config)
        self.response = None

    def scan(self):
        self.debug("scan")
        self._build_request()
        self._make_request()
        self.check_success()

    def check_success(self):
        self.debug("check_success")

    def check_fingerprint(self):
        self.debug("check_fingerprint")

    def _build_request(self):
        self.debug("_build_request")

    def _make_request(self):
        #self.config.logger.debug("[%s][_make_request]" % self._class_name())
        self.debug("_make_request")

