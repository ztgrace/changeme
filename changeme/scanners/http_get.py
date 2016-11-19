from scanner import Scanner


class HTTPGetScanner(Scanner):

    def __init__(self, creds, targets, config):
        super(HTTPGetScanner, self).__init__(creds, targets, config)
        self.response = None

    def scan(self):
        self.config.logger.debug("[%s][scan]" % self._class_name())
        self._build_request()
        self._make_request()
        self.check_success()

    def check_success(self):
        self.config.logger.debug("[%s][check_success]" % self._class_name())

    def check_fingerprint(self):
        self.config.logger.debug("[%s][check_fingerprint]" % self._class_name())

    def _build_request(self):
        self.config.logger.debug("[%s][_build_request]" % self._class_name())

    def _make_request(self):
        self.config.logger.debug("[%s][_make_request]" % self._class_name())

