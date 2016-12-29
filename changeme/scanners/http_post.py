from changeme.scanners.http_get import HTTPGetScanner


class HTTPPostScanner(HTTPGetScanner):

    def _make_request(self):
        self.config.logger.debug("[%s][_make_request]" % self._class_name())

    def _build_request(self):
        self.config.logger.debug("[%s][_build_request]" % self._class_name())

