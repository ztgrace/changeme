from scanners.http_get import HTTPGetScanner
from scanners.http_post import HTTPPostScanner
from scanners.http_basic_auth import HTTPBasicAuthScanner

class ScanEngine(object):
    def __init__(self, threads=10):
        self.threads = threads
        self.scanners = list()


    def scan(self, creds, targets, config):
        self._build_scanners(creds, targets, config)
        for e in self.scanners:
            e.scan()

    def _build_scanners(self, creds, targets, config):
        self.scanners = self.scanners + self._create_target_list(creds, targets, config)


    def _create_target_list(self, creds, targets, config):
        config.logger.debug("[ScanEngine][_create_target_list]")

        scanners = list()
        scanners.append(HTTPGetScanner(creds, targets, config),)
        scanners.append(HTTPPostScanner(creds, targets, config),)
        scanners.append(HTTPBasicAuthScanner(creds, targets, config),)
        return scanners