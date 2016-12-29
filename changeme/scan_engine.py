from scanners.http_get import HTTPGetScanner
from scanners.http_post import HTTPPostScanner
from scanners.http_basic_auth import HTTPBasicAuthScanner

class ScanEngine(object):
    def __init__(self, creds, targets, config, threads=10):
        self.threads = threads
        self.scanners = list()
        self.creds = creds
        self.targets = targets
        self.config = config

    def scan(self):
        self._build_scanners(self.creds, self.targets, self.config)
        for e in self.scanners:
            e.scan()

    def fingerprint_targets(self):
        self.config.logger.debug("[ScanEngine][fingerprint_targets]")

    def _build_scanners(self, creds, targets, config):
        self.scanners = self.scanners + self._create_target_list(creds, targets, config)

    def _create_target_list(self):
        self.config.logger.debug("[ScanEngine][_create_target_list]")

        scanners = list()
        scanners.append(HTTPGetScanner(self.creds, self.targets, self.config),)
        scanners.append(HTTPPostScanner(self.creds, self.targets, self.config),)
        scanners.append(HTTPBasicAuthScanner(self.creds, self.targets, self.config),)
        return scanners
