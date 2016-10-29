from scanengine import ScanEngine


class HTTPScanEngine(ScanEngine):

    def do_scan(self):
        self.logger.debug("[do_scan]")
        self._create_target_list()

        # iterate over fingerprint urls

    def _create_target_list(self):
        self.logger.debug("[_create_target_list]")
