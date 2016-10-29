class ScanEngine(object):
    def __init__(self, creds, targets, config):
        self.creds = creds
        self.targets = targets
        self.config = config
        self.logger = config.logger

    def do_scan(self):
        raise NotImplementedError("A ScanEngine class needs to implement a check_fingerprint method.")

    def _create_target_list(self):
        raise NotImplementedError("A ScanEngine class must implement a create_target_list method.")