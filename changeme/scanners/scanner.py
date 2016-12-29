class Scanner(object):
    def __init__(self, creds, target, config):
        """

        :param creds:
        :param target:
        :param config:
        """
        self.creds = creds
        self.target = target
        self.config = config
        self.logger = config.logger

    def scan(self):
        raise NotImplementedError("A Scanner class needs to implement a scan method.")

    def check_success(self):
        raise NotImplementedError( "A protocol class needs to implement a check_success method." )

    def check_fingerprint(self):
        raise NotImplementedError( "A protocol class needs to implement a check_fingerprint method." )

    def _class_name(self):
        return self.__class__.__name__

    def critical(self, method, message=""):
        self.config.logger.critical("[%s][%s] %s" % (self._class_name(), method, message))

    def warning(self, method, message=""):
        self.config.logger.warning("[%s][%s] %s" % (self._class_name(), method, message))

    def info(self, method, message=""):
        self.config.logger.info("[%s][%s] %s" % (self._class_name(), method, message))

    def debug(self, method, message=""):
        self.config.logger.debug("[%s][%s] %s" % (self._class_name(), method, message))
