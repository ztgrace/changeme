class Scanner(object):
    def __init__(self, creds, targets, config):
        """

        :param creds:
        :param targets:
        :param config:
        """
        self.creds = creds
        self.targets = targets
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
