import logging


class Scanner(object):
    def __init__(self, cred, target, config):
        """

        :param cred:
        :param target:
        :param config:
        """
        self.cred = cred
        self.target = target
        self.config = config
        self.logger = logging.getLogger('changeme')

    def scan(self):
        raise NotImplementedError("A Scanner class needs to implement a scan method.")

    def check_success(self):
        raise NotImplementedError( "A protocol class needs to implement a check_success method.")

