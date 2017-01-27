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

    def fingerprint(self):
        raise NotImplementedError("A Scanner class needs to implement a fingerprint method.")

    def check_success(self):
        raise NotImplementedError("A Scanner class needs to implement a check_success method.")

    def __getstate__(self):
        state = self.__dict__
        state['logger'] = None # Need to clear the logger when serializing otherwise mp.Queue blows up
        return state

    def __setstate__(self, d):
        self.__dict__ = d
        self.logger = logging.getLogger('changeme')
