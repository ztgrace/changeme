import logging
import socket


class Scanner(object):
    def __init__(self, cred, target, config, username, password):
        """

        :param cred:
        :param target:
        :param config:
        """
        self.cred = cred
        if ":" in target and not "http" in target:
                self.target = target.split(":")[0]
                self.port = target.split(":")[1]
        else:
            self.target = target
            self.port = self.cred['default_port']
        self.config = config
        self.username = username
        self.password = password
        self.logger = logging.getLogger('changeme')

    def scan(self):
        return self.check_success()

    def fingerprint(self):
        port = self.cred['default_port']
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            self.logger.error((str(self.target), port))
            result = sock.connect_ex((str(self.target), port))
            sock.shutdown(2)
            if result == 0:
                self.logger.info('Port %i open' % port)
                scanners = list()
                for pair in self.cred['auth']['credentials']:
                    scanners.append(self._mkscanner(self.cred, self.target, pair['username'], pair['password'], self.config))
                return scanners
            else:
                return False
        except Exception as e:
            self.logger.debug(str(e))
            return False

    def check_success(self):
        try:
            evidence = self._check()
            self.logger.critical('[+] Found %s default cred %s:%s at %s' % (self.cred['name'], self.username, self.password, '%s:%s' % (self.target, str(self.port))))
            self.logger.debug('%s %s:%s evidence: %s' % (self.target, self.username, self.password, evidence))
            return {'name': self.cred['name'],
                    'username': self.username,
                    'password': self.password,
                    'target': self.target,
                    'evidence': evidence}

        except Exception as e:
            self.logger.info('Invalid %s default cred %s:%s at %s' % (self.cred['name'], self.username, self.password, '%s:%s' % (self.target, str(self.port))))
            self.logger.debug('%s Exception: %s' % (type(e).__name__, str(e)))
            self.logger.debug('%s: %s' % (self.__class__, self.cred))
            return False

    def _check(self):
        raise NotImplementedError("A Scanner class needs to implement a _check method.")

    def __getstate__(self):
        state = self.__dict__
        state['logger'] = None  # Need to clear the logger when serializing otherwise mp.Queue blows up
        return state

    def __setstate__(self, d):
        self.__dict__ = d
        self.logger = logging.getLogger('changeme')
