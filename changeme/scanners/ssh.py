import paramiko
from scanner import Scanner
import socket


class SSH(Scanner):

    def __init__(self, cred, target, username, password, config):
        super(SSH, self).__init__(cred, target, config)
        self.password = password
        self.port = self.cred['default_port']
        self.username = username

    def scan(self):
        return self.check_success()

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

        except Exception, e:
            self.logger.info('Invalid %s default cred %s:%s at %s' % (self.cred['name'], self.username, self.password, '%s:%s' % (self.target, str(self.port))))
            self.logger.debug('%s Exception: %s' % (type(e).__name__, str(e)))
            return False

    def _check(self):
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())  # ignore unknown hosts
        c.connect(hostname=str(self.target), username=self.username, password=self.password)
        stdin, stdout, stderr = c.exec_command('uname -a')
        evidence = stdout.readlines()[0]
        c.close()

        return evidence

    def fingerprint(self):
        port = self.cred['default_port']
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
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
        except Exception, e:
            self.logger.debug(str(e))
            return False

    def _mkscanner(self, cred, target, u, p, config):
        return SSH(cred, target, u, p, config)
