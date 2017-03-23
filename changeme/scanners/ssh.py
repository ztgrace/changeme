import paramiko
from scanner import Scanner
import socket


class SSH(Scanner):

    def __init__(self, cred, target, username, password, config):
        super(SSH, self).__init__(cred, target, config, username, password)
        self.port = self.cred['default_port']

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



    def _mkscanner(self, cred, target, u, p, config):
        return SSH(cred, target, u, p, config)
