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
            ssh = paramiko.Transport((str(self.target), self.port))
            ssh.connect(username=self.username, password=self.password)
            ssh.close()
            self.logger.critical('[+] Found %s default cred %s:%s at %s' % (self.name, self.username, self.password, '%s:%s' % (self.target, str(self.port))))
            return {'name': self.cred['name'], 'username': self.username, 'password': self.password, 'target': self.target}
        except Exception, e:
            self.logger.info('Invalid %s default cred %s:%s at %s' % (self.name, self.username, self.password, '%s:%s' % (self.target, str(self.port))))
            self.logger.debug('Error: %s' % str(e))
            return False

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
                    scanners.append(SSH(self.cred, self.target, pair['username'], pair['password'], self.config))
                return scanners
            else:
                return False
        except Exception, e:
            self.logger.debug(str(e))
            return False
