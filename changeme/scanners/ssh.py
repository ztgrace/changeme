from scanner import Scanner
import paramiko
import socket

class SSH(Scanner):
    
    def __init__(self, data, target, config):

        super(SSH, self).__init__(data, target, config)
        self.config = config
        self.password_found = list()
        self.target = target

    def scan(self):
        self.logger.debug("[%s][scan]" % self._class_name())
        if self._checkOpenPort(self.target, self.port):
            for cred in self.creds:
                if self._check_success(self.target, self.port, cred['username'], cred['password']):
                    self.password_found.append(
                        {
                            'name': self.name, 
                            'username': cred['username'], 
                            'pasword': cred['password'], 
                            'url': '%s:%s' % (self.target, str(self.port))
                        }
                    )
        return self.password_found

    def _check_success(self, hostname, port, user, pwd):
        try:
            ssh = paramiko.Transport((str(hostname), port))
            ssh.connect(username=user, password=pwd)
            ssh.close()
            self.config.logger.critical('[+] Found %s default cred %s:%s at %s' % (self.name, user, pwd, '%s:%s' % (self.target, str(self.port))))
            return True
        except Exception, e:
            self.config.logger.info('[check_success] Invalid %s default cred %s:%s at %s' % (self.name, user, pwd, '%s:%s' % (self.target, str(self.port))))
            self.logger.debug('[check_success] error: %s' % str(e))
            return False

    def _checkOpenPort(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((str(ip), port))
            sock.shutdown(2)
            if result == 0:
                return True
            else:
                return False
        except Exception, e:
            self.logger.debug('[checkOpenPort] %s' % str(e))
            return False