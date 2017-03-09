from scanner import Scanner
import telnetlib


class Telnet(Scanner):

    def __init__(self, data, target, config):

        super(TELNET, self).__init__(data, target, config)
        self.config = config
        self.password_found = list()
        self.target = target
        self.telnet = ''

    def scan(self):
        self.logger.debug("[%s][scan]" % self._class_name())

        for cred in self.creds:
            if self._connexion(self.target, self.port):
                if self._check_success(cred['username'], cred['password']):

                    self.password_found.append(
                        {
                            'name': self.name,
                            'username': cred['username'],
                            'pasword': cred['password'],
                            'url': '%s:%s' % (self.target, str(self.port))
                        }
                    )
            else:
                # No route to host => stop
                break

        return self.password_found

    def _connexion(self, host, port=23, timeout=10):
        try:
            self.telnet = telnetlib.Telnet(str(host), int(port), int(timeout))
            return True
        except Exception, e:
            self.logger.debug('[connexion] error: %s' % str(e))
            return False

    def _check_success(self, username, password):
        try:
            self.telnet.read_until("login: ")
            self.telnet.write(username + "\n")

            if password:
                self.telnet.read_until("Password: ")
                self.telnet.write(password + "\n")

            # self.telnet.write("ls\n")
            self.telnet.write("exit\n")
            # self.telnet.read_all()
            self.config.logger.critical('[+] Found %s default cred %s:%s at %s' % (self.name, username, str(password), '%s:%s' % (self.target, str(self.port))))
            return True
        except Exception, e:
            self.config.logger.info('[check_success] Invalid %s default cred %s:%s at %s' % (self.name, username, str(password), '%s:%s' % (self.target, str(self.port))))
            self.logger.debug('[check_success] error: %s' % str(e))
            return False
