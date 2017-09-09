from .scanner import Scanner
import telnetlib


class Telnet(Scanner):

    def __init__(self, cred, target, config, username, password):
        raise NotImplementedError("Telnet has not been implemented yet")
        super(Telnet, self).__init__(cred, target, config, username, password)
        self.port = config['default_port']

    def scan(self):
        success = self.check_success()
        if success:
            self.logger.critical('[+] Found %s default cred %s:%s at %s' % (self.cred['name'], self.username, self.password))
        else:
            self.config.logger.info('Invalid %s default cred %s:%s at %s' % (self.cred['name'], self.username, self.password), '%s:%s' % (self.target, str(self.port)))
        self.logger.debug("[%s][scan]" % self._class_name())

    def check_success(self):
        try:
            telnet = telnetlib.Telnet(str(self.target), int(self.port), int(self.config.timeout))
            telnet.read_until("login: ")
            telnet.write(self.username + "\n")

            if self.password:
                telnet.read_until("Password: ")
                telnet.write(self.password + "\n")

            # telnet.write("ls\n")
            telnet.write("exit\n")
            # telnet.read_all()
            return True
        except Exception as e:
            self.logger.debug('[check_success] error: %s' % str(e))
            return False
