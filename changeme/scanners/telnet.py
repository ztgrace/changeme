from .scanner import Scanner
import telnetlib


class Telnet(Scanner):

    def __init__(self, cred, target, config, username, password):
        super(Telnet, self).__init__(cred, target, config, username, password)

    def _check(self):
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
            self.logger.debug('Error: %s' % str(e))
            return False

    def _mkscanner(self, cred, target, u, p, config):
        return Telnet(cred, target, u, p, config)
