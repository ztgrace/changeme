from scanner import Scanner
import paramiko


class SSHScanner(Scanner):

    def __init__(self, creds, target, config):
        super(SSHScanner, self).__init__(creds, target, config)
        self.success = False

    def scan(self):
        self.config.logger.debug("[%s][scan]" % self._class_name())
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())

        try:
            client.connect(self.targets, self.port, )

        return self.success