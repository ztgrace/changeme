import paramiko
from .scanner import Scanner
import socket


class SSH(Scanner):

    def __init__(self, cred, target, username, password, config):
        super(SSH, self).__init__(cred, target, config, username, password)

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
