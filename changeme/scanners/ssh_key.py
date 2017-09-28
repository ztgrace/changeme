import logging
import paramiko
from .ssh import SSH
from io import StringIO


class SSHKey(SSH):

    def __init__(self, cred, target, username, key, config):
        super(SSHKey, self).__init__(cred, target, username, key, config)
        self.logger = logging.getLogger('changeme')

    def _check(self):
        fake = StringIO(self.password)
        if "RSA PRIVATE KEY" in self.password:
            key = paramiko.RSAKey.from_private_key(fake)
        elif "DSA PRIVATE KEY" in self.password:
            key = paramiko.DSSKey.from_private_key(fake)

        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())  # ignore unknown hosts
        c.connect(hostname=self.target.host, port=self.target.port, username=self.username, pkey=key)
        stdin, stdout, stderr = c.exec_command('uname -a')
        evidence = stdout.readlines()[0]
        c.close()

        self.password = 'Private Key'
        return evidence

    def _mkscanner(self, cred, target, u, p, config):
        return SSHKey(cred, target, u, p, config)
