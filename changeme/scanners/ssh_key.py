import logging
import paramiko
from ssh import SSH
from StringIO import StringIO


class SSHKey(SSH):

    def __init__(self, cred, target, username, key, config):
        super(SSHKey, self).__init__(cred, target, username, key, config)
        self.logger = logging.getLogger('changeme')
        self.logger.error('target %s' % self.target)

    def _check(self):
        self.logger.error('target %s' % type(self.target))
        fake = StringIO(self.password)
        key = paramiko.RSAKey.from_private_key(fake)
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
        c.connect(hostname=str(self.target), username=self.username, pkey=key)
        stdin, stdout, stderr = c.exec_command('uname -a')
        evidence = stdout.readlines()
        c.close()

        return evidence

    def _mkscanner(self, cred, target, u, p, config):
        self.logger.error('mkscanner')
        return SSHKey(cred, target, u, p, config)
