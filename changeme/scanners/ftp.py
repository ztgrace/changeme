from .scanner import Scanner
import ftplib


class FTP(Scanner):
    def __init__(self, cred, target, username, password, config):
        super(FTP, self).__init__(cred, target, config, username, password)

    def _check(self):
        ftp = ftplib.FTP()
        ftp.connect(self.target.host, self.target.port)

        ftp.login(self.username, self.password)
        evidence = ftp.retrlines('LIST')
        ftp.quit()

        return evidence

    def _mkscanner(self, cred, target, u, p, config):
        return FTP(cred, target, u, p, config)
