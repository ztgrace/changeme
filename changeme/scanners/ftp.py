from scanner import Scanner
import ftplib


class FTP(Scanner):
    def __init__(self, cred, target, username, password, config):
        super(FTP, self).__init__(cred, target, config, username, password)
        self.port = self.cred['default_port']

    def _check(self):
        ftp = ftplib.FTP()
        ftp.connect(str(self.target), self.port)

        ftp.login(self.username, self.password)
        evidence = ftp.retrlines('LIST')
        ftp.quit()

        return evidence

    def _mkscanner(self, cred, target, u, p, config):
        return FTP(cred, target, u, p, config)
