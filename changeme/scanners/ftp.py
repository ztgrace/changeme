from scanner import Scanner
import ftplib

class FTP(Scanner):
    
    def __init__(self, data, target, config):

        super(FTP, self).__init__(data, target, config)
        self.config = config
        self.password_found = list()
        self.target = target

    def scan(self):
        self.logger.debug("[%s][scan]" % self._class_name())
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
            ftp = ftplib.FTP()
            ftp.connect(str(hostname), port)

            # check for anonymous connection
            if not pwd:
                ftp.login()
            else:
                ftp.login(user, pwd)
            
            ftp.quit()
            self.config.logger.critical('[+] Found %s default cred %s:%s at %s' % (self.name, user, str(pwd), '%s:%s' % (self.target, str(self.port))))
            return True
        except Exception, e:
            self.config.logger.info('[check_success] Invalid %s default cred %s:%s at %s' % (self.name, user, str(pwd), '%s:%s' % (self.target, str(self.port))))
            self.logger.debug('[check_success] error: %s' % str(e))
            return False