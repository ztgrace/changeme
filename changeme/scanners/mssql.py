from scanner import Scanner
from impacket import tds


class MSSQL(Scanner):

    def __init__(self, cred, target, username, password, config):
        super(MSSQL, self).__init__(data, target, config)
        self.cred = cred
        self.username = username
        self.password = password
        self.target = target
        self.config = config

    def scan(self):

        ms_sql = self._check_connection()
        if ms_sql:
            for cred in self.creds:
                db = None  # Default db name
                domain = ''
                res = ms_sql.login(db, cred['username'], cred['password'], domain, None, None)

                # ms_sql.printReplies()
                if res is True:
                    self.config.logger.critical('[+] Found %s default cred %s:%s at %s' % (self.name, cred['username'], str(cred['password']), '%s:%s' % (self.target, str(self.port))))
                    self.password_found.append(
                        {
                            'name': self.name,
                            'username': cred['username'],
                            'pasword': cred['password'],
                            'url': '{DOMAIN: %s} %s:%s' % (domain, self.target, str(self.port))
                        }
                    )
                else:
                    self.config.logger.info('[scan] Invalid %s default cred %s:%s at %s' % (self.name, cred['username'], str(cred['password']), '%s:%s' % (self.target, str(self.port))))
                ms_sql.disconnect()

        return self.password_found

    def _check_connection(self):
        try:
            ms_sql = tds.MSSQL(str(self.target), self.port)
            ms_sql.connect()
            return ms_sql
        except Exception, e:
            self.logger.debug('[check_success] error: %s' % str(e))
            return False
