from database import Database

class MySQL(Database):
    def __init__(self, cred, target, username, password, config):
        super(MySQL, self).__init__(cred, target, username, password, config)
        self.protocol = "mysql"
        self.database = ""
        self.query = "select version();"

    def _mkscanner(self, cred, target, u, p, config):
        return MySQL(cred, target, u, p, config)