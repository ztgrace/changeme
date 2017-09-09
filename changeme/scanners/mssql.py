from .database import Database

class MSSQL(Database):
    def __init__(self, cred, target, username, password, config):
        super(MSSQL, self).__init__(cred, target, username, password, config)
        self.protocol = "mssql+pyodbc"
        self.database = ""
        self.query = "SELECT @@VERSION AS 'SQL Server Version';"

    def _mkscanner(self, cred, target, u, p, config):
        return MSSQL(cred, target, u, p, config)