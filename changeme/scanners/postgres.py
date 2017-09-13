from .database import Database

class Postgres(Database):
    def __init__(self, cred, target, username, password, config):
        super(Postgres, self).__init__(cred, target, username, password, config)
        self.target.protocol = "postgresql+psycopg2"
        self.database = ""
        self.query = "select version();"

    def _mkscanner(self, cred, target, u, p, config):
        return Postgres(cred, target, u, p, config)