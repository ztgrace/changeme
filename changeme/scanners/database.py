from scanner import Scanner
import sqlalchemy


class Database(Scanner):

    def __init__(self, cred, target, username, password, config):
        super(Database, self).__init__(cred, target, config, username, password)
        self.port = self.cred['default_port']
        self.protocol = None
        self.database = None
        self.query = None

    def scan(self):
        return self.check_success()

    def _check(self):
        url = "%s://%s:%s@%s:%s/%s" % (self.protocol, self.username, self.password, self.target, self.port, self.database)
        engine = sqlalchemy.create_engine(url)
        c = engine.connect()
        res = c.execute(self.query)

        results = list()
        [results.append(i) for i in res.fetchall()]

        return str(results[0][0])

    def _mkscanner(self, cred, target, u, p, config):
        raise NotImplementedError("A Database class needs to implement a _mkscanner method.")
