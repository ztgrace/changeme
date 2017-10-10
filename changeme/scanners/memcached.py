import memcache
from .scanner import Scanner


class MemcachedScanner(Scanner):

    def __init__(self, cred, target, username, password, config):
        super(MemcachedScanner, self).__init__(cred, target, config, username, password)

    def _check(self):
        mc = memcache.Client(['%s:%s' % (self.target.host, self.target.port)], debug=0)
        stats = mc.get_stats()
        evidence = "version: %s" % (stats[0][1]['version'])

        return evidence

    def _mkscanner(self, cred, target, u, p, config):
        return MemcachedScanner(cred, target, u, p, config)
