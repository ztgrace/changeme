from libnmap.parser import NmapParser as np
import multiprocessing as mp
from netaddr import *
import requests
from scanners.http_fingerprint import HttpFingerprint
from scanners.http_get import HTTPGetScanner
from scanners.http_post import HTTPPostScanner
from scanners.http_basic_auth import HTTPBasicAuthScanner
import shodan


class ScanEngine(object):
    def __init__(self, creds, config):
        """

        :param creds:
        :param config:
        """
        self.creds = creds
        self.config = config
        self.scanners = list()
        self.targets = set() # a set() if unique hosts
        self.fingerprints = set()
        self.found_q = mp.Manager().Queue()


    def scan(self):

        # Phase I - Fingerprint
        ###############################################################################
        self._build_targets()
        self.fingerprint_targets()

        # TODO: Multithread
        for s in self.scanners:
            result = s.scan()
            if result:
                self.found_q.put(result)

    def fingerprint_targets(self):
        self.config.logger.debug("[ScanEngine][fingerprint_targets]")
        s = requests.Session()

        # Build a set of unique fingerprints
        for c in self.creds:
            if c['name'] == 'Apache Tomcat':
                self.config.logger.warning('Apache Tomcat')
            fp = c['fingerprint']
            for url in fp.get('url'):
                hfp = HttpFingerprint(
                    url,
                    c.get('default_port', 80),
                    c.get('ssl'),
                    fp.get('headers', None),
                    fp.get('cookie', None)
                )
                if hfp not in self.fingerprints:
                    self.fingerprints.add(hfp)

        self.config.logger.critical(len(self.fingerprints))
        # Scan all the fingerprints
        for target in self.targets:
            for fp in self.fingerprints:
                proto = 'http'
                if fp.ssl is True:
                    proto = 'https'
                url = "%s://%s:%s%s" % (proto, target, fp.port, fp.url)
                self.config.logger.critical(url + str(fp.headers) + str(fp.cookies))

                try:
                    res = s.get(
                            url,
                            timeout=self.config.timeout,
                            verify=False,
                            proxies=self.config.proxy,
                            headers=fp.headers,
                            cookies=fp.cookies
                    )
                except Exception as e:
                    self.config.logger.debug('[ScanEngine][fingerprint_targets] Failed to connect to %s' % url)
                    continue

                for c in self.creds:
                    if HttpFingerprint.ismatch(c, res, self.config.logger):
                        self._build_scanner(c, res.url, s)





    def _build_targets(self):
        self.config.logger.debug("[ScanEngine][_build_targets]")

        if self.config.subnet:
            for ip in IPNetwork(self.config.subnet).iter_hosts():
                self.targets.add(ip)

        if self.config.targets:
            with open(self.config.targets, 'r') as fin:
                self.targets = [x.strip('\n') for x in fin.readlines()]

        if self.config.target:
            self.targets.add(self.config.target)

        if self.config.shodan_query:
            api = shodan.Shodan(self.config.shodan_key)
            results = api.search(self.config.shodan_query)
            for r in results['matches']:
                self.targets.add(r['ip_str'])

        if self.config.nmap:
            report = np.parse_fromfile(self.config.nmap)
            self.config.logger.info('[ScanEngine][_build_targets] Loaded %i hosts from %s' %
                                    (len(report.hosts), self.config.nmap))
            for h in report.hosts:
                for s in h.services:
                    self.targets.add('%s:%s' % (h.address, s.port))

    def _build_scanner(self, cred, url, session):
        if cred['auth']['type'] == 'get':
            self.scanners.append(HTTPGetScanner(cred, url, self.config, session))
        elif cred['auth']['type'] == 'post':
            self.scanners.append(HTTPPostScanner(cred, url, self.config, session))
        elif cred['auth']['type'] == 'basic_auth':
            self.scanners.append(HTTPBasicAuthScanner(cred, url, self.config, session))
        #scanners = list()
        #scanners.append(HTTPGetScanner(self.creds, self.targets, self.config),)
        #scanners.append(HTTPPostScanner(self.creds, self.targets, self.config),)
        #scanners.append(HTTPBasicAuthScanner(self.creds, self.targets, self.config),)

