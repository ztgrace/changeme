from libnmap.parser import NmapParser as np
import multiprocessing as mp
from netaddr import *
import requests
from scanners.http_fingerprint import HttpFingerprint
from scanners.http_get import HTTPGetScanner
from scanners.http_post import HTTPPostScanner
from scanners.http_basic_auth import HTTPBasicAuthScanner
import shodan
from lxml import html


class ScanEngine(object):
    def __init__(self, creds, config):
        """

        :param creds:
        :param config:
        """
        self.creds = creds
        self.config = config
        self.scanners = list()
        #self.scanners = mp.Manager().Queue()
        self.targets = set() # a set() if unique hosts
        self.fingerprints = mp.Manager().Queue()
        self.found_q = mp.Manager().Queue()


    def scan(self):

        # Phase I - Fingerprint
        ###############################################################################
        self._build_targets()
        num_procs = self.config.threads if self.fingerprints.qsize() > self.config.threads else self.fingerprints.qsize()
        self.config.logger.debug('[ScanEngine][scan] number of fingerprint procs: %i' % num_procs)
        procs = [mp.Process(target=self.fingerprint_targets) for i in range(num_procs)]
        for proc in procs:
            proc.start()

        for proc in procs:
            proc.join()

        # Phase II - Scan
        ###############################################################################
        self.config.logger.debug("Running %i scanners" % len(self.scanners))
        for s in self.scanners:
            s._scan()
        """
        TODO: Multithread
        procs = [mp.Process(target=self._scan()) for i in range(self.config.threads)]
        for proc in procs:
            proc.start()

        for proc in procs:
            proc.join()
        """

    def _scan(self):
        if not self.scanners.empty():
            scanner = self.scanners.get().scan()
            result = scanner.scan()
            if result:
                self.found_q.put(result)

    def fingerprint_targets(self):
        self.config.logger.debug("[ScanEngine][fingerprint_targets]")
        s = requests.Session()

        # Scan all the fingerprints
        for target in self.targets:
            fp = self.fingerprints.get()
            proto = 'http'
            if fp.ssl is True:
                proto = 'https'
            url = "%s://%s:%s%s" % (proto, target, fp.port, fp.url)

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

            for cred in self.creds:
                if HttpFingerprint.ismatch(cred, res, self.config.logger):
                    csrf = self.get_csrf_token(res, cred)
                    for c in cred['auth']['credentials']:
                        for u in cred['auth']['url']:  # pass in the auth url
                            u = "%s%s" % (HTTPGetScanner.get_base_url(res.url), u)
                            self._build_scanner(cred, c, u, s.cookies, csrf=csrf)

    def get_csrf_token(self, res, cred):
        name = cred['auth'].get('csrf', False)
        if name:
            tree = html.fromstring(res.content)
            try:
                csrf = tree.xpath('//input[@name="%s"]/@value' % name)[0]
            except:
                self.config.logger.error(
                    "[get_csrf_token] failed to get CSRF token %s in %s" % (str(name), str(res.url)))
                return False
            self.config.logger.debug('[get_csrf_token] got CSRF token %s: %s' % (name, csrf))
        else:
            csrf = False

        return csrf

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

        self.config.logger.debug("[ScanEngine][_build_targets] %i targets" % len(self.targets))

        fingerprints = set()
        # Build a set of unique fingerprints
        for c in self.creds:
            fp = c['fingerprint']
            for url in fp.get('url'):
                hfp = HttpFingerprint(
                    url,
                    c.get('default_port', 80),
                    c.get('ssl'),
                    fp.get('headers', None),
                    fp.get('cookie', None)
                )
                if hfp not in fingerprints:
                    fingerprints.add(hfp)
        for fp in fingerprints:
            self.fingerprints.put(fp)
        self.config.logger.debug("[ScanEngine][_build_targets] %i fingerprints" % len(fingerprints))

    def _build_scanner(self, cred, c, url, cookies, **moar):
        self.config.logger.debug("[ScanEngine][_build_scanner] building %s %s:%s" % (cred['name'], c['username'], c['password']))
        if cred['auth']['type'] == 'get':
            self.scanners.append(HTTPGetScanner(cred, url, c['username'], c['password'], self.config, cookies))
        elif cred['auth']['type'] == 'post' or cred['auth']['type'] == 'raw_post':
            self.scanners.append(HTTPPostScanner(cred, url, c['username'], c['password'], self.config, cookies, moar.get('csrf', None)))
        elif cred['auth']['type'] == 'basic_auth':
            self.scanners.append(HTTPBasicAuthScanner(cred, url, c['username'], c['password'], self.config, cookies))

