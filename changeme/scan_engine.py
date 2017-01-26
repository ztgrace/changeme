from libnmap.parser import NmapParser as np
import logging
import multiprocessing as mp
from netaddr import *
from scanners.http_fingerprint import HttpFingerprint
from scanners.http_get import HTTPGetScanner
from scanners.http_post import HTTPPostScanner
from scanners.http_basic_auth import HTTPBasicAuthScanner
import shodan
from Queue import Empty


class ScanEngine(object):
    def __init__(self, creds, config):
        """

        :param creds:
        :param config:
        """
        self.creds = creds
        self.config = config
        self.logger = logging.getLogger('changeme')
        self.scanners = mp.Manager().JoinableQueue()
        self.targets = set()
        self.fingerprints = mp.Manager().JoinableQueue()
        self.found_q = mp.Manager().Queue()


    def scan(self):

        # Phase I - Fingerprint
        ###############################################################################
        self._build_targets()

        if self.config.dryrun:
            self.dry_run()

        num_procs = self.config.threads if self.fingerprints.qsize() > self.config.threads else self.fingerprints.qsize()
        self.logger.debug('Number of fingerprint procs: %i' % num_procs)
        procs = [mp.Process(target=self.do_scan, args=(self.fingerprints, self.scanners, self.found_q)) for i in range(num_procs)]
        for proc in procs:
            proc.start()

        for proc in procs:
            proc.join()

    def do_scan(self, fp_q, scan_q, found_q):
        self.fingerprint_targets(fp_q, scan_q)
        if not self.config.fingerprint:
            self._scan(scan_q, found_q)

    def _scan(self, scan_q, found_q):
        while not scan_q.empty():
            try:
                template = scan_q.get_nowait()
                if not template:  # handle a queue race condition and prevent deadlock
                    continue
            except Empty as e:
                self.logger.debug('Caught exception: %s' % type(e).__name__)
                continue

            scanner = self._build_scanner(template)
            result = scanner.scan()
            if result:
                found_q.put(result)

            scan_q.task_done()

    def fingerprint_targets(self, fp_q, scan_q):
        while not fp_q.empty():
            try:
                fp = fp_q.get_nowait()
                if not fp:  # handle a queue race condition and prevent deadlock
                    continue
            except Empty as e:
                self.logger.debug('Caught exception: %s' % type(e).__name__)
                continue

            results = fp.fingerprint(self.logger)
            if results:
                for result in results:
                    scan_q.put(result)

            fp_q.task_done()

    def _build_targets(self):
        self.logger.debug('Building targets')

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
            self.logger.info('Loaded %i hosts from %s' %
                                    (len(report.hosts), self.config.nmap))
            for h in report.hosts:
                for s in h.services:
                    self.targets.add('%s:%s' % (h.address, s.port))

        # Load set of targets into queue
        self.logger.debug('%i targets' % len(self.targets))

        fingerprints = list()
        # Build a set of unique fingerprints
        if 'http' in self.config.protocols:
            fingerprints = fingerprints + HttpFingerprint.build_fingerprints(self.targets, self.creds, self.config)

        for fp in set(fingerprints):
            self.fingerprints.put(fp)
        self.logger.debug('%i fingerprints' % self.fingerprints.qsize())

    def _build_scanner(self, template):
        scanner = None
        cred = template['cred']
        url = template['url']
        pair = template['pair']
        cookies = template['cookies']
        csrf = template.get('csrf', None)
        self.logger.debug('Building %s %s:%s' % (cred['name'], pair['username'], pair['password']))

        if cred['auth']['type'] == 'get':
            scanner = HTTPGetScanner(cred, url, pair['username'], pair['password'], self.config, cookies)
        elif cred['auth']['type'] == 'post' or cred['auth']['type'] == 'raw_post':
            scanner = HTTPPostScanner(cred, url, pair['username'], pair['password'], self.config, cookies, csrf)
        elif cred['auth']['type'] == 'basic_auth':
            scanner = HTTPBasicAuthScanner(cred, url, pair['username'], pair['password'], self.config, cookies)

        return scanner

    def dry_run(self):
        self.logger.info("Dry run URLs:")
        while not self.fingerprints.empty():
            fp = self.fingerprints.get_nowait()
            print fp.full_URL()
            self.fingerprints.task_done()
        quit()
