from libnmap.parser import NmapParser as np
import logging
import multiprocessing as mp
from netaddr import *
from scanners.http_fingerprint import HttpFingerprint
from scanners.ssh import SSH
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
        self.scanners = mp.Queue()
        self.targets = set()
        self.fingerprints = mp.Queue()
        self.found_q = mp.Queue()


    def scan(self):

        # Phase I - Fingerprint
        ###############################################################################
        self._build_targets()

        if self.config.dryrun:
            self.dry_run()

        num_procs = self.config.threads if self.fingerprints.qsize() > self.config.threads else self.fingerprints.qsize()
        self.logger.debug('Number of procs: %i' % num_procs)
        procs = [mp.Process(target=self.do_scan) for i in range(num_procs)]
        for proc in procs:
            proc.start()

        for proc in procs:
            proc.join()

    def do_scan(self):
        self.fingerprint_targets()
        if not self.config.fingerprint:
            self._scan()

    def _scan(self):
        while not self.scanners.empty():
            self.logger.debug('%i scanners remaining' % self.scanners.qsize())
            try:
                scanner = self.scanners.get()
                if not scanner:  # handle a queue race condition and prevent deadlock
                    continue
            except Empty as e:
                self.logger.debug('Caught exception: %s' % type(e).__name__)
                continue

            result = scanner.scan()
            if result:
                self.found_q.put(result)

    def fingerprint_targets(self):
        while not self.fingerprints.empty():
            self.logger.debug('%i fingerprints remaining' % self.fingerprints.qsize())
            try:
                fp = self.fingerprints.get()
                if not fp:  # handle a queue race condition and prevent deadlock
                    continue
            except Empty as e:
                self.logger.debug('Caught exception: %s' % type(e).__name__)
                continue

            results = fp.fingerprint()
            if results:
                for result in results:
                    self.scanners.put(result)

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

        fingerprints = list(set(fingerprints))  # unique the HTTP fingerprints

        if 'ssh' in self.config.protocols:
            for target in self.targets:
                fingerprints.append(SSH(self.creds, target, '', '', self.config))

        for fp in set(fingerprints):
            self.fingerprints.put(fp)
        self.logger.debug('%i fingerprints' % self.fingerprints.qsize())

    def dry_run(self):
        self.logger.info("Dry run URLs:")
        while not self.fingerprints.empty():
            fp = self.fingerprints.get_nowait()
            print fp.full_URL()
        quit()
