from libnmap.parser import NmapParser as np
import logging
import multiprocessing as mp
from netaddr import *
from persistqueue import FIFOSQLiteQueue
from scanners.ftp import FTP
from scanners.http_fingerprint import HttpFingerprint
from scanners.mssql import MSSQL
from scanners.mysql import MySQL
from scanners.postgres import Postgres
from scanners.snmp import SNMP
from scanners.ssh import SSH
from scanners.ssh_key import SSHKey
import shodan
import time


class ScanEngine(object):
    def __init__(self, creds, config):
        """

        :param creds:
        :param config:
        """
        self.creds = creds
        self.config = config
        self.logger = logging.getLogger('changeme')
        self.scanners = FIFOSQLiteQueue(path=".", multithreading=True, name="scanners")
        self.total_scanners = 0
        self.targets = set()
        self.fingerprints = FIFOSQLiteQueue(path=".", multithreading=True, name="fingerprints")
        self.total_fps = 0
        self.found_q = FIFOSQLiteQueue(path=".", multithreading=True, name="found")

    def scan(self):

        # Phase I - Fingerprint
        ######################################################################
        if not self.config.resume:
            self._build_targets()

        if self.config.dryrun:
            self.dry_run()

        num_procs = self.config.threads if self.fingerprints.qsize() > self.config.threads else self.fingerprints.qsize()

        self.logger.debug('Number of procs: %i' % num_procs)
        self.total_fps = self.fingerprints.qsize()
        procs = [mp.Process(target=self.fingerprint_targets, args=(self.fingerprints, self.scanners)) for i in range(num_procs)]
        for proc in procs:
            proc.start()
            proc.join(timeout=30)

        self.logger.info('Fingerprinting completed')

        # Phase II - Scan
        ######################################################################
        if not self.config.fingerprint:
            num_procs = self.config.threads if self.scanners.qsize() > self.config.threads else self.scanners.qsize()
            self.total_scanners = self.scanners.qsize()

            self.logger.debug('Starting %i scanner procs' % num_procs)
            procs = [mp.Process(target=self._scan, args=(self.scanners, self.found_q)) for i in range(num_procs)]
            for proc in procs:
                proc.start()
                proc.join(timeout=30)

            self.logger.info('Scanning Completed')

            # Hack to address a broken pipe IOError per https://stackoverflow.com/questions/36359528/broken-pipe-error-with-multiprocessing-queue
            time.sleep(0.1)

    def _scan(self, scanq, foundq):
        while scanq.qsize() != 0:
            remaining = self.scanners.qsize()
            self.logger.debug('%i scanners remaining' % remaining)

            try:
                scanner = scanq.get()
                if scanner is None:
                    return
            except Exception as e:
                self.logger.debug('Caught exception: %s' % type(e).__name__)
                break

            result = scanner.scan()
            if result:
                foundq.put(result)

    def fingerprint_targets(self, fpq, scannerq):
        while fpq.qsize() != 0:
            remaining = fpq.qsize()
            self.logger.debug('%i fingerprints remaining' % remaining)

            try:
                fp = fpq.get()
                if fp is None:
                    return
            except Exception as e:
                self.logger.debug('Caught exception: %s' % type(e).__name__)
                return

            results = fp.fingerprint()
            if results:
                for result in results:
                    scannerq.put(result)

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
            self.logger.info('Loaded %i hosts from %s' % (len(report.hosts), self.config.nmap))
            for h in report.hosts:
                for s in h.services:
                    self.targets.add('%s:%s' % (h.address, s.port))

        # Load set of targets into queue
        self.logger.debug('%i targets' % len(self.targets))

        fingerprints = list()
        # Build a set of unique fingerprints
        if 'http' in self.config.protocols or self.config.all:
            fingerprints = fingerprints + HttpFingerprint.build_fingerprints(self.targets, self.creds, self.config)

        fingerprints = list(set(fingerprints))  # unique the HTTP fingerprints
        # Debug
        for f in fingerprints:
            self.logger.debug(f.url)

        self.logger.info('Configured protocols: %s' % self.config.protocols)
        for target in self.targets:
            for cred in self.creds:
                if cred['protocol'] == 'ssh' and 'ssh' in self.config.protocols or self.config.all:
                    fingerprints.append(SSH(cred, target, self.config, '', ''))

                if cred['protocol'] == 'ssh_key' and 'ssh_key' in self.config.protocols or self.config.all:
                    fingerprints.append(SSHKey(cred, target, self.config, '', ''))

                if cred['protocol'] == 'postgres' and 'postgres' in self.config.protocols or self.config.all:
                    fingerprints.append(Postgres(cred, target, self.config, '', ''))

                if cred['protocol'] == 'mysql' and 'mysql' in self.config.protocols or self.config.all:
                    fingerprints.append(MySQL(cred, target, self.config, '', ''))

                if cred['protocol'] == 'mssql' and 'mssql' in self.config.protocols or self.config.all:
                    fingerprints.append(MSSQL(cred, target, self.config, '', ''))

                if cred['protocol'] == 'ftp' and 'ftp' in self.config.protocols or self.config.all:
                    fingerprints.append(FTP(cred, target, self.config, '', ''))

                if cred['protocol'] == 'snmp' and 'snmp' in self.config.protocols or self.config.all:
                    fingerprints.append(SNMP(cred, target, self.config, '', ''))

        for fp in set(fingerprints):
            self.fingerprints.put(fp)
        self.total_fps = self.fingerprints.qsize()
        self.logger.debug('%i fingerprints' % self.fingerprints.qsize())

    def dry_run(self):
        self.logger.info("Dry run URLs:")
        while self.fingerprints.qsize() > 0:
            fp = self.fingerprints.get()
            print fp.full_URL()
        quit()
