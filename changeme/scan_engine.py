import logging
import multiprocessing as mp
from persistqueue import FIFOSQLiteQueue
from .scanners.ftp import FTP
from .scanners.http_fingerprint import HttpFingerprint
from .scanners.mssql import MSSQL
from .scanners.mysql import MySQL
from .scanners.postgres import Postgres
from .scanners.snmp import SNMP
from .scanners.ssh import SSH
from .scanners.ssh_key import SSHKey
import shodan
from .target import Target
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
        # Unique the queue
        scanners = list()
        while self.scanners.qsize() > 0:
            s = self.scanners.get()
            if s not in scanners:
                scanners.append(s)

        for s in scanners:
            self.scanners.put(s)

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

        self.logger.debug('scanners: %i' % scannerq.qsize())

    def _build_targets(self):
        self.logger.debug('Building targets')

        self.targets = Target.parse_target(self.config.target)

        # Load set of targets into queue
        self.logger.debug('%i targets' % len(self.targets))

        fingerprints = list()
        # Build a set of unique fingerprints
        if 'http' in self.config.protocols or self.config.all:
            fingerprints = fingerprints + HttpFingerprint.build_fingerprints(self.targets, self.creds, self.config)

        fingerprints = list(set(fingerprints))  # unique the HTTP fingerprints

        for f in fingerprints:
            self.logger.debug("fingerprints: %s" % f.target)

        # If there's only one protocol and the user specified a protocol, override the defaults
        if len(self.targets) == 1:
            t = self.targets.pop()
            if t.protocol:
                self.config.protocols = t.protocol
                self.targets.add(t)

        # Add any protocols if they were included in the targets
        for t in self.targets:
            if t.protocol and t.protocol not in self.config.protocols:
                self.config.protocols += ",%s" % t.protocol

        self.logger.info('Configured protocols: %s' % self.config.protocols)
        for target in self.targets:
            for cred in self.creds:
                if cred['protocol'] == 'ssh' and ('ssh' in self.config.protocols or self.config.all):
                    fingerprints.append(SSH(cred, target, self.config, '', ''))

                if cred['protocol'] == 'ssh_key' and ('ssh_key' in self.config.protocols or self.config.all):
                    fingerprints.append(SSHKey(cred, target, self.config, '', ''))

                if cred['protocol'] == 'postgres' and ('postgres' in self.config.protocols or self.config.all):
                    fingerprints.append(Postgres(cred, target, self.config, '', ''))

                if cred['protocol'] == 'mysql' and ('mysql' in self.config.protocols or self.config.all):
                    fingerprints.append(MySQL(cred, target, self.config, '', ''))

                if cred['protocol'] == 'mssql' and ('mssql' in self.config.protocols or self.config.all):
                    fingerprints.append(MSSQL(cred, target, self.config, '', ''))

                if cred['protocol'] == 'ftp' and ('ftp' in self.config.protocols or self.config.all):
                    fingerprints.append(FTP(cred, target, self.config, '', ''))

                if cred['protocol'] == 'snmp' and ('snmp' in self.config.protocols or self.config.all):
                    fingerprints.append(SNMP(cred, target, self.config, '', ''))

        for fp in set(fingerprints):
            self.fingerprints.put(fp)
        self.total_fps = self.fingerprints.qsize()
        self.logger.debug('%i fingerprints' % self.fingerprints.qsize())

    def dry_run(self):
        self.logger.info("Dry run URLs:")
        while self.fingerprints.qsize() > 0:
            fp = self.fingerprints.get()
            print(fp.target)
        quit()
