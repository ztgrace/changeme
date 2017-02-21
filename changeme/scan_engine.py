from scanners.ftp import FTP
from scanners.http import HTTP
from scanners.mssql import MSSQL
from scanners.ssh import SSH
from scanners.telnet import TELNET

class ScanEngine(object):
    def __init__(self, threads=10):
        self.threads = threads
        self.scanners = list()
        self.pwd_found = list()

    def scan(self, creds, targets, config):
        self._build_scanners(creds, targets, config)
        for e in self.scanners:
            pwd = e.scan()
            if pwd:
                self.pwd_found += pwd
        return self.pwd_found

    def _build_scanners(self, creds, targets, config):
        config.logger.debug("[ScanEngine][_create_target_list]")        
                
        for target in targets:
            if ':' in str(target): 
                target, config.port = str(target).split(':')

            config.logger.debug("[ScanEngine][_create_target_list] adding host for scanning: %s]" % target)  
            for cred in creds:

                # MANAGE MANY PROTOCOL HERE 

                if cred['protocol'] == 'ftp':
                    self.scanners.append(FTP(cred, target, config),)

                elif cred['protocol'] == 'http':
                    self.scanners.append(HTTP(cred, target, config),)
                
                elif cred['protocol'] == 'mssql':
                    self.scanners.append(MSSQL(cred, target, config),)

                elif cred['protocol'] == 'ssh':
                    self.scanners.append(SSH(cred, target, config),)

                elif cred['protocol'] == 'telnet':
                    self.scanners.append(TELNET(cred, target, config),)

                # SNMP
                # https://github.com/allfro/sploitego/blob/master/src/sploitego/scapytools/snmp.py
                # https://github.com/SECFORCE/SNMP-Brute/blob/master/snmpbrute.py