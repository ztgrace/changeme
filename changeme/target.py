from libnmap.parser import NmapParser as np
import logging
from netaddr import IPNetwork
from netaddr.core import AddrFormatError
import re
from os.path import isfile
import shodan
import socket


class Target(object):
    def __init__(self, host=None, port=None, protocol=None, url=None):
        self.host = host
        if port:
            port = re.sub(r'\D','',str(port))
            if 0 < int(port) < 65535:
                self.port = int(port)
            else:
                #just disregard the port for now.
                self.port = None
        else:
            self.port = None
        self.protocol = protocol
        self.url = url
        self.ip = None

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __hash__(self):
        return id(self)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        target = self

        if self.host:
            target = self.host

        if self.port:
            target += ":%s" % self.port

        if self.protocol:
            target = "%s://" % self.protocol + target

        if self.url:
            target += self.url

        return str(target)

    def get_ip(self):
        if self.ip is None:
            regex = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
            result = regex.match(self.host)
            if not result:
                self.ip = socket.gethostbyname(self.host)
            else:
                self.ip = self.host

        return self.ip

    @staticmethod
    def parse_target(target):
        logger = logging.getLogger('changeme')
        targets = set()
        if isfile(target):
            try:
                # parse nmap
                report = np.parse_fromfile(target)
                logger.info('Loaded %i hosts from %s' % (len(report.hosts), target))
                for h in report.hosts:
                    for s in h.services:
                        targets.add(Target(host=h.address, port=s.port))
            except:
                # parse text file
                with open(target, 'r') as fin:
                    for line in fin:
                        res = Target._parse_target_string(line)
                        for t in res:
                            targets.add(t)
        else:
            targets = Target._parse_target_string(target)

        return targets

    @staticmethod
    def _parse_target_string(target):
        logger = logging.getLogger('changeme')
        logger.debug('Parsing target %s' % target)
        target = target.strip()
        targets = set()
        try:
            for ip in IPNetwork(target).iter_hosts(): #(covers IP or cidr) #3,4
                targets.add(Target(host=str(ip)))
        except AddrFormatError:
            if len(target.split(':')) == 3:
                # mysql://127.0.0.1:3306
                protocol = target.split(':')[0]
                host = target.split(':')[1].replace('//', '')
                port = target.split(':')[2]
                targets.add(Target(host=host, port=port, protocol=protocol))
            elif "://" in target:
                # snmp://127.0.0.1
                protocol = target.split(':')[0]
                host = target.split(':')[1].replace('//', '')
                targets.add(Target(host=host, protocol=protocol))
            elif ":" in target:
                # 127.0.0.1:8080
                host = target.split(':')[0]
                port = target.split(':')[1]
                targets.add(Target(host=host, port=port))
            else:
                targets.add(Target(host=target))

        return targets

    @staticmethod
    def get_shodan_targets(config):
        targets = set()
        api = shodan.Shodan(config.shodan_key)
        results = api.search(config.shodan_query)
        for r in results['matches']:
            targets.add(Target(host=r['ip_str']))

        return targets
