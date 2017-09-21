from pysnmp.hlapi import *
from .scanner import Scanner


class SNMP(Scanner):
    def __init__(self, cred, target, username, password, config):
        super(SNMP, self).__init__(cred, target, config, username, password)

    def fingerprint(self):
        # Just build the scanners instead of mess around detecting the UDP service
        scanners = list()
        for pair in self.cred['auth']['credentials']:
            scanners.append(self._mkscanner(self.cred, self.target, None, pair['password'], self.config))
        return scanners

    def _check(self):
        iterator = getCmd(SnmpEngine(),
                          CommunityData(self.password),
                          UdpTransportTarget((str(self.target.host), 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        evidence = ""
        if errorIndication:
            self.logger.debug(errorIndication)
        elif errorStatus:
            self.logger.debug('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        else:
            for varBind in varBinds:
                evidence += ' = '.join([x.prettyPrint() for x in varBind])

        if evidence == "":
            raise Exception

        return evidence

    def _mkscanner(self, cred, target, u, p, config):
        return SNMP(cred, target, u, p, config)
