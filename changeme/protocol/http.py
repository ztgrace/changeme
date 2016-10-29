from protocol import Protocol
from fingerprint import Fingerprint

class HTTP(Protocol):
    def __init__(self):
        pass

    def scan(self):
        print "HTTP scan"

    def check_success(self):
        pass

    def check_fingerprint(self):
        pass
    

class HTTPFingerprint(Fingerprint):

    def match(self, response):
        pass
