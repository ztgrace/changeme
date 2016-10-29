class Fingerprint(object):
    def __init__(self, name, fp=dict()):
        self.name = name
        self.fp = fp

    def match(self, response):
        raise NotImplementedError("A Fingerprint class needs to implement a match method.")
