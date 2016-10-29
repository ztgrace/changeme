
class Protocol(object):
    def __init__(self):
        pass

    def scan(self):
        raise NotImplementedError( "A protocol class needs to implement a scan method." )

    def check_success(self):
        raise NotImplementedError( "A protocol class needs to implement a check_success method." )

    def check_fingerprint(self):
        raise NotImplementedError( "A protocol class needs to implement a check_fingerprint method." )
        
