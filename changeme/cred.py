class Cred(object):
    def __init__(self, cdict):
        self.name = cdict['name']

        # fingerprint

        # auth
        self.credentials = cdict['auth']['credentials']
        self.csrf = cdict['auth']['csrf']
        self.headers = cdict['auth']['headers']

        self.username = cdict['auth']['username']
        self.password = cdict['auth']['password']
        self.b64 = cdict['auth']['base64']
        self.success = cdict['auth']['success']
