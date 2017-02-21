import yaml
import os
from schema import schema
from cerberus import Validator

class Credentials(object):
    def __init__(self):
        self.creds = list()
        self.total_creds = 0

    def _is_yaml(self, f):
        isyaml = False
        try:
            isyaml = os.path.basename(f).split('.')[1] == 'yml'
        except:
            pass
        return isyaml

    def _parse_yaml(self, f):
        with open(f, 'r') as fin:
            raw = fin.read()
            try:
                parsed = yaml.load(raw)
            except(yaml.parser.ParserError):
                print "[parse_yaml] %s is not a valid yaml file" % f
                return None
        return parsed

    def _validate_cred(self, cred, f):
        v = Validator()
        valid = v.validate(cred, schema)
        for e in v.errors:
            print "[validate_cred] Validation Error: %s, %s - %s" % (f, e, v.errors[e])
        return valid

    def _in_scope(self, name, category, cred):
        add = True

        if name and not name.lower() in cred['name'].lower():
            add = False
        elif category and not cred['category'] == category:
            add = False

        return add

    def _loop_through_dir(self, directory, protocol, name, category):
        for root, dirs, files in os.walk(directory):
            for fname in files:
                f = os.path.join(root, fname)
                if self._is_yaml(f):
                    parsed = self._parse_yaml(f)
                    if parsed:
                        if self._validate_cred(parsed, f):
                            if self._in_scope(name, category, parsed):
                                self.total_creds += len(parsed["auth"]["credentials"])
                                parsed['protocol'] = protocol
                                self.creds.append(parsed)

    def load_creds(self, protocol, name, category):
        
        if protocol:
            self._loop_through_dir(os.path.join('creds', protocol), protocol, name, category)
        else:
            for p in os.listdir('creds'):
                self._loop_through_dir(os.path.join('creds', p), p, name, category)

        print('Loaded %i default credential profiles' % len(self.creds))
        print('Loaded %i default credentials\n' % self.total_creds)

        return self.creds
