#!/usr/bin/env python


from cerberus import Validator
import yaml
import sys


schema = {
    'auth': {
        'type': 'dict',
        'required': True,
        'schema': {
            'credentials': {
                'type': 'list',
                'required': True,
                'schema': {
                    'type': 'dict',
                    'schema': {
                        'username': {
                            'type': ['string', 'integer'],
                            'nullable': True,
                            'required': True,
                        },
                        'password': {
                            'type': ['string', 'integer'],
                            'nullable': True,
                            'required': True,
                        },
                        'ref': {'type': 'string', 'required': False},
                        'raw': {'type': 'string', 'required': False},
                    }
                }
            },
            'headers': {
                'type': 'list',
                'required': False,
                'schema': {
                    'type': 'dict'
                }
            },
            'csrf': {
                'type': 'string',
                'nullable': True,
                'required': False,
            },
            'post': {
                'type': 'dict',
                'allow_unknown': True,
                'schema': {
                    'username': {'type': 'string', 'required': True},
                    'password': {'type': 'string', 'required': True},
                }
            },
            'get': {
                'type': 'dict',
                'allow_unknown': True,
                'schema': {
                    'username': {'type': 'string', 'required': True},
                    'password': {'type': 'string', 'required': True},
                }
            },
            'sessionid': {
                'type': 'string',
                'nullable': True,
                'required': False,
            },
            'base64': {
                'type': 'boolean',
                'nullable': False,
                'required': False,
            },
            'success': {
                'type': 'dict',
                'schema': {
                    'body': {'type': 'string', 'required': True},
                    'status': {'type': 'integer', 'required': True},
                },
            },
            'type': {
                'type': 'string',
                'regex': 'post|basic_auth|get|raw_post',
                'required': True
            },
            'url': {
                'type': 'list',
                'required': True,
                'schema': {'type': 'string'}
            },
        }
    },
    'category': {'type': 'string', 'required': True},
    'contributor': {'type': 'string', 'required': True},
    'fingerprint': {
        'type': 'dict',
        'required': True,
        'schema': {
            'body': {'type': 'string', 'required': False},
            'server_header': {'type': 'string', 'required': False},
            'cookie': {
                'type': 'list',
                'required': False,
                'schema': {
                    'type': 'dict'
                },
            },
            'headers': {
                'type': 'list',
                'required': False,
                'schema': {
                    'type': 'dict'
                }
            },
            'status': {'type': 'integer', 'required': True},
            'basic_auth_realm': {
                'type': 'string',
                'nullable': True,
                'required': False,
            },
            'url': {
                'type': 'list',
                'required': True,
                'schema': {'type': 'string'}
            },
        },
    },
    'default_port': {'type': 'integer', 'required': True},
    'name': {'type': 'string', 'required': True},
    'ssl': {'type': 'boolean', 'required': True},
    'references': {'type': 'list', 'required': False},
}

if __name__ == "__main__":
    cred_file = sys.argv[1]
    with open(cred_file, "r") as fin:
        raw = fin.read()
        cred = yaml.load(raw)

    v = Validator()
    v.validate(cred, schema)

    if v.errors:
        for e in v.errors:
            print "%s: %s" % (e, v.errors[e])
    else:
        print "Valid credential file."
