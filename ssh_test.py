#!/usr/bin/env python

import paramiko
import sys

if not len(sys.argv) == 5:
    print "Usage: %s host port user path_to_key" % sys.argv[0]
    quit()

paramiko.util.log_to_file(sys.argv[0].replace('py', 'log'))


client = paramiko.SSHClient()

# set to the policy to the interface so it doesn't warn us about an unknown
# host or add it to our known_hosts file
client.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())

# Load key
#key_path = "/path/to/key"
#key = paramiko.RSAKey.from_private_key_file(key_path)

success = True
try:
    client.connect(sys.argv[1], int(sys.argv[2]), sys.argv[3], key_filename=sys.argv[4])
except paramiko.ssh_exception.AuthenticationException:
    success = False

if success:
    print "Found credentials"
else:
    print "Failed to Auth"

client.close()
