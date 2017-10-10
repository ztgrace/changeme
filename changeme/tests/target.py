from changeme.target import Target
import os

"""
1. nmap.xml
2. targets.txt
3. 127.0.0.1
4. 192.168.1.0/24
5. 192.168.59.139:8080
6. snmp://192.168.59.101
7. mysql://192.168.59.101:33306
"""

def test_nmap():
    path = os.path.dirname(os.path.abspath(__file__))
    nmap = os.path.join(path, "tomcat_nmap.xml")
    targets = Target.parse_target(nmap)
    assert len(targets) == 1
    t = targets.pop()
    path = os.path.dirname(os.path.abspath(__file__))
    print("target: %s" % t)
    assert t == Target(host='127.0.0.1', port='8080')


def test_targets_file():
    target = '/tmp/targets.txt'
    with open(target, 'w') as fout:
        fout.write('127.0.0.1\n')
        fout.write('127.0.0.2:8080\n')

    targets = Target.parse_target(target)
    assert len(targets) == 2

    for t in targets:
        if t.host == '127.0.0.1':
            t1(t)
        else:
            t2(t)

    os.remove(target)


def t1(t):
    assert t == Target(host='127.0.0.1')


def t2(t):
    assert t == Target(host='127.0.0.2', port=8080)


def test_ip():
    target = '127.0.0.1'
    targets = Target.parse_target(target)
    assert len(targets) == 1
    t = targets.pop()
    assert t == Target(host=target)
    assert str(t) == target


def test_cidr():
    target = '192.168.1.0/24'
    targets = Target.parse_target(target)
    assert len(targets) == 254

    # TODO explicitly validate the range
    """
    for ip in IPNetwork(target).iter_hosts():
        print str(ip)
        assert Target(host=str(ip)) in targets
    """


def test_ip_port():
    target = '192.168.1.1:8080'
    targets = Target.parse_target(target)
    assert len(targets) == 1
    t = targets.pop()
    assert t == Target(host='192.168.1.1', port='8080')
    assert str(t) == target


def test_proto_ip():
    target = 'snmp://192.168.1.1'
    targets = Target.parse_target(target)
    assert len(targets) == 1

    t = targets.pop()
    assert t == Target(host='192.168.1.1', protocol='snmp')
    assert str(t) == target


def test_proto_ip_port():
    target = 'snmp://192.168.1.1:8080'
    targets = Target.parse_target(target)
    assert len(targets) == 1

    t = targets.pop()
    assert t == Target(host='192.168.1.1', port=8080, protocol='snmp')
    assert str(t) == target


def test_hostname():
    target = 'example.com'
    targets = Target.parse_target(target)
    assert len(targets) == 1

    t = targets.pop()
    assert t == Target(host='example.com')


def test_hostname_proto():
    target = 'http://example.com'
    targets = Target.parse_target(target)
    assert len(targets) == 1

    t = targets.pop()
    assert t == Target(host='example.com', protocol='http')


def test_hostname_proto_port():
    target = 'http://example.com:80'
    targets = Target.parse_target(target)
    assert len(targets) == 1

    t = targets.pop()
    assert t == Target(host='example.com', port='80', protocol='http')
