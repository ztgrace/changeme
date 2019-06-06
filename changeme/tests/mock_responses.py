import responses


class MockResponses:
    tomcat_fp = {
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/manager/html',
        'status': 401,
        'adding_headers': {
            'Server': 'Apache-Coyote/1.1',
            'WWW-Authenticate': 'Basic realm="Tomcat Manager Application'}
    }

    tomcat_fp_alt = {
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/tomcat/manager/html',
        'status': 404,
        'adding_headers': {
            'Server': 'Apache-Coyote/1.1',
            'WWW-Authenticate': 'Basic realm="Tomcat Manager Application'}
    }

    tomcat_auth = {
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/manager/html',
        'status': 200,
        'body': '<font size="+2">Tomcat Web Application Manager</font>',
        'adding_headers': {'Server': 'Apache-Coyote/1.1'}
    }

    jboss_fp = {
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/admin-console/login.seam',
        'status': 200,
        'body': '<p>Welcome to the JBoss AS 6 Admin Console.</p><input name="javax.faces.ViewState" value="foobar" />',
        'adding_headers': {
            'Server': 'Apache-Coyote/1.1',
            'Set-Cookie': 'JSESSIONID=foobar'
        }
    }

    jboss_fp_no_csrf = {
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/admin-console/login.seam',
        'status': 200,
        'body': '<p>Welcome to the JBoss AS 6 Admin Console.</p>',
        'adding_headers': {
            'Server': 'Apache-Coyote/1.1',
            'Set-Cookie': 'JSESSIONID=foobar'
        }
    }

    jboss_auth = {
        'method': responses.POST,
        'url': 'http://127.0.0.1:8080/admin-console/login.seam',
        'status': 200,
        'body': '<a>Logout</a>',
        'adding_headers': {'Server': 'Apache-Coyote/1.1'}
    }

    jboss_auth_fail = {
        'method': responses.POST,
        'url': 'http://127.0.0.1:8080/admin-console/login.seam',
        'status': 200,
        'body': 'Fail',
        'adding_headers': {'Server': 'Apache-Coyote/1.1'}
    }

    idrac_fp = {
        'method': responses.GET,
        'url': 'https://127.0.0.1:443/login.html',
        'status': 200,
        'body': '<title>Integrated Dell Remote Access Controller</title>',
        'adding_headers': {
            'Server': 'Mbedthis-Appweb/2.4.2',
            'Content-type': 'text/xml',
            'Set-Cookie': '_appwebSessionId_=dffaac7c4fb4e3c4cbd46d3691aeb40f;',
        },
        'body': '<title>Integrated Dell Remote Access Controller 6 - Express</title>',
    }

    idrac_auth = {
        'method': responses.POST,
        'url': 'https://127.0.0.1:443/data/login',
        'status': 200,
        'body': '<title>Integrated Dell Remote Access Controller</title>',
        'adding_headers': {
            'Server': 'Mbedthis-Appweb/2.4.2',
            'Content-type': 'text/xml',
            'Set-Cookie': '_appwebSessionId_=dffaac7c4fb4e3c4cbd46d3691aeb40f',
        },
        'body': '<? xml version="1.0" encoding="UTF-8"?> <root> <status>ok</status> <authResult>0</authResult> <forwardUrl>index.html</forwardUrl> </root>'
    }

    zabbix_fp = {
        'method': responses.GET,
        'url': 'http://127.0.0.1/zabbix/index.php',
        'status': 200,
        'body': 'by Zabbix SIA',
    }

    zabbix_auth = {
        'method': responses.POST,
        'url': 'http://127.0.0.1/zabbix/index.php',
        'status': 200,
        'body': '<a>Logout</a>',
    }

    zabbix_fail = {
        'method': responses.POST,
        'url': 'http://127.0.0.1/zabbix/index.php',
        'status': 200,
        'body': 'foobar',
    }

    ipcamera_fp = {
        'method': responses.GET,
        'url': 'http://127.0.0.1:81/',
        'status': 200,
        'body': 'GetXml("login.xml?"+param,OnLoginAckOK,OnLoginAckFail);'
    }

    ipcamera_auth = {
        'method': responses.GET,
        'url': 'http://127.0.0.1:81/login.xml',
        'status': 200,
        'body': '<?xml version="1.0" encoding="UTF-8" ?><Result><Success>1</Success><UserLevel>0</UserLevel><UserGroup>Admin</UserGroup></Result>'
    }

    elasticsearch = {
        'method': responses.GET,
        'url': 'http://127.0.0.1:9200/',
        'status': 200,
        'body': """{
  "name" : "foo",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "1C4hbDs6TRetjINxrOKBZw",
  "version" : {
    "number" : "5.0.2",
    "build_hash" : "f6b4951",
    "build_date" : "2016-11-24T10:07:18.101Z",
    "build_snapshot" : false,
    "lucene_version" : "6.2.1"
  },
  "tagline" : "You Know, for Search"
}"""
    }

    endpoint_protector_fp = {
        'method': responses.GET,
        'url': 'https://127.0.0.1/index.php/login',
        'status': 200,
        'body': 'Endpoint Protector - Reporting and Administration Tool <input name="csrf_token_anon" value="foobar" />',
        'adding_headers': {
            'Set-Cookie': 'ratool=foobar'
        }
    }

    endpoint_protector_auth = {
        'method': responses.POST,
        'url': 'http://127.0.0.1:8080/index.php/login',
        'status': 200,
        'body': 'Edit Profile</a>',
    }
