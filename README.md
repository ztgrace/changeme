# changeme [![Build Status](https://travis-ci.org/ztgrace/changeme.svg?branch=master)](https://travis-ci.org/ztgrace/changeme)

A default credential scanner.

![Basic Scan](https://raw.githubusercontent.com/wiki/ztgrace/changeme/images/basic.gif)

## About

changeme picks up where commercial scanners leave off. It focuses on detecting default and backdoor credentials and not necessarily common credentials. It's default mode is to scan HTTP default credentials, but has support for other credentials.

changeme is designed to be simple to add new credentials without having to write any code or modules. changeme keeps credential data separate from code. All credentials are stored in [yaml](http://yaml.org/) files so they can be both easily read by humans and processed by changeme. Credential files can be created by using the `./changeme.py --mkcred` tool and answering a few questions.

changeme supports the http/https, mssql, mysql, postgres, ssh, ssh w/key, snmp, mongodb and ftp protocols. Use `./changeme.py --dump` to output all of the currently available credentials.

You can load your targets using a variety of methods, single ip address/host, subnet, list of hosts, nmap xml file and Shodan query. All methods except for Shodan are loaded as a positional argument and the type is inferred.

## Installation

changeme has only been tested on Linux and has known issues on Windows and OS X/macOS. Use docker to run changeme on the unsupported platforms. It supports either a redis-backed queue (most stable) or an in-memory backed queue.

Stable versions of changeme can be found on the [releases](https://github.com/ztgrace/changeme/releases) page.

For mssql support, `unixodbc-dev` needs to be installed prior to installing the `pyodbc`.

For postgres support, `libpq-dev` needs to be installed.

[PhantomJS](http://phantomjs.org/) is required in your PATH for HTML report screenshots.

Use `pip` to install the required python modules: `pip install -r requirements.txt`

## Docker

A convenient way of running changeme is to do so inside a Docker container. You can run a pre-built container from Docker Hub, or build your own using the instructions below.

### Run changeme in Docker

Docker runs best in conjunction with Redis as a queue back end. Here's how to get a linked container setup working with Redis.

Get the latest containers: `docker pull redis && docker pull ztgrace/changeme`

Launch redis in the background: `docker run -d --name redis1 redis`

Start changeme linking the redis container by name and mounting a local directory into the container's `/mnt` directory: `docker run -it -v /tmp/results:/mnt --link redis1:redis ztgrace/changeme:latest /bin/sh`

Run changeme with a `--redishost` of `redis` and `--output` file in our mounted volume: `./changeme.py --redishost redis --output /tmp/mnt/results.csv --protocols ssh --threads 20 -d 192.168.1.0/24`

### Build from Dockerfile

1. Build the docker container: `docker build -t changeme .`
2. Run changeme from inside the container: `docker run -it changeme /bin/bash'

## Usage Examples

Below are some common usage examples.

* Scan a single host: `./changeme.py 192.168.59.100`
* Scan a subnet for default creds: `./changeme.py 192.168.59.0/24`
* Scan using an nmap file `./changeme.py subnet.xml`
* Scan a subnet for Tomcat default creds and set the timeout to 5 seconds: `./changeme.py -n "Apache Tomcat" --timeout 5 192.168.59.0/24`
* Use [Shodan](https://www.shodan.io/) to populate a targets list and check them for default credentials: `./changeme.py --shodan_query "Server: SQ-WEBCAM" --shodan_key keygoeshere -c camera`
* Scan for SSH and known SSH keys: `./changeme.py --protocols ssh,ssh_key 192.168.59.0/24`
* Scan a host for SNMP creds using the protocol syntax: `./changeme.py snmp://192.168.1.20`

See [Wiki Examples](https://github.com/ztgrace/changeme/wiki/Examples) for more detailed examples.

## Known Issues

The telnet scanner is broken.

Additionally, anything filed under https://github.com/ztgrace/changeme/issues as a bug.

## Bugs and Enhancements

Bugs and enhancements are tracked at [https://github.com/ztgrace/changeme/issues](https://github.com/ztgrace/changeme/issues).

**Request a credential:** Please add an issue to Github and apply the credential label.

**Vote for a credential:** If you would like to help us prioritize which credentials to add, you can add a comment to a credential issue.

Please see the [wiki](https://github.com/ztgrace/changeme/wiki) for more details.

## Contributors

Thanks for code contributions and suggestions.

* @AlessandroZ
* @m0ther_
* @GraphX
* @Equinox21_
* https://github.com/ztgrace/changeme/graphs/contributors
