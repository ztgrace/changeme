# changeme [![Build Status](https://travis-ci.org/ztgrace/changeme.svg?branch=master)](https://travis-ci.org/ztgrace/changeme)

A default credential scanner.

## About

I wrote changeme out of frustration with commercial vulnerability scanners missing common default credentials. Getting default credentials added to commercial scanners is often difficult and slow. changeme is designed to be simple to add new credentials without having to write any code or modules.

changeme keeps credential data separate from code. All credentials are stored in [yaml](http://yaml.org/) files so they can be both easily read by humans and processed by changeme. Credential files can be created by using the `./changeme.py --mkcred` tool and answering a few questions.

changeme supports the http/https, mssql, mysql, postgres, ssh and ssh w/key protocols. Use `./changeme.py --dump` to output all of the currently available credentials.

## Installation

changeme has only been tested on Linux and has known issues on Windows and OS X/macOS. Use docker to run changeme on the unsupported platforms.

Stable versions of changeme can be found on the [releases](https://github.com/ztgrace/changeme/releases) page.

For mssql support, `unixodbc-dev` needs to be installed prior to installing the `pyodbc`.

Use `pip` to install the python modules: `pip install -r requirements.txt`

## Docker

1. Build the docker container: `docker build -t changeme .`
2. Run changeme from inside the container: `docker run -it changeme changeme.py -h`

## Usage Examples

Scan a subnet for default creds: `./changeme.py -s 192.168.59.0/24`

Scan a single host: `./changeme.py -s 192.168.59.100`

Scan using an nmap file `./changeme.py -x subnet.xml`

Scan a subnet for Tomcat default creds and set the timeout to 5 seconds: `./changeme.py -s 192.168.59.0/24 -n "Apache Tomcat" --timeout 5`

Use [Shodan](https://www.shodan.io/) to populate a targets list and check them for default credentials: `./changeme.py --shodan_query "Server: SQ-WEBCAM" --shodan_key keygoeshere -c camera`

Scan for SSH and known SSH keys `./changeme.py -s 192.168.59.0/24 --protocols ssh,ssh_key`

## Known Issues

The ftp, mssql, and telnet scanners are broken.

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
