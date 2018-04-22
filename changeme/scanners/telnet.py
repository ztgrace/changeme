from .scanner import Scanner
import telnetlib
import re
import time

class Telnet(Scanner):

    def __init__(self, cred, target, username, password, config):
        super(Telnet, self).__init__(cred, target, config, username, password)

    def _check(self):
        try:
            telnet = telnetlib.Telnet(str(self.target.host))
            timeout_allowed = int(self.cred['auth']['blockingio_timeout'])
            wait_for_pass_prompt = int(self.cred['auth']['telnet_read_timeout'])

            retval = telnet.open(str(self.target.host), int(self.target.port), timeout=timeout_allowed)
            retval._has_poll = False    # telnetlib hackery :)
            banner = telnet.read_until("login: ")
            telnet.write(self.username + "\n")

            password = str(self.password) if self.password else ''

            result = telnet.read_until("Password: ", timeout=wait_for_pass_prompt)
            result = Telnet._trim_string(result)

            if "Password:" in result:
                telnet.write(password + "\n")

            else:
                self.logger.debug("Check closed at: 1")
                telnet.close()
                raise Exception("Telnet credential not found")

            telnet.write(b"ls\n")

            # evidence = '(slow connection, evidence not collected)'
            # try:
            #     evidence = telnet.read_all()
            # except:
            #     pass

            evidence = "(slow connection, evidence not collected)"
            time.sleep(3)
            evidence = telnet.read_very_eager()
            evidence_fp_check = Telnet._trim_string(evidence)

            self.logger.debug("Evidence string returned (stripped): %s" % str(evidence_fp_check))
            evidence_fp_check_as_bytes = ":".join("{:02x}".format(ord(c)) for c in evidence_fp_check)
            self.logger.debug("Evidence string returned (bytes): %s" % str(evidence_fp_check_as_bytes))

            # Remove simple echos or additional password prompt (wrong password)
            if (not evidence_fp_check) or (evidence_fp_check == "ls") or ("Password:" in evidence) or (evidence == ""):
                self.logger.debug("Check closed at: 2")
                telnet.close()
                raise Exception("Telnet credential not found")

            # Remove additional prompts to login - we have a correct username, but incorrect password
            if evidence_fp_check.endswith("login:") or evidence_fp_check.endswith("login: "):
                self.logger.debug("Check closed at: 3")
                telnet.close()
                raise Exception("Telnet credential not found")

            telnet.write("exit\n")
            telnet.close()

            return evidence

        except Exception as e:
            self.logger.debug("Error: %s" % str(e))
            raise e

    @staticmethod
    def _trim_string(str_to_trim):
        return str(str_to_trim).replace(' ','').replace('\s','').replace('\t','').replace('\r','').replace('\n','')

    def _mkscanner(self, cred, target, u, p, config):
        return Telnet(cred, target, u, p, config)
