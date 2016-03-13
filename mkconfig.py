#!/usr/bin/env python
""" 
TODO:
    - move credentials under auth
    - move auth url under auth
    - move success under auth
    - move auth url under auth
    - move type under auth
"""


import yaml
import os
import urllib

parameters = dict()


def get_data(field, prompt, boolean=False, integer=False):
    result = raw_input(prompt).strip()
    if boolean and result.lower() == "y":
        result = True
    elif boolean:
        result = False

    if integer:
        result = int(result)

    parameters[field] = result

get_data("contributor", "Your name or handle: ")
get_data("name", "Name of service (JBoss, Tomcat): ")
get_data("category", "Category of service (web, printer): ")
get_data("default_port", "Default port: ", integer=True)
get_data("ssl", "Does the service use ssl (y/n): ", boolean=True)

# Fingerprint
###############################################################################
fp = dict()

# Fingerprint url is confiured as a list so we can have more than one potential path
path = raw_input("Path to the fingerprint page (/index.php): ")
path_list = list()
path_list.append(path)
fp["url"] = path_list

fp_status = raw_input("HTTP status code of fingerprint (401, 200): ")
fp_body = raw_input("String in login page of fingerprint (Welcome to ***): ")
basic_auth_realm = raw_input("Basic Auth Realm: ")

fp["status"] = int(fp_status)
if fp_body:
    fp["body"] = fp_body
if basic_auth_realm:
    fp["basic_auth_realm"] = basic_auth_realm

parameters["fingerprint"] = fp


# Authentication
###############################################################################
auth = dict()
auth_urls = list()
url = raw_input("Authentication URL (/login.php): ")
auth_urls.append(url)
auth['url'] = auth_urls
auth['type'] = raw_input("Type of authentication method (form, basic_auth): ")
if auth["type"] == "form":
    form = dict()
    form["username"] = raw_input("Name of username form field: ")
    form["password"] = raw_input("Name of password form field: ")
    form_params = raw_input("Post parameters string (data from the post body): ")
    form_params = urllib.unquote_plus(form_params)  # decode the parameters

    for f in form_params.split("&"):
        fname = f.split("=")[0]
        fvalue = f.split("=")[1]
        if fname == form["username"] or fname == form["password"]:
            continue
        else:
            form[fname] = fvalue

    auth["form"] = form

csrf = raw_input("Name of csrf field: ")
if csrf:
    auth["csrf"] = csrf

sessionid =  raw_input("Name of session cookie: ")
if sessionid:
    auth["sessionid"] = sessionid

creds = list()
num_creds = raw_input("How many default creds for this service (1, 2, 3): ")
for i in range(0, int(num_creds)):
    user = raw_input("Username %i: " % (i + 1))
    passwd = raw_input("Password %i: " % (i + 1))
    creds.append({"username": user, "password": passwd})

auth["credentials"] = creds


success = dict()
success["status"] = int(raw_input("HTTP status code of success (200, 302): "))
success["body"] = raw_input("Unique string in page of a successful login (Logout</a>): ")


auth["success"] = success
parameters["auth"] = auth

print
fname = parameters["name"].lower().replace(" ", "_").replace("/", "_") + ".yml"
print "Writing config to %s" % fname

with open(os.path.join("creds", fname), "w") as fout:
    fout.write(yaml.dump(parameters, default_flow_style=False))

print yaml.dump(parameters, default_flow_style=False)
