#!/usr/bin/env python

import yaml
import os

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

get_data("name", "Name of service (JBoss, Tomcat): ")
get_data("category", "Category of service (web, printer): ")
get_data("default_port", "Default port: ", integer=True)
get_data("ssl", "Does the service use ssl (y/n): ", boolean=True)

# Path is confiured as a list so we can have more than one potential path
path = raw_input("Path to the login page: ")
parameters["path"] = list(path)

creds = list()
num_creds = raw_input("How many default creds for this service (1, 2, 3): ")
for i in range(0, int(num_creds)):
    user = raw_input("Username %i: " % (i + 1))
    passwd = raw_input("Password %i: " % (i + 1))
    creds.append({"username": user, "password": passwd})

parameters["credentials"] = creds
    
fp = list()
fp_status = raw_input("HTTP status code of fingerprint (401, 200): ")
fp_body = raw_input("String in login page of fingerprint (Welcome to ***): ")
basic_auth_realm = raw_input("Basic Auth Realm: ")

fp.append({"http_status": int(fp_status)})
if fp_body:
    fp.append({"http_body": fp_body})
if basic_auth_realm:
    fp.append({"basic_auth_realm": basic_auth_realm})

parameters["fingerprint"] = fp

get_data("type", "Type of authentication method (form, basic_auth): ")
form = list()
if parameters["type"] == "form":
    user_field = raw_input("Name of username form field: ")
    pass_field = raw_input("Name of password form field: ")
    form_params = raw_input("Post parameters string (data from the post body): ")

    form.append({"username": user_field})
    form.append({"password": pass_field})

    for f in form_params.split("&"):
        fname = f.split("=")[0] 
        fvalue = f.split("=")[1] 
        if fname == user_field or fname == pass_field:
            continue
        else:
            form.append({ fname: fvalue})
parameters["form"] = form

get_data("csrf", "Name of csrf field: ")
get_data("sessionid", "Name of session cookie: ")


success = list()
s_status = raw_input("HTTP status code of success (200, 302): ")
s_body = raw_input("Unique string in page of a successful login (Logout</a>): ")

success.append({"http_status": int(s_status)})
success.append({"http_body": s_body})

parameters["success"] = success

print
fname = parameters["name"].lower().replace(" ", "_") + ".yml"
print "Writing config to %s" % fname

with open(os.path.join("creds", fname), "w") as fout:
    fout.write(yaml.dump(parameters, default_flow_style=False))

print yaml.dump(parameters, default_flow_style=False)
