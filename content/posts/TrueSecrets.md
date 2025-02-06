---
title: TrueSecrets
date: 2025-02-06
author: Flavien
draft: false
tags:
  - CTF
  - HTB
  - Challenge
  - Veasy
  - Forensics
  - Volatility
  - Memprocfs
  - veracrypt
categories:
  - Writeup
  - Challenge
  - Forensics
description: HTB writeup for the  easy forensics challenge "TrueSecrets"
summary: this challenge makes us go through a .raw file containing all the content of a windows file system at some point. Checking the processes and applications, we see `TrueCrypt` file that we can use to retrieve content and break AES encryption to get the flag
---

```
Our cybercrime unit has been investigating a well-known APT group for several months. The group has been responsible for several high-profile attacks on corporate organizations. However, what is interesting about that case, is that they have developed a custom command & control server of their own. Fortunately, our unit was able to raid the home of the leader of the APT group and take a memory capture of his computer while it was still powered on. Analyze the capture to try to find the source code of the server.
```

==> For this challenge we get a single `TrueSecrets.raw`file, representing the memory capture of the enemy's computer. Looking at it, we see that it is an absolutely massive file:

```bash
wc -l TrueSecrets.raw 
477446 TrueSecrets.raw
```

==> To analyze this, we will use `volatility`and we can start off by getting the `imageInfo`:

```bash
./volatility_2.6_lin64_standalone -f ../TrueSecrets.raw imageinfo
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/flavien/Desktop/HTB_CTFs/Challenges/Forensics/Easy/TrueSecrets/TrueSecrets.raw)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x82732c78L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x82733d00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2022-12-14 21:33:30 UTC+0000
     Image local date and time : 2022-12-14 13:33:30 -0800
```

from this output, we can determine the profile which will help us get a lot of information for the next steps. We can go on and dump the processes running:

```bash
./volatility_2.6_lin64_standalone -f ../TrueSecrets.raw --profile=Win7SP1x86_23418 pslist   
Volatility Foundation Volatility Framework 2.6
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x8378ed28 System                    4      0     87      475 ------      0 2022-12-15 06:08:19 UTC+0000                                 
0x83e7e020 smss.exe                252      4      2       29 ------      0 2022-12-15 06:08:19 UTC+0000                                 
0x843cf980 csrss.exe               320    312      9      375      0      0 2022-12-15 06:08:19 UTC+0000                                 
0x837f6280 wininit.exe             356    312      3       79      0      0 2022-12-15 06:08:19 UTC+0000                                 
0x84402d28 csrss.exe               368    348      7      203      1      0 2022-12-15 06:08:19 UTC+0000                                 
0x84409030 winlogon.exe            396    348      3      110      1      0 2022-12-15 06:08:19 UTC+0000                                 
0x844577a0 services.exe            452    356      9      213      0      0 2022-12-15 06:08:19 UTC+0000                                 
0x8445e030 lsass.exe               468    356      7      591      0      0 2022-12-15 06:08:19 UTC+0000                                 
0x8445f030 lsm.exe                 476    356     10      142      0      0 2022-12-15 06:08:19 UTC+0000                                 
0x84488030 svchost.exe             584    452     10      347      0      0 2022-12-15 06:08:19 UTC+0000                                 
0x844a2030 VBoxService.ex          644    452     11      116      0      0 2022-12-15 06:08:19 UTC+0000                                 
0x844ab478 svchost.exe             696    452      7      243      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x844c3030 svchost.exe             752    452     18      457      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x845f5030 svchost.exe             864    452     16      399      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x845fcd28 svchost.exe             904    452     15      311      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x84484d28 svchost.exe             928    452     23      956      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x8e013488 svchost.exe             992    452      5      114      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x8e030a38 svchost.exe            1116    452     18      398      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x8e0525b0 spoolsv.exe            1228    452     13      275      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x84477d28 svchost.exe            1268    452     19      337      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x8e0a2658 taskhost.exe           1352    452      9      223      1      0 2022-12-14 21:08:22 UTC+0000                                 
0x844d2d28 dwm.exe                1448    864      3       69      1      0 2022-12-14 21:08:22 UTC+0000                                 
0x8e0d3a40 explorer.exe           1464   1436     32     1069      1      0 2022-12-14 21:08:22 UTC+0000                                 
0x8e1023a0 svchost.exe            1636    452     10      183      0      0 2022-12-14 21:08:22 UTC+0000                                 
0x8e10d998 svchost.exe            1680    452     14      224      0      0 2022-12-14 21:08:22 UTC+0000                                 
0x8e07d900 wlms.exe               1776    452      4       45      0      0 2022-12-14 21:08:22 UTC+0000                                 
0x83825540 VBoxTray.exe           1832   1464     12      140      1      0 2022-12-14 21:08:22 UTC+0000                                 
0x8e1cd8d0 sppsvc.exe              352    452      4      144      0      0 2022-12-14 21:08:23 UTC+0000                                 
0x8e1f6a40 svchost.exe            1632    452      5       91      0      0 2022-12-14 21:08:23 UTC+0000                                 
0x8e06f2d0 SearchIndexer.          856    452     13      626      0      0 2022-12-14 21:08:28 UTC+0000                                 
0x91892030 TrueCrypt.exe          2128   1464      4      262      1      0 2022-12-14 21:08:31 UTC+0000                                 
0x91865790 svchost.exe            2760    452     13      362      0      0 2022-12-14 21:10:23 UTC+0000                                 
0x83911848 WmiPrvSE.exe           2332    584      5      112      0      0 2022-12-14 21:12:23 UTC+0000                                 
0x8e1ef208 taskhost.exe           2580    452      5       86      1      0 2022-12-14 21:13:01 UTC+0000                                 
0x8382f198 7zFM.exe               2176   1464      3      135      1      0 2022-12-14 21:22:44 UTC+0000                                 
0x83c1d030 DumpIt.exe             3212   1464      2       38      1      0 2022-12-14 21:33:28 UTC+0000                                 
0x83c0a030 conhost.exe             272    368      2       34      1      0 2022-12-14 21:33:28 UTC+0000
```

and we see some interesting processes such as:
- `TrueCrypt.exe`which is used to encrypt files
- `7zFM.exe`which indicates we might be looking for some `.zip`files 
we can also dump the files but there are simply too many of them. To start, we can focus on some extensions:

```bash
./volatility_2.6_lin64_standalone -f ../TrueSecrets.raw --profile=Win7SP1x86_23418 filescan | grep -i ".zip"
Volatility Foundation Volatility Framework 2.6
0x0000000000483038      6      0 R--r-d \Device\HarddiskVolume1\Windows\System32\zipfldr.dll
0x00000000028acb78      6      0 R--r-d \Device\HarddiskVolume1\Windows\System32\en-US\zipfldr.dll.mui
0x00000000095796b0      1      1 R--r-d \Device\HarddiskVolume1\Windows\System32\en-US\zipfldr.dll.mui
0x000000000bbf6158      3      1 R--r-- \Device\HarddiskVolume1\Users\IEUser\Documents\backup_development.zip
0x000000000c4ae378      3      0 R--r-d \Device\HarddiskVolume1\Program Files\7-Zip\7z.dll
0x000000000c4aef80      6      0 R--r-d \Device\HarddiskVolume1\Program Files\7-Zip\7-zip.dll
0x000000000c4afd38      4      0 R--r-d \Device\HarddiskVolume1\Program Files\7-Zip\7zFM.exe
```

and in here we find the file: `\Device\HarddiskVolume1\Users\IEUser\Documents\backup_development.zip`that seems particularly interesting!! We can then dump it using:

```bash
./volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f TrueSecrets.raw --profile=Win7SP1x86_23418 dumpfiles --physoffset=0x000000000bbf6158 -u -n -D .
Volatility Foundation Volatility Framework 2.6
DataSectionObject 0x0bbf6158   None   \Device\HarddiskVolume1\Users\IEUser\Documents\backup_development.zip
SharedCacheMap 0x0bbf6158   None   \Device\HarddiskVolume1\Users\IEUser\Documents\backup_development.zip

ls
TrueSecrets.raw  file.None.0x839339d0.backup_development.zip.dat  file.None.0x9185db40.backup_development.zip.vacb  output  volatility_2.6_lin64_standalone
```

==> And we get 2 files, only the first one interests us right now, so we can move it to the `.zip`file format and then `unzip`it to see what it contains:

```bash
unzip backup_development.zip             
Archive:  backup_development.zip
 extracting: development.tc
```

and we see a file named `development.tc`which is a `TrueCrypt` file --> we then need to use `VeraCrypt`to handle it. We first need to install it using:

**NEEDS VERSION <= 1.25.9 TO HAVE `TRUECRYPT` SUPPORT**

```bash
tar -xvjf veracrypt-1.25.9-setup.tar.bz2 
veracrypt-1.25.9-setup-console-x64
veracrypt-1.25.9-setup-console-x86
veracrypt-1.25.9-setup-gtk2-gui-x64
veracrypt-1.25.9-setup-gtk2-gui-x86
veracrypt-1.25.9-setup-gui-x64
veracrypt-1.25.9-setup-gui-x86
sudo ./veracrypt-1.25.9-setup-console-x64
```

==> After this we can try to mount the `development.tc`file but we see that it is protected by a password --> we can then go back to the `.raw`file to try and see what we can find. After some research, we discover that we can search for it directly using `volatility`:

```bash
./volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -h | grep -i "true"                                                                               
Volatility Foundation Volatility Framework 2.6
                truecryptmaster Recover TrueCrypt 7.1a Master Keys
                truecryptpassphrase     TrueCrypt Cached Passphrase Finder
                truecryptsummary        TrueCrypt Summary

./volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f TrueSecrets.raw --profile=Win7SP1x86_23418 truecryptpassphrase                                 
Volatility Foundation Volatility Framework 2.6
Found at 0x89ebf064 length 28: X2Hk2XbEJqWYsh8VdbSYg6WpG9g7
```

and boom we found it! --> We can then use it to access the file with `Veracrypt` and after this we mount the file. We then get a folder `malware_agent` containing 4 files:
- C# encryption script
- 3 files encrypted using `DES`

==> Inside of the C# file we find the combination `key + iv`:

```C#
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;

class AgentServer {
  
    static void Main(String[] args)
    {
        var localPort = 40001;
        IPAddress localAddress = IPAddress.Any;
        TcpListener listener = new TcpListener(localAddress, localPort);
        listener.Start();
        Console.WriteLine("Waiting for remote connection from remote agents (infected machines)...");
    
        TcpClient client = listener.AcceptTcpClient();
        Console.WriteLine("Received remote connection");
        NetworkStream cStream = client.GetStream();
    
        string sessionID = Guid.NewGuid().ToString();
    
        while (true)
        {
            string cmd = Console.ReadLine();
            byte[] cmdBytes = Encoding.UTF8.GetBytes(cmd);
            cStream.Write(cmdBytes, 0, cmdBytes.Length);
            
            byte[] buffer = new byte[client.ReceiveBufferSize];
            int bytesRead = cStream.Read(buffer, 0, client.ReceiveBufferSize);
            string cmdOut = Encoding.ASCII.GetString(buffer, 0, bytesRead);
            
            string sessionFile = sessionID + ".log.enc";
            File.AppendAllText(@"sessions\" + sessionFile, 
                Encrypt(
                    "Cmd: " + cmd + Environment.NewLine + cmdOut
                ) + Environment.NewLine
            );
        }
    }
    
    private static string Encrypt(string pt)
    {
        string key = "AKaPdSgV";
        string iv = "QeThWmYq";
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
        byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(pt);
        
        using (DESCryptoServiceProvider dsp = new DESCryptoServiceProvider())
        {
            var mstr = new MemoryStream();
            var crystr = new CryptoStream(mstr, dsp.CreateEncryptor(keyBytes, ivBytes), CryptoStreamMode.Write);
            crystr.Write(inputBytes, 0, inputBytes.Length);
            crystr.FlushFinalBlock();
            return Convert.ToBase64String(mstr.ToArray());
        }
    }
}
```

```
wENDQtzYcL3CKv0lnnJ4hk0JYvJVBMwTj7a4Plq8h68=
M35jHmvkY9WGlWdXo0ByOJrYhHmtC8O0rZ28CviPexkfHCFTfKUQVw==
hufGZi+isAzspq9AOs+sIwqijQL53yIJa5EVcXF3QLLwXPS1AejOWfPzJZ/wHQbBAIOxsJJIcFq0+83hkFcz+Jz9HAGl8oDianTHILnUlzl1oEc30scurf41lEg+KSu/6orcZQl3Bws=
6ySb2CBt+Z1SZ4GlB7/yL4cOS/j1whoSEqkyri0dj0juRpFBc4kqLw==
U2ltlIYcyGYnuh0P+ahTMe3t9e+TYxKwU+PGm/UsltpkanmBmWym5mDDqqQ14J/VSSgCRKXn/E+DKaxmNc9PpPOG1vZndmflMUnuTUzbiIdHBUAEOWMO8wVCufhanIdN56BhtczjrJS5HRvl9NwE/FNkLGZt6HQNSgDRzrpY0mseJHjTbkal6nh226f43X3ZihIF4sdLn7l766ZksE9JDASBi7qEotE7f0yxEbStNOZ1QPDchKVFkw==


wENDQtzYcL3CKv0lnnJ4hk0JYvJVBMwTj7a4Plq8h68=
M35jHmvkY9WGlWdXo0ByOJrYhHmtC8O0eu8xtbA16kKagSu6MIFSWQ==
hufGZi+isAzspq9AOs+sI0VYrJ6o8j3e9a1tNb9m1bVwJZpRxCOxg3Vs0NdU9xNxPku+sBziVYsVaOtgWkbH9691++BUkD1BNVRMc0e69lVs2cJmQIAbnagMaJ6OQEZAAvZ/G6y57CQ=
6ySb2CBt+Z1SZ4GlB7/yL8asWs1F/wTUTOLEHO92yuzuTzdsiM5t5w==
U2ltlIYcyGYnuh0P+ahTMe3t9e+TYxKwU+PGm/UsltpkanmBmWym5mDDqqQ14J/VSSgCRKXn/E+DKaxmNc9PpPOG1vZndmflMUnuTUzbiIdHBUAEOWMO8wVCufhanIdN56BhtczjrJS5HRvl9NwE/FNkLGZt6HQNSgDRzrpY0mseJHjTbkal6nh226f43X3ZihIF4sdLn7l766ZksE9JDASBi7qEotE7f0yxEbStNOZ1QPDchKVFkw==


wENDQtzYcL3CKv0lnnJ4hk0JYvJVBMwTj7a4Plq8h68=
M35jHmvkY9WGlWdXo0ByOJrYhHmtC8O0hn+gLHaClb4QbACeOoSiYA==
hufGZi+isAzspq9AOs+sI/u+AS/aWPrAYd+mctDo7qEt+SpW2sELvSaxx6RRdK3vDavTsziAtb4/iCZ72v3QGh78yhY2KXZFu8qAcYdN7ltOOlg1LSrdkhjgr+CWTlvWh7A8IS7NwwI=
6ySb2CBt+Z1SZ4GlB7/yL4rJGeZ0WVaYW7N15aUsDAqzIYJWL/f0yw==
U2ltlIYcyGaSmL5xmAkEop+/f5MGUEWeWjpCTe5eStd/cg9FKp89l/EksGB90Z/hLbT44/Ur/6XL9aI27v0+SzaMFsgAeamjyYTRfLQk2fQlsRPCY/vMDj0FWRCGIZyHXCVoo4AePQB93SgQtOEkTQ2oBOeVU4X5sNQo23OcM1wrFrg8x90UOk2EzOm/IbS5BR+Wms1M2dCvLytaGCTmsUmBsATEF/zkfM2aGLytnu5+72bD99j7AiSvFDCpd1aFsogNiYYSai52YKIttjvao22+uqWMM/7Dx/meQWRCCkKm6s9ag1BFUQ==
+iTzBxkIgVWgWm/oyP/Uf6+qW+A+kMTQkouTEammirkz2efek8yfrP5l+mtFS+bWA7TCjJDK2nLAdTKssL7CrHnVW8fMvc6mJR4Ismbs/d/fMDXQeiGXCA==
```

and we can use it to decrypt the content of the 3 files, and the flag is in the last one, we can use [this website](https://devtoolcafe.com/tools/des) to decrypt it:

```
+iTzBxkIgVWgWm/oyP/Uf6+qW+A+kMTQkouTEammirkz2efek8yfrP5l+mtFS+bWA7TCjJDK2nLAdTKssL7CrHnVW8fMvc6mJR4Ismbs/d/fMDXQeiGXCA==


Cmd: type c:\users\greg\documents\flag.txt
HTB{570r1ng_53cr37_1n_m3m0ry_15_n07_g00d}
```

==> **`HTB{570r1ng_53cr37_1n_m3m0ry_15_n07_g00d}`**
