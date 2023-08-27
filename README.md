# A tool to run binaries in-memory, with masqueraded names
My attempt to play with memfd_create and fexecve syscalls, inspired by [this](https://0x00sec.org/t/super-stealthy-droppers/3715) great article. The tool works in two modes:
- **Remote:** Basically acts as a loader. Specify remote IP and port, the tool will get a payload from there, and run it in-memory without touching the disk and spawning other binaries.
- **Local:** Specify path to a local binary, its args, the tool will load it in memory, and execute it without leaving a trace in Auditd of which exact executable was launched.

## Build & Test
The tool is a single C source code without any external dependencies, should work on most modern Linux distros.
```bash
git clone https://github.com/maxvarm/memfd-process-hide
cd memfd-process-hide
gcc src/hide.c -o hide
./hide
# local /usr/bin/whoami
```
To test how the tool appears in logs, install auditd and apply a suitable config, like the one left in this repo:
- https://github.com/maxvarm/memfd-process-hide/blob/main/auditd/audit.conf

## Local Mode
The tool is configured to replace all executed filenames to /usr/bin/grep. You can change it to be something stealthy like [kworker:0:0]. On the left screen you input any commands you wish to run,
and on the right screen you can confirm that original executable name is never seen in Auditd logs or Process view:

Results:
- https://github.com/maxvarm/memfd-process-hide/blob/main/auditd/local.txt

Caveats:
- It is still easy to correlate the original **hide** binary with its following activities via PID
- You must enter an absolute path to a local binary. Relative paths (and sometimes symlinks) are not supported
- Command arguments are still seen in logs. You may wish to change a "fake" name to make your commands less suspicious

![image](https://github.com/maxvarm/memfd-process-hide/blob/main/images/local.png?raw=true)

## Remote Mode
The workflow is similar: open TCP listener on your source, and run the tool on your target. On the right screen you serve the payload,
and on the left screen you can confirm that it executes, again, without any "file creation" traces in Auditd or EDR:

Results:
- https://github.com/maxvarm/memfd-process-hide/blob/main/auditd/remote.txt

Caveats:
- Any payload's activity will be logged as if it originates directly from the **hide** binary, so its more suitable for static analysis evasion
- Only raw TCP sockets are supported, the tool won't be able to fetch web-hosted binary via HTTP, at least for now
- Command arguments are still seen in logs. You may wish to choose such a fake name to make your commands less suspicious

![image](https://github.com/maxvarm/memfd-process-hide/blob/main/images/remote.png?raw=true)

## Detection
The reason I wrote the code is because I was surprised to see how strange **local mode** looks in Auditd and SIEM logs and how cool it was to see a missed
EDR detection after this simple trick with a **remote mode**.

It is not hard to detect both modes when investigating manually ([link](https://0x00sec.org/t/super-stealthy-droppers/3715)).
But it may easily bypass your SIEM detections, because of this masquerading stuff and because of a huge amount of logs or performance exclusions.

Detection via third-party tools like Elastic Defend or OSquery may differ depending on how they trace the event, but for **Auditd**
you may simply monitor for all **memfd_create** syscalls, most server systems do not require any additional exclusions:
```
-a always,exit -S memfd_create -F key=fileless-malware
```
