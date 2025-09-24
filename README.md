# frida-iOS-syscall-tracer

An `strace`-like syscall tracer for 64-bit iOS devices based on [Frida's Stalker API](https://frida.re/docs/stalker/). It is not stable yet and often causes the traced process to crash.
The purpose of this tool is to allow you to backtrace certain anti-(jailbreak|debugging|tampering|reverse engineering) techniques that rely on syscalls.
Common file system-based syscalls that are used for anti-jailbreak techniques in many banking apps, for example, are `stat` and `open`. These scan the file system for file names such as _Cydia_, _Sileo_, _/etc/apt/sources.list_ etc.

## Requirements

- npm
- jailbroken iOS device
- frida and frida-tools on the remote device
- frida-server on the iOS device

## Installation

```bash
git clone https://github.com/juliangrtz/frida-iOS-syscall-tracer
cd frida-iOS-syscall-tracer
npm install
```

## Usage example

```bash
# Adjust config to your liking
nano agent/config.ts

# Be sure the jailbroken iOS device is connected via USB and everything is set up correctly.
frida -Uf com.apple.stocks -l _tracer.js 
```

## Output example

```text
$ frida -Uf com.heavily.protected.app -l _tracer.js
     ____
    / _  |   Frida 17.3.2 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Apple iPad (id=yadayadayada)
Spawning `com.heavily.protected.app`...
[+] Following thread 4099
Spawned `com.heavily.protected.app`. Resuming main thread!
[+] Following thread 10499
0x1ba77a2d0 proc_info(callnum=5, pid=89979, flavor=2, arg=NULL, buffer=ptr(0x170166f90), buffersize=15)
[+] Following thread 8963
Process terminated
...
```

## Troubleshooting

The script was tested on several iOS versions (13, 14 and 15) but is not guaranteed to work on all iOS versions.
There is a known issue where Frida is unable to spawn a process: "Failed to spawn: unable to launch iOS app via FBS: The operation couldn’t be completed."
If that occurs try to downgrade frida, frida-tools and frida-server.

## To do list

– Add proper backtracing

– Improve code quality

– Improve stability

– Support newest iOS versions
