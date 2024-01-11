# frida-iOS-syscall-tracer

An `strace`-like syscall tracer for 64-bit iOS devices based on [Frida's Stalker API](https://frida.re/docs/stalker/). It is not stable yet and often causes the traced process to crash.
The purpose of this tool is to allow you to backtrace certain anti-(jailbreak|debugging|tampering|reverse engineering) techniques that rely on syscalls.
Common file system-based syscalls that are used for anti-jailbreak techniques in many banking apps, for example, are `stat` and `open`. These scan the file system for file names such as _Cydia_, _Sileo_, _/etc/apt/sources.list_ etc.

## Requirements

- npm
- Jailbroken iOS device
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
# Be sure the jailbroken iOS device is connected via USB and everything is set up correctly.
cd agent
frida -Uf com.apple.stocks -l _tracer.js 
```

## Output example

```text
[+] Following thread 12295
ulock_wake()
proc_info()
ulock_wake()
ulock_wake()
ulock_wake()
psynch_mutexdrop()
ulock_wake()
psynch_mutexdrop()
ulock_wake()
ulock_wake()
psynch_mutexdrop()
ulock_wake()
proc_info()
kevent_qos()
ulock_wake()
ulock_wake()
ulock_wake()
kevent_qos()
mprotect(ptr(0x100d90000), 0x100000, 0x3)
stat64("/usr/lib/libRosetta.dylib", 0x16f853360)
open("/usr/lib/libRosetta.dylib", 0x0, 0x0)
open("/usr/lib", 0x100000, 0x0)
fcntl(21, 0x32, 0x16f8542d0)
close(21)
mprotect(ptr(0x100d90000), 0x100000, 0x1)
...
```

## to be done

– add proper backtracing

– improve code quality

– improve stability

– support newest iOS versions
