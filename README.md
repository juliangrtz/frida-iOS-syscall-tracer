# frida-iOS-syscall-tracer

An `strace`-like syscall tracer for 64-bit iOS devices based on [Frida's Stalker API](https://frida.re/docs/stalker/). It is not stable yet and often causes the traced process to crash.
The purpose of this tool is to allow you to backtrace certain anti-(jailbreak|debugging|tampering|reverse engineering) techniques that rely on syscalls.
Common file system-based syscalls that are used for anti-jailbreak techniques in many banking apps, for example, are `stat` and `open`. These scan the file system for file names such as _Cydia_, _Sileo_, _/etc/apt/sources.list_ etc.


# Installation

```
npm run build
```

# Usage example

```
frida -Uf com.apple.stocks -l _tracer.js 
```

# Output example

```
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

# License

Copyright 2023 Julian Goeritz

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
