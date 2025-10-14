# frida-iOS-syscall-tracer

![image](https://github.com/user-attachments/assets/734d0abb-6125-48da-86b2-9bf308d33640)

An `strace`-like syscall tracer for 64-bit iOS devices based on [Frida's Stalker API](https://frida.re/docs/stalker/).
The purpose of this tool is to allow you to backtrace certain anti-(jailbreak|debugging|tampering|reverse engineering) techniques that rely on syscalls, i.e. `SVC` instructions.
Common file system-based syscalls that are used for anti-jailbreak techniques in many banking apps, for example, are `stat` and `open`. These scan the file system for file names such as _Cydia_, _Sileo_, _/etc/apt/sources.list_ etc.

## Features

- traces syscalls (`SVC`s) on instruction level
- logs detailed information, including
  - address
  - syscall number
  - syscall name
  - return value
  - (optional: backtrace)
  - (optional: bytes of `SVC` instruction)
  - etc.
- callbacks for syscalls to defeat anti-RE measures
- configurable

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

## Configuration

Depending on your target application and goals you might want to change the tracer's behaviour. Its configuration can be found in `agent/config.ts`:

```ts
export let Config = {
    // Use FUZZY with caution.
    syscallLogBacktracerType: Backtracer.ACCURATE,
    exceptionBacktracerType: Backtracer.FUZZY,

    // Whether to log negative Mach syscalls. Might spam the console.
    logMachSyscalls: false,

    // Whether to trace on instruction level. Might spam the console.
    traceInstructions: false,

    // Whether to backtrace the origin of each syscall. Might spam the console.
    backtrace: false,

    // Whether to call syscall callbacks defined in callbacks.ts.
    callCallbacks: false,

    // Syscall exclusions.
    excludes: [
        // e.g. "ulock_wait", "ulock_wake"
    ] as string[],

    // Logs more information.
    verbose: true,
}
```

## Usage example

```bash
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
   . . . .   Connected to Apple iPad
Spawning `com.heavily.protected.app`...
[+] Following thread 6147
0x1ba77a148 [372] thread_selfid() -> 0x16ff9b000
[+] Following thread 9735
0x1ba7796fc [516] ulock_wake(p=ptr(0x1000002), args=ptr(0x10900e200), retval=NULL) -> 0x1000002
0x10a7a6570 [516] ulock_wake(p=ptr(0x1000002), args=ptr(0x10900e200), retval=NULL) -> 0x1000002
0x108dddca4 [26] ptrace(req=31, pid=NULL, addr=NULL, data=NULL) -> 0x1f
0x10a7a94f0 [26] ptrace(req=31, pid=NULL, addr=NULL, data=NULL) -> 0x1f
0x108dddcb4 [338] stat64(path="/usr/sbin/frida-server", buf=ptr(0x16ff9aee0)) -> 0x108fb1310
0x10a7a95a0 [338] stat64(path="/usr/sbin/frida-server", buf=ptr(0x16ff9aee0)) -> 0x108fb1310
...
```

## Troubleshooting

The script was tested on several iOS versions (13, 14 and 15) but is not guaranteed to work on all iOS versions, especially newer ones.

There is a known issue where Frida is unable to spawn a process: `Failed to spawn: unable to launch iOS app via FBS: The operation couldn’t be completed.`

If that occurs try to downgrade frida, frida-tools and frida-server.

## To do

- GUI

- Better code quality

- Better stability (reduce crashes)

- Python backend to
  - save results
  - dump memory contents
  - etc.
