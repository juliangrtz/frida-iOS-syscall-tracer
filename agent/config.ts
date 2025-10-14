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
