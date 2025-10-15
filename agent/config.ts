export let Config = {
    // Use FUZZY with caution.
    syscallLogBacktracerType: Backtracer.ACCURATE,
    exceptionBacktracerType: Backtracer.FUZZY,

    // Whether to log negative Mach syscalls. Might spam the console.
    logMachSyscalls: false,

    // Whether to log SVC instructions and their corresponding byte representations. Might spam the console.
    logSvcInstructions: false,

    // Whether to backtrace the origin of each syscall. Might spam the console.
    backtrace: false,

    // Syscall exclusions.
    excludes: [
        // e.g. "ulock_wait", "ulock_wake"
    ] as string[],

    // Logs more information.
    verbose: true,
}
