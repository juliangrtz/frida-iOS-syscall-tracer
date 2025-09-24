export let Config = {
    syscallLogBacktracerType: Backtracer.ACCURATE,
    exceptionBacktracerType: Backtracer.FUZZY,
    logMachSyscalls: false,
    traceInstructions: false,
    backtrace: false,
    verbose: true,
    excludes: [
        // e.g. "ulock_wait", "ulock_wake"
    ] as string[]
}
