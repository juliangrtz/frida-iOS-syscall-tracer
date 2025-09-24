export let Config = {
    syscallLogBacktracerType: Backtracer.ACCURATE,
    exceptionBacktracerType: Backtracer.FUZZY,
    logMachSyscalls: true,
    traceInstructions: false,
    verbose: true,
    excludes: [
        "ulock_wait", "ulock_wake"
    ] as string[]
}
