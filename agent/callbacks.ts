import { logCallback } from "./logger";

// Add your callbacks here. A few examples are below.

export function handlePtraceBefore(ctx: Arm64CpuContext) {
    const PT_DENY_ATTACH = 31; // https://github.com/knightsc/darwin-xnu/blob/master/bsd/sys/ptrace.h#L92
    const request = ctx.x0.toInt32();
    if (request === PT_DENY_ATTACH) {
        logCallback("Detected ptrace(PT_DENY_ATTACH) -- neutralizing before syscall!");
        ctx.x0 = ptr(-1);
    }
}

export function handleGetppidAfter(ctx: Arm64CpuContext) {
    logCallback("Detected getppid() -- neutralizing after syscall!");
    ctx.x0 = ptr(1);
}