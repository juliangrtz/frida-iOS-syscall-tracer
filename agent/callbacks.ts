import { logCallback } from "./logger";

export function handlePtrace(ctx: Arm64CpuContext) {
    const PT_DENY_ATTACH = 31; // https://github.com/knightsc/darwin-xnu/blob/master/bsd/sys/ptrace.h#L92
    const request = ctx.x0.toInt32();
    if (request === PT_DENY_ATTACH) {
        logCallback("Detected ptrace(PT_DENY_ATTACH) -- neutralizing before syscall!");
        ctx.x0 = ptr(0);
    }
}

export function handleProcinfo(ctx: Arm64CpuContext) {
    const PROC_PIDTASKALLINFO = 2;
    const flavor = ctx.x2.toInt32();

    if (flavor === PROC_PIDTASKALLINFO) {
        logCallback("Detected proc_info(PROC_PIDTASKALLINFO) -- neutralizing before syscall!");
        const ownPid = Process.id;
        ctx.x1 = ptr(ownPid);
        ctx.x3 = ptr(0);
        ctx.x4 = ptr(0);
        ctx.x5 = ptr(0);
    }
}

// Add your callbacks here.