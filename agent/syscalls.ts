import { handleGetppidAfter, handlePtraceBefore } from "./callbacks";
import { Config } from "./config";
import { log, logBacktrace, logWarning } from "./logger";

class Syscall {
    name!: string;
    retval_type?: string;
    args?: Record<string, string>;
    beforeCall?: (ctx: Arm64CpuContext) => void;
    afterCall?: (ctx: Arm64CpuContext) => void;
}

function formatValueByType(value: NativePointer, type: String) {
    if (value.isNull()) {
        return "NULL";
    }

    try {
        switch (type) {
            case "int":
            case "size_t":
            case "int32_t":
                return value.toInt32();
            case "uint":
                return value.toUInt32();
            case "long":
            case "int64_t":
                return value.readLong();
            case "ulong":
                return value.readULong();
            case "char*":
                return `"${value.readCString()}"`;
            default:
                return `ptr(${value})`;
        }
    } catch (e) { }
}

function formatRetval(x0: NativePointer, syscall: Syscall) {
    if (!syscall.retval_type) return "";
    // return ` -> ${formatValueByType(x0, syscall.retval_type)}`;
    return ` -> ${x0.toString()}`;
}

function formatArguments(syscall: Syscall, cpuContext: Arm64CpuContext) {
    if (!syscall.args) return "";

    return Object.entries(syscall.args)
        .map(([name, type], i) => {
            const value = cpuContext[`x${i}` as keyof Arm64CpuContext] as NativePointer;
            return `${name}=${formatValueByType(value, type)}`;
        })
        .join(", ");
}

let syscallInfo = new Map<ThreadId, { syscall: Syscall; number: number }>();

export function handleSyscallBeforeExecution(cpuContext: CpuContext) {
    const context = cpuContext as Arm64CpuContext;
    const threadId = Process.getCurrentThreadId();
    const number = context.x16.toInt32();

    let syscall: Syscall | undefined;
    if (number < 0) {
        if (!Config.logMachSyscalls) return;
        syscall = MACH_SYSCALLS[-number] ?? { name: "Unknown syscall" };
    } else {
        syscall = POSIX_SYSCALLS[number] ?? { name: "Unknown syscall" };
    }

    if (!syscall ||
        Config.excludes.includes(syscall.name) ||
        Config.excludes.includes(number.toString())) {
        return;
    }

    syscallInfo.set(threadId, { syscall, number });

    if (Config.callCallbacks) syscall.beforeCall?.(context);

    if (Config.backtrace) {
        const backtrace = Thread.backtrace(cpuContext, Config.syscallLogBacktracerType)
            .map(DebugSymbol.fromAddress);
        logBacktrace(backtrace.join(" <> "));
    }
}

export function handleSyscallAfterExecution(cpuContext: CpuContext) {
    const context = cpuContext as Arm64CpuContext;
    const threadId = Process.getCurrentThreadId();
    const info = syscallInfo.get(threadId);
    if (!info) return;

    const { syscall, number } = info;

    if (Config.callCallbacks) syscall.afterCall?.(context);

    const argsStr = formatArguments(syscall, context);
    const retvalStr = formatRetval(context.x0, syscall);

    log(`${Config.verbose ? context.pc + " " : ""}[${number}] ${syscall.name}(${argsStr})${retvalStr}`);

    syscallInfo.delete(threadId);
}


/*
Read this documentation if you want to learn about specific syscalls:
https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/
*/


// https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/syscall_sw.c#L105
export const MACH_SYSCALLS: Record<number, Syscall> = {
    1: { name: "kern_invalid" },
    2: { name: "kern_invalid" },
    3: { name: "kern_invalid" },
    4: { name: "kern_invalid" },
    5: { name: "kern_invalid" },
    6: { name: "kern_invalid" },
    7: { name: "kern_invalid" },
    8: { name: "kern_invalid" },
    9: { name: "kern_invalid" },
    10: { name: "_kernelrpc_mach_vm_allocate_trap" },
    11: { name: "_kernelrpc_mach_vm_purgable_control_trap" },
    12: { name: "_kernelrpc_mach_vm_deallocate_trap" },
    13: { name: "task_dyld_process_info_notify_get_trap" },
    14: { name: "_kernelrpc_mach_vm_protect_trap" },
    15: { name: "_kernelrpc_mach_vm_map_trap" },
    16: { name: "_kernelrpc_mach_port_allocate_trap" },
    17: { name: "kern_invalid" },
    18: { name: "_kernelrpc_mach_port_deallocate_trap" },
    19: { name: "_kernelrpc_mach_port_mod_refs_trap" },
    20: { name: "_kernelrpc_mach_port_move_member_trap" },
    21: { name: "_kernelrpc_mach_port_insert_right_trap" },
    22: { name: "_kernelrpc_mach_port_insert_member_trap" },
    23: { name: "_kernelrpc_mach_port_extract_member_trap" },
    24: { name: "_kernelrpc_mach_port_construct_trap" },
    25: { name: "_kernelrpc_mach_port_destruct_trap" },
    26: { name: "mach_reply_port" },
    27: { name: "thread_self_trap" },
    28: { name: "task_self_trap" },
    29: { name: "host_self_trap" },
    30: { name: "kern_invalid" },
    31: { name: "mach_msg_trap" },
    32: { name: "mach_msg_overwrite_trap" },
    33: { name: "semaphore_signal_trap" },
    34: { name: "semaphore_signal_all_trap" },
    35: { name: "semaphore_signal_thread_trap" },
    36: { name: "semaphore_wait_trap" },
    37: { name: "semaphore_wait_signal_trap" },
    38: { name: "semaphore_timedwait_trap" },
    39: { name: "semaphore_timedwait_signal_trap" },
    40: { name: "_kernelrpc_mach_port_get_attributes_trap" },
    41: { name: "_kernelrpc_mach_port_guard_trap" },
    42: { name: "_kernelrpc_mach_port_unguard_trap" },
    43: { name: "mach_generate_activity_id" },
    44: { name: "task_name_for_pid" },
    45: { name: "task_for_pid" },
    46: { name: "pid_for_task" },
    47: { name: "mach_msg2_trap" },
    48: { name: "macx_swapon" },
    49: { name: "macx_swapoff" },
    50: { name: "thread_get_special_reply_port" },
    51: { name: "macx_triggers" },
    52: { name: "macx_backing_store_suspend" },
    53: { name: "macx_backing_store_recovery" },
    54: { name: "kern_invalid" },
    55: { name: "kern_invalid" },
    56: { name: "kern_invalid" },
    57: { name: "kern_invalid" },
    58: { name: "pfz_exit" },
    59: { name: "swtch_pri" },
    60: { name: "swtch" },
    61: { name: "thread_switch" },
    62: { name: "clock_sleep_trap" },
    63: { name: "kern_invalid" },
    64: { name: "kern_invalid" },
    65: { name: "kern_invalid" },
    66: { name: "kern_invalid" },
    67: { name: "kern_invalid" },
    68: { name: "kern_invalid" },
    69: { name: "kern_invalid" },
    70: { name: "host_create_mach_voucher_trap" },
    71: { name: "kern_invalid" },
    72: { name: "mach_voucher_extract_attr_recipe_trap" },
    73: { name: "kern_invalid" },
    74: { name: "kern_invalid" },
    75: { name: "kern_invalid" },
    76: { name: "_kernelrpc_mach_port_type_trap" },
    77: { name: "_kernelrpc_mach_port_request_notification_trap" },
    78: { name: "kern_invalid" },
    79: { name: "kern_invalid" },
    80: { name: "kern_invalid" },
    81: { name: "kern_invalid" },
    82: { name: "kern_invalid" },
    83: { name: "kern_invalid" },
    84: { name: "kern_invalid" },
    85: { name: "kern_invalid" },
    86: { name: "kern_invalid" },
    87: { name: "kern_invalid" },
    88: { name: "kern_invalid" },
    89: { name: "mach_timebase_info_trap" },
    90: { name: "mach_wait_until_trap" },
    91: { name: "mk_timer_create_trap" },
    92: { name: "mk_timer_destroy_trap" },
    93: { name: "mk_timer_arm_trap" },
    94: { name: "mk_timer_cancel_trap" },
    95: { name: "mk_timer_arm_leeway_trap" },
    96: { name: "debug_control_port_for_pid" },
    97: { name: "kern_invalid" },
    98: { name: "kern_invalid" },
    99: { name: "kern_invalid" },
    100: { name: "iokit_user_client_trap" },
    101: { name: "kern_invalid" },
    102: { name: "kern_invalid" },
    103: { name: "kern_invalid" },
    104: { name: "kern_invalid" },
    105: { name: "kern_invalid" },
    106: { name: "kern_invalid" },
    107: { name: "kern_invalid" },
    108: { name: "kern_invalid" },
    109: { name: "kern_invalid" },
    110: { name: "kern_invalid" },
    111: { name: "kern_invalid" },
    112: { name: "kern_invalid" },
    113: { name: "kern_invalid" },
    114: { name: "kern_invalid" },
    115: { name: "kern_invalid" },
    116: { name: "kern_invalid" },
    117: { name: "kern_invalid" },
    118: { name: "kern_invalid" },
    119: { name: "kern_invalid" },
    120: { name: "kern_invalid" },
    121: { name: "kern_invalid" },
    122: { name: "kern_invalid" },
    123: { name: "kern_invalid" },
    124: { name: "kern_invalid" },
    125: { name: "kern_invalid" },
    126: { name: "kern_invalid" },
    127: { name: "kern_invalid" }
}

// https://github.com/xybp888/iOS-SDKs/blob/master/iPhoneOS26.0.sdk/usr/include/sys/syscall.h
export const POSIX_SYSCALLS: Record<number, Syscall> = {
    0: {
        "name": "syscall"
    },
    1: {
        "name": "exit",
        "retval_type": "void",
        "args": {
            "status": "int"
        }
    },
    2: {
        "name": "fork",
        "retval_type": "int"
    },
    3: {
        "name": "read",
        "retval_type": "size_t",
        "args": {
            "fd": "int",
            "cbuf": "void*",
            "nbyte": "size_t"
        }
    },
    4: {
        "name": "write",
        "retval_type": "size_t",
        "args": {
            "fd": "int",
            "cbuf": "void*",
            "nbyte": "size_t"
        }
    },
    5: {
        "name": "open",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "flags": "int",
            "mode": "int"
        }
    },
    6: {
        "name": "close",
        "retval_type": "int",
        "args": {
            "fd": "int"
        }
    },
    7: {
        "name": "wait4",
        "retval_type": "int",
        "args": {
            "pid": "int",
            "status": "void*",
            "options": "int",
            "rusage": "void*"
        }
    },
    8: {
        "name": "creat"
    },
    9: {
        "name": "link",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "link": "char*"
        }
    },
    10: {
        "name": "unlink",
        "retval_type": "int",
        "args": {
            "path": "char*"
        }
    },
    11: {
        "name": "execv"
    },
    12: {
        "name": "chdir",
        "retval_type": "int",
        "args": {
            "path": "char*"
        }
    },
    13: {
        "name": "fchdir",
        "retval_type": "int",
        "args": {
            "fd": "int"
        }
    },
    14: {
        "name": "mknod",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "mode": "int",
            "dev": "int"
        }
    },
    15: {
        "name": "chmod",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "mode": "int"
        }
    },
    16: {
        "name": "chown",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "uid": "int",
            "gid": "int"
        }
    },
    18: {
        "name": "getfsstat",
        "retval_type": "int",
        "args": {
            "buf": "void*",
            "bufsize": "int",
            "flags": "int"
        }
    },
    19: {
        "name": "lseek"
    },
    20: {
        "name": "getpid",
        "retval_type": "int"
    },
    21: {
        "name": "mount"
    },
    22: {
        "name": "umount"
    },
    23: {
        "name": "setuid",
        "retval_type": "int",
        "args": {
            "uid": "int"
        }
    },
    24: {
        "name": "getuid",
        "retval_type": "int"
    },
    25: {
        "name": "geteuid",
        "retval_type": "int"
    },
    26: {
        "name": "ptrace",
        "retval_type": "int",
        "args": {
            "req": "int",
            "pid": "int",
            "addr": "void*",
            "data": "int"
        },
        beforeCall: handlePtraceBefore
    },
    27: {
        "name": "recvmsg",
        "retval_type": "int",
        "args": {
            "s": "int",
            "msg": "void*",
            "flags": "int"
        }
    },
    28: {
        "name": "sendmsg",
        "retval_type": "int",
        "args": {
            "s": "int",
            "msg": "void*",
            "flags": "int"
        }
    },
    29: {
        "name": "recvfrom",
        "retval_type": "int",
        "args": {
            "s": "int",
            "buf": "void*",
            "len": "size_t",
            "flags": "int",
            "from": "void*",
            "fromlenaddr": "void*"
        }
    },
    30: {
        "name": "accept",
        "retval_type": "int",
        "args": {
            "s": "int",
            "name": "void*",
            "anamelen": "void*"
        }
    },
    31: {
        "name": "getpeername",
        "retval_type": "int",
        "args": {
            "fdes": "int",
            "asa": "void*",
            "alen": "void*"
        }
    },
    32: {
        "name": "getsockname",
        "retval_type": "int",
        "args": {
            "fdes": "int",
            "asa": "void*",
            "alen": "void*"
        }
    },
    33: {
        "name": "access",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "flags": "int"
        }
    },
    34: {
        "name": "chflags",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "flags": "int"
        }
    },
    35: {
        "name": "fchflags",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "flags": "int"
        }
    },
    36: {
        "name": "sync",
        "retval_type": "int"
    },
    37: {
        "name": "kill",
        "retval_type": "int",
        "args": {
            "pid": "int",
            "signum": "int",
            "posix": "int"
        }
    },
    38: {
        "name": "stat"
    },
    39: {
        "name": "getppid",
        "retval_type": "int",
        afterCall: handleGetppidAfter
    },
    40: {
        "name": "lstat"
    },
    41: {
        "name": "dup",
        "retval_type": "int",
        "args": {
            "fd": "uint"
        }
    },
    42: {
        "name": "pipe",
        "retval_type": "int"
    },
    43: {
        "name": "getegid",
        "retval_type": "int"
    },
    44: {
        "name": "profil",
        "retval_type": "int",
        "args": {
            "bufbase": "void*",
            "bufsize": "size_t",
            "pcoffset": "ulong",
            "pcscale": "uint"
        }
    },
    45: {
        "name": "ktrace"
    },
    46: {
        "name": "sigaction",
        "retval_type": "int",
        "args": {
            "signum": "int",
            "nsa": "void*",
            "osa": "void*"
        }
    },
    47: {
        "name": "getgid",
        "retval_type": "int"
    },
    48: {
        "name": "sigprocmask",
        "retval_type": "int",
        "args": {
            "how": "int",
            "mask": "void*",
            "omask": "void*"
        }
    },
    49: {
        "name": "getlogin",
        "retval_type": "int",
        "args": {
            "namebuf": "char*",
            "namelen": "uint"
        }
    },
    50: {
        "name": "setlogin",
        "retval_type": "int",
        "args": {
            "namebuf": "char*"
        }
    },
    51: {
        "name": "acct",
        "retval_type": "int",
        "args": {
            "path": "char*"
        }
    },
    52: {
        "name": "sigpending",
        "retval_type": "int",
        "args": {
            "osv": "void*"
        }
    },
    53: {
        "name": "sigaltstack",
        "retval_type": "int",
        "args": {
            "nss": "void*",
            "oss": "void*"
        }
    },
    54: {
        "name": "ioctl",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "com": "ulong",
            "data": "void*"
        }
    },
    55: {
        "name": "reboot",
        "retval_type": "int",
        "args": {
            "opt": "int",
            "command": "char*"
        }
    },
    56: {
        "name": "revoke",
        "retval_type": "int",
        "args": {
            "path": "char*"
        }
    },
    57: {
        "name": "symlink",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "link": "char*"
        }
    },
    58: {
        "name": "readlink",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "buf": "char*",
            "count": "int"
        }
    },
    59: {
        "name": "execve",
        "retval_type": "int",
        "args": {
            "fname": "char*",
            "argp": "char**",
            "envp": "char**"
        }
    },
    60: {
        "name": "umask",
        "retval_type": "int",
        "args": {
            "newmask": "int"
        }
    },
    61: {
        "name": "chroot",
        "retval_type": "int",
        "args": {
            "path": "char*"
        }
    },
    62: {
        "name": "fstat",
        "retval_type": "int",
        "args": {
            "fildes": "int",
            "buf": "void*"
        }
    },
    63: {
        "name": "invalid"
    },
    64: {
        "name": "getpagesize"
    },
    65: {
        "name": "msync",
        "retval_type": "int",
        "args": {
            "addr": "void*",
            "len": "size_t",
            "flags": "int"
        }
    },
    66: {
        "name": "vfork",
        "retval_type": "int"
    },
    67: {
        "name": "vread"
    },
    68: {
        "name": "vwrite"
    },
    69: {
        "name": "sbrk"
    },
    70: {
        "name": "sstk"
    },
    71: {
        "name": "mmap"
    },
    72: {
        "name": "vadvise"
    },
    73: {
        "name": "munmap",
        "retval_type": "int",
        "args": {
            "addr": "void*",
            "len": "size_t"
        }
    },
    74: {
        "name": "mprotect",
        "retval_type": "int",
        "args": {
            "addr": "void*",
            "len": "size_t",
            "prot": "int"
        }
    },
    75: {
        "name": "madvise",
        "retval_type": "int",
        "args": {
            "addr": "void*",
            "len": "size_t",
            "behav": "int"
        }
    },
    76: {
        "name": "vhangup"
    },
    77: {
        "name": "vlimit"
    },
    78: {
        "name": "mincore",
        "retval_type": "int",
        "args": {
            "addr": "void*",
            "len": "size_t",
            "vec": "void*"
        }
    },
    79: {
        "name": "getgroups",
        "retval_type": "int",
        "args": {
            "gidsetsize": "uint",
            "gidset": "void*"
        }
    },
    80: {
        "name": "setgroups",
        "retval_type": "int",
        "args": {
            "gidsetsize": "uint",
            "gidset": "void*"
        }
    },
    81: {
        "name": "getpgrp",
        "retval_type": "int"
    },
    82: {
        "name": "setpgid",
        "retval_type": "int",
        "args": {
            "pid": "int",
            "pgid": "int"
        }
    },
    83: {
        "name": "setitimer",
        "retval_type": "int",
        "args": {
            "which": "uint",
            "itv": "void*",
            "oitv": "void*"
        }
    },
    85: {
        "name": "swapon",
        "retval_type": "int"
    },
    86: {
        "name": "getitimer",
        "retval_type": "int",
        "args": {
            "which": "uint",
            "itv": "void*"
        }
    },
    89: {
        "name": "getdtablesize",
        "retval_type": "int"
    },
    90: {
        "name": "dup2",
        "retval_type": "int",
        "args": {
            "from": "uint",
            "to": "uint"
        }
    },
    91: {
        "name": "getdopt"
    },
    92: {
        "name": "fcntl",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "cmd": "int",
            "arg": "long"
        }
    },
    93: {
        "name": "select",
        "retval_type": "int",
        "args": {
            "nd": "int",
            "in": "uint*",
            "ou": "uint*",
            "ex": "uint*",
            "tv": "void*"
        }
    },
    95: {
        "name": "fsync",
        "retval_type": "int",
        "args": {
            "fd": "int"
        }
    },
    96: {
        "name": "setpriority",
        "retval_type": "int",
        "args": {
            "which": "int",
            "who": "id_t",
            "prio": "int"
        }
    },
    97: {
        "name": "socket",
        "retval_type": "int",
        "args": {
            "domain": "int",
            "type": "int",
            "protocol": "int"
        }
    },
    98: {
        "name": "connect",
        "retval_type": "int",
        "args": {
            "s": "int",
            "name": "char*",
            "namelen": "int"
        }
    },
    99: {
        "name": "accept"
    },
    100: {
        "name": "getpriority",
        "retval_type": "int",
        "args": {
            "which": "int",
            "who": "int"
        }
    },
    104: {
        "name": "bind",
        "retval_type": "int",
        "args": {
            "s": "int",
            "name": "char*",
            "namelen": "int"
        }
    },
    105: {
        "name": "setsockopt",
        "retval_type": "int",
        "args": {
            "s": "int",
            "level": "int",
            "name": "int",
            "val": "void*",
            "valsize": "size_t"
        }
    },
    106: {
        "name": "listen",
        "retval_type": "int",
        "args": {
            "s": "int",
            "backlog": "int"
        }
    },
    111: {
        "name": "sigsuspend",
        "retval_type": "int",
        "args": {
            "sigmask": "void*"
        }
    },
    116: {
        "name": "gettimeofday",
        "retval_type": "int",
        "args": {
            "tp": "void*",
            "tzp": "void*"
        }
    },
    117: {
        "name": "getrusage",
        "retval_type": "int",
        "args": {
            "class": "int",
            "r": "void*"
        }
    },
    118: {
        "name": "getsockopt",
        "retval_type": "int",
        "args": {
            "s": "int",
            "level": "int",
            "name": "int",
            "val": "void*",
            "valsize": "void*"
        }
    },
    120: {
        "name": "readv",
        "retval_type": "int",
        "args": {
            "filedes": "int",
            "iov": "void*",
            "iovcnt": "int"
        }
    },
    121: {
        "name": "writev",
        "retval_type": "int",
        "args": {
            "filedes": "int",
            "iov": "void*",
            "iovcnt": "int"
        }
    },
    122: {
        "name": "settimeofday",
        "retval_type": "int",
        "args": {
            "tp": "void*",
            "tzp": "void*"
        }
    },
    123: {
        "name": "fchown",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "uid": "int",
            "gid": "int"
        }
    },
    124: {
        "name": "fchmod",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "mode": "int"
        }
    },
    126: {
        "name": "setreuid",
        "retval_type": "int",
        "args": {
            "ruid": "int",
            "euid": "int"
        }
    },
    127: {
        "name": "setregid",
        "retval_type": "int",
        "args": {
            "rgid": "int",
            "egid": "int"
        }
    },
    128: {
        "name": "rename",
        "retval_type": "int",
        "args": {
            "from": "char*",
            "to": "char*"
        }
    },
    131: {
        "name": "flock",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "how": "int"
        }
    },
    132: {
        "name": "mkfifo",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "mode": "int"
        }
    },
    133: {
        "name": "sendto",
        "retval_type": "int",
        "args": {
            "s": "int",
            "buf": "void*",
            "len": "size_t",
            "to": "void*",
            "tolen": "size_t"
        }
    },
    134: {
        "name": "shutdown",
        "retval_type": "int",
        "args": {
            "s": "int",
            "how": "int"
        }
    },
    135: {
        "name": "socketpair",
        "retval_type": "int",
        "args": {
            "domain": "int",
            "type": "int",
            "protocol": "int",
            "rsv": "void*"
        }
    },
    136: {
        "name": "mkdir",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "mode": "int"
        }
    },
    137: {
        "name": "rmdir",
        "retval_type": "int",
        "args": {
            "path": "char*"
        }
    },
    138: {
        "name": "utimes",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "tptr": "void*"
        }
    },
    139: {
        "name": "futimes",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "tptr": "void*"
        }
    },
    140: {
        "name": "adjtime",
        "retval_type": "int",
        "args": {
            "delta": "void*",
            "olddelta": "void*"
        }
    },
    142: {
        "name": "gethostuuid",
        "retval_type": "int",
        "args": {
            "uuid_buf": "char*",
            "timeoutp": "void*"
        }
    },
    147: {
        "name": "setsid",
        "retval_type": "int"
    },
    151: {
        "name": "getpgid",
        "retval_type": "int",
        "args": {
            "pid": "int"
        }
    },
    152: {
        "name": "setprivexec",
        "retval_type": "int",
        "args": {
            "flag": "int"
        }
    },
    153: {
        "name": "pread",
        "retval_type": "size_t",
        "args": {
            "fd": "int",
            "buf": "void*",
            "nbyte": "size_t",
            "offset": "int"
        }
    },
    154: {
        "name": "pwrite",
        "retval_type": "size_t",
        "args": {
            "fd": "int",
            "buf": "void*",
            "nbyte": "usize_t",
            "offset": "int"
        }
    },
    155: {
        "name": "nfssvc",
        "retval_type": "int",
        "args": {
            "flag": "int",
            "argp": "void*"
        }
    },
    157: {
        "name": "statfs",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "buf": "void*"
        }
    },
    158: {
        "name": "fstatfs",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "buf": "void*"
        }
    },
    159: {
        "name": "unmount",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "flags": "int"
        }
    },
    161: {
        "name": "getfh",
        "retval_type": "int",
        "args": {
            "fname": "char*",
            "fhp": "void*"
        }
    },
    165: {
        "name": "quotactl",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "cmd": "int",
            "uid": "int",
            "arg": "void*"
        }
    },
    167: {
        "name": "mount",
        "retval_type": "void",
        "args": {
            "type": "char*",
            "path": "char*",
            "flags": "int",
            "data": "void*"
        }
    },
    169: {
        "name": "csops",
        "retval_type": "void",
        "args": {
            "pid": "int",
            "ops": "uint",
            "useraddr": "void*",
            "usersize": "size_t"
        }
    },
    170: {
        "name": "csops_audittoken"
    },
    173: {
        "name": "waitid",
        "retval_type": "int",
        "args": {
            "idtype": "void*",
            "id": "int",
            "infop": "siginfo_t",
            "options": "int"
        }
    },
    180: {
        "name": "kdebug_trace",
        "retval_type": "int",
        "args": {
            "code": "int",
            "arg1": "int",
            "arg2": "int",
            "arg3": "int",
            "arg4": "int",
            "arg5": "int"
        }
    },
    181: {
        "name": "setgid",
        "retval_type": "int",
        "args": {
            "egid": "int"
        }
    },
    182: {
        "name": "setegid",
        "retval_type": "int",
        "args": {
            "egid": "int"
        }
    },
    183: {
        "name": "seteuid",
        "retval_type": "int",
        "args": {
            "euid": "int"
        }
    },
    184: {
        "name": "sigreturn",
        "retval_type": "int",
        "args": {
            "uctx": "void*",
            "infostyle": "int"
        }
    },
    185: {
        "name": "chud",
        "retval_type": "int",
        "args": {
            "code": "ulong",
            "arg1": "ulong",
            "arg2": "ulong",
            "arg3": "ulong",
            "arg4": "ulong",
            "arg5": "ulong"
        }
    },
    187: {
        "name": "fdatasync",
        "retval_type": "int",
        "args": {
            "fd": "int"
        }
    },
    188: {
        "name": "stat",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "sb": "void*"
        }
    },
    189: {
        "name": "fstat",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "sb": "void*"
        }
    },
    190: {
        "name": "lstat",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "sb": "void*"
        }
    },
    191: {
        "name": "pathconf",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "name": "int"
        }
    },
    192: {
        "name": "fpathconf",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "name": "int"
        }
    },
    194: {
        "name": "getrlimit",
        "retval_type": "int",
        "args": {
            "which": "uint",
            "rlp": "void*"
        }
    },
    195: {
        "name": "setrlimit",
        "retval_type": "int",
        "args": {
            "which": "uint",
            "rlp": "void*"
        }
    },
    196: {
        "name": "getdirentries",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "buf": "char*",
            "count": "uint",
            "basep": "void*"
        }
    },
    197: {
        "name": "mmap",
        "retval_type": "void",
        "args": {
            "addr": "void*",
            "len": "size_t",
            "prot": "int",
            "flags": "int",
            "fd": "int",
            "pos": "int"
        }
    },
    199: {
        "name": "lseek",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "offset": "int",
            "whence": "int"
        }
    },
    200: {
        "name": "truncate",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "length": "int"
        }
    },
    201: {
        "name": "ftruncate",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "length": "int"
        }
    },
    202: {
        "name": "__sysctl",
        "retval_type": "int",
        "args": {
            "name": "void*",
            "namelen": "uint",
            "old": "void*",
            "oldlenp": "void*",
            "new": "void*",
            "newlen": "size_t"
        }
    },
    203: {
        "name": "mlock",
        "retval_type": "int",
        "args": {
            "addr": "void*",
            "len": "size_t"
        }
    },
    204: {
        "name": "munlock",
        "retval_type": "int",
        "args": {
            "addr": "void*",
            "len": "size_t"
        }
    },
    205: {
        "name": "undelete",
        "retval_type": "int",
        "args": {
            "path": "char*"
        }
    },
    216: {
        "name": "mkcomplex",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "mode": "int",
            "type": "ulong"
        }
    },
    220: {
        "name": "getattrlist",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "alist": "void*",
            "attributeBuffer": "void*",
            "bufferSize": "size_t",
            "options": "ulong"
        }
    },
    221: {
        "name": "setattrlist",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "alist": "void*",
            "attributeBuffer": "void*",
            "bufferSize": "size_t",
            "options": "ulong"
        }
    },
    222: {
        "name": "getdirentriesattr",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "alist": "void*",
            "buffer": "void*",
            "buffersize": "size_t",
            "count": "void*",
            "basep": "void*",
            "newstate": "void*",
            "options": "ulong"
        }
    },
    223: {
        "name": "exchangedata",
        "retval_type": "int",
        "args": {
            "path1": "char*",
            "path2": "char*",
            "options": "ulong"
        }
    },
    225: {
        "name": "searchfs",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "sblock": "void*",
            "nummatches": "uint*",
            "scriptcode": "uint",
            "options": "uint",
            "state": "void*"
        }
    },
    226: {
        "name": "delete",
        "retval_type": "int",
        "args": {
            "path": "char*"
        }
    },
    227: {
        "name": "copyfile",
        "retval_type": "int",
        "args": {
            "from": "char*",
            "to": "char*",
            "mode": "int",
            "flags": "int"
        }
    },
    228: {
        "name": "fgetattrlist",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "alist": "attrlist",
            "attributeBuffer": "void*",
            "bufferSize": "size_t",
            "options": "ulong"
        }
    },
    229: {
        "name": "fsetattrlist",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "alist": "attrlist",
            "attributeBuffer": "void*",
            "bufferSize": "size_t",
            "options": "ulong"
        }
    },
    230: {
        "name": "poll",
        "retval_type": "int",
        "args": {
            "fds": "pollfd",
            "nfds": "uint",
            "timeout": "int"
        }
    },
    231: {
        "name": "watchevent",
        "retval_type": "int",
        "args": {
            "u_req": "eventreq",
            "u_eventmask": "int"
        }
    },
    232: {
        "name": "waitevent",
        "retval_type": "int",
        "args": {
            "u_req": "eventreq",
            "tv": "timeval"
        }
    },
    233: {
        "name": "modwatch",
        "retval_type": "int",
        "args": {
            "u_req": "eventreq",
            "u_eventmask": "int"
        }
    },
    234: {
        "name": "getxattr",
        "retval_type": "size_t",
        "args": {
            "path": "char*",
            "attrname": "void*",
            "value": "void*",
            "size": "size_t",
            "position": "uint",
            "options": "int"
        }
    },
    235: {
        "name": "fgetxattr",
        "retval_type": "size_t",
        "args": {
            "fd": "int",
            "attrname": "void*",
            "value": "void*",
            "size": "size_t",
            "position": "uint",
            "options": "int"
        }
    },
    236: {
        "name": "setxattr",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "attrname": "void*",
            "value": "void*",
            "size": "size_t",
            "position": "uint",
            "options": "int"
        }
    },
    237: {
        "name": "fsetxattr",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "attrname": "void*",
            "value": "void*",
            "size": "size_t",
            "position": "uint",
            "options": "int"
        }
    },
    238: {
        "name": "removexattr",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "attrname": "void*",
            "options": "int"
        }
    },
    239: {
        "name": "fremovexattr",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "ttrname": "void* a",
            "options": "int"
        }
    },
    240: {
        "name": "listxattr",
        "retval_type": "size_t",
        "args": {
            "path": "char*",
            "namebuf": "void*",
            "bufsize": "size_t",
            "options": "int"
        }
    },
    241: {
        "name": "flistxattr",
        "retval_type": "size_t",
        "args": {
            "fd": "int",
            "namebuf": "char*",
            "size": "size_t",
            "options": "int"
        }
    },
    242: {
        "name": "fsctl",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "cmd": "ulong",
            "data": "caddr_t",
            "options": "uint"
        }
    },
    243: {
        "name": "initgroups",
        "retval_type": "int",
        "args": {
            "gidsetsize": "uint",
            "gidset": "int*",
            "gmuid": "int"
        }
    },
    244: {
        "name": "posix_spawn",
        "retval_type": "int",
        "args": {
            "pid": "int*",
            "path": "char*",
            "adesc": "_posix_spawn_args_desc",
            "argv": "char*",
            "envp": "char*"
        }
    },
    245: {
        "name": "ffsctl",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "cmd": "ulong",
            "data": "caddr_t",
            "options": "uint"
        }
    },
    250: {
        "name": "minherit",
        "retval_type": "int",
        "args": {
            "addr": "void*",
            "len": "size_t",
            "inherit": "int"
        }
    },
    266: {
        "name": "shm_open",
        "retval_type": "int",
        "args": {
            "name": "char*",
            "oflag": "int",
            //"...": null
        }
    },
    267: {
        "name": "shm_unlink",
        "retval_type": "int",
        "args": {
            "name": "char*"
        }
    },
    268: {
        "name": "sem_open"
    },
    269: {
        "name": "sem_close",
        "retval_type": "int",
        "args": {
            "sem": "sem_t"
        }
    },
    270: {
        "name": "sem_unlink",
        "retval_type": "int",
        "args": {
            "name": "char*"
        }
    },
    271: {
        "name": "sem_wait",
        "retval_type": "int",
        "args": {
            "sem": "sem_t"
        }
    },
    272: {
        "name": "sem_trywait",
        "retval_type": "int",
        "args": {
            "sem": "sem_t"
        }
    },
    273: {
        "name": "sem_post",
        "retval_type": "int",
        "args": {
            "sem": "sem_t"
        }
    },
    274: {
        "name": "sem_getvalue",
        "retval_type": "int",
        "args": {
            "sem": "sem_t",
            "sval": "int*"
        }
    },
    275: {
        "name": "sem_init",
        "retval_type": "int",
        "args": {
            "sem": "sem_t",
            "phsared": "int",
            "value": "uint"
        }
    },
    276: {
        "name": "sem_destroy",
        "retval_type": "int",
        "args": {
            "sem": "sem_t"
        }
    },
    277: {
        "name": "open_extended",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "flags": "int",
            "uid": "int",
            "gid": "int",
            "mode": "int",
            "xsecurity": "void*"
        }
    },
    278: {
        "name": "umask_extended",
        "retval_type": "int",
        "args": {
            "newmask": "int",
            "xsecurity": "void*"
        }
    },
    279: {
        "name": "stat_extended",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "ub": "void*",
            "xsecurity": "void*",
            "xsecurity_size": "void*"
        }
    },
    280: {
        "name": "lstat_extended",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "ub": "void*",
            "xsecurity": "void*",
            "xsecurity_size": "void*"
        }
    },
    281: {
        "name": "fstat_extended",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "ub": "void*",
            "xsecurity": "void*",
            "xsecurity_size": "void*"
        }
    },
    282: {
        "name": "chmod_extended",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "uid": "int",
            "gid": "int",
            "mode": "int",
            "xsecurity": "void*"
        }
    },
    283: {
        "name": "fchmod_extended",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "uid": "int",
            "gid": "int",
            "mode": "int",
            "xsecurity": "void*"
        }
    },
    284: {
        "name": "access_extended",
        "retval_type": "int",
        "args": {
            "entries": "void*",
            "size": "size_t",
            "results": "void*",
            "uid": "int"
        }
    },
    285: {
        "name": "settid",
        "retval_type": "int",
        "args": {
            "uid": "int",
            "gid": "int"
        }
    },
    286: {
        "name": "gettid",
        "retval_type": "int",
        "args": {
            "uidp": "int*",
            "gidp": "int*"
        }
    },
    287: {
        "name": "setsgroups",
        "retval_type": "int",
        "args": {
            "setlen": "int",
            "guidset": "void*"
        }
    },
    288: {
        "name": "getsgroups",
        "retval_type": "int",
        "args": {
            "setlen": "void*",
            "guidset": "void*"
        }
    },
    289: {
        "name": "setwgroups",
        "retval_type": "int",
        "args": {
            "setlen": "int",
            "guidset": "uint"
        }
    },
    290: {
        "name": "getwgroups"
    },
    291: {
        "name": "mkfifo_extended",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "uid": "int",
            "gid": "int",
            "mode": "int",
            "xsecurity": "void*"
        }
    },
    292: {
        "name": "mkdir_extended",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "uid": "int",
            "gid": "int",
            "mode": "int",
            "xsecurity": "void*"
        }
    },
    294: {
        "name": "shared_region_check_np",
        "retval_type": "int",
        "args": {
            "startaddress": "ulong*"
        }
    },
    296: {
        "name": "vm_pressure_monitor"
    },
    297: {
        "name": "psynch_rw_longrdlock",
        "retval_type": "uint",
        "args": {
            "rwlock": "void*",
            "lgenval": "uint",
            "ugenval": "uint",
            "rw_wc": "uint",
            "flags": "int"
        }
    },
    298: {
        "name": "psynch_rw_yieldwrlock",
        "retval_type": "uint",
        "args": {
            "rwlock": "void*",
            "lgenval": "uint",
            "ugenval": "uint",
            "rw_wc": "uint",
            "flags": "int"
        }
    },
    299: {
        "name": "psynch_rw_downgrade",
        "retval_type": "int",
        "args": {
            "rwlock": "void*",
            "lgenval": "uint",
            "ugenval": "uint",
            "rw_wc": "uint",
            "flags": "int"
        }
    },
    300: {
        "name": "psynch_rw_upgrade",
        "retval_type": "uint",
        "args": {
            "rwlock": "void*",
            "lgenval": "uint",
            "ugenval": "uint",
            "rw_wc": "uint",
            "flags": "int"
        }
    },
    301: {
        "name": "psynch_mutexwait",
        "retval_type": "uint",
        "args": {
            "mutex": "void*",
            "mgen": "uint",
            "ugen": "uint",
            "tid": "ulong",
            "flags": "uint"
        }
    },
    302: {
        "name": "psynch_mutexdrop",
        "retval_type": "uint",
        "args": {
            "mutex": "void*",
            "mgen": "uint",
            "ugen": "uint",
            "tid": "ulong",
            "flags": "uint"
        }
    },
    303: {
        "name": "psynch_cvbroad",
        "retval_type": "uint",
        "args": {
            "cv": "void*",
            "cvlsgen": "ulong",
            "cvudgen": "ulong",
            "flags": "uint",
            "mutex": "void*",
            "mugen": "ulong",
            "tid": "ulong"
        }
    },
    304: {
        "name": "psynch_cvsignal",
        "retval_type": "uint",
        "args": {
            "cv": "void*",
            "cvlsgen": "ulong",
            "cvugen": "uint",
            "thread_port": "int",
            "mutex": "void*",
            "mugen": "ulong",
            "tid": "ulong",
            "flags": "uint"
        }
    },
    305: {
        "name": "psynch_cvwait",
        "retval_type": "uint",
        "args": {
            "cv": "void*",
            "cvlsgen": "ulong",
            "cvugen": "uint",
            "mutex": "void*",
            "mugen": "ulong",
            "flags": "uint",
            "sec": "int64_t",
            "nsec": "uint"
        }
    },
    306: {
        "name": "psynch_rw_rdlock",
        "retval_type": "uint",
        "args": {
            "rwlock": "void*",
            "lgenval": "uint",
            "ugenval": "uint",
            "rw_wc": "uint",
            "flags": "int"
        }
    },
    307: {
        "name": "psynch_rw_wrlock",
        "retval_type": "uint",
        "args": {
            "rwlock": "void*",
            "lgenval": "uint",
            "ugenval": "uint",
            "rw_wc": "uint",
            "flags": "int"
        }
    },
    308: {
        "name": "psynch_rw_unlock",
        "retval_type": "uint",
        "args": {
            "rwlock": "void*",
            "lgenval": "uint",
            "ugenval": "uint",
            "rw_wc": "uint",
            "flags": "int"
        }
    },
    309: {
        "name": "psynch_rw_unlock2"
    },
    310: {
        "name": "getsid",
        "retval_type": "int",
        "args": {
            "pid": "int"
        }
    },
    311: {
        "name": "settid_with_pid",
        "retval_type": "int",
        "args": {
            "pid": "int",
            "assume": "int"
        }
    },
    312: {
        "name": "psynch_cvclrprepost"
    },
    313: {
        "name": "aio_fsync",
        "retval_type": "int",
        "args": {
            "op": "int",
            "aiocbp": "void*"
        }
    },
    314: {
        "name": "aio_return",
        "retval_type": "ssize_t",
        "args": {
            "aiocbp": "aiocb"
        }
    },
    315: {
        "name": "aio_suspend",
        "retval_type": "int",
        "args": {
            "aiocblist": "void*",
            "nent": "int",
            "timeoutp": "void*"
        }
    },
    316: {
        "name": "aio_cancel",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "aiocbp": "aiocb"
        }
    },
    317: {
        "name": "aio_error",
        "retval_type": "int",
        "args": {
            "aiocbp": "aiocb *"
        }
    },
    318: {
        "name": "aio_read",
        "retval_type": "int",
        "args": {
            "aiocbp": "aiocb *"
        }
    },
    319: {
        "name": "aio_write",
        "retval_type": "int",
        "args": {
            "aiocbp": "void*"
        }
    },
    320: {
        "name": "lio_listio"
    },
    322: {
        "name": "iopolicysys",
        "retval_type": "int",
        "args": {
            "cmd": "int",
            "arg": "void*"
        }
    },
    323: {
        "name": "process_policy",
        "retval_type": "int",
        "args": {
            "scope": "int",
            "action": "int",
            "policy": "int",
            "policy_subtype": "int",
            "attrp": "void*",
            "target_pid": "int",
            "target_threadid": "ulong"
        }
    },
    324: {
        "name": "mlockall",
        "retval_type": "int",
        "args": {
            "how": "int"
        }
    },
    325: {
        "name": "munlockall",
        "retval_type": "int",
        "args": {
            "how": "int"
        }
    },
    327: {
        "name": "issetugid",
        "retval_type": "int"
    },
    328: {
        "name": "__pthread_kill",
        "retval_type": "int",
        "args": {
            "thread_port": "int",
            "sig": "int"
        }
    },
    329: {
        "name": "__pthread_sigmask",
        "retval_type": "int",
        "args": {
            "how": "int",
            "set": "void*",
            "oset": "void*"
        }
    },
    330: {
        "name": "__sigwait",
        "retval_type": "int",
        "args": {
            "set": "sigset_t",
            "sig": "void*"
        }
    },
    331: {
        "name": "__disable_threadsignal",
        "retval_type": "int",
        "args": {
            "value": "int"
        }
    },
    332: {
        "name": "__pthread_markcancel",
        "retval_type": "int",
        "args": {
            "thread_port": "int"
        }
    },
    333: {
        "name": "__pthread_canceled",
        "retval_type": "int",
        "args": {
            "action": "int"
        }
    },
    334: {
        "name": "__semwait_signal",
        "retval_type": "int",
        "args": {
            "cond_sem": "int",
            "mutex_sem": "int",
            "timeout": "int",
            "relative": "int",
            "tv_sec": "int64_t",
            "tv_nsec": "int32_t"
        }
    },
    336: {
        "name": "proc_info",
        "retval_type": "int",
        "args": {
            "callnum": "int",
            "pid": "int",
            "flavor": "uint",
            "arg": "long",
            "buffer": "void*",
            "buffersize": "int"
        }
    },
    338: {
        "name": "stat64",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "buf": "void*"
        }
    },
    339: {
        "name": "fstat64",
        "retval_type": "int",
        "args": {
            "fildes": "int",
            "buf": "void*"
        }
    },
    340: {
        "name": "lstat64",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "buf": "void*"
        }
    },
    341: {
        "name": "stat64_extended"
    },
    342: {
        "name": "lstat64_extended"
    },
    343: {
        "name": "fstat64_extended"
    },
    344: {
        "name": "getdirentries64",
        "retval_type": "size_t",
        "args": {
            "fd": "int",
            "buf": "void*",
            "bufsize": "user_size_t",
            "position": "int*"
        }
    },
    345: {
        "name": "statfs64",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "buf": "void*"
        }
    },
    346: {
        "name": "fstatfs64",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "buf": "void*"
        }
    },
    347: {
        "name": "getfsstat64",
        "retval_type": "int",
        "args": {
            "buf": "char*",
            "bufsize": "int",
            "flags": "int"
        }
    },
    348: {
        "name": "__pthread_chdir",
        "retval_type": "int",
        "args": {
            "path": "char*"
        }
    },
    349: {
        "name": "__pthread_fchdir",
        "retval_type": "int",
        "args": {
            "fd": "int"
        }
    },
    350: {
        "name": "audit",
        "retval_type": "int",
        "args": {
            "record": "void*",
            "length": "int"
        }
    },
    351: {
        "name": "auditon",
        "retval_type": "int",
        "args": {
            "cmd": "int",
            "data": "void*",
            "length": "int"
        }
    },
    353: {
        "name": "getauid",
        "retval_type": "int",
        "args": {
            "auid": "au_id_t"
        }
    },
    354: {
        "name": "setauid",
        "retval_type": "int",
        "args": {
            "auid": "au_id_t"
        }
    },
    357: {
        "name": "getaudit_addr",
        "retval_type": "int",
        "args": {
            "ai_ad": "auditinfo_addr",
            "length": "int"
        }
    },
    358: {
        "name": "setaudit_addr",
        "retval_type": "int",
        "args": {
            "ai_ad": "auditinfo_addr",
            "length": "int"
        }
    },
    359: {
        "name": "auditctl",
        "retval_type": "int",
        "args": {
            "path": "char*"
        }
    },
    360: {
        "name": "bsdthread_create",
        "retval_type": "void*",
        "args": {
            "func": "void*",
            "func_arg": "void*",
            "stack": "void*",
            "pthread": "void*",
            "flags": "uint"
        }
    },
    361: {
        "name": "bsdthread_terminate",
        "retval_type": "int",
        "args": {
            "stackaddr": "void*",
            "freesize": "size_t",
            "port": "uint",
            "sem": "uint"
        }
    },
    362: {
        "name": "kqueue",
        "retval_type": "int"
    },
    363: {
        "name": "kevent",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "chglist": "kevent",
            "nchanges": "int",
            "eventlist": "kevent",
            "nevents": "int",
            "timeout": "timespec"
        }
    },
    364: {
        "name": "lchown",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "owner": "int",
            "group": "int"
        }
    },
    365: {
        "name": "stack_snapshot",
        "retval_type": "int",
        "args": {
            "pid": "int",
            "tracebuf": "void*",
            "tracebuf_size": "uint",
            "flags": "uint",
            "dispatch_offset": "uint"
        }
    },
    366: {
        "name": "bsdthread_register",
        "retval_type": "int",
        "args": {
            "threadstart": "void*",
            "wqthread": "void*",
            "pthsize": "int",
            "dummy_value": "void*",
            "targetconc_ptr": "void*",
            "dispatchqueue_offset": "ulong"
        }
    },
    367: {
        "name": "workq_open",
        "retval_type": "int"
    },
    368: {
        "name": "workq_kernreturn",
        "retval_type": "int",
        "args": {
            "options": "int",
            "item": "void*",
            "affinity": "int",
            "prio": "int"
        }
    },
    369: {
        "name": "kevent64",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "changelist": "kevent64_s",
            "nchanges": "int",
            "eventlist": "kevent64_s",
            "nevents": "int",
            "flags": "unsigned int",
            "timeout": "timespec"
        }
    },
    370: {
        "name": "__old_semwait_signal",
        "retval_type": "int",
        "args": {
            "cond_sem": "int",
            "mutex_sem": "int",
            "timeout": "int",
            "relative": "int",
            "ts": "timespec"
        }
    },
    371: {
        "name": "__old_semwait_signal_nocancel",
        "retval_type": "int",
        "args": {
            "cond_sem": "int",
            "mutex_sem": "int",
            "timeout": "int",
            "relative": "int",
            "ts": "timespec"
        }
    },
    372: {
        "name": "thread_selfid",
        "retval_type": "ulong"
    },
    373: {
        "name": "ledger"
    },
    374: {
        "name": "kevent_qos"
    },
    375: {
        "name": "kevent_id"
    },
    394: {
        "name": "setlcid",
        "retval_type": "int",
        "args": {
            "pid": "int",
            "lcid": "int"
        }
    },
    395: {
        "name": "getlcid",
        "retval_type": "int",
        "args": {
            "pid": "int"
        }
    },
    396: {
        "name": "read_nocancel",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "cbuf": "void*",
            "nbyte": "user_size_t"
        }
    },
    397: {
        "name": "write_nocancel",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "cbuf": "void*",
            "nbyte": "user_size_t"
        }
    },
    398: {
        "name": "open_nocancel",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "flags": "int",
            "mode": "int"
        }
    },
    399: {
        "name": "close_nocancel",
        "retval_type": "int",
        "args": {
            "fd": "int"
        }
    },
    400: {
        "name": "wait4_nocancel",
        "retval_type": "int",
        "args": {
            "pid": "int",
            "status": "void*",
            "options": "int",
            "rusage": "void*"
        }
    },
    401: {
        "name": "recvmsg_nocancel",
        "retval_type": "int",
        "args": {
            "s": "int",
            "msg": "msghdr",
            "flags": "int"
        }
    },
    402: {
        "name": "sendmsg_nocancel",
        "retval_type": "int",
        "args": {
            "s": "int",
            "msg": "caddr_t",
            "flags": "int"
        }
    },
    403: {
        "name": "recvfrom_nocancel",
        "retval_type": "int",
        "args": {
            "s": "int",
            "buf": "void*",
            "len": "size_t",
            "flags": "int",
            "from": "sockaddr",
            "fromlenaddr": "int*"
        }
    },
    404: {
        "name": "accept_nocancel",
        "retval_type": "int",
        "args": {
            "s": "int",
            "name": "caddr_t",
            "anamelen": "int*"
        }
    },
    405: {
        "name": "msync_nocancel",
        "retval_type": "int",
        "args": {
            "addr": "caddr_t",
            "len": "size_t",
            "flags": "int"
        }
    },
    406: {
        "name": "fcntl_nocancel",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "cmd": "int",
            "arg": "long"
        }
    },
    407: {
        "name": "select_nocancel",
        "retval_type": "int",
        "args": {
            "nd": "int",
            "in": "uint*",
            "ou": "uint*",
            "ex": "uint*",
            "tv": "timeval"
        }
    },
    408: {
        "name": "fsync_nocancel",
        "retval_type": "int",
        "args": {
            "fd": "int"
        }
    },
    409: {
        "name": "connect_nocancel",
        "retval_type": "int",
        "args": {
            "s": "int",
            "name": "caddr_t",
            "namelen": "int"
        }
    },
    410: {
        "name": "sigsuspend_nocancel",
        "retval_type": "int",
        "args": {
            "mask": "sigset_t"
        }
    },
    411: {
        "name": "readv_nocancel",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "iovp": "iovec",
            "iovcnt": "u_int"
        }
    },
    412: {
        "name": "writev_nocancel",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "iovp": "iovec",
            "iovcnt": "u_int"
        }
    },
    413: {
        "name": "sendto_nocancel",
        "retval_type": "int",
        "args": {
            "s": "int",
            "buf": "caddr_t",
            "len": "size_t",
            "flags": "int",
            "to": "caddr_t",
            "tolen": "int"
        }
    },
    414: {
        "name": "pread_nocancel",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "buf": "void*",
            "nbyte": "user_size_t",
            "offset": "int"
        }
    },
    415: {
        "name": "pwrite_nocancel",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "buf": "void*",
            "nbyte": "user_size_t",
            "offset": "int"
        }
    },
    416: {
        "name": "waitid_nocancel",
        "retval_type": "int",
        "args": {
            "idtype": "idtype_t",
            "id": "id_t",
            "infop": "siginfo_t",
            "options": "int"
        }
    },
    417: {
        "name": "poll_nocancel",
        "retval_type": "int",
        "args": {
            "fds": "pollfd",
            "nfds": "u_int",
            "timeout": "int"
        }
    },
    420: {
        "name": "sem_wait_nocancel",
        "retval_type": "int",
        "args": {
            "sem": "sem_t"
        }
    },
    421: {
        "name": "aio_suspend_nocancel",
        "retval_type": "int",
        "args": {
            "aiocblist": "void*",
            "nent": "int",
            "timeoutp": "void*"
        }
    },
    422: {
        "name": "__sigwait_nocancel",
        "retval_type": "int",
        "args": {
            "set": "void*",
            "sig": "void*"
        }
    },
    423: {
        "name": "__semwait_signal_nocancel",
        "retval_type": "int",
        "args": {
            "cond_sem": "int",
            "mutex_sem": "int",
            "timeout": "int",
            "relative": "int",
            "tv_sec": "int64_t",
            "tv_nsec": "int32_t"
        }
    },
    427: {
        "name": "fsgetpath",
        "retval_type": "int",
        "args": {
            "buf": "void*",
            "bufsize": "size_t",
            "fsid": "void*",
            "objid": "ulong"
        }
    },
    428: {
        "name": "audit_session_self",
        "retval_type": "mach_port_name_t"
    },
    429: {
        "name": "audit_session_join",
        "retval_type": "int",
        "args": {
            "port": "void*"
        }
    },
    430: {
        "name": "fileport_makeport",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "portnamep": "void*"
        }
    },
    431: {
        "name": "fileport_makefd",
        "retval_type": "int",
        "args": {
            "port": "void*"
        }
    },
    432: {
        "name": "audit_session_port",
        "retval_type": "int",
        "args": {
            "asid": "ibt",
            "portnamep": "void*"
        }
    },
    433: {
        "name": "pid_suspend",
        "retval_type": "int",
        "args": {
            "pid": "int"
        }
    },
    434: {
        "name": "pid_resume",
        "retval_type": "int",
        "args": {
            "pid": "int"
        }
    },
    435: {
        "name": "pid_hibernate",
        "retval_type": "int",
        "args": {
            "pid": "int"
        }
    },
    436: {
        "name": "pid_shutdown_sockets",
        "retval_type": "int",
        "args": {
            "pid": "int",
            "level": "int"
        }
    },
    438: {
        "name": "shared_region_map_and_slide_np",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "count": "uint",
            "mappings": "void*",
            "slide": "uint",
            "slide_start": "void*",
            "slide_size": "uint"
        }
    },
    439: {
        "name": "kas_info",
        "retval_type": "int",
        "args": {
            "selector": "int",
            "value": "void*",
            "size": "void*"
        }
    },
    440: {
        "name": "memorystatus_control",
        "retval_type": "int",
        "args": {
            "p": "void*",
            "args": "void*",
            "ret": "void*"
        }
    },
    441: {
        "name": "guarded_open_np",
        "retval_type": "int",
        "args": {
            "path": "char*",
            "guard": "void*",
            "guardflags": "uint",
            "flags": "int"
        }
    },
    442: {
        "name": "guarded_close_np"
    },
    443: {
        "name": "guarded_kqueue_np",
        "retval_type": "int",
        "args": {
            "guard": "void*",
            "guardflags": "uint"
        }
    },
    444: {
        "name": "change_fdguard_np",
        "retval_type": "int",
        "args": {
            "fd": "int",
            "guard": "void*",
            "guardflags": "uint",
            "nguard": "void*",
            "nguardflags": "uint",
            "fdflagsp": "void*"
        }
    },
    445: {
        "name": "usrctl",
        "retval_type": "int",
        "args": {
            "flags": "uint"
        }
    },
    446: {
        "name": "proc_rlimit_control",
        "retval_type": "int",
        "args": {
            "pid": "int",
            "flavor": "int",
            "arg": "void*"
        }
    },
    447: {
        "name": "connectx",
        "retval_type": "int",
        "args": {
            "socket": "int",
            "endpoints": "void*",
            "associd": "int",
            "flags": "uint",
            "iov": "void*",
            "iovcnt": "uint",
            "len": "void*",
            "connid": "void*"
        }
    },
    448: {
        "name": "disconnectx",
        "retval_type": "int",
        "args": {
            "s": "int",
            "aid": "int",
            "cid": "int"
        }
    },
    449: {
        "name": "peeloff",
        "retval_type": "int",
        "args": {
            "s": "int",
            "aid": "int"
        }
    },
    450: {
        "name": "socket_delegate",
        "retval_type": "int",
        "args": {
            "domain": "int",
            "type": "int",
            "protocol": "int",
            "epid": "int"
        }
    },
    451: {
        "name": "telemetry"
    },
    452: {
        "name": "proc_uuid_policy"
    },
    453: {
        "name": "memorystatus_get_level"
    },
    454: {
        "name": "system_override"
    },
    455: {
        "name": "vfs_purge"
    },
    456: {
        "name": "sfi_ctl"
    },
    457: {
        "name": "sfi_pidctl"
    },
    458: {
        "name": "coalition"
    },
    459: {
        "name": "coalition_info"
    },
    460: {
        "name": "necp_match_policy"
    },
    461: {
        "name": "getattrlistbulk"
    },
    462: {
        "name": "clonefileat"
    },
    463: {
        "name": "openat"
    },
    464: {
        "name": "openat_nocancel"
    },
    465: {
        "name": "renameat"
    },
    466: {
        "name": "faccessat"
    },
    467: {
        "name": "fchmodat"
    },
    468: {
        "name": "fchownat"
    },
    469: {
        "name": "fstatat"
    },
    470: {
        "name": "fstatat64"
    },
    471: {
        "name": "linkat"
    },
    472: {
        "name": "unlinkat"
    },
    473: {
        "name": "readlinkat"
    },
    474: {
        "name": "symlinkat"
    },
    475: {
        "name": "mkdirat"
    },
    476: {
        "name": "getattrlistat"
    },
    477: {
        "name": "proc_trace_log"
    },
    478: {
        "name": "bsdthread_ctl"
    },
    479: {
        "name": "openbyid_np"
    },
    480: {
        "name": "recvmsg_x"
    },
    481: {
        "name": "sendmsg_x"
    },
    482: {
        "name": "thread_selfusage"
    },
    483: {
        "name": "csrctl"
    },
    484: {
        "name": "guarded_open_dprotected_np"
    },
    485: {
        "name": "guarded_write_np"
    },
    486: {
        "name": "guarded_pwrite_np"
    },
    487: {
        "name": "guarded_writev_np"
    },
    488: {
        "name": "renameatx_np"
    },
    489: {
        "name": "mremap_encrypted"
    },
    490: {
        "name": "netagent_trigger"
    },
    491: {
        "name": "stack_snapshot_with_config"
    },
    492: {
        "name": "microstackshot"
    },
    493: {
        "name": "grab_pgo_data"
    },
    494: {
        "name": "persona"
    },
    499: {
        "name": "work_interval_ctl"
    },
    500: {
        "name": "getentropy"
    },
    501: {
        "name": "necp_open"
    },
    502: {
        "name": "necp_client_action"
    },
    515: {
        "name": "ulock_wait",
        "retval_type": "int",
        "args": {
            "p": "void*",
            "args": "void*",
            "retval": "void*"
        }
    },
    516: {
        "name": "ulock_wake",
        "retval_type": "int",
        "args": {
            "p": "void*",
            "args": "void*",
            "retval": "void*"
        }
    },
    517: {
        "name": "fclonefileat"
    },
    518: {
        "name": "fs_snapshot"
    },
    519: {
        "name": "enosys"
    },
    520: {
        "name": "terminate_with_payload"
    },
    521: {
        "name": "abort_with_payload"
    },
    522: {
        "name": "necp_session_open"
    },
    523: {
        "name": "necp_session_action"
    },
    524: {
        "name": "setattrlistat"
    },
    525: {
        "name": "net_qos_guideline"
    },
    526: {
        "name": "fmount"
    },
    527: {
        "name": "ntp_adjtime"
    },
    528: {
        "name": "ntp_gettime"
    },
    529: {
        "name": "os_fault_with_payload"
    },
    530: {
        "name": "kqueue_workloop_ctl"
    },
    531: {
        "name": "__mach_bridge_remote_time"
    },
    532: {
        "name": "coalition_ledger"
    },
    533: {
        "name": "log_data"
    },
    534: {
        "name": "memorystatus_available_memory"
    },
    535: {
        "name": "objc_bp_assist_cfg_np"
    },
    536: {
        "name": "shared_region_map_and_slide_2_np"
    },
    537: {
        "name": "pivot_root"
    },
    538: {
        "name": "task_inspect_for_pid"
    },
    539: {
        "name": "task_read_for_pid"
    },
    540: {
        "name": "preadv"
    },
    541: {
        "name": "pwritev"
    },
    542: {
        "name": "preadv_nocancel"
    },
    543: {
        "name": "pwritev_nocancel"
    },
    544: {
        "name": "ulock_wait2"
    },
    545: {
        "name": "proc_info_extended_id"
    },
    546: {
        "name": "tracker_action"
    },
    547: {
        "name": "debug_syscall_reject"
    },
    551: {
        "name": "freadlink"
    },
    552: {
        "name": "record_system_event"
    },
    553: {
        "name": "mkfifoat"
    },
    554: {
        "name": "mknodat"
    },
    555: {
        "name": "ungraftdmg"
    },
    556: {
        "name": "coalition_policy_set"
    },
    557: {
        "name": "coalition_policy_get"
    },
    558: {
        "name": "MAXSYSCALL"
    }
}