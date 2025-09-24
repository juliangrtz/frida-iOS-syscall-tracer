import { Config } from "./config";
import { log, logInstr } from "./logger";
import { handleSyscall } from "./syscalls";
import { bufToHexStr } from "./utils";

var threadsFollowed: { [id: ThreadId]: boolean } = {};

Process.setExceptionHandler(function (exp: ExceptionDetails) {
    console.log(`${exp.type} @ ${exp.address}`);

    let backtrace = Thread.backtrace(exp.context, Config.exceptionBacktracerType).map(DebugSymbol.fromAddress);
    for (let i in backtrace)
        console.log(backtrace[i]);

    return false;
});

function isThreadFollowed(threadId: ThreadId) {
    return threadsFollowed[threadId];
}

function followThread(threadId: ThreadId) {
    if (isThreadFollowed(threadId))
        return;

    threadsFollowed[threadId] = true;
    log("[+] Following thread " + threadId);

    Stalker.follow(threadId, {
        transform(iterator: StalkerArm64Iterator) {
            let instruction = iterator.next();

            do {
                if (instruction?.mnemonic === "svc") {
                    if (Config.traceInstructions) {
                        var buf = instruction.address.readByteArray(4); // svc is always 4 bytes
                        logInstr(`${instruction?.mnemonic} ${instruction?.opStr} ${buf != null ? `(hex: ${bufToHexStr(buf)})` : ""}`);
                    }
                    iterator.putCallout(handleSyscall);
                }
                iterator.keep();
            } while ((instruction = iterator.next()) !== null);
        },
    });
}

function unfollowThread(threadId: ThreadId) {
    if (!isThreadFollowed(threadId))
        return;

    delete threadsFollowed[threadId];
    log("[+] Unfollowing thread " + threadId);

    Stalker.unfollow(threadId);
    Stalker.garbageCollect();
}

function stalkThreads() {
    followThread(Process.getCurrentThreadId());
    const libSystem = Process.getModuleByName("libSystem.B.dylib");
    Interceptor.attach(libSystem.getExportByName("_pthread_start"), {
        onEnter(args) {
            if (isThreadFollowed(this.threadId)) {
                return;
            }
            const functionAddress = args[2];
            Interceptor.attach(functionAddress, {
                onEnter() {
                    followThread(this.threadId);
                },
                onLeave() {
                    unfollowThread(this.threadId);
                },
            });
        },
    });
}

stalkThreads();
