import { Config } from "./config";
import { log } from "./logger";
import { printSyscall } from "./syscalls";

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

    const cSource = `
    #include <gum/guminterceptor.h>
    #include <gum/gumdefs.h>
    #include <gum/gumstalker.h>
    #include <string.h>
    #include <stdio.h>

    extern void printSyscall(GumCpuContext * ctx, gpointer user_data);
    
    void transform(GumStalkerIterator *iterator, GumStalkerOutput *output, gpointer user_data) {
      cs_insn *instruction;
    
      while (gum_stalker_iterator_next(iterator, &instruction)) {
        if (strcmp(instruction->mnemonic, "svc") == 0) {
          gum_stalker_iterator_put_callout(iterator, printSyscall, user_data, NULL);
        }
    
        gum_stalker_iterator_keep(iterator);
      }
    }
    `;

    const cModule = new CModule(cSource, {
        printSyscall: new NativeCallback(printSyscall, 'void', ['pointer', 'pointer'])
    });

    Stalker.follow(threadId, cModule.transform);
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
    Interceptor.attach(Module.getExportByName(null, "_pthread_start"), {
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
