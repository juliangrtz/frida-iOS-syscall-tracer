#include <gum/gumdefs.h>
#include <gum/guminterceptor.h>
#include <gum/gumstalker.h>
#include <string.h>

extern void printSyscall(GumCpuContext *ctx, gpointer user_data);

void transform(GumStalkerIterator *iterator, GumStalkerOutput *output, gpointer user_data)
{
    cs_insn *instruction;

    while (gum_stalker_iterator_next(iterator, &instruction))
    {
        if(instruction->id == ARM64_INS_SVC) {
        {
           gum_stalker_iterator_put_callout(iterator, printSyscall, NULL, NULL);
        }

        gum_stalker_iterator_keep(iterator);
    }
}
