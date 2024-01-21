#include <gum/guminterceptor.h>
#include <gum/gumdefs.h>
#include <gum/gumstalker.h>
#include <string.h>
#include <stdio.h>

static void frida_log(const char *format, ...);
extern void _frida_log(const gchar *message);
static void on_ret(GumCpuContext *ctx, gpointer user_data);
// extern void printSyscall (GumCpuContext * ctx, gpointer user_data);

void transform(GumStalkerIterator *iterator, GumStalkerOutput *output, gpointer user_data)
{
  cs_insn *instruction;

  while (gum_stalker_iterator_next(iterator, &instruction))
  {
    if (strcmp(instruction->mnemonic, "svc") == 0)
    {
      gum_stalker_iterator_put_callout(iterator, on_ret, NULL, NULL);
    }

    gum_stalker_iterator_keep(iterator);
  }
}

static void on_ret(GumCpuContext *ctx, gpointer data)
{
  cs_insn *insn = (cs_insn *)data;
  _frida_log("insn: 0x%lx %s %s", (gpointer)insn->address, insn->mnemonic, insn->op_str, ctx->pc);
}

static void frida_log(const char *format, ...)
{
  gchar *message;
  va_list args;

  va_start(args, format);
  message = g_strdup_vprintf(format, args);
  va_end(args);

  _frida_log(message);

  g_free(message);
}