#ifndef CAPSTONE_ENGINE_H
#define CAPSTONE_ENGINE_H
#ifdef __cplusplus
extern "C" {
#endif
#include <stdarg.h>
#if defined(CAPSTONE_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include <stdlib.h>
#include <stdio.h>
#endif
#include "platform.h"
#ifdef _MSC_VER
#pragma warning(disable:4201)
#pragma warning(disable:4100)
#define __cdecl
#ifdef CAPSTONE_SHARED
#define CAPSTONE_EXPORT __declspec(dllexport)
#else
#define CAPSTONE_EXPORT
#endif
#else
#define CAPSTONE_API
#if (defined(__GNUC__) || defined(__IBMC__)) && !defined(CAPSTONE_STATIC)
#define CAPSTONE_EXPORT __attribute__((visibility("default")))
#else
#define CAPSTONE_EXPORT
#endif
#endif
#if (defined(__GNUC__) || defined(__IBMC__))
#define CAPSTONE_DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define CAPSTONE_DEPRECATED __declspec(deprecated)
#else
#pragma message("WARNING: You need to implement CAPSTONE_DEPRECATED for this compiler")
#define CAPSTONE_DEPRECATED
#endif
#define CS_API_MAJOR 5
#define CS_API_MINOR 0
#define CS_NEXT_VERSION 5
#define CS_VERSION_MAJOR CS_API_MAJOR
#define CS_VERSION_MINOR CS_API_MINOR
#define CS_VERSION_EXTRA 0
#define CS_MAKE_VERSION(major, minor) ((major << 8) + minor)
#define CS_MNEMONIC_SIZE 32
typedef size_t csh;
typedef enum cs_arch {
	CS_ARCH_ARM = 0,
	CS_ARCH_ARM64,
	CS_ARCH_MIPS,
	CS_ARCH_X86,
	CS_ARCH_PPC,
	CS_ARCH_SPARC,
	CS_ARCH_SYSZ,
	CS_ARCH_XCORE,
	CS_ARCH_M68K,
	CS_ARCH_TMS320C64X,
	CS_ARCH_M680X,
	CS_ARCH_EVM,
	CS_ARCH_MOS65XX,
	CS_ARCH_WASM,
	CS_ARCH_BPF,
	CS_ARCH_RISCV,
	CS_ARCH_MAX,
	CS_ARCH_ALL = 0xFFFF,
} cs_arch;
#define CS_SUPPORT_DIET (CS_ARCH_ALL + 1)
#define CS_SUPPORT_X86_REDUCE (CS_ARCH_ALL + 2)
typedef enum cs_mode {
	CS_MODE_LITTLE_ENDIAN = 0,
	CS_MODE_ARM = 0,
	CS_MODE_16 = 1 << 1,
	CS_MODE_32 = 1 << 2,
	CS_MODE_64 = 1 << 3,
	CS_MODE_THUMB = 1 << 4,
	CS_MODE_MCLASS = 1 << 5,
	CS_MODE_V8 = 1 << 6,
	CS_MODE_MICRO = 1 << 4,
	CS_MODE_MIPS3 = 1 << 5,
	CS_MODE_MIPS32R6 = 1 << 6,
	CS_MODE_MIPS2 = 1 << 7,
	CS_MODE_V9 = 1 << 4,
	CS_MODE_QPX = 1 << 4,
	CS_MODE_SPE = 1 << 5,
	CS_MODE_BOOKE = 1 << 6,
	CS_MODE_PS = 1 << 7,
	CS_MODE_M68K_000 = 1 << 1,
	CS_MODE_M68K_010 = 1 << 2,
	CS_MODE_M68K_020 = 1 << 3,
	CS_MODE_M68K_030 = 1 << 4,
	CS_MODE_M68K_040 = 1 << 5,
	CS_MODE_M68K_060 = 1 << 6,
	CS_MODE_BIG_ENDIAN = 1U << 31,
	CS_MODE_MIPS32 = CS_MODE_32,
	CS_MODE_MIPS64 = CS_MODE_64,
	CS_MODE_M680X_6301 = 1 << 1,
	CS_MODE_M680X_6309 = 1 << 2,
	CS_MODE_M680X_6800 = 1 << 3,
	CS_MODE_M680X_6801 = 1 << 4,
	CS_MODE_M680X_6805 = 1 << 5,
	CS_MODE_M680X_6808 = 1 << 6,
	CS_MODE_M680X_6809 = 1 << 7,
	CS_MODE_M680X_6811 = 1 << 8,
	CS_MODE_M680X_CPU12 = 1 << 9,
	CS_MODE_M680X_HCS08 = 1 << 10,
	CS_MODE_BPF_CLASSIC = 0,
	CS_MODE_BPF_EXTENDED = 1 << 0,
	CS_MODE_RISCV32  = 1 << 0,
	CS_MODE_RISCV64  = 1 << 1,
	CS_MODE_RISCVC   = 1 << 2,
	CS_MODE_MOS65XX_6502 = 1 << 1,
	CS_MODE_MOS65XX_65C02 = 1 << 2,
	CS_MODE_MOS65XX_W65C02 = 1 << 3,
	CS_MODE_MOS65XX_65816 = 1 << 4,
	CS_MODE_MOS65XX_65816_LONG_M = (1 << 5),
	CS_MODE_MOS65XX_65816_LONG_X = (1 << 6),
	CS_MODE_MOS65XX_65816_LONG_MX = CS_MODE_MOS65XX_65816_LONG_M | CS_MODE_MOS65XX_65816_LONG_X,
} cs_mode;
typedef void* (*cs_malloc_t)(size_t size);
typedef void* (*cs_calloc_t)(size_t nmemb, size_t size);
typedef void* (*cs_realloc_t)(void *ptr, size_t size);
typedef void (*cs_free_t)(void *ptr);
typedef int (*cs_vsnprintf_t)(char *str, size_t size, const char *format, va_list ap);
typedef struct cs_opt_mem {
	cs_malloc_t malloc;
	cs_calloc_t calloc;
	cs_realloc_t realloc;
	cs_free_t free;
	cs_vsnprintf_t vsnprintf;
} cs_opt_mem;
typedef struct cs_opt_mnem {
	unsigned int id;
	const char *mnemonic;
} cs_opt_mnem;
typedef enum cs_opt_type {
	CS_OPT_INVALID = 0,
	CS_OPT_SYNTAX,
	CS_OPT_DETAIL,
	CS_OPT_MODE,
	CS_OPT_MEM,
	CS_OPT_SKIPDATA,
	CS_OPT_SKIPDATA_SETUP,
	CS_OPT_MNEMONIC,
	CS_OPT_UNSIGNED,
} cs_opt_type;
typedef enum cs_opt_value {
	CS_OPT_OFF = 0,
	CS_OPT_ON = 3,
	CS_OPT_SYNTAX_DEFAULT = 0,
	CS_OPT_SYNTAX_INTEL,
	CS_OPT_SYNTAX_ATT,
	CS_OPT_SYNTAX_NOREGNAME,
	CS_OPT_SYNTAX_MASM,
	CS_OPT_SYNTAX_MOTOROLA,
} cs_opt_value;
typedef enum cs_op_type {
	CS_OP_INVALID = 0,
	CS_OP_REG,
	CS_OP_IMM,
	CS_OP_MEM,
	CS_OP_FP,
} cs_op_type;
typedef enum cs_ac_type {
	CS_AC_INVALID = 0,
	CS_AC_READ    = 1 << 0,
	CS_AC_WRITE   = 1 << 1,
} cs_ac_type;
typedef enum cs_group_type {
	CS_GRP_INVALID = 0,
	CS_GRP_JUMP,
	CS_GRP_CALL,
	CS_GRP_RET,
	CS_GRP_INT,
	CS_GRP_IRET,
	CS_GRP_PRIVILEGE,
	CS_GRP_BRANCH_RELATIVE,
} cs_group_type;
typedef size_t (*cs_skipdata_cb_t)(const uint8_t *code, size_t code_size, size_t offset, void *user_data);
typedef struct cs_opt_skipdata {
	const char *mnemonic;
	cs_skipdata_cb_t callback;
	void *user_data;
} cs_opt_skipdata;
typedef int cs_arm;
typedef int cs_arm64;
typedef int cs_m68k;
typedef int cs_mips;
typedef int cs_ppc;
typedef int cs_sparc;
typedef int cs_sysz;
#include "x86.h"
typedef int cs_xcore;
typedef int cs_tms320c64x;
typedef int cs_m680x;
typedef int cs_evm;
typedef int cs_riscv;
typedef int cs_wasm;
typedef int cs_mos65xx;
typedef int cs_bpf;
typedef struct cs_detail {
	uint16_t regs_read[16];
	uint8_t regs_read_count;
	uint16_t regs_write[20];
	uint8_t regs_write_count;
	uint8_t groups[8];
	uint8_t groups_count;
	union {
		cs_x86 x86;
		cs_arm64 arm64;
		cs_arm arm;
		cs_m68k m68k;
		cs_mips mips;
		cs_ppc ppc;
		cs_sparc sparc;
		cs_sysz sysz;
		cs_xcore xcore;
		cs_tms320c64x tms320c64x;
		cs_m680x m680x;
		cs_evm evm;
		cs_mos65xx mos65xx;
		cs_wasm wasm;
		cs_bpf bpf;
		cs_riscv riscv;
	};
} cs_detail;
typedef struct cs_insn {
	unsigned int id;
	uint64_t address;
	uint16_t size;
	uint8_t bytes[24];
	char mnemonic[CS_MNEMONIC_SIZE];
	char op_str[160];
	cs_detail *detail;
} cs_insn;
#define CS_INSN_OFFSET(insns, post) (insns[post - 1].address - insns[0].address)
typedef enum cs_err {
	CS_ERR_OK = 0,
	CS_ERR_MEM,
	CS_ERR_ARCH,
	CS_ERR_HANDLE,
	CS_ERR_CSH,
	CS_ERR_MODE,
	CS_ERR_OPTION,
	CS_ERR_DETAIL,
	CS_ERR_MEMSETUP,
	CS_ERR_VERSION,
	CS_ERR_DIET,
	CS_ERR_SKIPDATA,
	CS_ERR_X86_ATT,
	CS_ERR_X86_INTEL,
	CS_ERR_X86_MASM,
} cs_err;
unsigned int cs_version(int *major, int *minor);
void cs_arch_register_arm(void);
void cs_arch_register_arm64(void);
void cs_arch_register_mips(void);
void cs_arch_register_x86(void);
void cs_arch_register_ppc(void);
void cs_arch_register_sparc(void);
void cs_arch_register_sysz(void);
void cs_arch_register_xcore(void);
void cs_arch_register_m68k(void);
void cs_arch_register_tms320c64x(void);
void cs_arch_register_m680x(void);
void cs_arch_register_evm(void);
void cs_arch_register_mos65xx(void);
void cs_arch_register_wasm(void);
void cs_arch_register_bpf(void);
void cs_arch_register_riscv(void);
bool cs_support(int query);
cs_err cs_open(cs_arch arch, cs_mode mode, csh *handle);
cs_err cs_close(csh *handle);
cs_err cs_option(csh handle, cs_opt_type type, size_t value);
cs_err cs_errno(csh handle);
const char * cs_strerror(cs_err code);
size_t cs_disasm(csh handle,
		const uint8_t *code, size_t code_size,
		uint64_t address,
		size_t count,
		cs_insn **insn);
void cs_free(cs_insn *insn, size_t count);
cs_insn * cs_malloc(csh handle);
bool cs_disasm_iter(csh handle,
	const uint8_t **code, size_t *size,
	uint64_t *address, cs_insn *insn);
const char * cs_reg_name(csh handle, unsigned int reg_id);
const char * cs_insn_name(csh handle, unsigned int insn_id);
const char * cs_group_name(csh handle, unsigned int group_id);
bool cs_insn_group(csh handle, const cs_insn *insn, unsigned int group_id);
bool cs_reg_read(csh handle, const cs_insn *insn, unsigned int reg_id);
bool cs_reg_write(csh handle, const cs_insn *insn, unsigned int reg_id);
int cs_op_count(csh handle, const cs_insn *insn, unsigned int op_type);
int cs_op_index(csh handle, const cs_insn *insn, unsigned int op_type,
		unsigned int position);
typedef uint16_t cs_regs[64];
cs_err cs_regs_access(csh handle, const cs_insn *insn,
		cs_regs regs_read, uint8_t *regs_read_count,
		cs_regs regs_write, uint8_t *regs_write_count);
#ifdef __cplusplus
}
#endif
#endif
