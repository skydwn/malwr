# ============================================================
# Makefile - Shellcode Loader (cross-compile mingw-w64 no WSL)
#
# Requer: x86_64-w64-mingw32-gcc, nasm
#   sudo apt install mingw-w64 nasm
#
# Uso:
#   make            # compila build/loader.exe
#   make clean      # limpa artefatos
# ============================================================

CC       = x86_64-w64-mingw32-gcc
NASM     = nasm
CFLAGS   = -O2 -Wall -mconsole -I src
LDFLAGS  = -lkernel32 -lntdll -s

SRC_DIR   = src
BUILD_DIR = build

OBJS = $(BUILD_DIR)/loader.o $(BUILD_DIR)/syscalls.o

TARGET = $(BUILD_DIR)/malwr.exe

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/syscalls.o: $(SRC_DIR)/syscalls_nasm.asm | $(BUILD_DIR)
	$(NASM) -f win64 $< -o $@

$(BUILD_DIR)/loader.o: $(SRC_DIR)/loader.c $(SRC_DIR)/loader.h $(SRC_DIR)/shellcode.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo ""
	@echo "[+] Build concluido: $(TARGET)"
	@x86_64-w64-mingw32-strip --strip-all $(TARGET) 2>/dev/null || true

clean:
	rm -rf $(BUILD_DIR)
	@echo "[+] Limpo."

.PHONY: all clean
