import sys
import os
import struct
import argparse
from capstone import *

def detect_arch_from_elf(filepath):
    """
    ELFヘッダー（e_machine）を覗き見して、CPUアーキテクチャを自動判定するよ！
    """
    try:
        with open(filepath, "rb") as f:
            ident = f.read(20)
            if len(ident) < 20 or ident[:4] != b'\x7fELF':
                return None
            
            # エンディアン判定 (ident[5] == 1 がリトルエンディアン)
            endian = '<' if ident[5] == 1 else '>'
            # 18-20バイト目が e_machine (マシンタイプ)
            e_machine = struct.unpack(endian + 'H', ident[18:20])[0]
            
            # e_machine のコード体系
            machine_map = {
                3: "x86",       # x86 (32bit)
                40: "arm",      # ARM (32bit)
                62: "x86_64",   # x86_64 (64bit)
                183: "arm64"    # ARM64 (AArch64)
            }
            return machine_map.get(e_machine, None)
    except Exception:
        return None

def get_capstone_engine(arch_str):
    """
    指定されたアーキテクチャ文字列から、最適な Capstone エンジンを召喚する！
    """
    arch_str = arch_str.lower()
    if arch_str in ["arm64", "aarch64"]:
        return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    elif arch_str in ["arm", "arm32"]:
        return Cs(CS_ARCH_ARM, CS_MODE_ARM)
    elif arch_str in ["x86", "i386"]:
        return Cs(CS_ARCH_X86, CS_MODE_32)
    elif arch_str in ["x64", "x86_64", "amd64"]:
        return Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch_str in ["mips"]:
        return Cs(CS_ARCH_MIPS, CS_MODE_MIPS32)
    else:
        raise ValueError(f"[!] サポートされていないアーキテクチャだよ、隊長: {arch_str}")

def capstone_disassemble(bin_path, out_path, arch_override=None):
    print(f"[*] 対象バイナリ: {bin_path}")
    
    # アーキテクチャの決定（手動指定があれば優先、なければELFヘッダーから自動探知！）
    arch = arch_override
    if not arch:
        print("[*] ELFヘッダーからアーキテクチャを自動スキャン中...")
        arch = detect_arch_from_elf(bin_path)
        if arch:
            print(f"[*] 自動検知成功！ 判定されたアーキテクチャ: [{arch}]")
        else:
            arch = "arm64" # 検知できなければデフォルトでARM64
            print(f"[!] 自動検知できませんでした。デフォルトの [{arch}] で出撃します！")
    else:
        print(f"[*] 手動オーバーライド指定: [{arch}]")

    try:
        cs = get_capstone_engine(arch)
    except Exception as e:
        print(f"[!] エラー: {e}")
        return

    file_size = os.path.getsize(bin_path)
    print(f"[*] 爆速Capstoneエンジン起動！ (サイズ: {file_size} バイト)")
    print("-" * 55)

    try:
        # ストリーミング読み込み（4KBずつのチャンクでメモリ爆食いを完全に阻止）
        with open(bin_path, "rb") as f_in, open(out_path, "w", encoding="utf-8") as f_out:
            f_out.write(f"; Capstone Disassembly Result\n")
            f_out.write(f"; Source: {bin_path} | Arch: {arch}\n")
            f_out.write("-" * 55 + "\n")
            
            offset = 0
            chunk_size = 4096 # 4KBごとに爆速処理
            instruction_count = 0
            
            while True:
                code = f_in.read(chunk_size)
                if not code:
                    break
                
                # Capstoneによるネイティブ超高速逆アセンブル
                for i in cs.disasm(code, offset):
                    f_out.write(f"0x{i.address:08x} | {i.bytes.hex():<16} | {i.mnemonic:<8} {i.op_str}\n")
                    instruction_count += 1
                
                offset += len(code)
                
        print(f"-" * 55)
        print(f"[*] 航海終了、隊長！出力ファイル: {out_path}")
        print(f"[*] 総逆アセンブル命令数: {instruction_count} 個")
        
    except Exception as e:
        print(f"[!] 逆アセンブル中にエラーが発生したよ: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="全自動＆手動指定対応 Capstoneストリーミング逆アセンブラ")
    parser.add_argument("binary", help="解析したいバイナリファイル（または .text セクション）")
    parser.add_argument("output", help="出力先のテキストファイル")
    parser.add_argument("--arch", "-a", default=None, help="アーキテクチャを手動指定 (例: arm64, x86_64, arm)")
    
    args = parser.parse_args()
    capstone_disassemble(args.binary, args.output, args.arch)
