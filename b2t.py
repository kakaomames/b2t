import sys
import os
import json

def load_instruction_dictionary(json_path="all.json"):
    """
    BuildJson.py が生成した all.json を安全にロードし、
    16進数文字列のマスクとバリューを確実に整数 (int) に変換する！
    """
    if not os.path.exists(json_path):
        print(f"[!] エラー: 辞書ファイル '{json_path}' が見つからないよ、隊長！")
        sys.exit(1)
        
    print(f"[*] 外部辞書 '{json_path}' を読み込み中...")
    with open(json_path, "r", encoding="utf-8") as f:
        instructions = json.load(f)
        
    valid_instructions = []
    for inst in instructions:
        try:
            # 辞書の文字列を確実に整数に変換（ズレを完全防止）
            mask_val = int(inst["mask"], 16)
            value_val = int(inst["value"], 16)
            
            valid_instructions.append({
                "name": inst["name"],
                "mask": mask_val,
                "value": value_val,
                "source_file": inst.get("source_file", "")
            })
        except (ValueError, KeyError):
            # パースに異常がある項目は安全にスキップ
            continue
        
    print(f"[*] ロード完了: 有効な命令データ {len(valid_instructions)} 個の準備OK！")
    return valid_instructions

def b2t(bin_path, text_filename, json_path="all.json", cpu_type="arm"):
    print(f"[*] 対象バイナリ: {bin_path}")
    print(f"[*] 出力先テキスト: {text_filename}")
    print("-" * 55)
    
    # 1. 総ファイルサイズから全ブロック数（4バイト単位）を算出
    file_size = os.path.getsize(bin_path)
    total_blocks = file_size // 4
    print(f"[*] ファイル総サイズ: {file_size} バイト (全ブロック数: {total_blocks} 単位)")
    print("-" * 55)
    
    # 2. 辞書のロード
    all_instructions = load_instruction_dictionary(json_path)
    chunk_size = 4
    address = 0x00000000
    matched_count = 0
    total_count = 0
    
    try:
        with open(bin_path, "rb") as f_in, open(text_filename, "w", encoding="utf-8") as f_out:
            f_out.write(f"; Binary to Text Disassembly Result (ARM64)\n")
            f_out.write(f"; Source: {bin_path}\n")
            f_out.write(f"; Total Blocks: {total_blocks}\n")
            f_out.write("-" * 55 + "\n")
            
            while True:
                current_byte_pos = f_in.tell()
                current_block = current_byte_pos // 4
                progress_percent = (current_byte_pos / file_size) * 100 if file_size > 0 else 100
                
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                
                if len(chunk) < chunk_size:
                    f_out.write(f"0x{address:08x} | {chunk.hex():<10} | [Truncated Bytes]\n")
                    break
                
                total_count += 1
                # リトルエンディアンで4バイト整数に変換
                inst_val = int.from_bytes(chunk, byteorder="little")
                
                mnemonic = None
                source_file = ""
                
                # ── 4,605個の辞書と真っ向から照合（ビットマスク判定） ──
                for inst_def in all_instructions:
                    if (inst_val & inst_def["mask"]) == inst_def["value"]:
                        mnemonic = inst_def["name"]
                        source_file = inst_def["source_file"]
                        matched_count += 1
                        break
                
                # 一致しない場合のフォールバック
                if not mnemonic:
                    mnemonic = f"unknown_0x{inst_val:08x}"
                
                # テキストファイルへ書き出し
                f_out.write(f"0x{address:08x} | 0x{inst_val:08x} | {mnemonic:<16} ; ({source_file})\n")
                
                # ── 進捗をコンソールへ実況（1000ブロックごと） ──
                if current_block > 0 and current_block % 1000 == 0:
                    print(f"[*] 航行中: ブロック [{current_block} / {total_blocks}] ({progress_percent:.1f}%) 完了")
                
                address += chunk_size
                
        print("-" * 55)
        print(f"[*] 航海終了、隊長！出力ファイル: {text_filename}")
        print(f"[*] 処理完了: 全 {total_blocks} ブロック (一致成功: {matched_count} 個)")
        
    except Exception as e:
        print(f"[!] エラーが発生したよ: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python b2t.py <binary_file> <output_text_file> [all.json_path]")
    else:
        target_bin = sys.argv[1]
        out_text = sys.argv[2]
        json_file = sys.argv[3] if len(sys.argv) > 3 else "all.json"
        b2t(target_bin, out_text, json_file, cpu_type="arm")
