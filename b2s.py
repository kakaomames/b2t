import os
import struct
import sys

def parse_elf_sections(filepath, output_dir):
    """
    ELF64ファイルを解析し、すべてのセクションを個別のファイルとして切り出す！
    """
    if not os.path.exists(filepath):
        print(f"[!] エラー: ファイル '{filepath}' が見つからないよ、隊長！")
        return

    # 出力用ディレクトリを作成
    os.makedirs(output_dir, exist_ok=True)

    with open(filepath, "rb") as f:
        # 1. ELFマジックナンバーの確認 (最初の16バイト)
        ident = f.read(16)
        if len(ident) < 16 or ident[:4] != b'\x7fELF':
            print(f"[!] エラー: '{filepath}' は標準的な ELF ファイルではないみたい！")
            return

        # 64-bit かどうかの判定 (ident[4] == 2 が ELF64)
        is_64bit = (ident[4] == 2)
        # エンディアン判定 (ident[5] == 1 がリトルエンディアン)
        endian = '<' if ident[5] == 1 else '>'

        if not is_64bit:
            print("[!] 現状、このスクリプトは 64-bit ELF (ELF64) に対応しているよ！")
            return

        # 2. ELF64ヘッダーからセクションヘッダー関連のオフセット情報を取得
        # e_shoff (オフセット40: セクションヘッダーテーブルのファイル内位置)
        f.seek(40)
        e_shoff = struct.unpack(endian + 'Q', f.read(8))[0]
        
        # e_shentsize (58: 1エントリーのサイズ), e_shnum (60: エントリー数), e_shstrndx (62: セクション名文字列テーブルのインデックス)
        f.seek(58)
        e_shentsize = struct.unpack(endian + 'H', f.read(2))[0]
        e_shnum = struct.unpack(endian + 'H', f.read(2))[0]
        e_shstrndx = struct.unpack(endian + 'H', f.read(2))[0]

        if e_shoff == 0 or e_shnum == 0:
            print("[!] セクションヘッダーが見つからないよ（ストリップされている可能性が高いね）")
            return

        # 3. セクション名文字列テーブル（shstrtab）のデータを読み込む
        f.seek(e_shoff + e_shstrndx * e_shentsize)
        shstrtab_header = f.read(e_shentsize)
        shstrtab_offset = struct.unpack(endian + 'Q', shstrtab_header[24:32])[0]
        shstrtab_size = struct.unpack(endian + 'Q', shstrtab_header[32:40])[0]

        f.seek(shstrtab_offset)
        shstrtab = f.read(shstrtab_size)

        print(f"[*] セクション数: {e_shnum} 個の部屋を発見！抽出を開始します...")

        # 4. 各セクションを走査して個別ファイルに書き出す
        extracted_count = 0
        for i in range(e_shnum):
            f.seek(e_shoff + i * e_shentsize)
            sh_entry = f.read(e_shentsize)

            sh_name_idx = struct.unpack(endian + 'I', sh_entry[0:4])[0]
            sh_offset = struct.unpack(endian + 'Q', sh_entry[24:32])[0]
            sh_size = struct.unpack(endian + 'Q', sh_entry[32:40])[0]

            # セクション名の取得（shstrtabからヌル文字まで）
            name_end = shstrtab.find(b'\x00', sh_name_idx)
            if name_end == -1:
                name_end = len(shstrtab)
            section_name = shstrtab[sh_name_idx:name_end].decode('utf-8', errors='ignore')

            if not section_name:
                section_name = f"section_{i}"

            # サイズとオフセットが有効なセクションのみ抽出
            if sh_size > 0 and sh_offset > 0:
                f.seek(sh_offset)
                sec_data = f.read(sh_size)

                # ファイル名として安全な名前に調整（例: .text -> text など）
                safe_name = section_name.strip('.')
                if not safe_name:
                    safe_name = f"unnamed_{i}"
                
                out_path = os.path.join(output_dir, safe_name)

                with open(out_path, "wb") as f_sec:
                    f_sec.write(sec_data)
                
                print(f"    - 抽出: {section_name:<15} -> {out_path} ({sh_size} バイト)")
                extracted_count += 1

    print(f"-" * 55)
    print(f"[*] スプリット完了、隊長！ 合計 {extracted_count} 個のセクションをディレクトリに展開したよ: {output_dir}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python b2s.py <target_elf_file>")
    else:
        target_file = sys.argv[1]
        # 出力先フォルダ名は 「ファイル名_sections」 に設定
        output_folder = target_file + "_sections"
        parse_elf_sections(target_file, output_folder)
