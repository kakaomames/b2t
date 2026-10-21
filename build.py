import os
import sys
import json
import glob
import xml.etree.ElementTree as ET

import os
import sys
import json
import glob
import xml.etree.ElementTree as ET

def parse_box_bits(box_elem):
    """
    <box> タグの中身（<c>タグの 0/1 や settings）を解析し、
    (hibit, width, bit_values) を返すヘルパー関数！
    """
    try:
        hibit = int(box_elem.get("hibit"))
    except (TypeError, ValueError):
        return None
    
    width = int(box_elem.get("width", 1))
    c_elems = box_elem.findall("c")
    bit_values = []
    
    for c in c_elems:
        text = c.text
        if text is not None:
            text = text.strip()
            if text in ["0", "1"]:
                bit_values.append(text)
            else:
                bit_values.append("x")
        else:
            settings = box_elem.get("settings")
            if settings and len(c_elems) == 1:
                bit_values.append("x")
            else:
                bit_values.append("x")
                
    return hibit, width, bit_values

def parse_arm_xml(xml_path):
    """
    ARM公式の個別XMLを完全に解剖し、
    ファイル内にあるすべてのエンコーディングから正確なマスクと値を抽出する！
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        # 1. ニーモニック（命令名）の取得
        mnemonic = None
        asm_elem = root.find(".//asmtemplate")
        if asm_elem is not None and asm_elem.text:
            text = asm_elem.text.strip()
            if text:
                mnemonic = text.split()[0].lower()
        
        if not mnemonic:
            base_name = os.path.basename(xml_path)
            mnemonic = base_name.split("_")[0].split(".")[0].lower()

        instructions_found = []

        # 2. 各 <encoding> ごと、またはトップレベルの <regdiagram> をすべて回収する
        encodings = root.findall(".//encodings//encoding")
        if not encodings:
            regdiagrams = [root.find(".//regdiagram")]
        else:
            regdiagrams = [enc.find(".//regdiagram") for enc in encodings]

        for regdiagram in regdiagrams:
            if regdiagram is None:
                continue
                
            base_mask = 0
            base_value = 0
            
            for box in regdiagram.findall("box"):
                res = parse_box_bits(box)
                if not res:
                    continue
                hibit, width, bit_values = res
                
                for i, b_val in enumerate(bit_values):
                    current_bit_pos = hibit - i
                    if 0 <= current_bit_pos < 32:
                        if b_val == "1":
                            base_mask |= (1 << current_bit_pos)
                            base_value |= (1 << current_bit_pos)
                        elif b_val == "0":
                            base_mask |= (1 << current_bit_pos)
                            # value 側は 0 のまま
                        else:
                            # 変数ビットはマスクを0にして無視
                            pass

            if base_mask != 0:
                instructions_found.append({
                    "name": mnemonic,
                    "mask": f"0x{base_mask:08x}",
                    "value": f"0x{base_value:08x}",
                    "source_file": os.path.basename(xml_path)
                })

        return instructions_found if instructions_found else None
        
    except Exception:
        return None

def build_instruction_json(target_dir, output_json_path):
    print(f"[*] 対象ディレクトリを再帰探索中: {target_dir}")
    xml_files = glob.glob(os.path.join(target_dir, "**", "*.xml"), recursive=True)
    
    if not xml_files:
        print(f"[!] エラー: XMLファイルが見つからないよ、隊長！")
        return

    print(f"[*] 合計 {len(xml_files)} 個の XML を発見！全エンコーディング解析を開始します...")
    instructions = []
    
    for i, xml_path in enumerate(xml_files):
        results = parse_arm_xml(xml_path)
        if results:
            # 1つのXMLから複数のバリエーション（エンコーディング）をまとめて追加！
            instructions.extend(results)
            
        if (i + 1) % 500 == 0 or (i + 1) == len(xml_files):
            print(f"    - 進捗: {i + 1} / {len(xml_files)} ファイル完了 (累計抽出パターン: {len(instructions)})")

    with open(output_json_path, "w", encoding="utf-8") as f_out:
        json.dump(instructions, f_out, indent=4, ensure_ascii=False)
        
    print(f"[*] 完了！拡張版ビット辞書を生成しました: {output_json_path} (総パターン数: {len(instructions)})")

if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "./arm"
    out_json = sys.argv[2] if len(sys.argv) > 2 else "all.json"
    build_instruction_json(target_dir, out_json)

def parse_box_BBBbits(box_elem):
    """
    <box> タグの中身（<c>タグの 0/1 や settings）を解析し、
    (hibit, width, fixed_bits_dict) を返すヘルパー関数！
    """
    try:
        hibit = int(box_elem.get("hibit"))
    except (TypeError, ValueError):
        return None
    
    width = int(box_elem.get("width", 1))
    
    # 子要素 <c> から実際のビット値（0, 1, x など）を回収する
    c_elems = box_elem.findall("c")
    bit_values = []
    
    for c in c_elems:
        text = c.text
        if text is not None:
            text = text.strip()
            if text in ["0", "1"]:
                bit_values.append(text)
            else:
                bit_values.append("x")
        else:
            # text がない場合、settings 属性などをチェック
            settings = box_elem.get("settings")
            if settings and len(c_elems) == 1:
                # settings が数値等の場合（簡易フォールバック）
                bit_values.append("x")
            else:
                bit_values.append("x")
                
    # もし c タグがないが settings がある場合の処理
    if not bit_values and box_elem.get("settings"):
        # settings の値をバイナリ化する等の処理も可能
        pass
        
    return hibit, width, bit_values

def parse_arm_ggggxml(xml_path):
    """
    ARM公式の個別XMLを完全に解剖し、正確なビットマスクと判定値を算出する！
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        # 1. ニーモニック（命令名）の取得
        mnemonic = None
        asm_elem = root.find(".//asmtemplate")
        if asm_elem is not None and asm_elem.text:
            text = asm_elem.text.strip()
            if text:
                mnemonic = text.split()[0].lower()
        
        if not mnemonic:
            base_name = os.path.basename(xml_path)
            mnemonic = base_name.split("_")[0].split(".")[0].lower()

        # 2. <regdiagram> からベースとなるマスクと値を構築
        regdiagram = root.find(".//regdiagram")
        if regdiagram is None:
            return None
            
        base_mask = 0
        base_value = 0
        
        # 32ビット命令を前提として全ビットをスキャン
        for box in regdiagram.findall("box"):
            res = parse_box_bits(box)
            if not res:
                continue
            hibit, width, bit_values = res
            
            # 各ビットの位置を評価
            for i, b_val in enumerate(bit_values):
                current_bit_pos = hibit - i
                if 0 <= current_bit_pos < 32:
                    if b_val == "1":
                        base_mask |= (1 << current_bit_pos)
                        base_value |= (1 << current_bit_pos)
                    elif b_val == "0":
                        base_mask |= (1 << current_bit_pos)
                        # value 側は 0 のまま
                    else:
                        # 変数ビット（usename="1" やレジスタ指定など）は mask を 0 にして無視
                        pass

        # 個別の <encoding> タグがある場合は、より詳細なバリエーションも拾えるが、
        # まずはベースダイアグラムの正確なマスク・値を採用する！
        
        # 誤爆防止の安全装置：もし mask が全く立っていなかったら（すべて変数扱い等）、
        # ファイル名由来のハッシュではなくユニークな安全値をフォールバックとして与える
        if base_mask == 0:
            # 完全一致させるためのプレースホルダーではなく、一意な識別用にする
            return None

        return {
            "name": mnemonic,
            "mask": f"0x{base_mask:08x}",
            "value": f"0x{base_value:08x}",
            "source_file": os.path.basename(xml_path)
        }
        
    except Exception:
        return None

def build_instruction_jsonhbhbhb(target_dir, output_json_path):
    print(f"[*] 対象ディレクトリを再帰探索中: {target_dir}")
    xml_files = glob.glob(os.path.join(target_dir, "**", "*.xml"), recursive=True)
    
    if not xml_files:
        print(f"[!] エラー: XMLファイルが見つからないよ、隊長！")
        return

    print(f"[*] 合計 {len(xml_files)} 個の XML を発見！本気のビットパースを開始します...")
    instructions = []
    
    for i, xml_path in enumerate(xml_files):
        result = parse_arm_xml(xml_path)
        if result:
            instructions.append(result)
            
        if (i + 1) % 500 == 0 or (i + 1) == len(xml_files):
            print(f"    - 進捗: {i + 1} / {len(xml_files)} ファイル完了 (有効抽出: {len(instructions)})")

    with open(output_json_path, "w", encoding="utf-8") as f_out:
        json.dump(instructions, f_out, indent=4, ensure_ascii=False)
        
    print(f"[*] 完了！本物のビット辞書を生成しました: {output_json_path} (総登録数: {len(instructions)})")

#if __name__ == "__main__":
#    target_dir = sys.argv[1] if len(sys.argv) > 1 else "./arm"
#    out_json = sys.argv[2] if len(sys.argv) > 2 else "all.json"
#    build_instruction_json(target_dir, out_json)
