import os
import sys
import json
import glob
import xml.etree.ElementTree as ET

def parse_boxes_from_diagram(regdiagram_elem):
    """
    <regdiagram> 内のすべての <box> を走査し、
    ビット位置ごとの (bit_type, bit_value) を辞書で返す！
    bit_type: '0', '1', または 'x' (変数・プレースホルダー)
    """
    bits_map = {}
    if regdiagram_elem is None:
        return bits_map
        
    for box in regdiagram_elem.findall("box"):
        try:
            hibit = int(box.get("hibit"))
        except (TypeError, ValueError):
            continue
            
        width = int(box.get("width", 1))
        c_elems = box.findall("c")
        
        # 各ビットの値を収集
        box_bits = []
        for c in c_elems:
            text = c.text
            if text is not None:
                text = text.strip()
                if text in ["0", "1"]:
                    box_bits.append(text)
                else:
                    box_bits.append("x")
            else:
                settings = box.get("settings")
                if settings and len(c_elems) == 1:
                    box_bits.append("x")
                else:
                    box_bits.append("x")
        
        # もし cタグの数が足りない場合や幅と合わない場合のフォールバック
        while len(box_bits) < width:
            box_bits.append("x")
            
        # hibit から下位に向かってビットを割り当て
        for i in range(width):
            current_bit_pos = hibit - i
            if 0 <= current_bit_pos < 32:
                bits_map[current_bit_pos] = box_bits[i]
                
    return bits_map

def parse_arm_xml(xml_path):
    """
    ARM公式XMLを解析し、親の regdiagram と 各 encoding の差分を合成して
    すべてのエンコーディングパターンから正確なマスクと値を抽出する！
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

        # 2. 親（共通）の regdiagram を取得してベースのビットマップを作る
        base_regdiagram = root.find(".//regdiagram")
        base_bits_map = parse_boxes_from_diagram(base_regdiagram)

        # 3. すべての <encoding> ブロックを探索
        encodings = root.findall(".//encodings//encoding")
        
        if not encodings:
            # encodingがない場合は、親の regdiagram のみで1パターン生成
            if base_bits_map:
                mask, value = compute_mask_and_value(base_bits_map)
                if mask != 0:
                    instructions_found.append({
                        "name": mnemonic,
                        "mask": f"0x{mask:08x}",
                        "value": f"0x{value:08x}",
                        "source_file": os.path.basename(xml_path)
                    })
        else:
            for enc in encodings:
                enc_name = enc.get("name", mnemonic)
                # コピーして親ベースを汚さないようにする
                merged_bits_map = base_bits_map.copy()
                
                # encoding内の固有の regdiagram や box (bitdiffs含む) で上書き
                enc_regdiagram = enc.find(".//regdiagram")
                enc_bits_map = parse_boxes_from_diagram(enc_regdiagram)
                merged_bits_map.update(enc_bits_map)
                
                # encoding直下の <box> タグ（bitdiffsなど）も網羅的にチェックして上書き
                for box in enc.findall(".//box"):
                    try:
                        hibit = int(box.get("hibit"))
                    except (TypeError, ValueError):
                        continue
                    width = int(box.get("width", 1))
                    c_elems = box.findall("c")
                    for i, c in enumerate(c_elems):
                        if c.text and c.text.strip() in ["0", "1"]:
                            pos = hibit - i
                            if 0 <= pos < 32:
                                merged_bits_map[pos] = c.text.strip()

                mask, value = compute_mask_and_value(merged_bits_map)
                if mask != 0:
                    instructions_found.append({
                        "name": mnemonic,
                        "mask": f"0x{mask:08x}",
                        "value": f"0x{value:08x}",
                        "source_file": os.path.basename(xml_path)
                    })

        return instructions_found if instructions_found else None
        
    except Exception as e:
        return None

def compute_mask_and_value(bits_map):
    """
    ビットマップ（位置 -> '0', '1', 'x'）から 32bit の mask と value を計算する
    """
    base_mask = 0
    base_value = 0
    
    for pos, val in bits_map.items():
        if val == "1":
            base_mask |= (1 << pos)
            base_value |= (1 << pos)
        elif val == "0":
            base_mask |= (1 << pos)
            # value は 0 のまま
        else:
            # "x" (変数ビット) はマスクを 0 にして無視
            pass
            
    return base_mask, base_value

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
