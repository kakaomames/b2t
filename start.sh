echo "=================================="
echo "          Downloading...          "
echo "=================================="
curl -L "https://developer.arm.com/-/cdn-downloads/permalink/Exploration-Tools-A64-ISA/ISA_A64/ISA_A64_xml_A_profile-2026-09.tar.gz" -o "armA64.tar.gz"
mkdir -p arm
cd arm
pwd
ls -F
echo "=================================="
echo "            Thawing...            "
echo "=================================="
tar -xvf $(pwd)/../armA64.tar.gz # 展開
echo "=================================="
echo "           building...            "
echo "=================================="
cd ..

bash build.sh # 中身はpython build.py
head -20 all.json
bash b2t.sh $1
