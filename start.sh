echo "=================================="
echo "          Downloading...          "
echo "=================================="
curl -L "https://developer.arm.com/-/cdn-downloads/permalink/Exploration-Tools-A64-ISA/ISA_A64/ISA_A64_xml_A_profile-2026-09.tar.gz" -o "armA64.tar.gz"
mkdir -p arm
cd arm
echo "=================================="
echo "            Thawing...            "
echo "=================================="
tar -x ../armA64.tar.gz
echo "=================================="
echo "           building...            "
echo "=================================="
cd ..

bash build.sh
