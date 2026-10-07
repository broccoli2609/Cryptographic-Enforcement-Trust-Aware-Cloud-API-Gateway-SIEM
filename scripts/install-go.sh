#!/usr/bin/env bash
# Cài Go vào /usr/local/go từ go.dev, có kiểm SHA-256 trước khi giải nén.
# Chạy:  ./scripts/install-go.sh            (mặc định 1.27.1)
#        ./scripts/install-go.sh 1.27.2     (phiên bản khác)
set -euo pipefail
VERSION="${1:-1.27.1}"
FILE="go${VERSION}.linux-amd64.tar.gz"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "Tải https://go.dev/dl/${FILE}"
curl -fsSLo "$TMP/$FILE" "https://go.dev/dl/${FILE}"

# Lấy SHA-256 chính thức từ danh sách phát hành của go.dev rồi so với file vừa tải.
EXPECTED=$(curl -fsSL "https://go.dev/dl/?mode=json&include=all" | python3 -c '
import json, sys
name = sys.argv[1]
for rel in json.load(sys.stdin):
    for f in rel["files"]:
        if f["filename"] == name:
            print(f["sha256"]); sys.exit(0)
sys.exit("Không tìm thấy " + name + " trên go.dev")
' "$FILE")
ACTUAL=$(sha256sum "$TMP/$FILE" | cut -d' ' -f1)
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "SHA-256 KHÔNG khớp — dừng lại, không cài."
  exit 1
fi
echo "SHA-256 khớp: $ACTUAL"

sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "$TMP/$FILE"
if ! grep -q '/usr/local/go/bin' "$HOME/.profile"; then
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$HOME/.profile"
fi
echo "Xong. Chạy:  source ~/.profile && go version"
