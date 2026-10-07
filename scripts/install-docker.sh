#!/usr/bin/env bash
# Cài Docker Engine trong Ubuntu (WSL2) theo hướng dẫn chính thức của Docker.
# KHÔNG chạy script này nếu bạn đã dùng Docker Desktop có bật WSL integration
# (gõ "docker version" trong Ubuntu mà thấy "Server: Docker Desktop" là đã có).
set -euo pipefail

sudo apt update
sudo apt install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

sudo tee /etc/apt/sources.list.d/docker.sources > /dev/null <<SRC
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
SRC

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Cho user hiện tại gọi docker không cần sudo. Lưu ý: nhóm docker tương đương quyền root
# trên máy (đây chính là TB6 trong trust boundary tuần 1).
sudo usermod -aG docker "$USER"

if [ "$(ps -p 1 -o comm=)" = systemd ]; then
  sudo systemctl enable --now docker
else
  sudo service docker start
fi
echo "Xong. Đóng terminal, mở lại, rồi chạy:  docker run --rm hello-world"
