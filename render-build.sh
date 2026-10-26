#!/usr/bin/env bash
set -eu

apt-get update
apt-get install -y ffmpeg

mkdir -p bin
curl -fL https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp -o bin/yt-dlp
chmod +x bin/yt-dlp

./bin/yt-dlp --version
ffmpeg -version
echo "YT-DLP AND FFMPEG CHECK COMPLETE"

npm install