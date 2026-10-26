
#!/usr/bin/env bash
set -eu

mkdir -p bin
curl -fL https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp -o bin/yt-dlp
chmod +x bin/yt-dlp

npm install
