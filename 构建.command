#!/bin/zsh
set -eu
cd "$(dirname "$0")"
browser_support="$HOME/Library/Application Support/LocalFingerprintBrowser"
browser_bundle="$PWD/dist/本地指纹浏览器.app"
if [[ ! -x "$browser_support/runtime/bin/python" ]]; then
  print -u2 '缺少本机运行环境，请先按 README.md 安装 Python 依赖和浏览器内核。'
  exit 1
fi
mkdir -p "$browser_bundle/Contents/MacOS"
cp macos/Info.plist "$browser_bundle/Contents/Info.plist"
swiftc -swift-version 5 -O -parse-as-library BrowserManager.swift ProxyConfiguration.swift \
  -o "$browser_bundle/Contents/MacOS/LocalBrowser" \
  -framework SwiftUI -framework AppKit -framework Security
cp worker.py "$browser_support/worker.py"
codesign --force --sign - "$browser_bundle"
print "构建完成：$browser_bundle"
print '可双击运行，也可把应用拖到「应用程序」。'
