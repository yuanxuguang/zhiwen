# 本地指纹浏览器

面向 Apple Silicon Mac 的轻量本地环境管理器，使用 SwiftUI 和开源 Camoufox / Firefox 内核。当前版本为 0.2.0。

## 功能

- 创建独立环境，持久保存指纹配置、Cookie 和网站本地存储，无环境数量限制。
- Canvas / WebGL 读回保护、WebGL 开关、WebRTC 阻止。
- HTTP / SOCKS5 代理及账号密码认证；整条代理粘贴、复制和多行批量导入。
- 启动前按出口 IP 自动匹配语言、时区、国家和大致位置；检测失败停止启动。
- 默认启动网址为 Google，代理密码存储在 macOS 钥匙串。

详细操作及限制见 [使用说明](使用说明.md)。Canvas 保护使用随机读回数据，不能保证所有检测值固定，也不能保证网站不会识别环境。动态住宅代理建议配置供应商的粘性会话。

## 安装与构建

要求 macOS 14 或以上、Apple Silicon、Xcode Command Line Tools 和 Python 3.12。需要网络下载 Python 依赖及官方 Camoufox 内核；内核和运行依赖约占 2.7 GB，环境数据另计。

```sh
git clone git@github.com:yuanxuguang/zhiwen.git
cd zhiwen

# 若尚未安装 Xcode Command Line Tools，先运行并完成安装：
xcode-select --install
```

确认 `python3.12` 已安装，然后在项目根目录运行：

```sh
browser_support="$HOME/Library/Application Support/LocalFingerprintBrowser"
mkdir -p "$browser_support"
python3.12 -m venv "$browser_support/runtime"
"$browser_support/runtime/bin/python" -m pip install -r requirements.lock
"$browser_support/runtime/bin/python" -m camoufox fetch
zsh ./构建.command
open "dist/本地指纹浏览器.app"
```

构建前请退出旧版管理器。脚本编译 `.app`、更新 Application Support 中的 `worker.py` 并执行本地 ad hoc 签名；不包含开发者签名、公证或 DMG 安装包。`requirements.lock` 记录当前开发机器的依赖版本。内核由 Camoufox 下载器获取，当前验证版本为 158.0.1-beta.41；下载器以后可能提供更新版本。

使用 venv 时应保留创建它的 Python 安装。只复制生成的 `.app` 到另一台电脑不能直接运行，另一台电脑需要按上述步骤配置运行环境和内核。

## 数据位置

- 运行环境、worker 和环境列表：`~/Library/Application Support/LocalFingerprintBrowser/`
- 每个环境的浏览器数据：上述目录的 `data/<环境 ID>/browser-data/`
- 内核缓存：`~/Library/Caches/camoufox/`
- 代理密码：macOS 钥匙串服务 `local.fingerprint.browser.proxy`

仓库只存源码、构建元数据、依赖版本和测试，不存代理凭据、浏览器环境数据或编译后的应用。首次运行不会导入本机其他浏览器的账户。

自动地区检测访问 [ipwho.is](https://ipwho.is/)，服务可看到出口 IP，代理凭据不会发送给地区服务。语言使用内核附带的 Unicode CLDR 国家语言数据，大致位置由 IP 数据库估算，不读取 Mac 的真实定位。

## 源码结构

| 文件 | 用途 |
| --- | --- |
| `BrowserManager.swift` | 环境界面、配置、钥匙串和 worker 生命周期 |
| `ProxyConfiguration.swift` | 代理连接串解析与编码 |
| `worker.py` | 持久浏览器、SOCKS5 认证转发、出口检测和指纹配置 |
| `macos/Info.plist` | 应用元数据 |
| `构建.command` | 本机构建及 worker 安装 |
| `requirements.lock` | Python 依赖版本 |
| `tests/` | 代理解析和地区匹配的针对性验证 |

## 验证

在项目根目录运行：

```sh
browser_python="$HOME/Library/Application Support/LocalFingerprintBrowser/runtime/bin/python"
"$browser_python" tests/test_region.py
mkdir -p build
swiftc ProxyConfiguration.swift tests/ProxyTests.swift -o build/proxy-tests
./build/proxy-tests
```

Python 测试使用模拟网络响应，验证地区数据校验、语言匹配、代理参数、失败不改直连，以及基础身份配置保留。Swift 测试验证支持的连接串、特殊字符及复制往返。

已在开发机器上人工验证环境隔离、持久化、WebRTC / WebGL 开关、批量粘贴和网页实际语言/时区/定位，并使用本机认证测试代理验证 HTTPS 地区查询。这些验证不代表所有供应商线路和网站都兼容。

内核及依赖来自 [Camoufox 官方项目](https://github.com/daijro/camoufox)和 PyPI，本项目没有修改或打包分发浏览器内核。
