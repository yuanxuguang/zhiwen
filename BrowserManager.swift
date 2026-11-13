import SwiftUI
import AppKit
import Security

struct ExitRegion: Codable, Equatable {
    var ip: String
    var countryCode: String
    var countryName: String
    var region: String
    var city: String
    var locale: String
    var timezone: String
    var latitude: Double
    var longitude: Double
    var location: String { [countryName, region, city].filter { !$0.isEmpty }.joined(separator: " · ") }
}

struct BrowserEnvironment: Codable, Identifiable, Equatable {
    var id = UUID().uuidString
    var name: String
    var startURL = "https://www.google.com/"
    var locale = "ja-JP"
    var timezone = "Asia/Tokyo"
    var canvasNoise = true
    var webgl = true
    var blockWebRTC = true
    var proxyType = "direct"
    var proxyHost = ""
    var proxyPort = ""
    var proxyUsername = ""
    // 0.1 profiles predate automatic matching. Missing keys opt into the new default.
    var autoRegion: Bool?
    var lastRegion: ExitRegion?
    var matchesExit: Bool {
        get { autoRegion ?? true }
        set { autoRegion = newValue }
    }

    mutating func apply(_ proxy: ProxyConfiguration) {
        proxyType = proxy.kind; proxyHost = proxy.host; proxyPort = proxy.port; proxyUsername = proxy.username
        lastRegion = nil
    }
}

enum PasswordStore {
    static let service = "local.fingerprint.browser.proxy"
    static func query(_ id: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service, kSecAttrAccount as String: id]
    }
    static func load(_ id: String) throws -> String {
        var q = query(id)
        q[kSecReturnData as String] = true
        var item: CFTypeRef?
        let code = SecItemCopyMatching(q as CFDictionary, &item)
        if code == errSecItemNotFound { return "" }
        guard code == errSecSuccess, let data = item as? Data,
              let value = String(data: data, encoding: .utf8) else { throw failure(code) }
        return value
    }
    static func save(_ id: String, _ value: String) throws {
        let q = query(id)
        if value.isEmpty {
            let code = SecItemDelete(q as CFDictionary)
            if code != errSecSuccess && code != errSecItemNotFound { throw failure(code) }
            return
        }
        let attrs = [kSecValueData as String: Data(value.utf8)]
        let code = SecItemUpdate(q as CFDictionary, attrs as CFDictionary)
        if code == errSecItemNotFound {
            let insert = SecItemAdd(q.merging(attrs) { _, new in new } as CFDictionary, nil)
            if insert != errSecSuccess { throw failure(insert) }
        } else if code != errSecSuccess { throw failure(code) }
    }
    static func failure(_ code: OSStatus) -> NSError {
        NSError(domain: "钥匙串", code: Int(code), userInfo: [NSLocalizedDescriptionKey:
            "无法读取或保存代理密码：\(SecCopyErrorMessageString(code, nil) as String? ?? String(code))"])
    }
}

final class Manager: ObservableObject {
    static let shared = Manager()
    let root = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("LocalFingerprintBrowser", isDirectory: true)
    @Published var environments: [BrowserEnvironment] = []
    @Published var selected: String?
    @Published var states: [String: String] = [:]
    @Published var running: Set<String> = []
    @Published var checking: Set<String> = []
    @Published var error: String?
    @Published var logs: [String: String] = [:]
    private var processes: [String: Process] = [:]
    private var inputPipes: [String: Pipe] = [:]
    private var buffers: [String: Data] = [:]
    private var secrets: [String: String] = [:]
    var dataDirectory: URL { root.appendingPathComponent("data", isDirectory: true) }
    var registry: URL { dataDirectory.appendingPathComponent("environments.json") }

    init() {
        do {
            try FileManager.default.createDirectory(at: dataDirectory, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            if FileManager.default.fileExists(atPath: registry.path) {
                environments = try JSONDecoder().decode([BrowserEnvironment].self, from: Data(contentsOf: registry))
                var updated = environments
                for index in updated.indices where ["https://muse.ai/", "https://muse.ai"].contains(updated[index].startURL) {
                    updated[index].startURL = "https://www.google.com/"
                }
                if updated != environments { try persist(updated) }
                selected = environments.first?.id
            }
        } catch { self.error = "加载环境失败：\(error.localizedDescription)" }
    }
    func persist(_ items: [BrowserEnvironment]) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(items).write(to: registry, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: registry.path)
        environments = items
    }
    func create() {
        do {
            let item = BrowserEnvironment(name: "环境 \(environments.count + 1)")
            try persist(environments + [item]); selected = item.id
        } catch { self.error = error.localizedDescription }
    }
    func importProxies(_ proxies: [ProxyConfiguration], template: BrowserEnvironment) throws {
        var count = 0
        do {
            for proxy in proxies {
                var item = template
                item.id = UUID().uuidString; item.name = "代理环境 \(environments.count + 1)"
                item.apply(proxy)
                try validate(item)
                try PasswordStore.save(item.id, proxy.password)
                try persist(environments + [item])
                selected = item.id; count += 1
            }
        } catch {
            throw NSError(domain: "导入", code: 1, userInfo: [NSLocalizedDescriptionKey:
                "已导入 \(count) 个环境，后续导入失败：\(error.localizedDescription)"])
        }
    }
    func validate(_ e: BrowserEnvironment) throws {
        func invalid(_ message: String) -> NSError {
            NSError(domain: "设置", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
        }
        guard !e.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw invalid("请填写环境名称。") }
        guard TimeZone(identifier: e.timezone) != nil else { throw invalid("请选择有效时区。") }
        if !e.startURL.isEmpty {
            guard let u = URL(string: e.startURL), ["https", "http"].contains(u.scheme), u.host != nil else {
                throw invalid("启动网址需要以 https:// 或 http:// 开头。")
            }
        }
        if e.proxyType != "direct" {
            guard !e.proxyHost.isEmpty, !e.proxyHost.contains("://"), !e.proxyHost.contains("/"),
                  !e.proxyHost.contains("@"), !e.proxyHost.contains(where: { $0.isWhitespace }),
                  let port = Int(e.proxyPort), (1...65535).contains(port) else {
                throw invalid("代理主机只填写域名或 IP，端口填写 1–65535 的数字。")
            }
        }
    }
    func save(_ item: BrowserEnvironment, password: String) throws {
        guard !running.contains(item.id) else { throw NSError(domain: "设置", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "请先关闭该环境，再修改配置。"] ) }
        try validate(item)
        if item.proxyType == "socks5" && !item.proxyUsername.isEmpty && password.isEmpty {
            throw NSError(domain: "设置", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "SOCKS5 账号认证需要填写密码。"])
        }
        try PasswordStore.save(item.id, password)
        guard let index = environments.firstIndex(where: { $0.id == item.id }) else {
            throw NSError(domain: "环境", code: 1, userInfo: [NSLocalizedDescriptionKey: "找不到该环境。"])
        }
        var items = environments; items[index] = item; try persist(items)
    }
    func redact(_ text: String, id: String) -> String {
        guard let secret = secrets[id], !secret.isEmpty else { return text }
        return text.replacingOccurrences(of: secret, with: "[已隐藏]")
    }
    func appendLog(_ text: String, id: String) {
        logs[id] = String(((logs[id] ?? "") + redact(text, id: id)).suffix(10000))
    }
    func launch(_ e: BrowserEnvironment, action: String = "launch") {
        guard processes[e.id] == nil else { return }
        do {
            try validate(e)
            let python = root.appendingPathComponent("runtime/bin/python")
            guard FileManager.default.isExecutableFile(atPath: python.path) else {
                throw NSError(domain: "运行环境", code: 1, userInfo: [NSLocalizedDescriptionKey: "找不到本机运行环境，请检查 Application Support/LocalFingerprintBrowser。"])
            }
            let password = try PasswordStore.load(e.id)
            secrets[e.id] = password
            var spec = try JSONSerialization.jsonObject(with: JSONEncoder().encode(e)) as! [String: Any]
            spec["proxyPassword"] = password
            spec["autoRegion"] = e.matchesExit
            spec["action"] = action
            let process = Process(), input = Pipe(), output = Pipe(), errors = Pipe()
            process.executableURL = python
            process.arguments = ["-u", root.appendingPathComponent("worker.py").path,
                dataDirectory.appendingPathComponent(e.id).path]
            process.currentDirectoryURL = root
            process.standardInput = input; process.standardOutput = output; process.standardError = errors
            var childEnv = ProcessInfo.processInfo.environment
            // Each environment owns its proxy; the app never silently inherits a shell proxy.
            for key in Array(childEnv.keys) where key.lowercased().contains("proxy") { childEnv.removeValue(forKey: key) }
            process.environment = childEnv
            buffers[e.id] = Data(); logs[e.id] = ""
            output.fileHandleForReading.readabilityHandler = { [weak self] handle in
                let data = handle.availableData
                if data.isEmpty { handle.readabilityHandler = nil; return }
                DispatchQueue.main.async { self?.consume(data, id: e.id) }
            }
            errors.fileHandleForReading.readabilityHandler = { [weak self] handle in
                let data = handle.availableData
                if data.isEmpty { handle.readabilityHandler = nil; return }
                if let text = String(data: data, encoding: .utf8) {
                    let safeText = password.isEmpty ? text : text.replacingOccurrences(of: password, with: "[已隐藏]")
                    DispatchQueue.main.async { self?.appendLog(safeText, id: e.id) }
                }
            }
            process.terminationHandler = { [weak self] p in
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.processes.removeValue(forKey: e.id); self.inputPipes.removeValue(forKey: e.id)
                    self.running.remove(e.id); self.secrets.removeValue(forKey: e.id)
                    self.checking.remove(e.id)
                    if p.terminationStatus == 0 {
                        self.states[e.id] = action == "detect" ? "检测结束，结果见上次检测" : "已关闭，登录数据已保留"
                    }
                    else if self.states[e.id] != "启动失败" {
                        self.states[e.id] = "异常退出（\(p.terminationStatus)），请查看运行详情"
                    }
                }
            }
            try process.run()
            processes[e.id] = process; inputPipes[e.id] = input; running.insert(e.id); states[e.id] = "启动中…"
            if action == "detect" { checking.insert(e.id) }
            var data = try JSONSerialization.data(withJSONObject: spec); data.append(10)
            try input.fileHandleForWriting.write(contentsOf: data)
        } catch { self.error = error.localizedDescription }
    }
    func consume(_ data: Data, id: String) {
        buffers[id, default: Data()].append(data)
        while let index = buffers[id]?.firstIndex(of: 10) {
            let line = buffers[id]!.prefix(upTo: index)
            buffers[id]!.removeSubrange(...index)
            guard let event = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
                  let type = event["event"] as? String else {
                appendLog(String(decoding: line, as: UTF8.self) + "\n", id: id); continue
            }
            switch type {
            case "ready": states[id] = "运行中"
            case "closed": states[id] = checking.contains(id) ? "正在结束检测…" : "正在保存并关闭…"
            case "status": states[id] = event["message"] as? String
            case "region":
                do {
                    guard let object = event["result"], let index = environments.firstIndex(where: { $0.id == id }) else {
                        throw NSError(domain: "地区", code: 1, userInfo: [NSLocalizedDescriptionKey: "地区检测结果缺少所属环境。"])
                    }
                    let region = try JSONDecoder().decode(ExitRegion.self, from: JSONSerialization.data(withJSONObject: object))
                    var items = environments
                    items[index].locale = region.locale; items[index].timezone = region.timezone; items[index].lastRegion = region
                    try persist(items)
                } catch {
                    self.error = "保存出口地区失败：\(error.localizedDescription)"
                    stop(id)
                }
            case "error":
                states[id] = "启动失败"
                let message = redact(event["message"] as? String ?? "浏览器报告了无法解析的错误", id: id)
                appendLog(message + "\n", id: id); error = message
            case "navigation_error":
                appendLog("页面加载失败：" + (event["message"] as? String ?? "未知响应") + "\n", id: id)
                states[id] = "浏览器已打开，页面加载失败"
            case "proxy_error":
                appendLog((event["message"] as? String ?? "无法解析代理错误") + "\n", id: id)
            default: appendLog("未知事件：\(type)\n", id: id)
            }
        }
    }
    func stop(_ id: String) {
        guard let pipe = inputPipes[id] else { return }
        do {
            try pipe.fileHandleForWriting.write(contentsOf: Data("stop\n".utf8))
            states[id] = "正在保存并关闭…"
        } catch { self.error = "关闭失败：\(error.localizedDescription)" }
    }
    func shutdown() { for id in Array(inputPipes.keys) { stop(id) } }
}

struct EnvironmentEditor: View {
    @ObservedObject var manager: Manager
    @State var draft: BrowserEnvironment
    @State private var password = ""
    @State private var savedMessage = ""
    private var isRunning: Bool { manager.running.contains(draft.id) }

    private func pasteProxy(multiple: Bool) {
        do {
            guard let text = NSPasteboard.general.string(forType: .string) else {
                throw NSError(domain: "剪贴板", code: 1, userInfo: [NSLocalizedDescriptionKey: "剪贴板中没有代理文本。"])
            }
            let lines = text.split(whereSeparator: { $0.isNewline }).map(String.init).filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            guard !lines.isEmpty, multiple || lines.count == 1 else {
                throw NSError(domain: "剪贴板", code: 1, userInfo: [NSLocalizedDescriptionKey: "复制了多条代理，请点击「批量粘贴」，每条会新建一个环境。"])
            }
            let proxies = try lines.map { try ProxyConfiguration.parse($0, defaultKind: draft.proxyType) }
            if multiple {
                try manager.importProxies(proxies, template: draft)
            } else {
                draft.apply(proxies[0]); password = proxies[0].password
                savedMessage = "已填入代理，点击检测或保存"
            }
        } catch { manager.error = error.localizedDescription }
    }

    private func copyProxy() {
        do {
            try manager.validate(draft)
            let proxy = ProxyConfiguration(kind: draft.proxyType, host: draft.proxyHost,
                port: draft.proxyPort, username: draft.proxyUsername, password: password)
            NSPasteboard.general.clearContents()
            guard NSPasteboard.general.setString(proxy.connectionString, forType: .string) else {
                throw NSError(domain: "剪贴板", code: 1, userInfo: [NSLocalizedDescriptionKey: "无法写入剪贴板。"])
            }
            savedMessage = "代理连接串已复制（包含密码）"
        } catch { manager.error = error.localizedDescription }
    }
    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .center) {
                VStack(alignment: .leading, spacing: 5) {
                    Text(draft.name).font(.title2.bold())
                    Text(manager.states[draft.id] ?? "未运行").font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                if isRunning {
                    Button(manager.checking.contains(draft.id) ? "取消检测" : "关闭环境", systemImage: "stop.fill") { manager.stop(draft.id) }
                } else {
                    Button("保存并打开", systemImage: "play.fill") {
                        do { try manager.save(draft, password: password); manager.launch(draft) }
                        catch { manager.error = error.localizedDescription }
                    }.buttonStyle(.borderedProminent)
                }
            }.padding(24)
            Divider()
            Form {
                Section("环境") {
                    TextField("名称", text: $draft.name)
                    TextField("启动网址", text: $draft.startURL)
                    Toggle("按出口 IP 自动匹配地区", isOn: $draft.matchesExit)
                    Picker("语言", selection: $draft.locale) {
                        Text("日本語").tag("ja-JP")
                        Text("简体中文").tag("zh-CN")
                        Text("English (US)").tag("en-US")
                        if !["ja-JP", "zh-CN", "en-US"].contains(draft.locale) {
                            Text(draft.locale).tag(draft.locale)
                        }
                    }.disabled(draft.matchesExit)
                    Picker("时区", selection: $draft.timezone) {
                        Text("日本 · 东京").tag("Asia/Tokyo")
                        Text("中国 · 上海").tag("Asia/Shanghai")
                        Text("美国 · 洛杉矶").tag("America/Los_Angeles")
                        Text("美国 · 纽约").tag("America/New_York")
                        Text("英国 · 伦敦").tag("Europe/London")
                        if !["Asia/Tokyo", "Asia/Shanghai", "America/Los_Angeles", "America/New_York", "Europe/London"].contains(draft.timezone) {
                            Text(draft.timezone).tag(draft.timezone)
                        }
                    }.disabled(draft.matchesExit)
                    if draft.matchesExit {
                        Text("每次启动先检测出口，匹配语言、时区、国家和 IP 大致位置；检测失败会停止启动。动态住宅线路若每次请求换 IP，请在供应商处设置粘性会话。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if let region = draft.lastRegion {
                        LabeledContent("上次检测出口", value: region.ip).textSelection(.enabled)
                        LabeledContent("地区", value: region.location)
                        Text("\(region.locale) · \(region.timezone)").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Section {
                    Toggle("Canvas 与 WebGL 读回保护", isOn: $draft.canvasNoise)
                    Toggle("启用 WebGL", isOn: $draft.webgl)
                    Toggle("阻止 WebRTC", isOn: $draft.blockWebRTC)
                    Text("每个环境独立保存指纹和登录数据。修改语言、时区或保护选项会生成新的指纹配置，登录数据仍保留。")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("阻止 WebRTC 可避免它泄露网络地址，也会影响网页音视频通话。")
                        .font(.caption).foregroundStyle(.secondary)
                } header: { Text("指纹") }
                Section {
                    HStack {
                        Button("粘贴代理", systemImage: "doc.on.clipboard") { pasteProxy(multiple: false) }
                        Button("批量粘贴") { pasteProxy(multiple: true) }
                        Button("复制代理") { copyProxy() }.disabled(draft.proxyType == "direct")
                    }
                    Text("支持 账号:密码@主机:端口、主机:端口:账号:密码，以及 http://、socks5:// 连接串。无协议时按当前方式导入，未选择时使用 HTTP；批量粘贴每行新建一个环境。")
                        .font(.caption).foregroundStyle(.secondary)
                    Picker("连接方式", selection: $draft.proxyType) {
                        Text("不设置代理").tag("direct")
                        Text("HTTP").tag("http")
                        Text("SOCKS5").tag("socks5")
                    }
                    if draft.proxyType != "direct" {
                        TextField("主机", text: $draft.proxyHost)
                        TextField("端口", text: $draft.proxyPort)
                        TextField("账号", text: $draft.proxyUsername)
                        SecureField("密码", text: $password)
                        Text("代理密码保存在 macOS 钥匙串中。代理线路与流量由你提供。")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text("使用电脑当前网络；这不等于更换公网 IP。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Button("检测出口并匹配地区", systemImage: "location.magnifyingglass") {
                        do {
                            try manager.save(draft, password: password)
                            manager.launch(draft, action: "detect")
                        } catch { manager.error = error.localizedDescription }
                    }
                    Text("检测通过当前线路访问 ipwho.is，不发送代理账号密码给地区服务。语言按出口国家的主要语言匹配；地区位置是 IP 的估算位置，不读取 Mac 真实定位，自动匹配时网页定位也使用此估算位置。")
                        .font(.caption).foregroundStyle(.secondary)
                } header: { Text("代理") }
                HStack {
                    Button("保存配置") {
                        do { try manager.save(draft, password: password); savedMessage = "已保存" }
                        catch { manager.error = error.localizedDescription }
                    }
                    Text(savedMessage).foregroundStyle(.secondary)
                }
            }.formStyle(.grouped).disabled(isRunning)
            if let log = manager.logs[draft.id], !log.isEmpty {
                DisclosureGroup("运行详情") {
                    ScrollView { Text(log).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading) }.frame(maxHeight: 140)
                }.padding([.horizontal, .bottom], 20)
            }
        }
        .onAppear {
            do { password = try PasswordStore.load(draft.id) }
            catch { manager.error = error.localizedDescription }
        }
        .onReceive(manager.$environments) { items in
            if let item = items.first(where: { $0.id == draft.id }), manager.running.contains(draft.id) {
                draft.locale = item.locale; draft.timezone = item.timezone; draft.lastRegion = item.lastRegion
            }
        }
    }
}

struct MainView: View {
    @ObservedObject var manager = Manager.shared
    var body: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                List(selection: $manager.selected) {
                    ForEach(manager.environments) { item in
                        HStack {
                            Image(systemName: "globe").foregroundStyle(.blue)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(item.name).fontWeight(.medium)
                                Text(manager.running.contains(item.id) ? "运行中" : "已关闭")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }.padding(.vertical, 5).tag(item.id)
                    }
                }
                Divider()
                Button("新建环境", systemImage: "plus") { manager.create() }
                    .buttonStyle(.borderedProminent).padding(16)
                Text("本地保存 · 无环境数量限制").font(.caption).foregroundStyle(.secondary).padding(.bottom, 16)
            }.navigationTitle("本地浏览器").navigationSplitViewColumnWidth(min: 200, ideal: 230)
        } detail: {
            if let item = manager.environments.first(where: { $0.id == manager.selected }) {
                EnvironmentEditor(manager: manager, draft: item).id(item.id)
            } else {
                VStack(spacing: 18) {
                    Image(systemName: "globe.desk.fill").font(.system(size: 54)).foregroundStyle(.blue)
                    Text("创建你的第一个环境").font(.title2.bold())
                    Text("独立登录数据、代理和指纹配置，都保存在这台 Mac 上。")
                        .foregroundStyle(.secondary)
                    Button("新建环境") { manager.create() }.buttonStyle(.borderedProminent)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(minWidth: 880, minHeight: 720)
        .alert("操作未完成", isPresented: Binding(get: { manager.error != nil }, set: { if !$0 { manager.error = nil } })) {
            Button("好") { manager.error = nil }
        } message: { Text(manager.error ?? "") }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        let manager = Manager.shared
        guard !manager.running.isEmpty else { return .terminateNow }
        manager.shutdown()
        let timer = Timer(timeInterval: 0.25, repeats: true) { timer in
            if manager.running.isEmpty { timer.invalidate(); sender.reply(toApplicationShouldTerminate: true) }
        }
        RunLoop.main.add(timer, forMode: .common)
        return .terminateLater
    }
}

@main struct FingerprintBrowserApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    var body: some Scene {
        WindowGroup("本地指纹浏览器") { MainView() }
            .windowResizability(.contentMinSize)
            .commands { CommandGroup(replacing: .newItem) {
                Button("新建环境") { Manager.shared.create() }.keyboardShortcut("n")
            } }
    }
}
