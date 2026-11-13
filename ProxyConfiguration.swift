import Foundation

struct ProxyConfiguration: Equatable {
    let kind: String
    let host: String
    let port: String
    let username: String
    let password: String

    static func parse(_ input: String, defaultKind: String) throws -> ProxyConfiguration {
        func invalid(_ reason: String) -> NSError {
            NSError(domain: "代理", code: 1, userInfo: [NSLocalizedDescriptionKey: reason])
        }
        var text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, !text.contains(where: { $0.isWhitespace }) else {
            throw invalid("请复制一整条代理，不要包含空格。多条代理请使用「批量粘贴」。")
        }
        var kind = defaultKind == "socks5" ? "socks5" : "http"
        let isURL = text.contains("://")
        if let range = text.range(of: "://") {
            kind = String(text[..<range.lowerBound]).lowercased()
            text = String(text[range.upperBound...])
        }
        guard ["http", "socks5"].contains(kind) else { throw invalid("只支持 HTTP 或 SOCKS5 代理。") }
        var username = "", password = ""
        if let at = text.lastIndex(of: "@") {
            let credentials = String(text[..<at])
            guard let colon = credentials.firstIndex(of: ":") else {
                throw invalid("账号认证格式为 账号:密码@主机:端口。")
            }
            let rawUser = String(credentials[..<colon]), rawPass = String(credentials[credentials.index(after: colon)...])
            guard let user = isURL ? rawUser.removingPercentEncoding : rawUser,
                  let pass = isURL ? rawPass.removingPercentEncoding : rawPass else {
                throw invalid("代理账号或密码中的百分号编码无效。")
            }
            username = user; password = pass
            text = String(text[text.index(after: at)...])
        } else if !text.hasPrefix("[") {
            let parts = text.split(separator: ":", maxSplits: 3, omittingEmptySubsequences: false)
            if parts.count == 4 {
                text = "\(parts[0]):\(parts[1])"; username = String(parts[2]); password = String(parts[3])
            }
        }
        guard let colon = text.lastIndex(of: ":") else { throw invalid("代理缺少端口。") }
        var host = String(text[..<colon])
        let port = String(text[text.index(after: colon)...])
        if host.hasPrefix("[") && host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        guard !host.isEmpty, !host.contains(where: { "/@?#[]".contains($0) }),
              let number = Int(port), (1...65535).contains(number) else {
            throw invalid("代理主机或端口无效，端口应为 1–65535。")
        }
        if kind == "socks5" && !username.isEmpty && password.isEmpty {
            throw invalid("SOCKS5 账号认证需要填写密码。")
        }
        return ProxyConfiguration(kind: kind, host: host, port: String(number), username: username, password: password)
    }

    var connectionString: String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))
        let auth = username.isEmpty ? "" : "\(username.addingPercentEncoding(withAllowedCharacters: allowed)!):\(password.addingPercentEncoding(withAllowedCharacters: allowed)!)@"
        let address = host.contains(":") ? "[\(host)]" : host
        return "\(kind)://\(auth)\(address):\(port)"
    }
}
