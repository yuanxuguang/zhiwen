import Foundation

@main struct ProxyTests {
    static func main() throws {
        let inputs = ["user:pass@proxy.example:1466", "http://user:pass@proxy.example:1466",
            "proxy.example:1466:user:pass", "socks5://user:pass@proxy.example:1466",
            "http://user:p%40ss%3Aword@proxy.example:1466", "socks5://user:pass@[::1]:1466",
            "user:p%ss@word@proxy.example:1466"]
        for input in inputs {
            let proxy = try ProxyConfiguration.parse(input, defaultKind: "http")
            let roundTrip = try ProxyConfiguration.parse(proxy.connectionString, defaultKind: "http")
            assert(roundTrip == proxy)
        }
        for input in ["", "user:pass@host", "host:99999", "https://host:80", "u:p@host:80\nu:p@other:80", "socks5://user:@host:80"] {
            do {
                _ = try ProxyConfiguration.parse(input, defaultKind: "http")
                fatalError("应当拒绝无效代理")
            } catch {}
        }
        let implicit = try ProxyConfiguration.parse("host:80", defaultKind: "socks5")
        assert(implicit.kind == "socks5")
        print("代理格式解析与复制往返检查通过")
    }
}
