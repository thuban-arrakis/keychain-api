import Foundation
import Network

private final class RedirectBlocker: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            completionHandler(.performDefaultHandling, nil)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

final class APITransport {
    private let redirectBlocker = RedirectBlocker()
    private let session: URLSession

    init(proxy: SOCKSProxyPolicy? = nil) throws {
        let configuration = try Self.sessionConfiguration(proxy: proxy)
        session = URLSession(configuration: configuration, delegate: redirectBlocker, delegateQueue: nil)
    }

    static func sessionConfiguration(proxy: SOCKSProxyPolicy?) throws -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 45
        configuration.httpMaximumConnectionsPerHost = 2
        configuration.tlsMinimumSupportedProtocolVersion = .TLSv12
        if let proxy {
            guard #available(macOS 14.0, *) else {
                throw fail("Configured SOCKS proxy requires macOS 14 or newer; direct fallback is forbidden.", exitCode: 3)
            }
            // The endpoint is deliberately not configurable beyond its loopback port.
            var socks = ProxyConfiguration(socksv5Proxy: .hostPort(
                host: "127.0.0.1", port: NWEndpoint.Port(rawValue: proxy.port)!
            ))
            socks.allowFailover = false
            socks.excludedDomains = []
            socks.matchDomains = []
            configuration.proxyConfigurations = [socks]
        }
        return configuration
    }

    deinit {
        session.invalidateAndCancel()
    }

    private static func effectivePort(_ url: URL) -> Int {
        url.port ?? 443
    }

    static func requestURL(
        origin: URL,
        relativePath: String,
        method: String,
        operation: OperationPolicy
    ) throws -> URL {
        guard operation.permits(method: method, relativePath: relativePath),
              let relativeComponents = safeRelativeComponents(relativePath) else {
            throw fail("The request path is outside the selected policy operation.", exitCode: 2)
        }

        var targetComponents = URLComponents(url: origin, resolvingAgainstBaseURL: false)
        targetComponents?.percentEncodedPath = relativeComponents.percentEncodedPath
        targetComponents?.percentEncodedQuery = relativeComponents.percentEncodedQuery
        guard let url = targetComponents?.url,
              let finalComponents = URLComponents(url: url, resolvingAgainstBaseURL: false),
              url.scheme == origin.scheme,
              url.host == origin.host,
              effectivePort(url) == effectivePort(origin),
              url.user == nil,
              url.password == nil,
              url.fragment == nil,
              finalComponents.percentEncodedPath == relativeComponents.percentEncodedPath,
              finalComponents.percentEncodedQuery == relativeComponents.percentEncodedQuery else {
            throw fail("The request path is outside the selected policy operation.", exitCode: 2)
        }
        return url
    }

    private static func saveInterruptedResponse(_ data: Data, forbiddenSecrets: [String],
                                                output: ProtectedResponseFile?) throws {
        guard let output, !data.isEmpty else { return }
        try checkJSONCredentialEcho(data, forbiddenSecrets: forbiddenSecrets, exitCode: 5)
        if (try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])) == nil {
            // An incomplete JSON escape could conceal a credential. Refuse it rather than guess its decoded value.
            guard !data.contains(UInt8(ascii: "\\")) else {
                throw fail("The interrupted API response could not be checked safely; output was refused. Verify remote state before retrying.", exitCode: 5)
            }
        }
        _ = try output.commit(data)
    }

    func send(
        profile: ProfilePolicy,
        operation: OperationPolicy,
        method: String,
        relativePath: String,
        body: Data?,
        secrets: [String],
        secretOutput: ProtectedResponseFile? = nil
    ) async throws -> Any {
        try await send(profile: profile, operation: operation, method: method,
                       relativePath: relativePath, body: body, secrets: secrets,
                       secretOutput: secretOutput, loadResponse: { try await self.session.bytes(for: $0) })
    }

    // Keep the byte source separate so transport behavior can be exercised without a live service.
    func send<Bytes: AsyncSequence>(
        profile: ProfilePolicy,
        operation: OperationPolicy,
        method: String,
        relativePath: String,
        body: Data?,
        secrets: [String],
        secretOutput: ProtectedResponseFile? = nil,
        loadResponse: (URLRequest) async throws -> (Bytes, URLResponse)
    ) async throws -> Any where Bytes.Element == UInt8 {
        let url = try Self.requestURL(
            origin: profile.origin,
            relativePath: relativePath,
            method: method,
            operation: operation
        )
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.timeoutInterval = 30
        request.setValue(profile.mediaType.rawValue, forHTTPHeaderField: "Accept")

        for (credential, secret) in zip(profile.credentials, secrets) {
            let header = try credential.placement.requestHeader(secret: secret)
            request.setValue(header.value, forHTTPHeaderField: header.name)
        }

        try operation.body.validate(method: method, hasBody: body != nil)
        let forbiddenArtifacts = forbiddenCredentialArtifacts(profile: profile, secrets: secrets)
        if let body {
            _ = try checkedJSON(body, forbiddenSecrets: forbiddenArtifacts, exitCode: 2)
            request.httpBody = body
            request.setValue(profile.mediaType.rawValue, forHTTPHeaderField: "Content-Type")
        }

        let bytes: Bytes
        let response: URLResponse
        do {
            (bytes, response) = try await loadResponse(request)
        } catch {
            throw fail("No API response was received. A remote mutation may have succeeded; verify state before retrying.", exitCode: 5)
        }
        guard let http = response as? HTTPURLResponse,
              let responseURL = http.url,
              responseURL.scheme == profile.origin.scheme,
              responseURL.host == profile.origin.host,
              Self.effectivePort(responseURL) == Self.effectivePort(profile.origin),
              responseURL.user == nil,
              responseURL.password == nil else {
            throw fail("The API response origin did not match policy.", exitCode: 5)
        }
        guard (200...299).contains(http.statusCode) else {
            throw fail("The API rejected the request (HTTP \(http.statusCode)).", exitCode: 5)
        }

        if operation.response == .empty {
            return ["ok": true, "status": http.statusCode]
        }
        if http.expectedContentLength > maximumResponseBytes {
            throw fail("The API response exceeded the safe size limit.", exitCode: 5)
        }

        var data = Data()
        defer { data.resetBytes(in: 0..<data.count) }
        let expectedSize = http.expectedContentLength > 0 ? Int(http.expectedContentLength) : 0
        data.reserveCapacity(min(expectedSize, maximumResponseBytes))
        do {
            for try await byte in bytes {
                guard data.count < maximumResponseBytes else {
                    throw fail("The API response exceeded the safe size limit.", exitCode: 5)
                }
                data.append(byte)
            }
        } catch {
            let failure = error as? SafeFailure
                ?? fail("The API response ended unexpectedly. Check protected output and remote state before retrying.", exitCode: 5)
            try Self.saveInterruptedResponse(data, forbiddenSecrets: forbiddenArtifacts, output: secretOutput)
            throw failure
        }
        if data.isEmpty && operation.response == .jsonOrEmpty {
            guard secretOutput == nil else {
                throw fail("No secret response was saved. A remote mutation may have succeeded; verify state before retrying.", exitCode: 5)
            }
            return ["ok": true, "status": http.statusCode]
        }
        guard let mediaType = http.mimeType?.lowercased(),
              mediaType == "application/json" || mediaType.hasSuffix("+json") else {
            throw fail("The API returned an unexpected response type.", exitCode: 5)
        }
        let object = try checkedJSON(data, forbiddenSecrets: forbiddenArtifacts, exitCode: 5)
        if let secretOutput {
            return try secretOutput.commit(data)
        }
        return sanitizedAPIObject(
            object,
            forbiddenSecrets: forbiddenArtifacts,
            credentialContext: pathHasCredentialContext(relativePath)
        )
    }
}
