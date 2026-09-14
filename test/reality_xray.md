# REALITY interoperability regression (issues #4, #5 and #6)

`reality_xray.py` runs an isolated, real-payload matrix without public camouflage
servers, system Xray changes, Docker, or fixed service ports. Requirements:
Linux (prefer `ssh arch1`), uv with Python 3.10+, OpenSSL with TLS 1.3, Git, Go 1.26.4 for
sing-box, and Go 1.27.1 for the pinned Xray build. Do not enable Python `-O` (the
harness uses assertions). Build/download steps require network access; the test
matrix itself uses only loopback.

## Build and run

Run from the repository root on Linux. Keep the minimum sing-box toolchain
separate from the Xray toolchain; do not change `go.mod`, uTLS, or server source.

```sh
umask 077
work=$(mktemp -d /tmp/reality-issue6.XXXXXX)
GOTOOLCHAIN=go1.26.4 CGO_ENABLED=0 go build \
  -tags with_utls,badlinkname -ldflags=-checklinkname=0 \
  -o "$work/sing-box" ./cmd/sing-box

# Compile the unchanged pre-feature server as an independent reference.
mkdir "$work/base"
git archive 6a6a1e0a3172eb92fb1d64779776823aafaea0c3 | tar -x -C "$work/base"
(cd "$work/base" && GOTOOLCHAIN=go1.26.4 CGO_ENABLED=0 go build \
  -tags with_utls,badlinkname -ldflags=-checklinkname=0 \
  -o "$work/sing-box-base" ./cmd/sing-box)

pin=52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120
git clone https://github.com/XTLS/Xray-core.git "$work/xray-src"
git -C "$work/xray-src" checkout --detach "$pin"
test "$(git -C "$work/xray-src" rev-parse HEAD)" = "$pin"
(cd "$work/xray-src" && GOTOOLCHAIN=go1.27.1 go build \
  -ldflags "-X github.com/xtls/xray-core/core.build=$pin" -o "$work/xray" ./main)
"$work/xray" version

# kTLS requires the existing Linux TLS module to be loaded. Inspect first:
test -d /sys/module/tls && cat /proc/net/tls_stat
# If absent, obtain host-owner approval before sudo -n modprobe tls.
# Do not unload afterward on a shared host.
uv run test/reality_xray.py --sing-box "$work/sing-box" \
  --server-sing-box "$work/sing-box-base" --xray "$work/xray" --ktls
```

For cross-compilation from macOS to arch1, also set `GOOS=linux GOARCH=amd64
CGO_ENABLED=0` on both sing-box builds, copy those binaries and this Python script
to the isolated remote directory, and build Xray there. Never use `/usr/bin/xray`
as the test peer without independently verifying its source/version. The harness
checks the exact version and embedded commit; the preceding clean checkout and
build establish provenance (a version string alone is not cryptographic proof).
Without `--ktls` the non-kTLS cases run, but this does **not** complete Linux
acceptance. `--server-sing-box` may be omitted when testing an unchanged server
implementation in the new binary; the explicit baseline binary is preferred.

All listeners bind loopback with OS-assigned ports. The harness chooses unused
ports just before starting children; on a busy shared host another process can
claim a port in the short bind/release window, causing a clear test failure rather
than replacing an existing listener. Only owned child processes are terminated.
A private temporary directory contains ephemeral REALITY keys, UUID, short ID,
TLS certificate/key and configs. Successful runs remove it. Failed runs retain
it (mode 0700; files 0600) and print **only the path** for local inspection; delete
that directory after diagnosis. Do not publish its configs or raw logs. Do not
set REALITY `show`, debug build tags, or shell tracing. Remove `$work` after
collecting non-secret results; no test services remain running.

## Assertions and matrix

Each positive case sends a fresh random 256 KiB HTTP POST through SOCKS and compares the
entire echoed response. Negative ML-DSA-65 cases must reject the SOCKS request or
close/reset the connection without returning application data; timeout is a failure. A camouflage connection cannot satisfy this request:
VLESS authentication and the REALITY certificate verification gate must succeed
before the echo destination is reached. The local camouflage certificate is not
installed into system trust. The Python TLS target deliberately negotiates
X25519, proving that offering a valid hybrid share does not require hybrid final
negotiation. Its certificate includes a 5000-byte padding extension so REALITY can
mirror the larger ML-DSA-65 certificate flight. Mirrored incomplete handshakes run
on separate threads.

Xray v26.9.9 blocks loopback freedom destinations by default. Its **test-only**
`finalRules` permits exactly the temporary echo IP/port; this is not a server code
change or a recommended deployment rule.

With `--ktls`, expect 73 PASS lines (73 configurations, 107 connections: 72 payload
roundtrips and 35 authentication rejections). Without it, expect 61 PASS lines
(61 configurations, 83 connections: 48 payload roundtrips and 35 rejections).

Issue #6 adds 45 configurations (63 connections) before the regression matrix below:
Xray signing enabled, Xray signing disabled, and the unchanged sing-box server,
each crossed with absent/correct/wrong verification keys and sing-box
`default`/`chrome`/`random`/`randomized` plus the pinned Xray chrome reference client.
An absent key succeeds on every server; a configured key succeeds only with a
matching signature. The Xray `mldsa65` command generates ephemeral test keys;
its `Seed` stays in the server config and its `Verify` goes to the client.

| Client | Server | Cases |
| --- | --- | --- |
| New sing-box REALITY | Pinned Xray | default, chrome, random, randomized; default and randomized each with TX-only, RX-only, TX+RX |
| New sing-box REALITY | Pre-feature sing-box | same ten cases |
| Pinned Xray REALITY | Pinned Xray; pre-feature sing-box | chrome reference, one each |
| Ordinary sing-box uTLS | sing-box Trojan TLS | chrome, firefox, random |
| sing-box ShadowTLS v3 + Shadowsocks | sing-box ShadowTLS v3 | chrome, firefox, random |

Each REALITY `randomized` configuration keeps one client process alive for three
consecutive fresh connections, each with its own 256 KiB payload in positive cases.
Negative cases exercise all three rejections instead. No connection is
retried, and PASS is printed only after all three meet the expected outcome. This exercises repeated
handshakes with the retained process-wide seed; it does not assert fingerprint
variation or sample every possible seed. All other configurations use one connection.
Ordinary uTLS and ShadowTLS retain their existing chrome/firefox/random matrix.

Every requested kTLS direction must emit exactly one successful
`ktls: kernel TLS TX/RX enabled` event **and** complete the payload roundtrip for
that iteration. Only log bytes appended after that iteration starts are checked;
earlier connections cannot satisfy later checks. Configuration acceptance or
fallback to userspace is insufficient. On an idle host these 24 kTLS connections
increase `TlsTxSw` and `TlsRxSw` by 16 each, with no decrypt errors. Counters are
supplementary, since other users may share them.

The complementary Go tests capture final ClientHello bytes, independently
validate authentication AEAD, and assert zero writes for invalid input:

```sh
GOTOOLCHAIN=go1.26.4 go test -race -tags with_utls ./common/tls -count=1
GOTOOLCHAIN=go1.26.4 go vet -tags with_utls ./common/tls
GOTOOLCHAIN=go1.26.4 golangci-lint run ./common/tls/...
```

The issue #4 integration run on arch1 (Linux 7.2.4, sing-box Go 1.26.4, Xray Go
1.27.1) passed all 20 cases, including the independently compiled base server.
No server, dependency or system binary was modified. The previously unloaded
`tls` module was loaded with host-owner approval and left loaded.

## Fixed upstream sources

- [Xray-core v26.9.9 handshake/authentication](https://github.com/XTLS/Xray-core/blob/52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120/transport/internet/reality/reality.go)
- [Its REALITY key-share checks](https://github.com/XTLS/REALITY/blob/8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8/tls.go)
- [REALITY ML-DSA-65 signer](https://github.com/XTLS/REALITY/blob/8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8/handshake_server_tls13.go)
- [CIRCL v1.6.5 public ML-DSA-65 API](https://github.com/cloudflare/circl/blob/cfa7c70defd831ffb0792ab2af560bfef43d60ca/sign/mldsa/mldsa65/dilithium.go)
- MetaCubeX/uTLS v1.8.7 (`u_parrots.go`, `u_conn.go`, `u_public.go`); leave pinned.

On 2026-09-14, the expanded issue #5 matrix passed all 28 configurations and 44
payload connections on arch1, including all randomized repetitions and requested
kTLS directions. The run reused the user's existing Xray binary; its version,
source checkout and Go build metadata all identified the pinned commit above, with
`vcs.modified=false`. The independent sing-box
server was built from `6a6a1e0a3172eb92fb1d64779776823aafaea0c3` with Go 1.26.4.
The client used the corrected sources committed as `18dfab3a`, built before that
commit was finalized; its build metadata therefore reads `a56e0c79` with
`vcs.modified=true`. Its SHA-256 was
`de8ce47893ee0177e4d96f5f871969417babe6107db0c04921eccd1bd75a068f`,
matching the local build and remote tested binary. No system Xray, existing service,
or pre-existing Xray build directory was modified.

REALITY `randomized` builds a fresh spec per handshake with the same process-wide
seed initialized by ordinary uTLS, including across configuration clones and
sequential connections.
It constrains hybrid `supported_groups`/`key_share` ordering before native uTLS key
generation while retaining optional P-256 choices and ordinary shared weights.
Every successfully generated hello must be compliant. Unexpected TLS 1.2 generator
output fails before writes, without retries or fallback. This is random generation,
not browser impersonation; explicit fingerprints and `random` retain their behavior.

This does not cover VLESS Vision/splice or every ordinary browser fingerprint's full
handshake. Wire tests separately cover final ClientHello compliance, authentication,
deterministic randomized seeds, clone/connection seed retention, and invalid-input
zero writes. `reality_client_mldsa_test.go` exercises the public handshake and Clone
with missing, malformed, misplaced and tampered signatures, wrong keys, mutated
Hello inputs and base authentication failures. Its independent TLS 1.3 fixture
rebuilds CertificateVerify/Finished, checks client Finished and echoes real payload.
A subprocess trusts the fallback certificate and still asserts that no proxy
connection is returned after additional authentication fails.

## Issue #6 validation record

On 2026-09-14, arch1 (Linux 7.2.4-arch1-2) passed all 73 configurations and 107
connections with `--ktls`. Xray's existing checkout and binary identified the
pinned commit above, with `vcs.modified=false`; the independent sing-box server
remained the pre-feature `6a6a1e0a` build. No existing services or binaries were
modified and the TLS module was already loaded. The tested client was built with
Go 1.26.4 from this issue's working tree over `9844cc00` (`vcs.modified=true`). Its
local and remote SHA-256 matched:
`4e827990dd817005e42e8d6e084335a2079c57ca4b098c265b333932914b3285`.

Minimum-toolchain checks on macOS arm64:

- `go mod verify` passed; the resolved graph selects CIRCL v1.6.5 (Go 1.25.0)
  and unchanged uTLS v1.8.7. The root Go directive remains 1.26.4.
- Full `common/tls` race tests, `go vet -tags with_utls ./common/tls ./option`,
  and `golangci-lint run ./common/tls/...` passed.
- The full root suite with `with_utls,badlinkname` and `-checklinkname=0` passed.
  Linux amd64 with-uTLS and macOS without-uTLS command builds passed.
- The full root suite and command build with release tags were attempted but
  blocked by the missing embedded `service/admin_panel/dist` directory. The same
  build failure was reproduced in a clean archive of baseline `9844cc00`.
- Lint including `option` reports four unchanged findings in `ssh.go`, `call.go`,
  `resolved.go` and `rule_nested.go`; all four reproduce at the baseline.
- Full schema generation fails on the existing unmapped `badoption.Regexp` at
  `Options.endpoints.VPNClientEndpointOptions.outbound.GroupCommonOption.exclude`,
  also reproduced at the baseline. The localized schema edit exactly matches
  separately generated `OutboundRealityOptions`; JSON parsing passed.
- The separate `test` module cannot run as checked out: it requests `go.mod`
  updates and declares unavailable sibling `sing-mux`/`rmux` replacements.
  The clean baseline also fails on the missing sibling module. An isolated
  `go list -mod=mod -m all` probe of the current test module reaches that same
  missing replacement, so the required module updates remain unverified; they
  are not established to be entirely pre-existing. No nested module settings
  were changed; the standalone Linux matrix above did run.

These blockers prevent claiming a fully green release-tag or nested-module suite.

## 中文执行说明

此脚本用于 issue #4、#5 和 #6 的隔离互通回归，Python 脚本通过 uv 执行。
优先在 `arch1` 上执行上述命令：本项目用
Go 1.26.4，固定 Xray v26.9.9 提交用 Go 1.27.1；不得升级 uTLS、修改服务端、替换
系统 Xray 或重启已有服务。macOS 交叉编译时明确指定 `GOOS=linux GOARCH=amd64`。

测试仅使用本机回环地址、临时端口、临时密钥和自签名伪装站点，无需公网目标。
Xray 的测试配置仅放行临时 echo 地址和端口，以免新版默认的本地地址限制拦截载荷。
成功场景检查 256 KiB 随机载荷完整往返；拒绝场景必须拒绝 SOCKS 请求或关闭连接，
不得返回应用数据，超时算失败。每个 REALITY `randomized` 配置在同一个
客户端进程中连续建立三次独立连接，不重试，全部符合预期才输出该配置的 PASS。
这验证同一进程级 seed 的连续握手，不要求各次指纹不同，也不覆盖所有可能的 seed。
开启 `--ktls` 后，default 和 randomized 均覆盖 TX-only、RX-only、TX+RX；每次迭代
只检查该次开始后新增的日志，每个启用方向必须恰有一个成功事件，早先连接的事件不能
满足后续检查，不允许以用户态回退冒充 kTLS 成功。

完整验收应输出 73 项 PASS（107 次连接：72 次载荷往返、35 次认证拒绝）；
不加 `--ktls` 时为 61 项 PASS（83 次连接）。issue #6 新增 45 个配置、63 次连接，
交叉验证 Xray 签名开关、未改动的 sing-box 服务端、未配置/正确/错误验证公钥，以及
四类 sing-box 指纹和固定 Xray chrome 参考客户端。伪装证书增加 5000 字节扩展，
以容纳签名证书的镜像长度。另保留普通 uTLS 和 ShadowTLS v3 回归。
后两者仍仅使用 chrome/firefox/random。建议用 `--server-sing-box` 指定独立编译的
功能前基线服务端。24 次 kTLS 连接在空闲主机上应使 `TlsTxSw` 和 `TlsRxSw` 各增加
16，无解密错误；共享计数器仅作辅助证据。

kTLS 模块若未加载，先获得主机所有者授权再执行 `sudo -n modprobe tls`；共享主机上
不要在测试后卸载模块。成功时脚本自动删除临时认证材料；失败时保留权限受限的目录
并只输出路径，供本地检查后删除。不要分享配置或原始日志，不要开启 `show`、debug
构建标签或 shell tracing。所有自建进程均由脚本停止；构建目录需要手工清理。

2026-09-14，issue #5 扩展矩阵在 arch1 通过全部 28 个配置、44 次载荷连接，包括
randomized 的所有连续连接及要求的 kTLS 方向。测试复用了用户提供的 Xray 二进制，
版本信息与源码 checkout 均确认固定提交；本项目基线服务端从 `6a6a1e0a` 独立构建。
客户端使用后来提交为 `18dfab3a` 的修正源码，在提交更新前构建，因此版本元数据仍为
`a56e0c79` 且 `vcs.modified=true`。本地与远端二进制的 SHA-256 一致，见上方英文记录。
未修改系统 Xray、已有服务或既有 Xray 构建目录。
REALITY `randomized` 每次握手生成独立 spec，保留普通 uTLS 初始化的进程级 seed，
配置克隆和连续连接不重新播种；在 uTLS 原生密钥生成前约束混合组及 share 顺序，
保留可选 P-256、普通共享权重、显式指纹及 `random` 行为。成功生成的 ClientHello
必须合规；意外 TLS 1.2 输出在发送前报错，不重试或回退，不代表浏览器仿冒。
issue #6 的完整 73 项矩阵已在 arch1 通过，最低 Go 1.26.4 的完整 TLS race 测试、
基础标签根模块全套测试及相关 vet/lint 通过；release 标签构建/测试、完整 schema
生成和嵌套 test 模块仍有上述既有阻碍，详情见英文验证记录。
ML-DSA-65 的缺失/篡改签名、Hello 篡改、Clone 和可信证书回退仍拒绝代理连接，
由新增公开握手测试覆盖。Vision/splice 不在本测试范围。最终 ClientHello 合规性、认证、确定性 seed、
克隆与连接的 seed 保留及无效输入零发送，由 `common/tls/reality_client_test.go`
的线级测试另行验证。
