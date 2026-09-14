# REALITY interoperability regression (issue #4)

`reality_xray.py` runs an isolated, real-payload matrix without public camouflage
servers, system Xray changes, Docker, or fixed service ports. Requirements:
Linux (prefer `ssh arch1`), Python 3.10+, OpenSSL with TLS 1.3, Git, Go 1.26.4 for
sing-box, and Go 1.27.1 for the pinned Xray build. Do not enable Python `-O` (the
harness uses assertions). Build/download steps require network access; the test
matrix itself uses only loopback.

## Build and run

Run from the repository root on Linux. Keep the minimum sing-box toolchain
separate from the Xray toolchain; do not change `go.mod`, uTLS, or server source.

```sh
umask 077
work=$(mktemp -d /tmp/reality-issue4.XXXXXX)
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
python3 test/reality_xray.py --sing-box "$work/sing-box" \
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

Each case sends a fresh random 256 KiB HTTP POST through SOCKS and compares the
entire echoed response. A camouflage connection cannot satisfy this request:
VLESS authentication and the REALITY certificate verification gate must succeed
before the echo destination is reached. The local camouflage certificate is not
installed into system trust. The Python TLS target deliberately negotiates
X25519, proving that offering a valid hybrid share does not require hybrid final
negotiation. Mirrored incomplete handshakes run on separate threads.

Xray v26.9.9 blocks loopback freedom destinations by default. Its **test-only**
`finalRules` permits exactly the temporary echo IP/port; this is not a server code
change or a recommended deployment rule.

With `--ktls`, expect 20 PASS lines:

| Client | Server | Cases |
| --- | --- | --- |
| New sing-box REALITY | Pinned Xray | default, chrome, random; default TX-only, RX-only, TX+RX |
| New sing-box REALITY | Pre-feature sing-box | same six cases |
| Pinned Xray REALITY | Pinned Xray; pre-feature sing-box | chrome reference, one each |
| Ordinary sing-box uTLS | sing-box Trojan TLS | chrome, firefox, random |
| sing-box ShadowTLS v3 + Shadowsocks | sing-box ShadowTLS v3 | chrome, firefox, random |

Every requested kTLS direction must emit its successful per-connection
`ktls: kernel TLS TX/RX enabled` event **and** complete the payload roundtrip;
configuration acceptance or fallback to userspace is insufficient. On an idle
host these six connections increase `TlsTxSw` and `TlsRxSw` by four each, with no
decrypt errors. Counters are supplementary, since other users may share them.

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
- MetaCubeX/uTLS v1.8.7 (`u_parrots.go`, `u_conn.go`, `u_public.go`); leave pinned.

This does not cover ML-DSA-65 authentication, upgraded randomized generation,
VLESS Vision/splice, or every ordinary browser fingerprint's full handshake.
These are not claimed by the matrix. Wire tests separately cover the supported
ordinary uTLS fingerprint list and deterministic randomized seeds.

## 中文执行说明

此脚本用于 issue #4 的隔离互通回归。优先在 `arch1` 上执行上述命令：本项目用
Go 1.26.4，固定 Xray v26.9.9 提交用 Go 1.27.1；不得升级 uTLS、修改服务端、替换
系统 Xray 或重启已有服务。macOS 交叉编译时明确指定 `GOOS=linux GOARCH=amd64`。

测试仅使用本机回环地址、临时端口、临时密钥和自签名伪装站点，无需公网目标。
Xray 的测试配置仅放行临时 echo 地址和端口，以免新版默认的本地地址限制拦截载荷。
每项检查 256 KiB 随机载荷完整往返；开启 `--ktls` 后，还必须看到每个连接对应的
TX/RX 启用事件，不允许以用户态回退冒充 kTLS 成功。完整验收应输出 20 项 PASS，
覆盖新客户端到两类服务端、固定 Xray 客户端到两类服务端、普通 uTLS 和 ShadowTLS
v3 回归。建议用 `--server-sing-box` 指定独立编译的功能前基线服务端。

kTLS 模块若未加载，先获得主机所有者授权再执行 `sudo -n modprobe tls`；共享主机上
不要在测试后卸载模块。成功时脚本自动删除临时认证材料；失败时保留权限受限的目录
并只输出路径，供本地检查后删除。不要分享配置或原始日志，不要开启 `show`、debug
构建标签或 shell tracing。所有自建进程均由脚本停止；构建目录需要手工清理。

arch1 上上述 20 项（含独立基线服务端与真实 kTLS）已全部通过。ML-DSA-65、randomized
生成升级及 Vision/splice 不在本测试范围；最终 ClientHello 合规性与无效输入零发送由
`common/tls/reality_client_test.go` 的线级测试另行验证。
