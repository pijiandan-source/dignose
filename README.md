# dignose

`dignose` 是一个面向 Windows 10 / Windows 11 的网络环境只读诊断工具，用于帮助客服和技术支持排查客户使用加速器时遇到的基础网络环境问题。

第一版目标是：安全、只读、可解释、方便判断。工具只收集本机网络配置、DNS、Hosts、代理、端口、路由、连通性、默认网关和开发工具代理线索，不上传报告。

## 安全说明与只读声明

本工具不会执行以下操作：

- 不修改系统配置、DNS、Hosts、代理、路由或注册表
- 不重启服务，不清理 DNS 缓存，不结束进程
- 不请求管理员权限，不写入系统目录
- 不扫描整个局域网，只检测默认网关相关信息
- 不动态下载或执行远程代码
- 不上传数据，报告只保存在本地或输出到控制台

所有检测项都独立执行。某一项因为权限、命令不存在、编码、超时或系统语言差异失败时，程序会在报告中记录错误并继续运行。

## 支持系统

- Windows 10
- Windows 11
- 普通用户权限可运行
- Python 3.11 或 3.12 开发环境

## 使用方式

开发环境运行：

```powershell
python -m dignose
python -m dignose --json
python -m dignose --output .\network-report.json
```

EXE 运行：

```powershell
.\dignose.exe
.\dignose.exe --json
.\dignose.exe --output .\network-report.json
.\dignose.exe --txt .\network-report.txt
.\dignose.exe --skip-connectivity
.\dignose.exe --skip-dns-compare
```

## 参数说明

- `--json`：将完整 JSON 报告输出到控制台
- `--output PATH`：将完整 JSON 报告写入 UTF-8 文件
- `--txt PATH`：将控制台摘要写入 UTF-8 文本文件
- `--skip-connectivity`：跳过 ping 和 TCP 连通性测试
- `--skip-dns-compare`：跳过 DNS 多通道解析对比
- `--dns-compare-full`：使用完整域名列表和完整中国大陆 DNS provider 列表
- `--include-global-dns`：加入国际 UDP DNS 对照组
- `--include-global-doh`：加入国际 DoH 对照组
- `--dns-timeout SECONDS`：设置单个 DNS 查询超时时间，默认 2 秒
- `--dns-domain DOMAIN_OR_URL`：额外检测域名或 URL，可重复指定
- `--dns-provider IP`：额外检测 UDP DNS 服务器，可重复指定
- `--doh-provider URL`：额外检测 DoH endpoint，可重复指定
- `--skip-doh`：跳过 DoH 查询
- `--skip-udp-dns`：跳过第三方 UDP DNS 查询
- `--verbose`：预留详细输出参数
- `--version`：显示版本号

## 检测内容

- 系统信息：Windows 版本、架构、当前用户、管理员权限、运行路径、时间、程序版本
- 网络适配器：启用网卡、IPv4、IPv6、默认网关、DNS、网卡描述和类型判断
- Hosts：文件是否存在、是否可读、有效映射数量、关键域名映射
- DNS：DNS 服务器、本机 DNS、局域网 DNS、公共 DNS、常见域名解析测试
- DNS 多通道解析对比：本地系统 DNS、中国大陆常用 UDP DNS、中国大陆常用 DoH，以及可选国际对照
- 代理：系统 Internet 代理、WinHTTP 代理、代理环境变量
- 端口：重点只读检测本机监听端口和 PID、进程名
- 路由：IPv4 / IPv6 默认路由、网关、Metric、关联网卡
- 连通性：有限 ping 和 TCP 测试，可用 `--skip-connectivity` 跳过
- 默认网关：仅检测默认网关端口和 HTTP Header，不登录、不爆破、不扫描网段
- 开发工具代理：Git、npm、pip、Docker Desktop、WSL 相关只读线索

## DNS 多通道解析对比说明

默认 DNS 对比使用中国大陆常用 DNS / DoH，包括 AliDNS、DNSPod、114DNS、Baidu DNS、360 DoH 等。国际 DNS 如 Google、Cloudflare、Quad9 默认不启用，仅在 `--include-global-dns`、`--include-global-doh` 或 `--dns-compare-full` 下作为参考。

默认 UDP DNS：

- AliDNS `223.5.5.5`
- DNSPod / Tencent DNS `119.29.29.29`
- 114DNS `114.114.114.114`
- Baidu DNS `180.76.76.76`

默认 DoH：

- AliDNS DoH `https://dns.alidns.com/resolve`
- DNSPod DoH `https://doh.pub/dns-query`
- 360 DoH `https://doh.360.cn/dns-query`

完整模式会启用更多中国大陆 provider 和完整域名列表：

```powershell
.\dignose.exe --dns-compare-full
```

如需加入国际对照：

```powershell
.\dignose.exe --include-global-dns --include-global-doh
```

如果不希望进行外部 DNS 查询，可以运行：

```powershell
.\dignose.exe --skip-dns-compare
```

自定义域名或 URL 会先规范化为 hostname，不会把路径传给 DNS 查询函数：

```powershell
.\dignose.exe --dns-domain https://uu.163.com/api --dns-domain https://example.com:443/check
```

该检测只用于观察解析结果差异。由于 CDN、地域调度和运营商线路差异，不同 DNS 返回不同 IP 不一定代表异常。工具会优先识别明显异常，例如解析失败、返回回环地址、返回内网地址、DoH/UDP 大面积失败等。报告会使用“疑似”“可能”“检测到迹象”等描述，不直接做绝对结论。

## 控制台输出示例

```text
[DNS 多通道解析对比]
域名: uu.163.com
本地系统 DNS: 成功: 59.111.x.x
中国大陆 UDP DNS:
  AliDNS 223.5.5.5: 成功，59.111.x.x
  DNSPod Tencent 119.29.29.29: 成功，59.111.x.x
  114DNS 114.114.114.114: 成功，59.111.x.x
中国大陆 DoH:
  AliDNS DoH: 成功，59.111.x.x
  DNSPod DoH: 成功，59.111.x.x
  360 DoH: 成功，59.111.x.x
判断: 本地系统 DNS、中国大陆公共 UDP DNS、DoH 结果基本一致。
```

## JSON 示例

```json
{
  "meta": {
    "tool": "dignose",
    "version": "0.1.0",
    "readonly": true
  },
  "system": {},
  "adapters": [],
  "hosts": {},
  "dns": {},
  "dnsCompare": {
    "ok": true,
    "data": {
      "enabled": true,
      "profile": "china_default",
      "providers": {
        "system": true,
        "udpChina": [
          {
            "name": "AliDNS",
            "server": "223.5.5.5"
          }
        ],
        "dohChina": [
          {
            "name": "AliDNS DoH",
            "endpoint": "https://dns.alidns.com/resolve",
            "mode": "json_get"
          }
        ],
        "udpGlobal": [],
        "dohGlobal": []
      },
      "domains": []
    },
    "error": null
  },
  "proxy": {},
  "ports": [],
  "routes": [],
  "connectivity": [],
  "lanGateway": {},
  "devToolProxy": {},
  "risks": []
}
```

## 本地开发

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .[dev]
python -m pytest
python -m dignose --skip-connectivity
```

## 本地构建 EXE

```powershell
.\scripts\build_windows.ps1
```

构建命令使用 PyInstaller，并显式禁用 UPX：

```powershell
pyinstaller --onefile --name dignose --clean --noupx src/dignose/main.py
```

目标产物：

```text
dist/dignose.exe
```

## 远端编译

仓库包含 GitHub Actions workflow：

```text
.github/workflows/build-windows.yml
```

触发方式：

- push 到 `main`
- 手动 `workflow_dispatch`

workflow 会在 `windows-latest` runner 上安装 Python、运行测试、使用 PyInstaller 构建 `dist/dignose.exe`，并上传 `dignose-windows` artifact。

## 常见问题

### 是否需要管理员权限？

不需要。普通用户权限即可运行。部分检测项在权限不足时可能返回失败，但程序会继续输出其他结果。

### 是否会修复网络？

不会。`dignose` 只读检测，不执行修复操作。

### 是否会上传报告？

不会。报告只输出到控制台或保存到用户指定的本地文件。

### 是否会扫描我的局域网？

不会。工具只检测本机配置和默认网关相关信息，不扫描整个网段。

### DNS 多通道解析会修改系统 DNS 吗？

不会。该模块只发起有限的 DNS 查询，不修改系统 DNS、不清理缓存、不改 Hosts、不设置代理。

### 不想访问外部公共 DNS 怎么办？

可以使用 `--skip-dns-compare` 完全跳过 DNS 多通道解析对比，也可以用 `--skip-doh` 或 `--skip-udp-dns` 分别跳过 DoH 或第三方 UDP DNS。

## 杀毒误报说明

本工具为只读网络诊断工具，不会修改系统配置，不会上传数据，不会常驻后台，不会创建自启动项。由于 EXE 由 Python 打包生成，部分安全软件可能对未签名的单文件 EXE 产生误报。建议从官方 GitHub Releases 下载，并校验 SHA256。

为降低误报，项目不使用混淆、不加壳、不使用 UPX、不动态下载执行代码、不隐藏窗口执行可疑命令，并预留后续代码签名步骤。

## 当前验收标准

- 可以在 Windows 10 / Windows 11 普通用户权限下运行
- 可以通过 Python 开发环境运行
- 可以通过 GitHub Actions 构建不使用 UPX 的 `dignose.exe`
- 程序不修改系统配置、不上传数据、不隐藏执行行为
- 可以输出控制台摘要和 JSON 报告
- 可以检测 Hosts、DNS、代理、端口、路由、网关、连通性
- 默认 DNS 对比使用中国大陆常用 UDP DNS
- 默认 DoH 使用中国大陆常用 DoH
- 国际 DNS / DoH 默认不参与风险评分
- 支持通过参数启用国际 DNS / DoH 对照
- 支持网易 / 163 / 网易 UU 加速器相关域名解析对比
- 能区分“CDN 地域解析差异”和“明显异常解析”
- 能识别本地 DNS 返回内网、回环、保留 IP
- 能识别 UDP DNS 多数失败但 DoH 成功
- 能识别 DoH 多数失败但 UDP DNS 成功
- 域名输入支持 URL 规范化，不会把路径传入 DNS 查询
- 所有 DNS 查询都有 timeout
- DNS 模块失败不会影响其他检测模块
- JSON 报告中包含 `dnsCompare` 字段
- 控制台摘要能展示 DNS 对比关键差异和风险提示

