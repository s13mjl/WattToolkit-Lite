# WattToolkit-Lite

WattToolkit-Lite 是一个使用 Rust 重写 [WattToolkit (Steam++)](https://github.com/BeyondDimension/SteamTools)
**网络加速** 与 **设置** 功能的二次开发项目，仅支持 Windows。

## 下载

从 [Releases](https://github.com/s13mjl/WattToolkit-Lite/releases) 下载最新版本：

| 文件 | 说明 |
|---|---|
| `WattToolkit-Lite-<版本>-win-x64.zip` | **推荐**：主程序 + WinDivert 运行时（DNS 拦截模式需要），解压即用 |
| `wattoolkit-lite.exe` | 仅主程序（若已有 WinDivert.dll 时可单独下载） |

> 仓库不再跟踪编译产物，`dist/` 已加入 `.gitignore`。

## 功能

- **网络加速**（复现原项目逻辑）
  - 四种加速模式：**Hosts 文件**（默认）、**DNS 拦截**（WinDivert）、**PAC 代理**、**系统代理**
  - 本地反向代理：Hosts / DNS 拦截模式下监听 443 端口，MITM 解密后转发到真实上游（按 SNI 动态签发叶子证书）
  - 系统代理 / PAC 模式：正向代理（CONNECT 隧道 + 绝对 URI 转发），加速域名按自定义 DNS/DoH 解析
  - 加速项目数据：**Steam 服务**、**Github**（对齐官方客户端的加速清单）
- **证书管理**：生成 / 安装 / 删除 / 查看本地根证书（WattToolkit-Lite Certificate，有效期 300 天，ECDSA P-256）
- **Hosts 管理**：编辑 / 重置 / 打开，使用独立的 WattToolkit-Lite 标记块，不与原程序冲突
- **网络检测**：NAT、DoH 延迟（阿里云 / DNSPod / Google）、IPv6、默认域名连接测试（绿/橙/红 三级）
- **设置**：通用（开机自启、托盘、GPU）/ 加速（默认模式、二级代理等）/ 关于
- **系统托盘**：点击窗口关闭按钮最小化到托盘（加速继续运行），托盘单击 / 双击 / 菜单均可恢复窗口
- 代理日志、流量统计

## 与原项目的差异（按需求裁剪）

| 项目 | 说明 |
|---|---|
| 登录 / 通知消息 | 已去除 |
| 插件设置 / 已安装插件 | 已去除（加速插件始终启用，无开关 UI） |
| Steam 设置 | 已去除 |
| 启动时检查更新 | 已去除（本版本不含更新器） |
| 关于页 | 仅保留：版本号、软件名、图标（原图标更换色调）、许可证、两个链接 |
| 平台 | 仅 Windows |
| 根证书密钥 | ECDSA P-256（原为 RSA 2048；浏览器同样信任） |
| HTTP 版本 | HTTP/1.1（未复现 HTTP/2/3） |
| 加速项目数据 | 离线内置（原为服务器 API + 登录）；优先读取本地缓存 LOCAL_ACCELERATE.json，缺失时使用内置清单 |
| DNS 拦截驱动 | 缺失 WinDivert 时该模式提示不可用，其余三种模式正常（优雅降级） |
| 界面框架 | eframe/egui（原为 Avalonia），内存占用更小 |

## 构建

要求：Rust 工具链（MSVC，已验证 rustc 1.98.0）。

UI 使用 eframe/egui 0.29.1；exe 图标通过 `build.rs` + `app.rc`（embed-resource）在编译期嵌入，无需安装 Windows SDK 的 rc.exe。

release 构建使用 Windows GUI 子系统，启动不会弹出控制台窗口；运行日志写入
`%LOCALAPPDATA%\WattToolkit-Lite\logs\app.log`。

```bat
cargo build --release
```

- 可执行文件：`target\release\wattoolkit-lite.exe`
- 若希望构建产物放到临时目录便于清理，可设置 `CARGO_TARGET_DIR=%TEMP%\WattToolkit-Lite-target`。
- 将 `WinDivert.dll`（及配套 `WinDivert64.sys`）放在 exe 同目录，DNS 拦截模式才可用。

## 运行说明

- 应用数据目录：`%LOCALAPPDATA%\WattToolkit-Lite`（设置、证书、缓存、日志）。
- **Hosts 模式**需要管理员权限（监听 443 + 修改 hosts 文件）；首次使用需安装证书（右侧面板“安装证书”，需管理员）。
- **DNS 拦截模式**需要管理员权限 + WinDivert 驱动；驱动缺失时该模式会给出明确提示，其他模式不受影响。
- **系统代理 / PAC 模式**只写 HKCU 注册表，无需管理员。
- 关闭窗口 = 最小化到托盘（加速继续运行）；退出请使用托盘右键菜单的“退出”。

## 关于页链接

- 上游项目：https://github.com/BeyondDimension/SteamTools
- 二次开发：https://github.com/s13mjl/WattToolkit-Lite

## 许可证

GPL-3.0-or-later（与上游一致）。
