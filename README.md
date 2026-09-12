# WattToolkit-Lite

WattToolkit-Lite 是一个使用 Rust 重写 [WattToolkit (Steam++)](https://github.com/BeyondDimension/SteamTools)
**网络加速** 与 **设置** 功能的二次开发项目，仅支持 Windows。

## 功能

- **网络加速**（完整复现原项目逻辑）
  - 四种加速模式：**Hosts 文件**（默认）、**DNS 拦截**（WinDivert）、**PAC 代理**、**系统代理**
  - 本地反向代理：Hosts 模式下监听 443 端口，MITM 解密后转发到真实上游（按 SNI 动态签发叶子证书）
  - 系统代理 / PAC 模式：正向代理（CONNECT 隧道 + 绝对 URI 转发），加速域名按自定义 DNS/DoH 解析
  - 内置 Steam 商店 / 社区 / 客户端 / 创意工坊加速项目（离线内置数据，优先读取本地缓存 LOCAL_ACCELERATE）
- **证书管理**：生成 / 安装 / 删除 / 查看本地根证书（WattToolkit-Lite Certificate，有效期 300 天）
- **Hosts 管理**：编辑 / 重置 / 打开，使用独立的 WattToolkit-Lite 标记块，不与原程序冲突
- **网络检测**：NAT、DoH 延迟（阿里云 / DNSPod / Google）、IPv6、默认域名连接测试（绿/橙/红 三级）
- **设置**：通用（自动启动、托盘、GPU 等）/ 加速（默认模式、二级代理等）/ 关于
- **托盘图标**、开机自启动（注册表 HKCU Run）、代理日志、流量统计

## 与原项目的差异（按需求裁剪）

| 项目 | 说明 |
|---|---|
| 登录 / 通知消息 | 已去除 |
| 插件设置 / 已安装插件 | 已去除（加速插件始终启用，无开关 UI） |
| Steam 设置 | 已去除 |
| 关于页 | 仅保留：版本号、软件名、图标（原图标更换色调）、许可证、两个链接 |
| 平台 | 仅 Windows |
| 根证书密钥 | ECDSA P-256（原为 RSA 2048；浏览器同样信任） |
| HTTP 版本 | HTTP/1.1（未复现 HTTP/2/3） |
| 加速项目数据 | 内置 Steam 商店/社区/客户端/创意工坊 4 组（原为服务器 API + 登录；本版本无登录，离线内置，支持本地缓存 LOCAL_ACCELERATE.json） |
| DNS 拦截驱动 | 缺失 WinDivert 时该模式提示不可用，其余三种模式正常（优雅降级） |

## 构建

要求：Rust 工具链（MSVC，已验证 rustc 1.98.0）。

UI 使用 eframe/egui 0.29.1（本环境 registry 中的当前稳定版，内存占用小，符合“前端尽量小内存”的要求）。

编译产物默认放入系统临时目录，方便事后直接删除清理：

```bat
@echo off
set PATH=C:\Users\30816\.cargo\bin;%PATH%
set RUSTUP_TOOLCHAIN=1.98.0-x86_64-pc-windows-msvc
set CARGO_TARGET_DIR=%%TEMP%%\WattToolkit-Lite-target
cd /d D:\desktop\0824\Dev_Git\SteamTools\WattToolkit-Lite
cargo build --release
```

- 可执行文件：`%TEMP%\WattToolkit-Lite-target\release\wattoolkit-lite.exe`
- **清理**：构建完成后直接删除 `%TEMP%\WattToolkit-Lite-target` 整个目录即可，不留其他临时文件。
- 首次构建会自动下载依赖。原始图标 accelerator.ico 已**编译期嵌入** exe（include_bytes），换色后的 icon.png 在**首次运行**时自动生成并缓存于 %LOCALAPPDATA%\WattToolkit-Lite\cache\icon.png。

## 运行说明

- 应用数据目录：`%LOCALAPPDATA%\WattToolkit-Lite`（设置、证书、缓存、日志），与 %TEMP% 无关。
- **Hosts 模式**需要管理员权限（监听 443 + 修改 hosts 文件）；首次使用需安装证书（右侧面板“安装证书”，需管理员）。
- **DNS 拦截模式**需要 WinDivert 驱动：将 `WinDivert.dll` 放到 exe 同目录。驱动缺失时该模式会给出明确提示，其他模式不受影响。
- **系统代理 / PAC 模式**只写 HKCU 注册表，无需管理员。

## 关于页链接

- 上游项目：https://github.com/BeyondDimension/SteamTools
- 二次开发：https://github.com/your-name/WattToolkit-Lite （占位，请在 `crates/ui/src/pages/settings_page.rs` 中替换 `SECONDARY_REPO_URL`）

## 许可证

GPL-3.0-or-later（与上游一致）。
