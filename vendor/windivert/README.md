# WinDivert runtime

打包进 release zip 的 DNS 拦截驱动运行时，程序运行时通过 `libloading` 动态加载。

| 文件 | SHA-256 |
|---|---|
| `WinDivert.dll` | `31655b08f0a64f3bd48e4bd1d9a7593bb84c6f904908cbba8b6076fa58b472cf` |
| `WinDivert64.sys` | `53ab28ec00be6e6f8aefa9ee76fc2735e94d7f3f9dbc06eb2b7ac8cd3084a6af` |

取自 `BeyondDimension/SteamTools` 提交 `d04213147` 的 `ref/WinDivert.dll`、`ref/WinDivert64.sys`。
文件本身未携带版本号元数据，与上游 WattToolkit 使用的二进制完全一致；更新时请连同上表一起替换，
以保证 GitHub Actions 的发布构建可离线复现。

许可证：WinDivert 采用 LGPL v3 与 GPL v2 双许可（任选其一），见上游 `basil00/WinDivert` 的 `LICENSE`；
此处仅原样再分发运行时二进制。
