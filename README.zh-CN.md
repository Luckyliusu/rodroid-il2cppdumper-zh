<p align="center">
  <img src="https://img.shields.io/badge/Tauri-FFC131?style=for-the-badge&logo=tauri&logoColor=black" />
  <img src="https://img.shields.io/badge/SvelteKit-FF3E00?style=for-the-badge&logo=svelte&logoColor=white" />
  <img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" />
  <img src="https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

<h1 align="center">🛡️ Rodroid Il2CppDumper — 桌面端与移动端图形界面</h1>

<p align="center">
  <b>Rodroid Il2CppDumper 引擎的现代化跨平台图形界面。</b><br/>
  基于 <a href="https://tauri.app/">Tauri 2</a>、<a href="https://kit.svelte.dev/">SvelteKit</a> 与 <a href="https://www.typescriptlang.org/">TypeScript</a> 构建 —— 可原生运行于 Windows、macOS、Linux、Android 和 iOS。
</p>

<p align="center">
  <a href="https://t.me/+WmudnO0-xoNhMDQ8">📢 Telegram 频道</a> &nbsp;·&nbsp;
  <a href="https://t.me/+QylrYL1GNsJiYjc0">💬 Telegram 群组</a> &nbsp;·&nbsp;
  <b>开发者:</b> <a href="https://t.me/rodroidmods"><code>@rodroidmods</code></a>
</p>

---
## ✨ V8.5 新特性 —— C# 反编译器（预 Alpha）

**V8.5 将最终的预 Alpha 引擎同步进图形界面。** 该反编译器在此版本被标注为**预 Alpha**；进入 Alpha 取决于 `il2cpp-dumper-rs/NEXT_STEPS.md` §0 中的工作清单。应用版本、窗口标题与引擎均为 v8.5。

引擎规模从 v8.0 的约 11.1 万行增长到**约 22.5 万行**；其中 C# 反编译器（`recovery/`）从 7.8 万行增长到 118 个文件中的**18.7 万行**。

在参考语料 Temple Run 2（`OUT_R208AC`，24,195 个方法，仅 `Assembly-CSharp`）上测得：**512,595 行 / 18.1 MB** 的 `dump.cs`，`target not emitted` 标记 **291** 处（原 6,449），原始 `*(…)` 指针访问 **36,410** 处（原 55,121），`// body not recoverable` **5** 处（原 1,248），未定义局部变量标注 **248** 行分布于 1,280 个可疑方法中，重复标签为零。在第二份语料（*Tomb of Maze*，含 `UnityEngine.CoreModule`）上，1,067 个 Unity 内部调用会渲染为 `extern` 声明而非解析器方法体。CLI、Tauri 图形界面与 Android JNI 内核共用同一套 v8.5 引擎。

V8.5 可将原生 IL2CPP 方法体恢复为可读的类 C# 输出，并与 `dump.cs` 中的元数据和类型信息并列呈现。

### v8.5 修复内容

- **Free Fire、Free Fire MAX 与 Free Fire India：** 修复了导致这些游戏转储失败的 IL2CPP **版本检测** —— 现在能被正确识别并成功转储。
- **CODM：** 修复了**完整转储**失败的问题；CODM 二进制文件现在可生成完整转储。
- **C# 反编译器（预 Alpha）：** 修复大量缺陷，恢复出的高层代码远多于旧的 v8 beta 反编译器（守卫条件展平为 `&&` 链、对象初始化器、闭包字段、out/ref 方法体、类初始化检查、尾返回三元表达式、更智能的死存储清理）。此外：Unity 内部调用渲染为 `[MethodImpl(InternalCall)] extern` 声明，不再从运行时元数据 token 凭空生成 `new T()` 行，丢失的尾值重新绑定为 `return E;`（仅此一项就恢复了 413 个此前被放弃的方法体），委托回调渲染为 `onPreCull(cam)`。
- **新增「完整转储」选项（C# 选项）：** 启用类过滤器时保留所有类型/方法；仅选中的 DLL 带方法体，其余渲染为 `{ }`。
- **类选择器：** 展开的类型列表在滚动时不再折叠（展开状态现可在列表复用后保持）。
- 桌面端/移动端/CLI 共享完全相同的 v8.5 引擎。

### 原生方法体恢复

- 为受支持的原生架构恢复类 C# 伪代码。
- 在保留单工作线程模式下相同恢复特性的同时，并行处理方法。
- 将转储聚焦于选定的程序集或类型。

### 更广的游戏与元数据兼容性

- **Free Fire 与 Free Fire MAX 内存转储：** 修复处理内存转储文件时的崩溃。
- **Unity 6000.1：** 修复一处元数据解析问题。
- **元数据版本 106.1、107 与 108：** 新增支持。
- 另含对解析、原生分析与转储生成的进一步修复。

V8 让本应用不仅能浏览 IL2CPP 的类型、字段与元数据，也能用于探索恢复出的方法逻辑。

## ✨ V7 新特性

V7 为共享引擎引入了多核转储、更清晰的错误提示与稳定性改进。V8 在此基础上加入了原生 C# 方法体恢复。

## ✨ V6.1 新特性

### 引擎
- 🐛 **修复 CODM 基于磁盘的转储因 "Auto mode failed" 崩溃** —— `CodeRegistration`/`MetadataRegistration` 结构体中被混淆的内部指针不再导致整个 `init()` 中止。启用 CODM 模式时会跳过坏指针并输出 `[WARN]`；非 CODM 游戏仍保持严格的错误传播。
- 🛡️ `load_pointers`、`load_types`、`load_generics`（ELF）以及 `Il2Cpp::init`（Mach-O/PE/NSO/WASM）中的 **CODM 条件容错**
- 🔄 **所有目标同步**：Tauri 桌面端/移动端、CLI、Android JNI —— 同一套引擎修复

---

## ✨ V6 新特性

### 引擎（与 CLI v6 相同）
- Thread-static + FieldRVA 导出（`static_metadata.json`、dump.cs 注释、DummyDll）—— **默认关闭**，请在「转储选项」中启用
- 开启静态元数据后嵌套的 FieldRVA 选项：十六进制数据开关 + 最大字节上限
- iOS 端 CODM 自动标志与 Android 对齐
- PE / Mach-O / NSO / WASM 上的 Unity 27+ FieldRva 二进制扫描
- 内存转储 CODM 二进制文件修复（镜像基址 / 转储文件路径，以及 CODM 解密）

### 界面重构（Material 3）
桌面端/移动端图形界面基于 **[noph-ui](https://www.npmjs.com/package/noph-ui)**（一套面向 Svelte 的 Material 3 组件库）重建，以贴近 Android Jetpack Compose 的观感：

- **Material 3 主题** —— `data-theme` 深色 / 浅色 / 跟随系统、动态表面容器、M3 字体与高度层级
- **迁移的界面** —— 空闲、转储中（实时日志）、结果、错误、设置、关于、启动页、崩溃、配置对话框、输入提示
- **与 Android 对齐的布局** —— 全宽「开始转储」栏、色调「转储选项」按钮、带文件夹选择器的路径卡片
- **配置对话框分区** —— 输出 · 生成 · 高级泛型 · C++ 头文件 · 反汇编 · **静态字段元数据** · 高级
- **动画** —— 卡片交错入场、嵌套开关可折叠（泛型 / 反汇编 / 静态元数据）、对话框遮罩淡入
- **自定义组件** —— `PathInput`（全宽等宽路径）、`ConfigSwitch`、`AnimatedExpand`
- **国际化（i18n）** —— 8 种语言（简体中文 ZH、EN、SQ、AR、ES、HI、ID、JV），默认简体中文

> 骨架屏 UI 已被移除，改用 noph-ui 的 M3 基础组件（`Button`、`Switch`、`TextField`、`SegmentedButton`、`ChipSet` 等）。

## ✨ V5 新特性

- 实时流式日志，逐步显示注册地址
- 配置面板中开放完整反汇编引擎
- CODM 开关、移动端文件选择器、自动识别 Unity 版本的标签

---

## 🖼️ 界面示意

```
┌─────────────────────────────────────┐
│  Rodroid IL2CPP 转储器  v8 桌面端    │
│  ─────────────────────────────────  │
│  IL2CPP 二进制文件  [路径]    [📁]   │
│  元数据文件         [路径]    [📁]   │
│  [ 转储选项 ]                        │
│  ┌───────────────────────────────┐  │
│  │  ▶  开始转储                  │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

**转储选项** 对话框分区：

- **输出** —— 方法、字段、属性、特性、偏移、typedef 索引、程序集名称、按类型拆分
- **生成** —— 结构体、DummyDLL、Token
- **高级泛型** —— 总开关 + 7 个子选项（RGCTX、MethodSpecs 等）
- **C++ 头文件** —— 脚手架、名称重整、IDA 元数据、Unity 头文件、拓扑排序、GCC/MSVC
- **反汇编** —— 输出目标（dump.cs / DiffableCs / 两者）、十六进制字节、字段名、注释、CFG、最大指令数
- **静态字段元数据** —— thread-static / FieldRVA 导出 + 嵌套 FieldRVA 十六进制 + 最大字节数
- **高级** —— 强制 IL2CPP 版本、强制转储、不重定向指针、CODM

---

## 🚀 功能特性

[il2cpp_dumper](../il2cpp_dumper/README.md) CLI 的全部能力都可通过图形界面使用：

### 核心
- IL2CPP **v16 – v39**（Unity 5.3 → Unity 6），以及元数据格式 v104、v106、v106.1、v107 和 v108
- 自动 XOR 元数据解密（1 字节、4 字节、8 字节、滚动、位置相关）
- ELF / PE / Mach-O / Fat Mach-O / NSO / WASM
- 面向 v39 / Unity 6 的可变宽度索引
- 用于恢复方法体的原生 C# 反编译器，带程序集/类型过滤器
- 自动编号的输出目录（Dump0/、Dump1/…）

### 反汇编引擎（V5 亮点）
- **后向切片** —— 将 `BLR Xn` 虚调用解析为 `// virtual call: TypeName.MethodName`
- **初始化检查折叠** —— 把 `il2cpp_codegen_initialize_method` / `Il2CppCodeGenWriteBarrier` / 基于 bit 0 的 TBZ 前言折叠为单条 `// [init check]` 注释
- **字符串字面量间接解析** —— 用实际字面内容注释 `il2cpp_string_new_wrapper` 调用
- **泛型实例化追踪** —— 用具体特化注释调用（`// → List<int>.Add(this, item)`）
- **switch 表重建** —— 检测 ARM64 跳转表并在 CFG 中生成 `switch (var)` 块
- **装箱 / 拆箱检测** —— 用解析出的类型注释 `il2cpp_codegen_box` / `il2cpp_unbox`
- **静态字段访问注释** —— 解析 `ADRP+ADD → static_fields → field_offset` 链
- 以及 V4 的全部能力：前向常量传播、寄存器对内存访问、语义变量追踪、ARM64/ARM32/x86/x64 多架构解码器

### CODM（Call of Duty Mobile）
- 自定义 v23 元数据布局，带双槽 `type_definitions_count` 指纹锚点
- Android 压缩重定位（`DT_ANDROID_RELA` / `DT_ANDROID_REL`，APS2 + SLEB128）—— 32 位与 64 位 ELF
- iOS 链式修正（`LC_DYLD_CHAINED_FIXUPS`）与旧式 rebase 操作码（`LC_DYLD_INFO_ONLY`）—— 32 位与 64 位 Mach-O
- 指针格式：`DYLD_CHAINED_PTR_64`、`_64_OFFSET`、ARM64E
- 在配置对话框的**高级**分区中开启 —— 附加代码路径，不影响标准 Unity 游戏

---

## 📦 安装

### 预编译二进制
从 [Releases](https://github.com/rodroidmods/il2cpp-dumper-rs/releases) 页面获取对应平台的最新安装包。

| 平台 | 产物 |
|----------|----------|
| Windows | `Rodroid-Il2CppDumper-setup.exe` / `.msi` |
| macOS | `Rodroid-Il2CppDumper.dmg` |
| Linux | `.AppImage` / `.deb` / `.rpm` |
| Android | `.apk` |
| iOS | `.ipa`（通过 AltStore / TrollStore 侧载） |

### 从源码构建

环境要求：
- [Node.js](https://nodejs.org/) ≥ 18 + [pnpm](https://pnpm.io/)
- [Rust](https://rustup.rs/) 稳定版工具链
- 对应操作系统的 Tauri 前置依赖 —— 参见 [Tauri 前置依赖指南](https://tauri.app/start/prerequisites/)

```bash
git clone https://github.com/rodroidmods/il2cpp-dumper-rs.git
cd il2cpp-dumper-rs/rodroid-il2cppdumper
pnpm install
```

以开发模式运行：
```bash
pnpm tauri dev
```

构建发布包：
```bash
pnpm tauri build
```

移动端目标：
```bash
pnpm tauri android init
pnpm tauri android dev      # or: pnpm tauri android build

pnpm tauri ios init
pnpm tauri ios dev          # or: pnpm tauri ios build
```

---

## 🔧 使用方法

1. 启动应用
2. **选择二进制文件** —— `libil2cpp.so`、`GameAssembly.dll`、`UnityFramework`、`.nso` 或 `.wasm`
3. **选择元数据文件** —— 通常是 `global-metadata.dat`
4. *（可选）* 打开 **转储选项** —— 启用 **静态字段元数据**、反汇编、CODM 等
5. 点击 **开始转储** —— 观察实时日志，并在自动编号的 `Dump0/`、`Dump1/`、… 目录中找到输出

---

## 🏗️ 架构

```
rodroid-il2cppdumper/
├── src/                              # SvelteKit + noph-ui（Material 3）
│   ├── lib/
│   │   ├── components/               # IdleScreen、ConfigDialog、DumpingScreen 等
│   │   ├── dumpRunner.ts             # 单次转储启动 + 日志上限
│   │   ├── dumpEvents.ts             # Tauri 事件监听器
│   │   ├── stores.ts                 # 配置、i18n、主题
│   │   └── types.ts                  # DumperConfig（含 v6 静态字段键）
│   ├── app.css                       # M3 设计令牌、对话框、动画
│   └── routes/+page.svelte           # 界面路由 + 配置对话框宿主
├── src-tauri/
│   ├── src/lib.rs                    # Tauri 命令 + v8 转储流程
│   ├── config.json                   # 默认 Rust 配置参考
│   └── Cargo.toml
└── package.json                      # 前端脚本与依赖
```

后端将 [`il2cpp_dumper`](../il2cpp_dumper) Rust crate 作为库封装，并通过 Tauri 的事件系统把进度事件流式回传给前端。

---

## 📜 许可证

MIT

---

## 🙏 致谢

- [Perfare/Il2CppDumper](https://github.com/Perfare/Il2CppDumper) —— 原始 C# 实现
- [SamboyCoding/Cpp2IL](https://github.com/SamboyCoding/Cpp2IL) —— 高级 IL2CPP 分析工具
- [tauri-apps](https://tauri.app/) —— 跨平台原生外壳
- [SvelteKit](https://kit.svelte.dev/) —— 前端框架
- [noph-ui](https://www.npmjs.com/package/noph-ui) —— 面向 Svelte 的 Material 3 组件
- [console-rs](https://github.com/console-rs) —— CLI 复用的终端样式生态

---

## 📬 社区

| | 链接 |
|---|---|
| 📢 **Telegram 频道** | [加入频道](https://t.me/+WmudnO0-xoNhMDQ8) |
| 💬 **Telegram 群组** | [加入群组](https://t.me/+QylrYL1GNsJiYjc0) |
| 👤 **开发者** | [`@rodroidmods`](https://t.me/rodroidmods) |

---

> **⚠️ Disclaimer**: This tool is for educational and research purposes only. Respect game developers' rights and terms of service.