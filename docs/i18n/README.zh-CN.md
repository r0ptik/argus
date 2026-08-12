# Argus

[English](../../README.md) · [繁體中文](README.zh-TW.md) · 简体中文 · [日本語](README.ja.md) · [한국어](README.ko.md)

**为 AI agent 提供**运行中**进程证据的 MCP server。**

目前所有的逆向工程 MCP server 都是接在*静态*分析器上 —— Ghidra、IDA、apktool。
它们把磁盘上的文件交给你的 agent，但没有一个能告诉 agent 程序此刻实际在做什么：
那个缓冲区里解密出了什么、vtable 槽位在运行时解析到哪个地址、是哪个调用点发出了那个数据包。

Argus 是另外一半。它附加到运行中的 Windows 进程，返回运行时证据：真实地址上的真实字节、
实际执行过的代码的反汇编、解析后的 IAT thunk、从活内存中走出来的调用链，
以及一本假设账本 —— 记录什么已被证明、什么还只是猜测。

它不替模型下结论。它返回地址、模块/RVA 上下文、指令、caller、callee 和局部证据，然后让开。

---

## 这个项目为什么存在

游戏会死。运营商关掉服务器、工作室倒闭、品类退出流行。留下来的是一份躺在某人硬盘里、
再也连不上任何东西的客户端 —— 没有源码、没有协议文档、没有服务器可以对话。
只剩一个还记得怎么说某种语言、却再也没人在听的可执行文件。

Argus 就是为了把它们救回来而生的。

给一款已经死掉的游戏重建服务器，意味着要把它的协议还原出来：包结构、加密、
opcode 分派、线路另一端的状态机。而唯一幸存的规格书，就是客户端本身。
你需要的那份文档从来没有人写过，知道答案的人也早就各奔东西了。

静态分析能带你走一段。但一个二十年前的客户端是加壳的、字符串是加密的、
handler 通过只在进程跑起来之后才存在的表来分派。所以你把它跑起来，然后看着它动 ——
接下来那一节讲的就是这件事。

这个工具的用途就是这样：不是闯进还活着的东西，而是让已经死掉的东西重新开口说话。

---

## 为什么要跑到运行中的进程里去看

**CPU 没法执行密文。**

一个程序在磁盘上做了多少保护 —— 加壳、字符串加密、指令虚拟化、加载时才解析 import ——
在处理器能跑这段代码之前，统统得先还原回去。在执行的那一瞬间，
真正的指令和真正的数据就以明文形式躺在内存里。**它们非如此不可。**
这不是某个保护壳写得不好，而是处理器工作方式的必然结果，再强的混淆也绕不过去。

所以这两种做法读的根本是不同的东西：

- **静态分析读的是文件。** 也就是作者交出来的那个东西。
- **运行时分析读的是文件变成了什么。** 也就是机器实际在跑的那个东西。

两者不一致的时候，后者才是真相。

| 场景 | 静态分析器 | Argus |
|---|---|---|
| 加壳 / 自解密代码 | 看到壳 | 反汇编内存中已解开的字节 |
| 通过 vtable 的间接调用 | 看到 `call [rax+0x18]` | 把槽位解析成具体目标 |
| 运行时才解析的 import | 看到 thunk stub | 把 thunk 解析成真正的 API |
| 解密后的缓冲区内容 | 没有 | 读出明文 |
| 40 个调用点中实际触发的是哪个 | 靠猜 | 记录实际执行的那个 |

### 静态分析赢在哪里

反过来的取舍也该说清楚：静态分析器看得到**每一条**路径，包括那些从来没被执行到的。
Argus 只看得到实际跑过的部分。没被走到的分支不会留下任何运行时证据，
没被调用过的函数等于不存在。

单靠任何一边都不完整。这就是 `correlate_addr` 存在的理由 ——
把运行时地址对回模块与 RVA，拿去 Ghidra 或 IDA 查，两边一起用。
Argus 是设计来跟静态分析器并肩协作的，不是取代它。

---

## 工具

**进程与内存**
`processes_list` · `processes_find` · `mem_attach` · `mem_modules` · `memory_regions`
`mem_read` · `mem_read_chain` · `mem_write`

**扫描**
`scan_bytes` · `scan_string` · `scan_regex` · `scan_pointers_to` · `scan_callers`
`scan_x86_call_sites` · `value_scan_start` · `value_scan_refine` · `value_explain` · `real_rate`

**反汇编与结构还原**
`disasm_at` · `analyze_function` · `find_vtable` · `extract_dispatch_tables`
`analyze_send_call_sites` · `read_struct` · `diff_struct`

**Import 与 API 解析**
`runtime_imports` · `runtime_exports` · `resolve_iat_thunks` · `resolve_api_targets`

**追踪与关联**
`trace_call_chain` · `correlate_addr` · `locate`

**证据账本**
`record_hypothesis` · `verify_hypothesis` · `query_hypotheses` · `add_evidence`

---

## 两个值得一提的设计决策

### 自动架构路由

把 64 位分析器附加到 32 位（WOW64）目标，是指针运算悄悄算错、PE 解析出垃圾的经典来源。
Argus 提供一个轻量前端 `argus-router`，它会检查目标进程、判断是 x86 还是 x64，
然后分派给对应的 `argus-rs` 构建版本。你只配置一个可执行文件，正确的引擎会按目标自动选用。

### 证据账本

Agent 很擅长给出合理的解释，很不擅长察觉某个合理解释其实毫无根据。
`record_hypothesis` / `verify_hypothesis` / `add_evidence` 强制区分这两者：
一个主张先以假设的形式存下，只有在附上证据且通过验证后才成为既定事实。
`query_hypotheses` 让后续的 session 可以接上一次停下的地方，不必重新推导一遍。

---

## 安装

### 预编译二进制

下载最新的 release，解压到任意位置：

**[Releases](https://github.com/r0ptik/argus/releases)**

压缩包内含 `argus-router.exe` 以及两个引擎构建版本
（`argus-rs-x64.exe`、`argus-rs-x86.exe`）。请保持它们位于同一目录下。

### 从源码构建

需要安装了两个 Windows target 的 Rust 工具链：

```bash
rustup target add x86_64-pc-windows-msvc i686-pc-windows-msvc

git clone https://github.com/r0ptik/argus
cd argus
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc
```

---

## 配置

### Claude Code

```bash
claude mcp add argus -- C:\path\to\argus-router.exe
```

### 任意 MCP client

```json
{
  "mcpServers": {
    "argus": {
      "command": "C:\\path\\to\\argus-router.exe"
    }
  }
}
```

---

## 适用范围与使用声明

Argus 是逆向工程与程序分析工具，为以下工作而建：游戏与服务器保存、网络协议分析、
互操作性与净室重新实现、恶意软件分析、崩溃与内存损坏调试，以及安全研究。

它明确地**不是**为了攻击仍在运营的服务而做的。本项目不接受任何外挂功能 ——
见 [CONTRIBUTING.md](../../CONTRIBUTING.md)。

它需要打开并读取其他进程的能力，因此请只用在你拥有或已获授权分析的进程上。
附加到你没有权限分析的软件，可能违反该软件的条款或你所在地的法律。
那是你的责任，不是工具的责任。

---

## 平台支持

仅支持 Windows。内存访问层（`argus-winmem`）建立在 Win32 进程与内存 API 之上，
目前没有 Linux 或 macOS 后端。

x86 与 x64 目标都支持，包括在 WOW64 下运行的 32 位进程。

---

## Crate 结构

| Crate | 职责 |
|---|---|
| `argus-router` | 前端可执行文件；架构检测与分派 |
| `argus-rs` | MCP server；工具定义与请求处理 |
| `argus-engine` | 分析引擎；反汇编、结构还原、追踪 |
| `argus-winmem` | Win32 进程与内存访问 |
| `argus-scan` | 模式与数值扫描原语 |
| `evidence-core` | 地址、模块、RVA 与证据数据模型 |

---

## 许可

MIT。见 [LICENSE](../../LICENSE)。
