# Argus

[English](../../README.md) · 繁體中文 · [简体中文](README.zh-CN.md) · [日本語](README.ja.md) · [한국어](README.ko.md)

**讓 AI agent 取得**執行中**行程證據的 MCP server。**

目前所有的逆向工程 MCP server 都是接到*靜態*分析器上 —— Ghidra、IDA、apktool。
它們把磁碟上的檔案交給你的 agent,但沒有一個能告訴 agent 程式此刻實際在做什麼:
那個緩衝區裡被解密出了什麼、vtable 槽位在執行期解析到哪個位址、是哪個呼叫點送出了那個封包。

Argus 是另外一半。它 attach 到執行中的 Windows 行程,回傳執行期證據:真實位址上的真實位元組、
實際執行過的程式碼的反組譯、解析後的 IAT thunk、從活記憶體走出來的呼叫鏈,
以及一本假設帳本 —— 記錄什麼已經被證明、什麼還只是猜測。

它不替模型下結論。它回傳位址、模組/RVA 上下文、指令、caller、callee 和局部證據,然後讓開。

---

## 這個專案為什麼存在

遊戲會死。營運商關掉伺服器、工作室倒閉、類型退流行。留下來的是一份躺在某人硬碟裡、
再也連不上任何東西的客戶端 —— 沒有原始碼、沒有協定文件、沒有伺服器可以對話。
只剩一個還記得怎麼說某種語言、卻再也沒人在聽的執行檔。

Argus 就是為了把它們救回來而生的。

替一款已經死掉的遊戲重建伺服器,意思是要把它的協定還原出來:封包結構、加密、
opcode 分派、線路另一端的狀態機。而唯一倖存的規格書,就是客戶端本身。
你需要的那份文件從來沒有人寫過,知道答案的人也早就各奔東西了。

靜態分析能帶你走一段。但一個二十年前的客戶端是加殼的、字串是加密的、
handler 透過只在行程跑起來之後才存在的表來分派。所以你把它跑起來,然後看著它動 ——
接下來那一節講的就是這件事。

這個工具的用途就是這樣:不是闖進還活著的東西,而是讓已經死掉的東西重新開口說話。

---

## 為什麼要跑到執行中的行程裡找

**CPU 沒辦法執行密文。**

一支程式在磁碟上做了多少保護 —— 加殼、字串加密、指令虛擬化、載入時才解析 import ——
在處理器能跑這段程式碼之前,通通得先還原回去。在執行的那一瞬間,
真正的指令和真正的資料就以明文的形式躺在記憶體裡。**它們非得如此不可。**
這不是某個保護殼寫得不好,而是處理器運作方式的必然結果,再厲害的混淆也繞不過去。

所以這兩種做法讀的根本是不同的東西:

- **靜態分析讀的是檔案。** 也就是作者交出來的那個東西。
- **執行期分析讀的是檔案變成了什麼。** 也就是機器實際在跑的那個東西。

兩者不一致的時候,後者才是真相。

| 情境 | 靜態分析器 | Argus |
|---|---|---|
| 加殼 / 自解密程式碼 | 看到殼 | 反組譯記憶體中已解開的位元組 |
| 透過 vtable 的間接呼叫 | 看到 `call [rax+0x18]` | 把槽位解析成具體目標 |
| 執行期才解析的 import | 看到 thunk stub | 把 thunk 解析成真正的 API |
| 解密後的緩衝區內容 | 沒有 | 讀出明文 |
| 40 個呼叫點中實際觸發的是哪個 | 用猜的 | 記錄實際執行的那個 |

### 靜態分析贏在哪裡

反過來的取捨也該講清楚:靜態分析器看得到**每一條**路徑,包含那些從來沒被執行到的。
Argus 只看得到實際跑過的部分。沒被走到的分支不會留下任何執行期證據,
沒被呼叫過的函式等於不存在。

單靠任何一邊都不完整。這就是 `correlate_addr` 存在的理由 ——
把執行期位址對回模組與 RVA,拿去 Ghidra 或 IDA 查,兩邊一起用。
Argus 是設計來跟靜態分析器並肩協作,不是取代它。

---

## 工具

**行程與記憶體**
`processes_list` · `processes_find` · `mem_attach` · `mem_modules` · `memory_regions`
`mem_read` · `mem_read_chain` · `mem_write`

**掃描**
`scan_bytes` · `scan_string` · `scan_regex` · `scan_pointers_to` · `scan_callers`
`scan_x86_call_sites` · `value_scan_start` · `value_scan_refine` · `value_explain` · `real_rate`

**反組譯與結構還原**
`disasm_at` · `analyze_function` · `find_vtable` · `extract_dispatch_tables`
`analyze_send_call_sites` · `read_struct` · `diff_struct`

**Import 與 API 解析**
`runtime_imports` · `runtime_exports` · `resolve_iat_thunks` · `resolve_api_targets`

**追蹤與關聯**
`trace_call_chain` · `correlate_addr` · `locate`

**證據帳本**
`record_hypothesis` · `verify_hypothesis` · `query_hypotheses` · `add_evidence`

---

## 兩個值得一提的設計決策

### 自動架構路由

把 64 位元的分析器 attach 到 32 位元(WOW64)目標,是指標運算悄悄算錯、PE 解析出垃圾的經典來源。
Argus 提供一個輕量前端 `argus-router`,它會檢查目標行程、判斷是 x86 還是 x64,
然後分派給對應的 `argus-rs` 建置版本。你只設定一個執行檔,正確的引擎會依目標自動選用。

### 證據帳本

Agent 很擅長生出合理的解釋,很不擅長察覺某個合理解釋其實毫無根據。
`record_hypothesis` / `verify_hypothesis` / `add_evidence` 強制區分這兩者:
一個主張先以假設的形式存下,只有在附上證據且通過驗證後才成為既定事實。
`query_hypotheses` 讓後續的 session 可以接續上一次停下的地方,不必重新推導一遍。

---

## 安裝

### 預編執行檔

下載最新的 release,解壓到任何位置:

**[Releases](https://github.com/r0ptik/argus/releases)**

壓縮檔內含 `argus-router.exe` 以及兩個引擎建置版本
(`argus-rs-x64.exe`、`argus-rs-x86.exe`)。請保持它們在同一個目錄下。

### 從原始碼建置

需要安裝了兩個 Windows target 的 Rust toolchain:

```bash
rustup target add x86_64-pc-windows-msvc i686-pc-windows-msvc

git clone https://github.com/r0ptik/argus
cd argus
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc
```

---

## 設定

### Claude Code

```bash
claude mcp add argus -- C:\path\to\argus-router.exe
```

### 任何 MCP client

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

## 適用範圍與使用聲明

Argus 是逆向工程與程式分析工具,為以下工作而建:遊戲與伺服器保存、網路協定分析、
互通性與淨室重新實作、惡意程式分析、當機與記憶體損毀除錯,以及安全研究。

它明確地**不是**為了攻擊仍在營運的服務而做的。本專案不接受任何外掛功能 ——
見 [CONTRIBUTING.md](../../CONTRIBUTING.md)。

它需要開啟並讀取其他行程的能力,因此請只用在你擁有或已獲授權分析的行程上。
attach 到你沒有權限分析的軟體,可能違反該軟體的條款或你所在地的法律。
那是你的責任,不是工具的責任。

---

## 平台支援

僅支援 Windows。記憶體存取層(`argus-winmem`)建立在 Win32 行程與記憶體 API 之上,
目前沒有 Linux 或 macOS 的後端。

x86 與 x64 目標都支援,包含在 WOW64 下執行的 32 位元行程。

---

## Crate 結構

| Crate | 職責 |
|---|---|
| `argus-router` | 前端執行檔;架構偵測與分派 |
| `argus-rs` | MCP server;工具定義與請求處理 |
| `argus-engine` | 分析引擎;反組譯、結構還原、追蹤 |
| `argus-winmem` | Win32 行程與記憶體存取 |
| `argus-scan` | 樣式與數值掃描原語 |
| `evidence-core` | 位址、模組、RVA 與證據資料模型 |

---

## 授權

MIT。見 [LICENSE](../../LICENSE)。
