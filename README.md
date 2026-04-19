# Curicata PCAP 分析平台

網路封包側錄、威脅分析、視覺化一體化平台。透過瀏覽器完成從封包側錄到威脅分析儀表板的全流程操作。

---

## 目前架構（現狀）

```
capture.sh          → 手動執行，側錄封包
1.pcap_to_json.py   → 手動執行，Suricata 威脅分析
2.tshark.py         → 手動執行，TShark 流量統計 + GeoIP
3.ui.py             → Flask Web UI，讀取結果顯示
```

**問題：** 四個步驟需要分別手動執行，且 `capture.sh` 僅限 Linux/macOS。

---

## 優化建議：全整合架構

### 核心思路

將所有腳本整合進一個 Flask 應用程式，以網頁作為唯一操作介面。

**建議採用 Flask-SocketIO**，透過 WebSocket 實現即時封包數更新與分析進度推送，取代輪詢（polling）方式，使用者體驗更流暢。

### 新版架構

```
Flask App（單一入口 main.py）
│
├── 前端
│   ├── Dashboard          → 專案管理（建立 / 刪除 / 查看）
│   ├── 側錄頁面           → 選擇網卡、開始 / 停止側錄、即時封包數
│   └── 分析儀表板         → 流量趨勢、Top IP、國別分布、異常警示
│
├── 後端 API
│   ├── /api/interfaces         → 列出可用網卡
│   ├── /api/capture/start      → 啟動 dumpcap
│   ├── /api/capture/stop       → 停止 dumpcap
│   └── /api/project/<name>/... → 讀取分析結果
│
├── WebSocket 事件（Flask-SocketIO）
│   ├── packet_count            → 即時封包數（每秒推送）
│   ├── analysis_progress       → 分析進度百分比
│   └── analysis_complete       → 分析完成通知
│
└── 背景分析流水線（Background Pipeline）
    ├── CaptureWorker   → 封裝 dumpcap subprocess
    ├── WatcherWorker   → 監控 PCAP 檔案寫入完成
    ├── SuricataWorker  → 執行 Suricata 分析（1.py 邏輯）
    └── TSharkWorker    → 執行 TShark + GeoIP 分析（2.py 邏輯）
```

### 建議目錄結構（重構後）

```
curicata/
├── main.py                  ← 單一啟動入口（Flask + SocketIO）
├── capture.py               ← dumpcap 封裝模組
├── pipeline.py              ← 分析流水線協調器
├── analyzer/
│   ├── suricata.py          ← Suricata 分析（原 1.py）
│   └── tshark.py            ← TShark 分析（原 2.py）
├── templates/               ← Jinja2 HTML 模板
├── static/                  ← CSS / JS 靜態資源
├── GeoLite2-City.mmdb       ← GeoIP 資料庫
├── requirements.txt
└── project/                 ← 所有專案資料（自動產生）
    └── {專案名稱}/
        ├── pcap/            ← 側錄的 PCAP 檔
        ├── suricata/        ← Suricata 輸出（fast.log）
        ├── *_analysis.json  ← 每個 PCAP 的 TShark 分析
        └── analysis_summary.json ← 整合摘要
```

---

## 操作流程（優化後）

```
瀏覽器
  │
  ▼
① Dashboard → 建立專案（輸入名稱）
  │
  ▼
② 進入專案 → 選擇側錄網卡 → 設定排除 IP（可選）
  │
  ▼
③ 點擊「開始側錄」
  │  └─ 後端啟動 dumpcap，每 1GB 自動切割 PCAP
  │  └─ WebSocket 每秒推送即時封包數
  │
  ▼
④ 點擊「停止側錄」（或檔案達到分割大小時自動觸發）
  │  └─ 偵測到 PCAP 寫入完成
  │  └─ 自動執行 Suricata 分析
  │  └─ 自動執行 TShark + GeoIP 分析
  │  └─ WebSocket 推送分析進度
  │
  ▼
⑤ 分析完成 → 自動跳轉至分析儀表板
```

---

## 安裝需求

### 系統相依工具

| 工具 | 用途 | 下載 |
|------|------|------|
| Python 3.9+ | 執行 Flask 應用 | https://python.org |
| Suricata 7.x | 威脅規則偵測 | https://suricata.io |
| Wireshark / TShark | 封包解析 | https://wireshark.org |
| Npcap（Windows）| 網卡擷取驅動 | https://npcap.com |

### Python 套件

```bash
pip install flask flask-socketio flask-cors geoip2 requests eventlet
```

> **注意：** Flask-SocketIO 需要搭配 `eventlet` 或 `gevent` 作為非同步後端。

### GeoLite2 資料庫

將 `GeoLite2-City.mmdb` 放置於專案根目錄（已提供，或至 https://dev.maxmind.com 重新下載）。

---

## 安裝步驟

```bash
# 1. 複製專案
git clone <repo-url>
cd curicata

# 2. 安裝 Python 套件
pip install -r requirements.txt

# 3. 啟動應用（單一指令）
python main.py

# 4. 開啟瀏覽器
# http://localhost:5000
```

---

## 功能說明

### Dashboard（任務總覽）
- 顯示所有已建立的專案卡片
- 每張卡片顯示：封包數、事件數、異常數、側錄時間範圍
- 可建立新專案 / 刪除專案

### 側錄頁面
- 下拉選單列出系統所有可用網卡（呼叫 `dumpcap -D`）
- 輸入欲排除的 IP 位址（多個以空格分隔）
- 即時顯示已擷取封包數量（WebSocket 每秒更新）
- 開始 / 停止按鈕控制側錄

### 自動分析流水線
- 停止側錄後自動觸發，無需手動操作
- 進度條顯示：Suricata 分析中 → TShark 分析中 → 完成
- 分析完成後通知橫幅並提供跳轉連結

### 分析儀表板
- **流量趨勢：** 折線圖，以 10 分鐘為單位顯示流量變化
- **Top IP：** 長條圖 + 表格，流量排行前 N 名
- **國別分布：** 圓餅圖，連線來源國家佔比
- **事件分析：** 協議分布、Suricata 事件類型統計
- **異常警示：** 大流量連線、可疑來源國、異常協議比例

---

## 技術細節

### 即時推送（WebSocket）
使用 `flask-socketio` + `eventlet`，後端主動推送事件至前端，避免前端反覆輪詢：

```
server → client: { "type": "packet_count", "count": 1234 }
server → client: { "type": "analysis_progress", "stage": "suricata", "percent": 60 }
server → client: { "type": "analysis_complete", "project": "my_project" }
```

### 自動觸發分析
`WatcherWorker` 監控 PCAP 目錄，偵測到 dumpcap 關閉檔案後（檔案大小穩定超過 2 秒），自動加入分析佇列。

### PCAP 檔案切割
dumpcap 使用 `-b filesize:1048576`（每 1GB 切割），切割完成的檔案立即觸發分析，側錄中的最新檔案等待停止後再分析。

### Windows 相容性
原本的 `capture.sh`（bash 腳本）改以 Python `subprocess` 呼叫 `dumpcap.exe`，完整支援 Windows。

---

## 注意事項

1. **系統權限：** dumpcap 需要管理員權限（Windows 請以系統管理員身份執行）或將使用者加入 `wireshark` 群組（Linux）。
2. **Suricata 規則：** 首次使用請確認 `C:\Program Files\Suricata\rules\` 目錄已有規則檔，或讓 1.py 自動下載。
3. **GeoLite2 資料庫：** `GeoLite2-City.mmdb` 需存在於根目錄，否則 GeoIP 功能會停用但不影響其他分析。
4. **儲存空間：** PCAP 檔案體積龐大，側錄前請確認磁碟空間充足（建議至少 10GB 可用空間）。

---

## 相依版本

| 套件 | 版本建議 |
|------|----------|
| Flask | >= 3.0 |
| Flask-SocketIO | >= 5.3 |
| eventlet | >= 0.35 |
| geoip2 | >= 4.8 |
| Suricata | 7.0.x |
| TShark | 4.x |
