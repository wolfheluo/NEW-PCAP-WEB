# PCAP Web 平台 — 待辦事項 & 問題清單

> 最後更新：2026-04-23

---

## 目錄

- [三、效能問題](#三效能問題)
- [四、程式碼設計問題](#四程式碼設計問題)
- [五、功能完整性建議](#五功能完整性建議)

---

## 三、效能問題

### 3.1 每完成一個 PCAP 就全量重新合併 `O(n²)`

`_analyze_single_pcap_inner()` 在每個 PCAP 分析完後都呼叫 `merge_all_results()`，  
後者會**重讀所有已分析的 `_analysis.json`**。

| PCAP 數量 | 總讀取次數 |
|:---------:|:---------:|
| 10 個 | 55 次 |
| 50 個 | 1,275 次 |
| 100 個 | 5,050 次 |

> **建議：** 只在最後一個 PCAP 完成後（`all_analysis_done`）統一合併一次，或用**累加方式**維護 summary，避免重複 I/O。

---

### 3.2 同一個 PCAP 執行 4 次 TShark

`run_tshark_on_pcap()` 依序呼叫四個分析函式，每個都啟動獨立的 `subprocess.run(tshark)` 讀取同一個 PCAP。

```
run_tshark_on_pcap(pcap)
  ├── analyze_traffic()     → subprocess(tshark)  ← 第 1 次讀取
  ├── analyze_protocols()   → subprocess(tshark)  ← 第 2 次讀取
  ├── analyze_geo()         → subprocess(tshark)  ← 第 3 次讀取
  └── analyze_alerts()      → subprocess(tshark)  ← 第 4 次讀取
```

> **建議：** 合併為**一次 tshark 呼叫**，可節省約 **75% 的磁碟 I/O**。

---

### 3.3 GeoIP Reader 每個 PCAP 都重新開關

每次 `run_tshark_on_pcap()` 都開啟再關閉 `geoip2.database.Reader`。  
高並發時（如 8 個 PCAP 同時分析）會同時存在 8 個 mmdb 讀取器實例。

> **建議：** 在應用層級維護**單例（Singleton）**，或至少在 `run_tshark_on_pcap` 開啟後傳入所有子函式共用。

---

### 3.4 等待分析完成用輪詢而非事件

`_run_remaining()` 和 `_run_all()` 使用忙碌等待：

```python
# 現況 — 低效輪詢
for _ in range(300):
    time.sleep(1)
    if is_done():
        break
```

> **建議：** 改用 `threading.Event`，讓最後一個分析執行緒完成時**主動通知**，避免不必要的 CPU 空轉。

```python
# 建議 — 事件驅動
done_event = threading.Event()
# 分析完成時：done_event.set()
done_event.wait(timeout=300)
```

---

## 四、程式碼設計問題

### 4.1 刪除專案時未等待分析執行緒結束

`delete_project()` 直接執行 `shutil.rmtree(project_dir)`，  
若背景分析執行緒仍在寫入 JSON，將導致：

- `FileNotFoundError`
- 靜默地寫入已刪除目錄

> **建議：** 刪除前先確認 `analyzing == 0`，或向所有相關執行緒發送取消信號並等待其結束。

---

### 4.2 Semaphore 在執行時重建不安全

儲存設定時若有執行緒正持有舊的 semaphore 等待，  
舊 semaphore 被丟棄但舊執行緒仍持有它 → **新設定的並發上限對這些執行緒無效**。

> **建議：** 更換 semaphore 前，先等待所有持有舊 semaphore 的執行緒釋放，或改用可動態調整上限的 `BoundedSemaphore` 包裝類別。

---

### 4.3 `filter_log_file` 去重 key 與 `_parse_fast_log_alerts` 不一致

| 函式 | 去重 Key |
|------|---------|
| `filter_log_file` | `(event_full_string, src_ip, dst_ip)` |
| `_parse_fast_log_alerts` | `(sig_id, msg)` |

兩者邏輯不同步 → 過濾後的 log 可能保留比儀表板顯示**更多的重複項**。

> **建議：** 統一去重邏輯，或明確定義兩者各自的職責範圍。

---

## 五、功能完整性建議

| 項目 | 現況 | 建議 |
|------|------|------|
| 流量時間軸空洞 | 無流量的時間段不出現在圖表 | 補 `0` 值，使折線圖保持連續 |
| `per_10_minutes` 粒度固定 | 只有 10 分鐘粒度 | 支援 1 / 5 / 30 分鐘動態切換 |
| Suricata `eve.json` | 完全未使用 | 可提取 DNS / HTTP 詳細事件資訊 |
| 無認證機制 | API 全公開 | 部署於共用網路時，加入簡單 token 或 IP 白名單 |
| 封包數統計跨 session | 只有 `total_packets`，未區分 session | 加上每次側錄的獨立記錄列表 |

---

*由 GitHub Copilot 整理*
