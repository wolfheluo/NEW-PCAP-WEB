#!/usr/bin/env python3
"""
Suricata 分析模組
提供對單一 PCAP 檔案執行 Suricata 分析的函式，
以及合併、過濾 fast.log 的工具。
"""

import os
import glob
import json
import subprocess
import re
import urllib.request
import ssl
from pathlib import Path


SURICATA_EXE_DEFAULT = r"C:\Program Files\Suricata\suricata.exe"

# 與 main.py 的 _FAST_LOG_RE 相同結構，用於 filter_log_file 去重，
# 確保 (sig_id, msg, src_ip, dst_ip) key 與 _parse_fast_log_alerts 一致。
_FILTER_LOG_RE = re.compile(
    r'\[\*\*\]\s+\[\d+:(\d+):\d+\]\s+(.+?)\s+\[\*\*\]'
    r'.*?'
    r'(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+):\d+\s*->\s*'
    r'(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+):\d+',
    re.DOTALL
)


def update_suricata_rules(suricata_exe=SURICATA_EXE_DEFAULT):
    """下載並更新 Suricata 規則文件"""
    rules_url = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules"
    rules_dir = os.path.dirname(suricata_exe) + r"\rules"
    rules_file = os.path.join(rules_dir, "emerging-all.rules")

    print("正在更新 Suricata 規則...")
    try:
        os.makedirs(rules_dir, exist_ok=True)
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(rules_url, context=ssl_context) as response:
            rules_content = response.read()

        with open(rules_file, 'wb') as f:
            f.write(rules_content)

        print(f"規則更新成功: {rules_file} ({len(rules_content)/1024:.1f} KB)")
        return True
    except Exception as e:
        print(f"規則更新失敗: {e}，將使用現有規則")
        return False


def extract_key_fields(line):
    """從 fast.log 行中提取關鍵字段，用於去重過濾。返回 None 表示應過濾。

    去重 key 為 (sig_id, msg, src_ip, dst_ip)，與 main.py 的
    _parse_fast_log_alerts 及 detect_anomalies 保持一致：
    - 同一告警類型在不同 IP 對之間的連線都會被保留（供儀表板聚合顯示）
    - 完全相同的 (告警, 來源, 目的) 重複行才被去除
    """
    if "Priority: 3" in line:
        return None
    if "ET INFO HTTP Request to a" in line and ".tw domain" in line:
        return None
    if "ET DNS Query for .cc TLD" in line:
        return None

    if "[**]" not in line:
        return None

    m = _FILTER_LOG_RE.search(line)
    if not m:
        return None

    sig_id, msg, src_ip, dst_ip = m.groups()
    return (sig_id, msg.strip(), src_ip, dst_ip)


def filter_log_file(input_file, output_file):
    """過濾 fast.log，去除低優先級與重複記錄"""
    if not os.path.exists(input_file):
        return False

    seen = set()
    count = 0

    try:
        with open(input_file, "r", encoding="utf-8") as infile, \
             open(output_file, "w", encoding="utf-8") as outfile:
            for line in infile:
                key = extract_key_fields(line)
                if key and key not in seen:
                    seen.add(key)
                    outfile.write(line)
                    count += 1

        print(f"過濾完成，保留 {count} 筆記錄 -> {output_file}")
        return True
    except Exception as e:
        print(f"過濾日誌失敗: {e}")
        return False


def run_suricata_on_pcap(pcap_file, out_dir, suricata_exe=SURICATA_EXE_DEFAULT, checksum_offload=False):
    """對單一 PCAP 檔案執行 Suricata 分析"""
    os.makedirs(out_dir, exist_ok=True)

    if not os.path.exists(suricata_exe):
        raise FileNotFoundError(f"找不到 Suricata: {suricata_exe}")

    cmd = [
        suricata_exe,
        "-r", pcap_file,
        "-l", out_dir,
    ]
    if checksum_offload:
        cmd += ["-k", "none"]
    result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')

    if result.returncode != 0:
        print(f"Suricata 警告 ({os.path.basename(pcap_file)}): {result.stderr[:200]}")
    else:
        print(f"Suricata 完成: {os.path.basename(pcap_file)}")

    return result.returncode == 0


def parse_eve_json(eve_file):
    """解析單一 eve.json，回傳 { 'dns': [...], 'http': [...] }。
    每筆 DNS 保留: timestamp, src_ip, dest_ip, query(rrname), rrtype, answers
    每筆 HTTP 保留: timestamp, src_ip, dest_ip, hostname, url, method, status, user_agent
    """
    dns_events = []
    http_events = []

    if not os.path.exists(eve_file):
        return {'dns': dns_events, 'http': http_events}

    try:
        with open(eve_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue

                etype = ev.get('event_type')
                ts    = ev.get('timestamp', '')
                src   = ev.get('src_ip', '')
                dst   = ev.get('dest_ip', '')

                if etype == 'dns':
                    dns = ev.get('dns', {})
                    # 只取 request（type == 'request'）或 query（version 2 用 type==query）
                    if dns.get('type') in ('request', 'query'):
                        for q in dns.get('queries', []):
                            dns_events.append({
                                'timestamp': ts,
                                'src_ip': src,
                                'dest_ip': dst,
                                'rrname': q.get('rrname', ''),
                                'rrtype': q.get('rrtype', ''),
                            })
                        # version 2 格式：queries 可能不存在，改用頂層 rrname
                        if not dns.get('queries') and dns.get('rrname'):
                            dns_events.append({
                                'timestamp': ts,
                                'src_ip': src,
                                'dest_ip': dst,
                                'rrname': dns.get('rrname', ''),
                                'rrtype': dns.get('rrtype', ''),
                            })

                elif etype == 'http':
                    http = ev.get('http', {})
                    http_events.append({
                        'timestamp': ts,
                        'src_ip': src,
                        'dest_ip': dst,
                        'hostname': http.get('hostname', ''),
                        'url': http.get('url', ''),
                        'method': http.get('http_method', ''),
                        'status': http.get('status', ''),
                        'user_agent': http.get('http_user_agent', ''),
                    })

    except Exception as e:
        print(f"解析 eve.json 失敗 ({eve_file}): {e}")

    return {'dns': dns_events, 'http': http_events}


def merge_eve_json(project_dir):
    """
    合併 project_dir/suricata/**/eve.json，統計 DNS Top 查詢域名與 HTTP Top 主機名稱，
    結果儲存為 project_dir/eve_summary.json。
    回傳合併結果 dict，若無資料則回傳 None。
    """
    import json as _json
    from collections import Counter

    eve_files = glob.glob(os.path.join(project_dir, 'suricata', '*', 'eve.json'))
    if not eve_files:
        print("沒有找到 eve.json 檔案，跳過合併")
        return None

    dns_counter   = Counter()   # rrname -> count
    http_hostname_counter = Counter()   # hostname -> count
    http_url_counter = Counter()   # hostname+url -> count
    dns_client_counter = Counter()   # src_ip -> count
    http_events_sample = []   # 最多保留 500 筆原始 HTTP 記錄（供前端顯示）
    dns_events_sample  = []   # 最多保留 500 筆原始 DNS 記錄

    for eve_file in eve_files:
        result = parse_eve_json(eve_file)

        for d in result['dns']:
            rrname = d.get('rrname', '').strip()
            if rrname:
                dns_counter[rrname] += 1
                dns_client_counter[d.get('src_ip', '')] += 1
        if len(dns_events_sample) < 500:
            remaining = 500 - len(dns_events_sample)
            dns_events_sample.extend(result['dns'][:remaining])

        for h in result['http']:
            hostname = h.get('hostname', '').strip()
            if hostname:
                http_hostname_counter[hostname] += 1
                url_key = hostname + h.get('url', '')
                http_url_counter[url_key] += 1
        if len(http_events_sample) < 500:
            remaining = 500 - len(http_events_sample)
            http_events_sample.extend(result['http'][:remaining])

    # Top 50 DNS 查詢域名
    top_dns = [{'rrname': k, 'count': v}
               for k, v in dns_counter.most_common(50)]
    # Top 30 DNS 查詢用戶端
    top_dns_clients = [{'src_ip': k, 'count': v}
                       for k, v in dns_client_counter.most_common(30)]
    # Top 50 HTTP 主機名稱
    top_http_hosts = [{'hostname': k, 'count': v}
                      for k, v in http_hostname_counter.most_common(50)]

    summary = {
        'total_dns_queries': sum(dns_counter.values()),
        'total_http_requests': sum(http_hostname_counter.values()),
        'unique_dns_domains': len(dns_counter),
        'unique_http_hosts': len(http_hostname_counter),
        'top_dns_queries': top_dns,
        'top_dns_clients': top_dns_clients,
        'top_http_hosts': top_http_hosts,
        'dns_sample': dns_events_sample,
        'http_sample': http_events_sample,
    }

    out_path = os.path.join(project_dir, 'eve_summary.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        _json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"eve_summary 已儲存: {out_path} "
          f"(DNS {summary['total_dns_queries']} 筆, HTTP {summary['total_http_requests']} 筆)")
    return summary


def merge_suricata_logs(project_dir):
    """
    合併 project_dir/suricata/**/fast.log 為一個 merged_fast.log，
    並產生過濾後的 filtered_merged_fast.log。
    """
    merged_path = os.path.join(project_dir, "merged_fast.log")
    filtered_path = os.path.join(project_dir, "filtered_merged_fast.log")

    fast_log_files = glob.glob(os.path.join(project_dir, "suricata", "*", "fast.log"))

    if not fast_log_files:
        print("沒有找到 fast.log 檔案，跳過合併")
        return False

    try:
        with open(merged_path, 'w', encoding='utf-8') as merged:
            for fast_log in fast_log_files:
                try:
                    with open(fast_log, 'r', encoding='utf-8') as f:
                        merged.write(f.read())
                except Exception as e:
                    print(f"讀取 {fast_log} 失敗: {e}")

        print(f"合併完成: {merged_path}")
        filter_log_file(merged_path, filtered_path)
        return True

    except Exception as e:
        print(f"合併 Suricata 日誌失敗: {e}")
        return False
