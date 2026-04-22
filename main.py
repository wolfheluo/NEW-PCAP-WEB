#!/usr/bin/env python3
"""
PCAP 分析平台 - 統一入口
整合封包側錄（dumpcap）、Suricata 威脅分析、TShark 流量分析、Web 儀表板。
單一指令啟動，在瀏覽器完成全部操作。

使用方式：
    python main.py
    開啟 http://localhost:5000
"""

import os
import json
import glob
import subprocess
import threading
import time
import re
import ipaddress
import requests
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from urllib.parse import unquote

from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_socketio import SocketIO

from analyzer.suricata import run_suricata_on_pcap, merge_suricata_logs
from analyzer.tshark_analyzer import run_tshark_on_pcap, merge_all_results, parse_filter_ips

# ─────────────────────────────────────────────
# 設定
# ─────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = 'suricata_pcap_analyzer_secret_key_2025'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

PROJECT_DIR = "project"  # 預設值，可由 settings.json 覆寫
SURICATA_EXE = r"C:\Program Files\Suricata\suricata.exe"
TSHARK_EXE   = r"C:\Program Files\Wireshark\tshark.exe"
DUMPCAP_EXE  = r"C:\Program Files\Wireshark\dumpcap.exe"
GEOIP_DB     = "GeoLite2-City.mmdb"
SETTING_FILE = "settings.json"
PCAP_SPLIT_SIZE_KB = 204800  # 預設 200 MB
CHECKSUM_OFFLOAD   = False   # NIC Checksum Offload，啟用則加 -k none

os.makedirs(PROJECT_DIR, exist_ok=True)

# ── 讀取 / 寫入 settings.json ──────────────────────────────
def _load_settings() -> dict:
    if os.path.exists(SETTING_FILE):
        try:
            with open(SETTING_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def _save_settings(data: dict):
    existing = _load_settings()
    existing.update(data)
    with open(SETTING_FILE, 'w', encoding='utf-8') as f:
        json.dump(existing, f, ensure_ascii=False, indent=2)

# 套用已儲存的設定
_cfg = _load_settings()
if 'pcap_split_mb' in _cfg:
    PCAP_SPLIT_SIZE_KB = int(_cfg['pcap_split_mb']) * 1024
if 'project_dir' in _cfg and _cfg['project_dir'].strip():
    PROJECT_DIR = _cfg['project_dir'].strip()
if 'checksum_offload' in _cfg:
    CHECKSUM_OFFLOAD = bool(_cfg['checksum_offload'])

os.makedirs(PROJECT_DIR, exist_ok=True)

# 全局側錄狀態
# { project_name: { process, status, packet_count, started_at, filter_ips, analyzing } }
capture_states: dict = {}
capture_states_lock = threading.Lock()


# ── 專案設定（persist exclude_ips 等，跨重啟保留）─────────────────
def _load_project_settings(project_name: str) -> dict:
    path = os.path.join(get_project_dir(project_name), 'project_settings.json')
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def _save_project_settings(project_name: str, data: dict):
    existing = _load_project_settings(project_name)
    existing.update(data)
    path = os.path.join(get_project_dir(project_name), 'project_settings.json')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(existing, f, ensure_ascii=False, indent=2)


# ─────────────────────────────────────────────
# 工具函式
# ─────────────────────────────────────────────

_FAST_LOG_RE = re.compile(
    r'^(\S+)\s+\[\*\*\]\s+\[\d+:(\d+):\d+\]\s+(.+?)\s+\[\*\*\]'
    r'(?:\s+\[Classification:\s*([^\]]+)\])?'
    r'\s+\[Priority:\s*(\d+)\]'
    r'\s+\{(\S+)\}\s+(\S+)\s+->\s+(\S+)'
)

def get_project_dir(name):
    return os.path.join(PROJECT_DIR, name)

def get_pcap_dir(name):
    return os.path.join(PROJECT_DIR, name, "pcap")

def format_bytes(b):
    if b == 0:
        return '0 B'
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"

def detect_anomalies(project_name):
    """Count Priority 1+2 alerts from filtered_merged_fast.log (deduplicated by sig_id+msg)."""
    log_path = os.path.join(get_project_dir(project_name), 'filtered_merged_fast.log')
    if not os.path.exists(log_path):
        return 0
    seen = set()
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                m = _FAST_LOG_RE.match(line.strip())
                if m:
                    _, sig_id, msg, _, priority_str, *_ = m.groups()
                    if int(priority_str) in (1, 2):
                        seen.add((sig_id, msg))
    except Exception:
        pass
    return len(seen)

def get_tasks():
    tasks = []
    if not os.path.exists(PROJECT_DIR):
        return tasks

    for item in os.listdir(PROJECT_DIR):
        project_path = os.path.join(PROJECT_DIR, item)
        if not os.path.isdir(project_path):
            continue

        task = {
            'name': item,
            'path': project_path,
            'created_time': datetime.fromtimestamp(os.path.getctime(project_path)),
            'analyzed': False,
            'total_bytes': 0,
            'start_time': '',
            'end_time': '',
            'anomaly_count': 0,
            'total_events': 0,
            'pcap_count': 0,
        }

        pcap_dir = get_pcap_dir(item)
        if os.path.exists(pcap_dir):
            task['pcap_count'] = len(glob.glob(os.path.join(pcap_dir, "*.pcap")))

        summary_file = os.path.join(project_path, "analysis_summary.json")
        if os.path.exists(summary_file):
            try:
                with open(summary_file, 'r', encoding='utf-8') as f:
                    summary = json.load(f)
                task['analyzed'] = True
                task['total_bytes'] = summary.get('flow', {}).get('total_bytes', 0)
                task['start_time'] = summary.get('flow', {}).get('start_time', '')
                task['end_time'] = summary.get('flow', {}).get('end_time', '')
                events = summary.get('event', {})
                task['total_events'] = sum(e.get('count', 0) for e in events.values())
                task['anomaly_count'] = detect_anomalies(item)
            except Exception:
                pass

        with capture_states_lock:
            state = capture_states.get(item)
            task['capture_status'] = state['status'] if state else 'idle'
            task['packet_count'] = state['packet_count'] if state else 0

        tasks.append(task)

    tasks.sort(key=lambda x: x['created_time'], reverse=True)
    return tasks


# ─────────────────────────────────────────────
# 背景側錄 Workers
# ─────────────────────────────────────────────

def _read_dumpcap_stderr(project_name, proc):
    """
    讀取 dumpcap stderr 解析封包數。
    dumpcap 在 Windows 上使用 \r 原地更新封包數，
    必須以 chunk 方式讀取並以 \r 或 \n 拆行，不能用 readline()。
    """
    try:
        buf = b''
        while True:
            chunk = proc.stderr.read(512)
            if not chunk:
                break
            buf += chunk
            # 以 \r 或 \n 拆分（處理 Windows carriage-return 更新）
            parts = re.split(b'[\r\n]+', buf)
            buf = parts[-1]  # 保留未完成的尾端片段
            for part in parts[:-1]:
                text = part.decode('utf-8', errors='ignore').strip()
                if not text:
                    continue
                # 嘗試多種格式解析封包數
                match = re.search(r'Packets captured[:\s]+([\d,]+)', text, re.IGNORECASE)
                if not match:
                    match = re.search(r'([\d,]+)\s+packets?\s+(?:captured|written)', text, re.IGNORECASE)
                if match:
                    count = int(match.group(1).replace(',', ''))
                    with capture_states_lock:
                        if project_name in capture_states:
                            capture_states[project_name]['packet_count'] = count
                    socketio.emit('packet_count', {'project': project_name, 'count': count})
    except Exception:
        pass


def _poll_packet_count(project_name, pcap_dir):
    """
    備用封包計數：每 3 秒用 capinfos 統計已完成的 PCAP 檔案封包數。
    當 dumpcap stderr 無法提供即時數據時（常見於 Windows piped 模式）作為補充。
    """
    capinfos_exe = os.path.join(os.path.dirname(DUMPCAP_EXE), 'capinfos.exe')
    if not os.path.exists(capinfos_exe):
        return  # capinfos 不存在則跳過

    while True:
        time.sleep(3)
        with capture_states_lock:
            state = capture_states.get(project_name)
            if not state or state['status'] not in ('capturing',):
                break

        pcap_files = sorted(glob.glob(os.path.join(pcap_dir, '*.pcap')))
        if not pcap_files:
            continue

        # 只統計本次側錄 session 的 PCAP 檔（依 pcap_prefix 過濾）
        with capture_states_lock:
            pcap_prefix = capture_states.get(project_name, {}).get('pcap_prefix', '')
        if pcap_prefix:
            pcap_files = [f for f in pcap_files if os.path.basename(f).startswith(pcap_prefix)]
        if not pcap_files:
            continue

        # 若有多個檔案，最新一個可能正在寫入，先只統計其餘的
        check_files = pcap_files[:-1] if len(pcap_files) > 1 else pcap_files
        total = 0
        for f in check_files:
            try:
                result = subprocess.run(
                    [capinfos_exe, '-c', '-M', f],
                    capture_output=True, text=True, encoding='utf-8', timeout=5
                )
                m = re.search(r'Number of packets:\s+([\d,]+)', result.stdout)
                if m:
                    total += int(m.group(1).replace(',', ''))
            except Exception:
                pass

        if total > 0:
            with capture_states_lock:
                if project_name in capture_states:
                    current = capture_states[project_name].get('packet_count', 0)
                    if total > current:
                        capture_states[project_name]['packet_count'] = total

        # 每輪都更新檔案大小（PCAP 持續增長，即使封包數未變也要推送）
        all_pcaps = glob.glob(os.path.join(pcap_dir, '*.pcap'))
        total_pcap_bytes = sum(os.path.getsize(f) for f in all_pcaps if os.path.isfile(f))
        with capture_states_lock:
            if project_name in capture_states:
                pcap_prefix = capture_states[project_name].get('pcap_prefix', '')
                current_bytes = sum(
                    os.path.getsize(f) for f in all_pcaps
                    if os.path.isfile(f) and (not pcap_prefix or os.path.basename(f).startswith(pcap_prefix))
                )
                current_count = capture_states[project_name].get('packet_count', 0)
                socketio.emit('packet_count', {
                    'project': project_name,
                    'count': current_count,
                    'current_bytes': current_bytes,
                    'total_pcap_bytes': total_pcap_bytes,
                })


def _load_pcap_stats(project_name: str) -> dict:
    """讀取專案累計封包統計（跨 session 持久化）"""
    stats_path = os.path.join(get_project_dir(project_name), 'pcap_stats.json')
    if os.path.exists(stats_path):
        try:
            with open(stats_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {'total_packets': 0}


def _save_pcap_stats(project_name: str, delta_packets: int):
    """將本次 session 封包數累加寫入 pcap_stats.json"""
    if delta_packets <= 0:
        return
    try:
        stats = _load_pcap_stats(project_name)
        stats['total_packets'] = stats.get('total_packets', 0) + delta_packets
        stats_path = os.path.join(get_project_dir(project_name), 'pcap_stats.json')
        with open(stats_path, 'w', encoding='utf-8') as f:
            json.dump(stats, f)
    except Exception:
        pass


def _append_capture_log(project_name: str, msg: str, stage: str = ''):
    """將分析進度附加寫入 project/<name>/capture.log（JSON Lines 格式）"""
    try:
        log_path = os.path.join(get_project_dir(project_name), 'capture.log')
        entry = json.dumps({
            'time': datetime.now().strftime('%H:%M:%S'),
            'stage': stage,
            'msg': msg,
        }, ensure_ascii=False)
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(entry + '\n')
    except Exception:
        pass


def _analyze_single_pcap(project_name, pcap_file, filter_ips):
    """對單一 PCAP 執行 Suricata + TShark 分析並推送進度"""
    project_dir = get_project_dir(project_name)
    pcap_stem = Path(pcap_file).stem
    fname = os.path.basename(pcap_file)

    with capture_states_lock:
        if project_name in capture_states:
            capture_states[project_name]['analyzing'] = capture_states[project_name].get('analyzing', 0) + 1

    def _emit(stage, percent):
        pcap_dir_path = get_pcap_dir(project_name)
        all_pcaps = sorted(glob.glob(os.path.join(pcap_dir_path, '*.pcap')))
        # 側錄中時，最新那個可能仍在寫入，不計入 total（與 _watch_pcap_files 邏輯一致）
        with capture_states_lock:
            is_capturing = capture_states.get(project_name, {}).get('status') == 'capturing'
        if is_capturing and len(all_pcaps) > 1:
            total_pcap = len(all_pcaps) - 1
        else:
            total_pcap = len(all_pcaps)
        analyzed = len(glob.glob(os.path.join(project_dir, '*_analysis.json')))
        socketio.emit('analysis_progress', {
            'project': project_name, 'stage': stage,
            'file': fname, 'percent': percent,
            'analyzed': analyzed, 'total': total_pcap,
        })
        stage_msg = {
            'suricata': f'Suricata 分析中：{fname}',
            'tshark':   f'TShark 統計中：{fname}',
            'merging':  f'合併分析結果：{fname}',
            'complete': f'完成：{fname}',
        }.get(stage, f'{stage}: {fname}')
        _append_capture_log(project_name, stage_msg, stage)

    try:
        _emit('suricata', 10)
        suricata_out = os.path.join(project_dir, "suricata", pcap_stem)
        run_suricata_on_pcap(pcap_file, suricata_out, SURICATA_EXE, checksum_offload=CHECKSUM_OFFLOAD)

        _emit('tshark', 50)
        run_tshark_on_pcap(pcap_file, project_dir, TSHARK_EXE, GEOIP_DB, filter_ips)

        _emit('merging', 80)
        merge_suricata_logs(project_dir)
        merge_all_results(project_dir, filter_ips)

        _emit('complete', 100)
        pcap_dir_path = get_pcap_dir(project_name)
        all_pcaps_done = sorted(glob.glob(os.path.join(pcap_dir_path, '*.pcap')))
        with capture_states_lock:
            is_capturing = capture_states.get(project_name, {}).get('status') == 'capturing'
        if is_capturing and len(all_pcaps_done) > 1:
            total_pcap = len(all_pcaps_done) - 1
        else:
            total_pcap = len(all_pcaps_done)
        analyzed = len(glob.glob(os.path.join(project_dir, '*_analysis.json')))
        socketio.emit('analysis_complete', {
            'project': project_name, 'file': fname,
            'analyzed': analyzed, 'total': total_pcap,
        })
        _append_capture_log(project_name, f'完成分析 ({analyzed}/{total_pcap})：{fname}', 'done')

    except Exception as e:
        socketio.emit('analysis_error', {'project': project_name, 'error': str(e)})
        _append_capture_log(project_name, f'分析發生錯誤：{e}', 'error')
    finally:
        with capture_states_lock:
            if project_name in capture_states:
                n = capture_states[project_name].get('analyzing', 1)
                capture_states[project_name]['analyzing'] = max(0, n - 1)


def _watch_pcap_files(project_name, pcap_dir, filter_ips):
    """監控 pcap 目錄，偵測已完成的 PCAP 並觸發分析"""
    # 預先將已有對應分析輸出的 pcap 標記為已處理，避免重啟後重複分析
    processed = set()
    project_dir = get_project_dir(project_name)
    for existing_pcap in glob.glob(os.path.join(pcap_dir, "*.pcap")):
        stem = Path(existing_pcap).stem
        tshark_out = os.path.join(project_dir, f"{stem}_analysis.json")
        suricata_out = os.path.join(project_dir, "suricata", stem, "eve.json")
        if os.path.exists(tshark_out) or os.path.exists(suricata_out):
            processed.add(existing_pcap)

    while True:
        time.sleep(3)

        with capture_states_lock:
            state = capture_states.get(project_name)
            is_running = state is not None and state['status'] == 'capturing'

        all_pcap = set(glob.glob(os.path.join(pcap_dir, "*.pcap")))

        if is_running:
            # 最新（剛修改）的檔案可能還在寫入，其餘視為完成
            if len(all_pcap) > 1:
                sorted_files = sorted(all_pcap, key=os.path.getmtime)
                completed = set(sorted_files[:-1]) - processed
            else:
                completed = set()
        else:
            # 側錄停止：所有未處理的檔案都已完成
            completed = all_pcap - processed

        for pcap_file in sorted(completed):
            processed.add(pcap_file)
            threading.Thread(
                target=_analyze_single_pcap,
                args=(project_name, pcap_file, filter_ips),
                daemon=True
            ).start()

        # 側錄停止且所有檔案都已處理，結束監控
        if not is_running and all_pcap and all_pcap <= processed:
            # 等所有分析執行緒收尾（analyzing 歸零）再宣告完成
            for _ in range(30):  # 最多等 30 秒
                with capture_states_lock:
                    remaining = capture_states.get(project_name, {}).get('analyzing', 0)
                if remaining == 0:
                    break
                time.sleep(1)
            total_pcap = len(all_pcap)
            analyzed = len(glob.glob(os.path.join(project_dir, '*_analysis.json')))
            socketio.emit('all_analysis_done', {
                'project': project_name,
                'analyzed': analyzed, 'total': total_pcap,
            })
            break
        if not is_running and not all_pcap:
            break


# ─────────────────────────────────────────────
# 頁面路由
# ─────────────────────────────────────────────

@app.route('/api/capture/resume/<project_name>', methods=['POST'])
def api_resume(project_name):
    """僅分析尚未完成的 PCAP 檔案（用於程式中斷後繼續分析）"""
    project_dir = get_project_dir(project_name)
    pcap_dir    = get_pcap_dir(project_name)

    if not os.path.isdir(project_dir):
        return jsonify({'error': '專案不存在'}), 404

    with capture_states_lock:
        state = capture_states.get(project_name, {})
    if state.get('status') == 'capturing':
        return jsonify({'error': '側錄進行中，請先停止側錄'}), 400
    if state.get('analyzing', 0) > 0:
        return jsonify({'error': '分析進行中，請稍後再試'}), 400

    # 找出尚未分析的 PCAP（沒有對應 _analysis.json）
    all_pcaps = sorted(glob.glob(os.path.join(pcap_dir, '*.pcap')))
    remaining = []
    for pcap_file in all_pcaps:
        stem = Path(pcap_file).stem
        analysis_out = os.path.join(project_dir, f"{stem}_analysis.json")
        if not os.path.exists(analysis_out):
            remaining.append(pcap_file)

    if not remaining:
        return jsonify({'error': '所有 PCAP 已分析完成'}), 400

    # 優先用記憶體中的 filter_ips，否則從持久化設定讀取
    filter_ips = state.get('filter_ips') or parse_filter_ips(
        _load_project_settings(project_name).get('exclude_ips', '')
    )

    with capture_states_lock:
        if project_name not in capture_states:
            capture_states[project_name] = {
                'status': 'idle',
                'packet_count': 0,
                'analyzing': 0,
                'filter_ips': filter_ips,
            }
        capture_states[project_name]['analyzing'] = 0

    def _run_remaining():
        for pcap_file in remaining:
            threading.Thread(
                target=_analyze_single_pcap,
                args=(project_name, pcap_file, filter_ips),
                daemon=True
            ).start()
        for _ in range(300):
            with capture_states_lock:
                rem = capture_states.get(project_name, {}).get('analyzing', 0)
            if rem == 0:
                break
            time.sleep(1)
        total = len(all_pcaps)
        analyzed = len(glob.glob(os.path.join(project_dir, '*_analysis.json')))
        socketio.emit('all_analysis_done', {
            'project': project_name,
            'analyzed': analyzed, 'total': total,
        })

    threading.Thread(target=_run_remaining, daemon=True).start()
    _append_capture_log(project_name, f'繼續分析，尚有 {len(remaining)} 個 PCAP 待處理…', 'start')
    return jsonify({'ok': True, 'remaining': len(remaining)})


@app.route('/api/capture/reanalyze/<project_name>', methods=['POST'])
def api_reanalyze(project_name):
    """刪除現有分析結果並重新分析所有 PCAP；可透過 exclude_ips 更新排除列表"""
    project_dir = get_project_dir(project_name)
    pcap_dir    = get_pcap_dir(project_name)

    if not os.path.isdir(project_dir):
        return jsonify({'error': '專案不存在'}), 404

    with capture_states_lock:
        state = capture_states.get(project_name, {})
    if state.get('status') == 'capturing':
        return jsonify({'error': '側錄進行中，請先停止側錄'}), 400
    if state.get('analyzing', 0) > 0:
        return jsonify({'error': '分析進行中，請稍後再試'}), 400

    all_pcaps = sorted(glob.glob(os.path.join(pcap_dir, '*.pcap')))
    if not all_pcaps:
        return jsonify({'error': '沒有找到 PCAP 檔案'}), 400

    # 若請求帶有 exclude_ips，更新持久化設定並重新解析
    req_data = request.get_json(force=True) or {}
    if 'exclude_ips' in req_data:
        exclude_ips_str = req_data['exclude_ips'].strip()
        _save_project_settings(project_name, {'exclude_ips': exclude_ips_str})
        filter_ips = parse_filter_ips(exclude_ips_str)
        # 同步到記憶體狀態
        with capture_states_lock:
            if project_name in capture_states:
                capture_states[project_name]['filter_ips'] = filter_ips
    else:
        # 優先記憶體，否則從持久化設定讀取
        filter_ips = state.get('filter_ips') or parse_filter_ips(
            _load_project_settings(project_name).get('exclude_ips', '')
        )

    # 清除舊的分析結果
    import shutil
    for f in glob.glob(os.path.join(project_dir, '*_analysis.json')):
        os.remove(f)
    for f in glob.glob(os.path.join(project_dir, '*.log')):
        os.remove(f)
    suricata_dir = os.path.join(project_dir, 'suricata')
    if os.path.isdir(suricata_dir):
        shutil.rmtree(suricata_dir)
    # 清除 summary（但不清除 project_settings.json）
    for f in glob.glob(os.path.join(project_dir, '*.json')):
        if os.path.basename(f) != 'project_settings.json':
            os.remove(f)

    with capture_states_lock:
        if project_name not in capture_states:
            capture_states[project_name] = {'status': 'idle', 'packet_count': 0, 'analyzing': 0}
        capture_states[project_name]['analyzing'] = 0

    def _run_all():
        for pcap_file in all_pcaps:
            threading.Thread(
                target=_analyze_single_pcap,
                args=(project_name, pcap_file, filter_ips),
                daemon=True
            ).start()
        for _ in range(300):
            with capture_states_lock:
                rem = capture_states.get(project_name, {}).get('analyzing', 0)
            if rem == 0:
                break
            time.sleep(1)
        total = len(all_pcaps)
        analyzed = len(glob.glob(os.path.join(project_dir, '*_analysis.json')))
        socketio.emit('all_analysis_done', {
            'project': project_name,
            'analyzed': analyzed, 'total': total,
        })

    threading.Thread(target=_run_all, daemon=True).start()
    return jsonify({'ok': True, 'total': len(all_pcaps)})


@app.route('/api/project/settings/<project_name>', methods=['GET'])
def api_get_project_settings(project_name):
    """回傳專案設定（目前排除 IP 等）"""
    if not os.path.isdir(get_project_dir(project_name)):
        return jsonify({'error': '專案不存在'}), 404
    settings = _load_project_settings(project_name)
    return jsonify({
        'exclude_ips': settings.get('exclude_ips', ''),
    })


@app.route('/')
def index():
    tasks = get_tasks()
    return render_template('index.html', tasks=tasks)


@app.route('/project/new', methods=['POST'])
def new_project():
    name = request.form.get('project_name', '').strip()
    if not name:
        flash('請輸入專案名稱', 'error')
        return redirect(url_for('index'))
    if re.search(r'[\\/:*?"<>|]', name):
        flash('專案名稱包含非法字元（不可含 \\ / : * ? " < > |）', 'error')
        return redirect(url_for('index'))
    project_path = get_project_dir(name)
    if os.path.exists(project_path):
        flash(f'專案「{name}」已存在', 'warning')
    else:
        os.makedirs(os.path.join(project_path, "pcap"), exist_ok=True)
        flash(f'專案「{name}」建立成功', 'success')
    return redirect(url_for('capture_page', project_name=name))


@app.route('/project/<project_name>/capture')
def capture_page(project_name):
    if not os.path.exists(get_project_dir(project_name)):
        flash('專案不存在', 'error')
        return redirect(url_for('index'))
    return render_template('capture.html', project_name=project_name)


@app.route('/project/<project_name>/delete', methods=['POST'])
def delete_project(project_name):
    import shutil
    with capture_states_lock:
        state = capture_states.get(project_name)
        if state and state.get('process'):
            try:
                state['process'].terminate()
            except Exception:
                pass
        capture_states.pop(project_name, None)

    project_dir = get_project_dir(project_name)
    if os.path.exists(project_dir):
        shutil.rmtree(project_dir)

    flash(f'專案「{project_name}」已刪除', 'success')
    return redirect(url_for('index'))


@app.route('/dashboard/<task_name>')
def dashboard(task_name):
    summary_file = os.path.join(PROJECT_DIR, task_name, "analysis_summary.json")
    if not os.path.exists(summary_file):
        flash('分析結果不存在，請先完成側錄與分析', 'warning')
        return redirect(url_for('capture_page', project_name=task_name))
    return render_template('dashboard.html', task_name=task_name)


# ─────────────────────────────────────────────
# 側錄 API
# ─────────────────────────────────────────────

@app.route('/api/interfaces')
def api_interfaces():
    """列出 dumpcap 可用的網路介面"""
    try:
        result = subprocess.run(
            [DUMPCAP_EXE, '-D'],
            capture_output=True, text=True, encoding='utf-8', timeout=10
        )
        interfaces = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # Format: "1. \Device\NPF_{GUID} (Description)"
            m = re.match(r'^(\d+)\.\s+\S+\s+\((.+)\)\s*$', line)
            if m:
                interfaces.append({'index': m.group(1), 'name': m.group(2)})
            else:
                # Fallback: split on first dot
                parts = line.split('.', 1)
                if len(parts) == 2:
                    interfaces.append({'index': parts[0].strip(), 'name': parts[1].strip()})
        return jsonify(interfaces)
    except FileNotFoundError:
        return jsonify({'error': f'找不到 dumpcap：{DUMPCAP_EXE}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/capture/start', methods=['POST'])
def api_capture_start():
    data = request.get_json(force=True) or {}
    project_name = data.get('project_name', '').strip()
    iface_index = data.get('iface_index', '').strip()
    exclude_ips = data.get('exclude_ips', '').strip()

    if not project_name or not iface_index:
        return jsonify({'error': '缺少 project_name 或 iface_index'}), 400

    with capture_states_lock:
        state = capture_states.get(project_name)
        if state and state['status'] == 'capturing':
            return jsonify({'error': '已在側錄中'}), 400

    pcap_dir = get_pcap_dir(project_name)
    os.makedirs(pcap_dir, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    # 輸出檔名加上 .pcap 副檔名，dumpcap ring-buffer 模式會自動加上序號
    # 產生檔案名稱如：test_20260419_123456_00001_20260419123456.pcap
    pcap_base = os.path.join(pcap_dir, f"{project_name}_{timestamp}.pcap")

    # Build BPF filter
    base_filter = "(tcp or udp) and not broadcast and not multicast"
    if exclude_ips:
        ip_parts = [p for p in exclude_ips.replace(',', ' ').replace(';', ' ').split() if p]
        exclude_parts = " and ".join(f"not host {ip}" for ip in ip_parts)
        bpf_filter = f"{base_filter} and {exclude_parts}" if exclude_parts else base_filter
    else:
        bpf_filter = base_filter

    # shell=False + CREATE_NEW_PROCESS_GROUP：
    # - proc.pid 直接是 dumpcap 的 PID（不經過 cmd.exe）
    # - 停止時 os.kill(proc.pid, CTRL_BREAK_EVENT) 可精準送給 dumpcap
    # - dumpcap 收到後正常 flush 並關閉 PCAP，等同在終端機按 Ctrl+C
    cmd = [
        DUMPCAP_EXE,
        '-i', iface_index,
        '-f', bpf_filter,
        '-b', f'filesize:{PCAP_SPLIT_SIZE_KB}',
        '-w', pcap_base,
    ]

    print(f"[dumpcap cmd] {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0,
        )
    except FileNotFoundError:
        return jsonify({'error': f'找不到 dumpcap：{DUMPCAP_EXE}'}), 500
    except Exception as e:
        return jsonify({'error': f'啟動 dumpcap 失敗：{e}'}), 500

    filter_ips = parse_filter_ips(exclude_ips)

    # 持久化 exclude_ips（供重啟後 reanalyze/resume 使用）
    _save_project_settings(project_name, {'exclude_ips': exclude_ips})

    with capture_states_lock:
        capture_states[project_name] = {
            'process': proc,
            'status': 'capturing',
            'packet_count': 0,
            'started_at': datetime.now().isoformat(),
            'filter_ips': filter_ips,
            'iface': iface_index,
            'analyzing': 0,
            'pcap_prefix': f"{project_name}_{timestamp}",
        }

    threading.Thread(target=_read_dumpcap_stderr, args=(project_name, proc), daemon=True).start()
    threading.Thread(target=_poll_packet_count, args=(project_name, pcap_dir), daemon=True).start()
    threading.Thread(target=_watch_pcap_files, args=(project_name, pcap_dir, filter_ips), daemon=True).start()

    split_mb = PCAP_SPLIT_SIZE_KB // 1024
    _append_capture_log(project_name, f'開始側錄（介面 {iface_index}），每 {split_mb} MB 自動切割', 'start')

    return jsonify({'status': 'started', 'project': project_name, 'split_mb': split_mb})


@app.route('/api/capture/stop', methods=['POST'])
def api_capture_stop():
    data = request.get_json(force=True) or {}
    project_name = data.get('project_name', '').strip()

    with capture_states_lock:
        state = capture_states.get(project_name)
        if not state or state['status'] != 'capturing':
            return jsonify({'error': '目前未在側錄'}), 400
        state['status'] = 'stopping'
        proc = state['process']

    try:
        # shell=False + CREATE_NEW_PROCESS_GROUP 的停止方式：
        # CTRL_BREAK_EVENT 送給 process group（group ID = proc.pid），
        # dumpcap 收到後會正常 flush 並關閉 PCAP，效果等同 Ctrl+C。
        if os.name == 'nt':
            import signal as _signal
            os.kill(proc.pid, _signal.CTRL_BREAK_EVENT)
        else:
            proc.terminate()
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

    with capture_states_lock:
        if project_name in capture_states:
            capture_states[project_name]['status'] = 'stopped'
            final_packets = capture_states[project_name].get('packet_count', 0)
        else:
            final_packets = 0

    # 將本次 session 封包數累加到持久化統計
    _save_pcap_stats(project_name, final_packets)

    _append_capture_log(project_name, '側錄已停止，正在排入分析佇列…', 'stop')
    socketio.emit('capture_stopped', {'project': project_name})
    return jsonify({'status': 'stopped'})


@app.route('/api/capture/status/<project_name>')
def api_capture_status(project_name):
    pcap_dir = get_pcap_dir(project_name)
    project_dir = get_project_dir(project_name)
    all_pcaps = glob.glob(os.path.join(pcap_dir, '*.pcap'))
    total_pcap_bytes = sum(os.path.getsize(f) for f in all_pcaps if os.path.isfile(f))
    saved_stats = _load_pcap_stats(project_name)
    saved_total_packets = saved_stats.get('total_packets', 0)
    total_pcap_count = len(all_pcaps)
    analyzed_count = len(glob.glob(os.path.join(project_dir, '*_analysis.json')))

    with capture_states_lock:
        state = capture_states.get(project_name)

    if not state:
        return jsonify({
            'status': 'idle', 'packet_count': 0, 'analyzing': 0,
            'current_bytes': 0,
            'total_pcap_bytes': total_pcap_bytes,
            'total_packets': saved_total_packets,
            'analyzed_count': analyzed_count,
            'total_pcap_count': total_pcap_count,
        })

    pcap_prefix = state.get('pcap_prefix', '')
    current_bytes = sum(
        os.path.getsize(f) for f in all_pcaps
        if os.path.isfile(f) and (not pcap_prefix or os.path.basename(f).startswith(pcap_prefix))
    )
    current_packets = state['packet_count']
    status = state['status']
    # 若仍在側錄中，total 加上本次尚未持久化的封包數；若已停止，已在 stop 時寫入
    total_packets = saved_total_packets + (current_packets if status in ('capturing', 'stopping') else 0)

    return jsonify({
        'status': status,
        'packet_count': current_packets,
        'started_at': state.get('started_at', ''),
        'analyzing': state.get('analyzing', 0),
        'current_bytes': current_bytes,
        'total_pcap_bytes': total_pcap_bytes,
        'total_packets': total_packets,
        'analyzed_count': analyzed_count,
        'total_pcap_count': total_pcap_count,
    })


@app.route('/api/capture/log/<project_name>')
def api_capture_log(project_name):
    """讀取專案的 capture.log，回傳 JSON Lines 解析後的陣列"""
    log_path = os.path.join(get_project_dir(project_name), 'capture.log')
    entries = []
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except Exception:
                            pass
        except Exception:
            pass
    return jsonify(entries)


# ─────────────────────────────────────────────
# 分析結果 API（沿用 3.ui.py 路由）
# ─────────────────────────────────────────────

def _load_summary(task_name):
    summary_file = os.path.join(PROJECT_DIR, task_name, "analysis_summary.json")
    with open(summary_file, 'r', encoding='utf-8') as f:
        return json.load(f)


@app.route('/api/flow/<task_name>')
def api_flow(task_name):
    try:
        return jsonify(_load_summary(task_name).get('flow', {}))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/flow_details/<task_name>/<path:time_period>')
def api_flow_details(task_name, time_period):
    try:
        summary = _load_summary(task_name)
        flow_data = summary.get('flow', {})
        top_ip_per_10_minutes = flow_data.get('top_ip_per_10_minutes', {})
        decoded = unquote(time_period)
        if decoded not in top_ip_per_10_minutes:
            return jsonify({'error': f'找不到時間段 {decoded}'}), 404
        return jsonify({
            'time_period': decoded,
            'total_bytes': flow_data.get('per_10_minutes', {}).get(decoded, 0),
            'top_connections': top_ip_per_10_minutes[decoded]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/top_ip/<task_name>')
def api_top_ip(task_name):
    try:
        return jsonify(_load_summary(task_name).get('top_ip', []))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/geo/<task_name>')
def api_geo(task_name):
    try:
        geo_data = _load_summary(task_name).get('geo', {})
        filtered = {k: v for k, v in geo_data.items()
                    if k.upper() not in ['LOCAL', 'LOCALHOST', 'PRIVATE', 'LAN']}
        return jsonify(filtered)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/events/<task_name>')
def api_events(task_name):
    try:
        return jsonify(_load_summary(task_name).get('event', {}))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/event_details/<task_name>/<protocol>')
def api_event_details(task_name, protocol):
    try:
        events_data = _load_summary(task_name).get('event', {})
        protocol_data = events_data.get(protocol, {})
        if not protocol_data:
            return jsonify({'error': f'找不到協議 {protocol}'}), 404
        return jsonify({
            'protocol': protocol,
            'total_count': protocol_data.get('count', 0),
            'top_connections': protocol_data.get('detailed_stats', [])
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/anomaly/<task_name>')
def api_anomaly(task_name):
    try:
        return jsonify(_parse_fast_log_alerts(task_name))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _parse_fast_log_alerts(task_name):
    log_path = os.path.join(get_project_dir(task_name), 'filtered_merged_fast.log')
    if not os.path.exists(log_path):
        return []

    # key = (sig_id, alert_msg) -> { alert, connections: set }
    seen: dict = {}

    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = _FAST_LOG_RE.match(line)
            if not m:
                continue
            ts, sig_id, msg, classification, priority_str, proto, src, dst = m.groups()
            priority = int(priority_str)
            if priority not in (1, 2):
                continue

            key = (sig_id, msg)
            conn_str = f'{src} -> {dst}'
            if key not in seen:
                seen[key] = {
                    'sig_id': sig_id,
                    'msg': msg,
                    'classification': classification or '',
                    'priority': priority,
                    'proto': proto,
                    'first_time': ts,
                    'connections': set(),
                }
            seen[key]['connections'].add(conn_str)

    alerts = []
    for entry in seen.values():
        count = len(entry['connections'])
        severity = 'critical' if entry['priority'] == 1 else 'high'
        severity_label = '嚴重' if entry['priority'] == 1 else '高風險'
        conn_sample = ', '.join(sorted(entry['connections'])[:5])
        if count > 5:
            conn_sample += f' … 共 {count} 筆'
        alerts.append({
            'type': 'suricata_alert',
            'severity': severity,
            'title': entry['msg'],
            'description': f'[{severity_label}] {entry["msg"]}（{count} 筆連線）',
            'ip': entry['connections'] and sorted(entry['connections'])[0].split(' -> ')[0] or '',
            'time': entry['first_time'],
            'details': {
                'sig_id': entry['sig_id'],
                'classification': entry['classification'],
                'priority': entry['priority'],
                'proto': entry['proto'],
                'connections': conn_sample,
                'count': count,
            }
        })

    # 先嚴重後高風險，同優先級按 count 降冪
    alerts.sort(key=lambda a: (a['details']['priority'], -a['details']['count']))
    return alerts


# ─────────────────────────────────────────────
# 設定頁面
# ─────────────────────────────────────────────

@app.route('/settings')
def settings():
    return render_template('settings.html')


def _get_suricata_rules():
    """從 suricata.yaml 解析啟用中的 rule files，失敗時改列 rules 目錄下的 .rules 檔。"""
    suricata_dir = os.path.dirname(SURICATA_EXE)
    rules_list = []

    yaml_path = os.path.join(suricata_dir, 'suricata.yaml')
    if os.path.exists(yaml_path):
        try:
            in_rule_files = False
            with open(yaml_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    stripped = line.strip()
                    if stripped.startswith('rule-files:'):
                        in_rule_files = True
                        continue
                    if in_rule_files:
                        if stripped.startswith('- '):
                            rules_list.append(stripped[2:].strip().strip('"').strip("'"))
                        elif stripped and not stripped.startswith('#') and ':' in stripped and not stripped.startswith('- '):
                            break
            if rules_list:
                return rules_list
        except Exception:
            pass

    # 備用：列出 rules 目錄下的 .rules 檔
    rules_dir = os.path.join(suricata_dir, 'rules')
    if os.path.exists(rules_dir):
        for fname in sorted(os.listdir(rules_dir)):
            if fname.endswith('.rules'):
                rules_list.append(fname)
    return rules_list


@app.route('/api/settings/config', methods=['GET'])
def api_settings_get_config():
    cfg = _load_settings()
    return jsonify({
        'pcap_split_mb':    cfg.get('pcap_split_mb', PCAP_SPLIT_SIZE_KB // 1024),
        'project_dir':      cfg.get('project_dir', ''),
        'checksum_offload': cfg.get('checksum_offload', False),
    })


@app.route('/api/settings/config', methods=['POST'])
def api_settings_save_config():
    global PCAP_SPLIT_SIZE_KB, PROJECT_DIR, CHECKSUM_OFFLOAD
    data = request.get_json(force=True)
    save = {}

    # PCAP 分割大小
    try:
        mb = int(data.get('pcap_split_mb', PCAP_SPLIT_SIZE_KB // 1024))
        if mb < 10 or mb > 10240:
            return jsonify({'ok': False, 'error': '請輸入 10 ~ 10240 MB 之間的數值'}), 400
        PCAP_SPLIT_SIZE_KB = mb * 1024
        save['pcap_split_mb'] = mb
    except (ValueError, TypeError):
        return jsonify({'ok': False, 'error': '無效的數值'}), 400

    # project 資料夾路徑
    project_dir_input = data.get('project_dir', '').strip()
    if project_dir_input:
        # 安全性：不允許包含 .. 以防目錄穿越
        if '..' in project_dir_input:
            return jsonify({'ok': False, 'error': '路徑不可包含 ..'}), 400
        try:
            os.makedirs(project_dir_input, exist_ok=True)
        except Exception as e:
            return jsonify({'ok': False, 'error': f'無法建立資料夾：{e}'}), 400
        PROJECT_DIR = project_dir_input
    else:
        PROJECT_DIR = 'project'
        os.makedirs(PROJECT_DIR, exist_ok=True)
    save['project_dir'] = project_dir_input

    # checksum offload
    CHECKSUM_OFFLOAD = bool(data.get('checksum_offload', False))
    save['checksum_offload'] = CHECKSUM_OFFLOAD

    _save_settings(save)
    return jsonify({'ok': True, 'pcap_split_mb': save['pcap_split_mb'], 'project_dir': PROJECT_DIR, 'checksum_offload': CHECKSUM_OFFLOAD})


@app.route('/api/settings/check')
def api_settings_check():
    result = {}

    geoip_abs = os.path.abspath(GEOIP_DB)
    result['geoip'] = {
        'label': 'GeoLite2-City.mmdb',
        'ok': os.path.exists(GEOIP_DB),
        'detail': geoip_abs
    }

    result['tshark'] = {
        'label': 'TShark',
        'ok': os.path.exists(TSHARK_EXE),
        'detail': TSHARK_EXE
    }

    result['suricata'] = {
        'label': 'Suricata',
        'ok': os.path.exists(SURICATA_EXE),
        'detail': SURICATA_EXE
    }

    rules_files = _get_suricata_rules()
    result['rules'] = {
        'label': 'Suricata 啟用 Rules',
        'ok': len(rules_files) > 0,
        'detail': f'{len(rules_files)} 個規則檔',
        'rules': rules_files
    }

    return jsonify(result)


@app.route('/api/settings/download/<target>', methods=['POST'])
def api_settings_download(target):
    if target == 'geolite':
        url = 'https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb'
        save_path = os.path.abspath(GEOIP_DB)
    elif target == 'rules':
        url = 'https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules'
        suricata_dir = os.path.dirname(SURICATA_EXE)
        save_path = os.path.abspath(os.path.join(suricata_dir, 'rules', 'emerging-all.rules'))
    else:
        return jsonify({'error': '無效的目標'}), 400

    def _download(url, save_path, target):
        try:
            socketio.emit('download_progress', {'target': target, 'status': 'start', 'progress': 0, 'message': '下載中...'})
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            with requests.get(url, stream=True, timeout=120) as r:
                r.raise_for_status()
                total = int(r.headers.get('content-length', 0))
                downloaded = 0
                with open(save_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=1024 * 1024):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total > 0:
                                progress = int(downloaded / total * 100)
                                socketio.emit('download_progress', {
                                    'target': target, 'status': 'downloading',
                                    'progress': progress,
                                    'message': f'{progress}%'
                                })
            socketio.emit('download_progress', {'target': target, 'status': 'done', 'progress': 100, 'message': '完成'})
        except Exception as e:
            socketio.emit('download_progress', {'target': target, 'status': 'error', 'progress': 0, 'message': str(e)})

    t = threading.Thread(target=_download, args=(url, save_path, target), daemon=True)
    t.start()
    return jsonify({'ok': True, 'message': '下載已開始'})


# ─────────────────────────────────────────────
# 主程式
# ─────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 50)
    print("  PCAP 分析平台")
    print("=" * 50)
    print(f"  專案目錄 : {os.path.abspath(PROJECT_DIR)}")
    print(f"  Suricata : {SURICATA_EXE}")
    print(f"  TShark   : {TSHARK_EXE}")
    print(f"  Dumpcap  : {DUMPCAP_EXE}")
    print(f"  PCAP 分割 : {PCAP_SPLIT_SIZE_KB // 1024} MB")
    print()
    print("  開啟瀏覽器：http://localhost:5000")
    print("=" * 50)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
