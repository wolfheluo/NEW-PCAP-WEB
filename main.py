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

PROJECT_DIR = "project"
SURICATA_EXE = r"C:\Program Files\Suricata\suricata.exe"
TSHARK_EXE = r"C:\Program Files\Wireshark\tshark.exe"
DUMPCAP_EXE = r"C:\Program Files\Wireshark\dumpcap.exe"
GEOIP_DB = "GeoLite2-City.mmdb"
PCAP_SPLIT_SIZE_KB = 204800  # 200 MB

os.makedirs(PROJECT_DIR, exist_ok=True)

# 全局側錄狀態
# { project_name: { process, status, packet_count, started_at, filter_ips, analyzing } }
capture_states: dict = {}
capture_states_lock = threading.Lock()


# ─────────────────────────────────────────────
# 工具函式
# ─────────────────────────────────────────────

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

def detect_anomalies(summary):
    count = 0
    try:
        top_ip = summary.get('top_ip', [])
        if top_ip and top_ip[0].get('bytes', 0) > 100 * 1024 * 1024:
            count += 1
        events = summary.get('event', {})
        total_events = sum(e.get('count', 0) for e in events.values())
        if total_events > 0 and events.get('TLS', {}).get('count', 0) / total_events > 0.8:
            count += 1
        geo = summary.get('geo', {})
        total_geo = sum(geo.values())
        if total_geo > 0:
            suspicious = sum(v for k, v in geo.items() if k not in ['LOCAL', 'TW', 'US'])
            if suspicious / total_geo > 0.3:
                count += 1
    except Exception:
        pass
    return count

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
                task['anomaly_count'] = detect_anomalies(summary)
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
                        socketio.emit('packet_count', {'project': project_name, 'count': total})


def _analyze_single_pcap(project_name, pcap_file, filter_ips):
    """對單一 PCAP 執行 Suricata + TShark 分析並推送進度"""
    project_dir = get_project_dir(project_name)
    pcap_stem = Path(pcap_file).stem
    fname = os.path.basename(pcap_file)

    with capture_states_lock:
        if project_name in capture_states:
            capture_states[project_name]['analyzing'] = capture_states[project_name].get('analyzing', 0) + 1

    def _emit(stage, percent):
        socketio.emit('analysis_progress', {
            'project': project_name, 'stage': stage,
            'file': fname, 'percent': percent
        })

    try:
        _emit('suricata', 10)
        suricata_out = os.path.join(project_dir, "suricata", pcap_stem)
        run_suricata_on_pcap(pcap_file, suricata_out, SURICATA_EXE)

        _emit('tshark', 50)
        run_tshark_on_pcap(pcap_file, project_dir, TSHARK_EXE, GEOIP_DB, filter_ips)

        _emit('merging', 80)
        merge_suricata_logs(project_dir)
        merge_all_results(project_dir, filter_ips)

        _emit('complete', 100)
        socketio.emit('analysis_complete', {'project': project_name, 'file': fname})

    except Exception as e:
        socketio.emit('analysis_error', {'project': project_name, 'error': str(e)})
    finally:
        with capture_states_lock:
            if project_name in capture_states:
                n = capture_states[project_name].get('analyzing', 1)
                capture_states[project_name]['analyzing'] = max(0, n - 1)


def _watch_pcap_files(project_name, pcap_dir, filter_ips):
    """監控 pcap 目錄，偵測已完成的 PCAP 並觸發分析"""
    processed = set()

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
            break
        if not is_running and not all_pcap:
            break


# ─────────────────────────────────────────────
# 頁面路由
# ─────────────────────────────────────────────

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
        ip_parts = exclude_ips.split()
        exclude_parts = " and ".join(f"not host {ip}" for ip in ip_parts if ip)
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

    with capture_states_lock:
        capture_states[project_name] = {
            'process': proc,
            'status': 'capturing',
            'packet_count': 0,
            'started_at': datetime.now().isoformat(),
            'filter_ips': filter_ips,
            'iface': iface_index,
            'analyzing': 0,
        }

    threading.Thread(target=_read_dumpcap_stderr, args=(project_name, proc), daemon=True).start()
    threading.Thread(target=_poll_packet_count, args=(project_name, pcap_dir), daemon=True).start()
    threading.Thread(target=_watch_pcap_files, args=(project_name, pcap_dir, filter_ips), daemon=True).start()

    return jsonify({'status': 'started', 'project': project_name})


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

    socketio.emit('capture_stopped', {'project': project_name})
    return jsonify({'status': 'stopped'})


@app.route('/api/capture/status/<project_name>')
def api_capture_status(project_name):
    with capture_states_lock:
        state = capture_states.get(project_name)
    if not state:
        return jsonify({'status': 'idle', 'packet_count': 0, 'analyzing': 0})
    return jsonify({
        'status': state['status'],
        'packet_count': state['packet_count'],
        'started_at': state.get('started_at', ''),
        'analyzing': state.get('analyzing', 0),
    })


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
        summary = _load_summary(task_name)
        return jsonify(_generate_anomaly_alerts(summary))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _generate_anomaly_alerts(summary):
    alerts = []
    try:
        top_ip = summary.get('top_ip', [])
        for i, conn in enumerate(top_ip[:5]):
            bytes_val = conn.get('bytes', 0)
            if bytes_val > 50 * 1024 * 1024:
                connection = conn.get('connection', '')
                src_ip = connection.split(' -> ')[0].split(':')[0] if ' -> ' in connection else ''
                alerts.append({
                    'type': 'high_traffic',
                    'severity': 'high' if bytes_val > 200 * 1024 * 1024 else 'medium',
                    'title': '大流量連接警示',
                    'description': f'偵測到異常大流量連接：{format_bytes(bytes_val)}',
                    'ip': src_ip, 'connection': connection,
                    'time': summary.get('flow', {}).get('start_time', ''),
                    'details': {'bytes': bytes_val, 'rank': i + 1,
                                'percentage': round(bytes_val / max(summary.get('flow', {}).get('total_bytes', 1), 1) * 100, 2)}
                })

        events = summary.get('event', {})
        total_events = sum(e.get('count', 0) for e in events.values())
        if total_events > 0:
            for protocol, event_data in events.items():
                count = event_data.get('count', 0)
                percentage = count / total_events * 100
                if protocol == 'OTHER' and percentage > 50:
                    alerts.append({
                        'type': 'protocol_anomaly', 'severity': 'medium',
                        'title': '未識別協議過多',
                        'description': f'未識別協議佔 {percentage:.1f}%，可能存在惡意流量',
                        'ip': event_data.get('top_ip', ''),
                        'time': summary.get('flow', {}).get('start_time', ''),
                        'details': {'protocol': protocol, 'count': count, 'percentage': round(percentage, 2)}
                    })
                elif protocol in ['TLS', 'TCP'] and percentage > 70:
                    alerts.append({
                        'type': 'protocol_anomaly', 'severity': 'low',
                        'title': f'{protocol} 協議流量過多',
                        'description': f'{protocol} 佔 {percentage:.1f}%，建議進一步檢查',
                        'ip': event_data.get('top_ip', ''),
                        'time': summary.get('flow', {}).get('start_time', ''),
                        'details': {'protocol': protocol, 'count': count, 'percentage': round(percentage, 2)}
                    })

        geo = summary.get('geo', {})
        total_geo = sum(geo.values())
        if total_geo > 0:
            for country, bytes_val in geo.items():
                pct = bytes_val / total_geo * 100
                if country in ['RU', 'CN', 'KP', 'IR'] and pct > 5:
                    alerts.append({
                        'type': 'geo_anomaly', 'severity': 'medium',
                        'title': '可疑國家流量警示',
                        'description': f'偵測到來自 {country} 的流量：{format_bytes(bytes_val)} ({pct:.1f}%)',
                        'ip': '', 'time': summary.get('flow', {}).get('start_time', ''),
                        'details': {'country': country, 'bytes': bytes_val, 'percentage': round(pct, 2)}
                    })

        per_10_minutes = summary.get('flow', {}).get('per_10_minutes', {})
        for time_str, bytes_val in per_10_minutes.items():
            try:
                hour = datetime.strptime(time_str, '%Y-%m-%d %H:%M').hour
                if (hour >= 22 or hour <= 6) and bytes_val > 100 * 1024 * 1024:
                    alerts.append({
                        'type': 'time_anomaly', 'severity': 'medium',
                        'title': '深夜異常流量',
                        'description': f'{time_str} 偵測到大流量：{format_bytes(bytes_val)}',
                        'ip': '', 'time': time_str,
                        'details': {'time_period': time_str, 'bytes': bytes_val, 'hour': hour}
                    })
            except ValueError:
                continue
    except Exception as e:
        print(f"異常警示生成失敗: {e}")
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
