#!/usr/bin/env python3
"""
TShark 分析模組
提供對 PCAP 檔案進行流量統計、IP 分析、協議統計、GeoIP 查詢的函式，
以及合併多個分析結果為 analysis_summary.json 的工具。
"""

import os
import glob
import subprocess
import json
import ipaddress
import shutil
import requests
from datetime import datetime
from pathlib import Path
from collections import defaultdict

TSHARK_EXE_DEFAULT = r"C:\Program Files\Wireshark\tshark.exe"
GEOIP_DB_DEFAULT = "GeoLite2-City.mmdb"

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


# ─────────────────────────────────────────────
# 工具函式
# ─────────────────────────────────────────────

def parse_filter_ips(ip_input):
    """解析使用者輸入的 IP 列表（支援單個 IP、空格/逗號分隔、CIDR）"""
    filter_ips = set()
    if not ip_input or ip_input.strip() == "":
        return filter_ips

    ip_parts = ip_input.replace(',', ' ').replace(';', ' ').split()
    for ip_part in ip_parts:
        ip_part = ip_part.strip()
        if not ip_part:
            continue
        try:
            if '/' in ip_part:
                network = ipaddress.ip_network(ip_part, strict=False)
                if network.num_addresses <= 256:
                    for ip in network.hosts():
                        filter_ips.add(str(ip))
                    filter_ips.add(str(network.network_address))
                    filter_ips.add(str(network.broadcast_address))
                else:
                    filter_ips.add(str(network.network_address))
            else:
                filter_ips.add(str(ipaddress.ip_address(ip_part)))
        except ValueError:
            print(f"無效的 IP: {ip_part}")
    return filter_ips


def should_filter_connection(src_ip, dst_ip, filter_ips):
    if not filter_ips:
        return False
    primary_src = parse_multiple_values(src_ip, "ip") if src_ip else None
    primary_dst = parse_multiple_values(dst_ip, "ip") if dst_ip else None
    if primary_src and primary_src in filter_ips:
        return True
    if primary_dst and primary_dst in filter_ips:
        return True
    return False


def parse_multiple_values(value_string, value_type="ip"):
    if not value_string:
        return None
    if ',' not in value_string:
        return value_string.strip()

    values = [v.strip() for v in value_string.split(',') if v.strip()]
    if not values:
        return None

    if value_type == "ip":
        for value in values:
            try:
                ip_obj = ipaddress.ip_address(value)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast):
                    return value
            except ValueError:
                continue
        for value in values:
            try:
                ipaddress.ip_address(value)
                return value
            except ValueError:
                continue
    elif value_type == "port":
        for value in values:
            try:
                port_num = int(value)
                if 0 <= port_num <= 65535:
                    return value
            except ValueError:
                continue

    return values[0] if values else None


def create_connection_string(src_ip, dst_ip, src_port, dst_port):
    primary_src = parse_multiple_values(src_ip, "ip")
    primary_dst = parse_multiple_values(dst_ip, "ip")
    if not primary_src or not primary_dst:
        return None
    primary_src_port = parse_multiple_values(src_port, "port") if src_port else ''
    primary_dst_port = parse_multiple_values(dst_port, "port") if dst_port else ''
    if primary_src_port and primary_dst_port:
        return f"{primary_src}:{primary_src_port} -> {primary_dst}:{primary_dst_port}"
    return f"{primary_src} -> {primary_dst}"


def get_country_code(geo_reader, ip_address_str):
    if not geo_reader or not ip_address_str:
        return None
    try:
        ip_obj = ipaddress.ip_address(ip_address_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
            return 'LOCAL'
        response = geo_reader.city(ip_address_str)
        return response.country.iso_code or 'UNKNOWN'
    except Exception:
        return 'UNKNOWN'


def download_geoip_database(dest='GeoLite2-City.mmdb'):
    db_url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
    try:
        response = requests.get(db_url, stream=True, timeout=60)
        response.raise_for_status()
        with open(dest, 'wb') as f:
            shutil.copyfileobj(response.raw, f)
        print(f"GeoLite2-City.mmdb 下載完成")
        return True
    except Exception as e:
        print(f"GeoIP 下載失敗: {e}")
        return False


# ─────────────────────────────────────────────
# TShark 執行
# ─────────────────────────────────────────────

def run_tshark_command(tshark_exe, pcap_file, fields, filter_expr=""):
    cmd = [tshark_exe, "-r", pcap_file, "-T", "fields", "-E", "separator=|"]
    for field in fields:
        cmd.extend(["-e", field])
    if filter_expr:
        cmd.extend(["-Y", filter_expr])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        return result.stdout.strip().split('\n') if result.stdout.strip() else []
    except Exception as e:
        print(f"tshark 執行失敗: {e}")
        return []


# ─────────────────────────────────────────────
# 分析函式
# ─────────────────────────────────────────────

def analyze_pcap_basic_info(tshark_exe, pcap_file, filter_ips=None):
    fields = ["frame.time_epoch", "frame.len", "ip.src", "ip.dst",
              "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]
    lines = run_tshark_command(tshark_exe, pcap_file, fields)

    if not lines or lines == ['']:
        return None

    timestamps = []
    total_bytes = 0
    filtered_count = 0
    per_10_minutes = {}
    per_10_minutes_ip_traffic = {}

    for line in lines:
        if '|' not in line:
            continue
        parts = line.split('|')
        if len(parts) < 8:
            continue
        try:
            timestamp = float(parts[0])
            frame_len = int(parts[1])
            src_ip = parts[2]
            dst_ip = parts[3]
            tcp_src_port = parts[4]
            tcp_dst_port = parts[5]
            udp_src_port = parts[6]
            udp_dst_port = parts[7]

            if should_filter_connection(src_ip, dst_ip, filter_ips):
                filtered_count += 1
                continue

            timestamps.append(timestamp)
            total_bytes += frame_len

            dt = datetime.fromtimestamp(timestamp)
            minute_boundary = (dt.minute // 10) * 10
            time_key = dt.replace(minute=minute_boundary, second=0, microsecond=0).strftime('%Y-%m-%d %H:%M')

            per_10_minutes.setdefault(time_key, 0)
            per_10_minutes_ip_traffic.setdefault(time_key, defaultdict(int))
            per_10_minutes[time_key] += frame_len

            if src_ip and dst_ip:
                final_src_port = tcp_src_port or udp_src_port
                final_dst_port = tcp_dst_port or udp_dst_port
                connection = create_connection_string(src_ip, dst_ip, final_src_port, final_dst_port)
                if connection:
                    per_10_minutes_ip_traffic[time_key][connection] += frame_len

        except (ValueError, IndexError):
            continue

    if not timestamps:
        return None

    top_ip_per_10_minutes = {}
    for time_key in sorted(per_10_minutes_ip_traffic.keys()):
        top_conns = sorted(per_10_minutes_ip_traffic[time_key].items(), key=lambda x: x[1], reverse=True)[:5]
        top_ip_per_10_minutes[time_key] = [{'connection': c, 'bytes': b} for c, b in top_conns]

    return {
        'start_time': datetime.fromtimestamp(min(timestamps)).isoformat(),
        'end_time': datetime.fromtimestamp(max(timestamps)).isoformat(),
        'total_bytes': total_bytes,
        'per_10_minutes': dict(sorted(per_10_minutes.items())),
        'top_ip_per_10_minutes': top_ip_per_10_minutes,
        'filtered_packets': filtered_count,
    }


def analyze_ip_traffic(tshark_exe, pcap_file, filter_ips=None):
    fields = ["frame.time_epoch", "ip.src", "ip.dst",
              "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "frame.len"]
    lines = run_tshark_command(tshark_exe, pcap_file, fields)

    connection_stats = defaultdict(int)
    connection_time_stats = defaultdict(lambda: defaultdict(int))
    connection_protocols = {}
    total_traffic = 0

    for line in lines:
        if '|' not in line or not line.strip():
            continue
        parts = line.split('|')
        if len(parts) < 8:
            continue
        try:
            timestamp = float(parts[0]) if parts[0] else 0
            src_ip = parts[1] or 'N/A'
            dst_ip = parts[2] or 'N/A'
            tcp_src = parts[3]
            tcp_dst = parts[4]
            udp_src = parts[5]
            udp_dst = parts[6]
            frame_len = int(parts[7]) if parts[7] else 0

            if should_filter_connection(src_ip, dst_ip, filter_ips):
                continue

            total_traffic += frame_len

            src_port = tcp_src or udp_src
            dst_port = tcp_dst or udp_dst
            protocol = 'TCP' if tcp_src else ('UDP' if udp_src else 'OTHER')

            if src_ip != 'N/A' and dst_ip != 'N/A':
                connection = create_connection_string(src_ip, dst_ip, src_port, dst_port)
                if connection:
                    connection_stats[connection] += frame_len
                    connection_protocols[connection] = protocol
                    if timestamp > 0:
                        dt = datetime.fromtimestamp(timestamp)
                        minute_boundary = (dt.minute // 10) * 10
                        time_key = dt.replace(minute=minute_boundary, second=0, microsecond=0).strftime('%Y-%m-%d %H:%M')
                        connection_time_stats[connection][time_key] += frame_len

        except (ValueError, IndexError):
            continue

    sorted_connections = sorted(connection_stats.items(), key=lambda x: x[1], reverse=True)[:10]
    result = []
    for connection, bytes_total in sorted_connections:
        time_stats = connection_time_stats[connection]
        top_time_periods = sorted(time_stats.items(), key=lambda x: x[1], reverse=True)[:3]
        top_periods_info = []
        for i, (time_period, period_bytes) in enumerate(top_time_periods, 1):
            period_percentage = (period_bytes / total_traffic * 100) if total_traffic > 0 else 0
            top_periods_info.append({
                'rank': i,
                'time_period': time_period,
                'bytes': period_bytes,
                'percentage_of_total': round(period_percentage, 2)
            })
        result.append({
            'connection': connection,
            'bytes': bytes_total,
            'protocol': connection_protocols.get(connection, 'UNKNOWN'),
            'top_3_time_periods': top_periods_info
        })
    return result


def analyze_protocols(tshark_exe, pcap_file, filter_ips=None):
    target_protocols = {'DNS', 'DHCP', 'SMTP', 'TCP', 'TLS', 'SNMP',
                        'HTTP', 'FTP', 'SMB3', 'SMB2', 'SMB', 'HTTPS', 'ICMP'}

    fields = ["frame.protocols", "ip.src", "ip.dst", "frame.len"]
    lines = run_tshark_command(tshark_exe, pcap_file, fields)

    protocol_stats = {}
    other_stats = {'count': 0, 'top_ip': '', 'ip_stats': defaultdict(int),
                   'connections': defaultdict(lambda: {'packet_count': 0, 'packet_size': 0})}

    for line in lines:
        if '|' not in line or not line.strip():
            continue
        parts = line.split('|')
        if len(parts) < 4:
            continue
        try:
            protocols = parts[0].split(':') if parts[0] else []
            src_ip = parts[1] or 'N/A'
            dst_ip = parts[2] or 'N/A'
            frame_len = int(parts[3]) if parts[3] else 0

            if should_filter_connection(src_ip, dst_ip, filter_ips):
                continue

            found_protocol = None
            for p in reversed(protocols):
                if p.upper() in target_protocols:
                    found_protocol = p.upper()
                    break

            main_protocol = found_protocol or 'OTHER'

            if main_protocol != 'OTHER':
                if main_protocol not in protocol_stats:
                    protocol_stats[main_protocol] = {
                        'count': 0, 'top_ip': '', 'ip_stats': defaultdict(int),
                        'connections': defaultdict(lambda: {'packet_count': 0, 'packet_size': 0})
                    }
                target_stats = protocol_stats[main_protocol]
            else:
                target_stats = other_stats

            target_stats['count'] += 1
            if src_ip != 'N/A':
                target_stats['ip_stats'][src_ip] += 1
            if dst_ip != 'N/A':
                target_stats['ip_stats'][dst_ip] += 1

            if src_ip != 'N/A' and dst_ip != 'N/A':
                primary_src = parse_multiple_values(src_ip, "ip")
                primary_dst = parse_multiple_values(dst_ip, "ip")
                if primary_src and primary_dst:
                    conn_key = f"{primary_src} -> {primary_dst}"
                    target_stats['connections'][conn_key]['packet_count'] += 1
                    target_stats['connections'][conn_key]['packet_size'] += frame_len

        except (ValueError, IndexError):
            continue

    if other_stats['count'] > 0:
        protocol_stats['OTHER'] = other_stats

    result = {}
    for protocol, stats in protocol_stats.items():
        top_ip = max(stats['ip_stats'].items(), key=lambda x: x[1])[0] if stats['ip_stats'] else ''
        connections_list = []
        for conn_key, conn_stats in stats['connections'].items():
            src_ip, dst_ip = conn_key.split(' -> ')
            connections_list.append({
                'src_ip': src_ip, 'dst_ip': dst_ip,
                'packet_count': conn_stats['packet_count'],
                'packet_size': conn_stats['packet_size']
            })
        connections_list.sort(key=lambda x: x['packet_size'], reverse=True)
        result[protocol] = {
            'count': stats['count'],
            'top_ip': top_ip,
            'detailed_stats': connections_list[:5]
        }
    return result


def analyze_ip_countries(tshark_exe, pcap_file, geo_reader, filter_ips=None):
    fields = ["ip.src", "ip.dst", "frame.len"]
    lines = run_tshark_command(tshark_exe, pcap_file, fields)

    country_bytes = defaultdict(int)

    for line in lines:
        if '|' not in line or not line.strip():
            continue
        parts = line.split('|')
        if len(parts) < 3:
            continue
        try:
            src_ip = parts[0] or None
            dst_ip = parts[1] or None
            frame_len = int(parts[2]) if parts[2] else 0

            if should_filter_connection(src_ip, dst_ip, filter_ips):
                continue

            if src_ip:
                primary_src = parse_multiple_values(src_ip, "ip")
                if primary_src:
                    code = get_country_code(geo_reader, primary_src)
                    if code:
                        country_bytes[code] += frame_len
            if dst_ip:
                primary_dst = parse_multiple_values(dst_ip, "ip")
                if primary_dst:
                    code = get_country_code(geo_reader, primary_dst)
                    if code:
                        country_bytes[code] += frame_len
        except (ValueError, IndexError):
            continue

    return dict(sorted(country_bytes.items(), key=lambda x: x[1], reverse=True))


# ─────────────────────────────────────────────
# 單檔處理 & 合併
# ─────────────────────────────────────────────

def run_tshark_on_pcap(pcap_file, project_dir, tshark_exe=TSHARK_EXE_DEFAULT,
                        geoip_db=GEOIP_DB_DEFAULT, filter_ips=None):
    """對單一 PCAP 執行完整 TShark 分析，結果儲存為 <stem>_analysis.json"""
    if not os.path.exists(tshark_exe):
        raise FileNotFoundError(f"找不到 tshark: {tshark_exe}")

    # 載入 GeoIP
    geo_reader = None
    if GEOIP_AVAILABLE and os.path.exists(geoip_db):
        try:
            import geoip2.database
            geo_reader = geoip2.database.Reader(geoip_db)
        except Exception as e:
            print(f"GeoIP 載入失敗: {e}")

    print(f"TShark 分析: {os.path.basename(pcap_file)}")
    flow_info = analyze_pcap_basic_info(tshark_exe, pcap_file, filter_ips)
    if not flow_info:
        print(f"無法取得基本資訊: {pcap_file}")
        return None

    top_connections = analyze_ip_traffic(tshark_exe, pcap_file, filter_ips)
    events = analyze_protocols(tshark_exe, pcap_file, filter_ips)
    geo = analyze_ip_countries(tshark_exe, pcap_file, geo_reader, filter_ips)

    if geo_reader:
        geo_reader.close()

    result = {
        'flow': flow_info,
        'top_ip': top_connections,
        'event': events,
        'geo': geo,
        'analysis_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'source_file': os.path.basename(pcap_file),
        'filter_settings': {
            'filtered_ips': list(filter_ips) if filter_ips else [],
            'total_filtered_ips': len(filter_ips) if filter_ips else 0,
        }
    }

    pcap_stem = Path(pcap_file).stem
    output_file = os.path.join(project_dir, f"{pcap_stem}_analysis.json")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"TShark 完成: {output_file}")
    return result


def merge_all_results(project_dir, filter_ips=None):
    """讀取 project_dir 下所有 *_analysis.json 並合併為 analysis_summary.json"""
    analysis_files = glob.glob(os.path.join(project_dir, "*_analysis.json"))

    if not analysis_files:
        print("沒有分析結果可合併")
        return None

    all_results = []
    for f in analysis_files:
        try:
            with open(f, 'r', encoding='utf-8') as fp:
                data = json.load(fp)
            if isinstance(data, dict) and 'flow' in data:
                all_results.append(data)
        except Exception as e:
            print(f"讀取 {f} 失敗: {e}")

    if not all_results:
        return None

    # 合併
    merged_flow = {
        'start_time': None, 'end_time': None, 'total_bytes': 0,
        'per_10_minutes': defaultdict(int),
        'top_ip_per_10_minutes': defaultdict(lambda: defaultdict(int)),
        'total_filtered_packets': 0,
    }
    merged_top_ip = defaultdict(int)
    merged_top_ip_time_stats = defaultdict(lambda: defaultdict(int))
    merged_top_ip_protocols = {}
    merged_events = {}
    merged_geo = defaultdict(int)

    for result in all_results:
        flow = result['flow']

        if merged_flow['start_time'] is None or flow['start_time'] < merged_flow['start_time']:
            merged_flow['start_time'] = flow['start_time']
        if merged_flow['end_time'] is None or flow['end_time'] > merged_flow['end_time']:
            merged_flow['end_time'] = flow['end_time']

        merged_flow['total_bytes'] += flow['total_bytes']
        merged_flow['total_filtered_packets'] += flow.get('filtered_packets', 0)

        for time_key, bytes_val in flow['per_10_minutes'].items():
            merged_flow['per_10_minutes'][time_key] += bytes_val

        for time_key, top_conn_list in flow.get('top_ip_per_10_minutes', {}).items():
            for conn_info in top_conn_list:
                merged_flow['top_ip_per_10_minutes'][time_key][conn_info['connection']] += conn_info['bytes']

        for conn_info in result['top_ip']:
            connection = conn_info['connection']
            merged_top_ip[connection] += conn_info['bytes']
            if 'protocol' in conn_info:
                merged_top_ip_protocols[connection] = conn_info['protocol']
            for period_info in conn_info.get('top_3_time_periods', []):
                merged_top_ip_time_stats[connection][period_info['time_period']] += period_info['bytes']

        for protocol, protocol_data in result['event'].items():
            if protocol not in merged_events:
                merged_events[protocol] = {
                    'count': 0, 'top_ip': protocol_data['top_ip'],
                    'ip_stats': defaultdict(int),
                    'connections': defaultdict(lambda: {'packet_count': 0, 'packet_size': 0})
                }
            merged_events[protocol]['count'] += protocol_data['count']
            for stat in protocol_data['detailed_stats']:
                conn_key = f"{stat['src_ip']} -> {stat['dst_ip']}"
                merged_events[protocol]['connections'][conn_key]['packet_count'] += stat['packet_count']
                merged_events[protocol]['connections'][conn_key]['packet_size'] += stat['packet_size']

        for country_code, bytes_val in result['geo'].items():
            merged_geo[country_code] += bytes_val

    # 整理 top_ip
    top_connections = []
    for connection, total_bytes in sorted(merged_top_ip.items(), key=lambda x: x[1], reverse=True)[:10]:
        time_stats = merged_top_ip_time_stats[connection]
        top_time_periods = sorted(time_stats.items(), key=lambda x: x[1], reverse=True)[:3]
        top_periods_info = []
        for i, (time_period, period_bytes) in enumerate(top_time_periods, 1):
            pct = (period_bytes / merged_flow['total_bytes'] * 100) if merged_flow['total_bytes'] > 0 else 0
            top_periods_info.append({
                'rank': i, 'time_period': time_period,
                'bytes': period_bytes, 'percentage_of_total': round(pct, 2)
            })
        top_connections.append({
            'connection': connection, 'bytes': total_bytes,
            'protocol': merged_top_ip_protocols.get(connection, 'UNKNOWN'),
            'top_3_time_periods': top_periods_info
        })

    # 整理 events
    final_events = {}
    for protocol, data in merged_events.items():
        connections_list = []
        for conn_key, conn_stats in data['connections'].items():
            src_ip, dst_ip = conn_key.split(' -> ')
            connections_list.append({
                'src_ip': src_ip, 'dst_ip': dst_ip,
                'packet_count': conn_stats['packet_count'],
                'packet_size': conn_stats['packet_size']
            })
        connections_list.sort(key=lambda x: x['packet_size'], reverse=True)
        final_events[protocol] = {
            'count': data['count'], 'top_ip': data['top_ip'],
            'detailed_stats': connections_list[:5]
        }

    # 整理 per_10_minutes top_ip
    final_top_ip_per_10_minutes = {}
    for time_key in sorted(merged_flow['top_ip_per_10_minutes'].keys()):
        ip_traffic = merged_flow['top_ip_per_10_minutes'][time_key]
        top_conns = sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)[:5]
        final_top_ip_per_10_minutes[time_key] = [
            {'connection': c, 'bytes': b} for c, b in top_conns
        ]

    merged_flow['per_10_minutes'] = dict(sorted(merged_flow['per_10_minutes'].items()))
    merged_flow['top_ip_per_10_minutes'] = final_top_ip_per_10_minutes

    total_summary = {
        'summary': {
            'total_files_processed': len(all_results),
            'analysis_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'filter_settings': {
                'filtered_ips': list(filter_ips) if filter_ips else [],
                'total_filtered_ips': len(filter_ips) if filter_ips else 0,
                'total_filtered_packets': merged_flow['total_filtered_packets'],
            }
        },
        'flow': merged_flow,
        'top_ip': top_connections,
        'event': final_events,
        'geo': dict(sorted(merged_geo.items(), key=lambda x: x[1], reverse=True))
    }

    summary_file = os.path.join(project_dir, "analysis_summary.json")
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(total_summary, f, ensure_ascii=False, indent=2)

    print(f"分析摘要已儲存: {summary_file}")
    return total_summary
