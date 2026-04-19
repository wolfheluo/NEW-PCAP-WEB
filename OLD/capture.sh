#!/bin/bash

echo "==== 可用網路介面 ===="
dumpcap -D

read -p "請輸入你要使用的網卡編號: " iface_index

read -p "請輸入你要排除的 IP（多個 IP 請用空格分隔，可留空）: " exclude_ips

read -p "請輸入單位名稱（例如：114_tycg）: " unit_name

# 產生 timestamp
timestamp=$(date +%Y%m%d_%H%M%S)

# 建立儲存路徑（若不存在）
save_dir="$HOME/Desktop/pcap_capture"
mkdir -p "$save_dir"

# 輸出檔案名稱
outfile="$save_dir/${unit_name}_${timestamp}.pcap"

# 建立 BPF filter 字串
base_filter="(tcp or udp) and not broadcast and not multicast"
if [ -n "$exclude_ips" ]; then
    # 將多個 IP 分割並建立排除條件
    exclude_filter=""
    for ip in $exclude_ips; do
        if [ -n "$exclude_filter" ]; then
            exclude_filter="$exclude_filter and not host $ip"
        else
            exclude_filter="not host $ip"
        fi
    done
    filter="$base_filter and $exclude_filter"
else
    filter="$base_filter"
fi

echo "開始擷取封包到: $outfile"
echo "使用介面編號: $iface_index"
echo "擷取條件: $filter"

# 執行 dumpcap
dumpcap -i "$iface_index" -f "$filter" -b filesize:512000 -w "$outfile"
