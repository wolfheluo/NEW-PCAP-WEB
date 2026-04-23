@echo off
cd /d "C:\Users\PCAP\Documents\workspace\NEW-PCAP-WEB"

if not exist "C:\Users\PCAP\Documents\workspace\NEW-PCAP-WEB\venv\Scripts\activate.bat" (
    echo [*] 建立虛擬環境...
    python -m venv "C:\Users\PCAP\Documents\workspace\NEW-PCAP-WEB\venv"
    echo [*] 安裝套件...
    "C:\Users\PCAP\Documents\workspace\NEW-PCAP-WEB\venv\Scripts\pip" install -r "C:\Users\PCAP\Documents\workspace\NEW-PCAP-WEB\requirements.txt"
)

echo [*] 啟動虛擬環境...
call "C:\Users\PCAP\Documents\workspace\NEW-PCAP-WEB\venv\Scripts\activate.bat"

echo [*] 執行 main.py...
python "C:\Users\PCAP\Documents\workspace\NEW-PCAP-WEB\main.py"

pause
