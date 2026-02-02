#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author: yinkaisheng@foxmail.com
import os
import sys
import time
import shlex
import shutil
import locale
import functools
import traceback
import subprocess
from datetime import datetime, timedelta

import psutil

from log_util import logger, log, Fore

PythonExePath = os.path.realpath(sys.executable) # get real python path(may be link such as /usr/bin/python3)
ExePath = os.path.abspath(sys.argv[0])
ExeDir, ExeNameWithExt = os.path.split(ExePath)
ExeNameNoExt = os.path.splitext(ExeNameWithExt)[0]

if sys.platform == 'win32':
    mem_properties = ['wset', "private"]
elif sys.platform == 'linux':
    mem_properties = ['vms', 'rss', "uss"]
else:
    mem_properties = ['rss', "uss"]


def get_exception_stack(with_color: bool = False) -> str:
    ex_type, ex_value, ex_traceback = sys.exc_info()
    # printx(ex_type, ex_value, ex_traceback)
    tb: traceback.StackSummary = traceback.extract_tb(ex_traceback)
    # printx(tb)
    frame: traceback.FrameSummary
    frame_count = len(tb)
    color = Fore.Red if with_color else ''
    stacks = [f'--------{ex_type}']
    for i, frame in enumerate(tb):
        # filename, lineno, funcname, code = frame
        filename = frame.filename[frame.filename.rfind(os.sep)+1:]
        if i < frame_count - 1:
            stacks.append(f'|{"  "*i}{filename} {frame.lineno} {frame.name}: {frame.line}')
        else:
            stacks.append(f'|{color}{"  "*i}{filename} {frame.lineno} {frame.name}: {frame.line}')
    stacks.append(f'{Fore.Reset}--------' if with_color else '--------')
    return '\n'.join(stacks)


def catch_exception(exception_return=None):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except BaseException as ex:
                print(f'\n\nfunction {Fore.Yellow}{func.__name__!r}{Fore.Reset} got an Exception: {Fore.Magenta}{ex!r}{Fore.Reset}\n{get_exception_stack(True)}\n')
                return exception_return
        return wrapper
    return decorator


def async_catch_exception(exception_return=None):
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except BaseException as ex:
                print(f'\n\nfunction {Fore.Yellow}{func.__name__!r}{Fore.Reset} got an Exception: {Fore.Magenta}{ex!r}{Fore.Reset}\n{get_exception_stack(True)}\n')
                return exception_return
        return wrapper
    return decorator


def get_default_encoding():
    if sys.version_info >= (3, 11):
        encoding = locale.getencoding()
    else:
        encoding = locale.getpreferredencoding(False)
    return encoding


def delete_old_directory(directory: str, keep_days: int, subdirectory_name_format: str = '%Y%m%d'):
    """Delete subdirectories older than specified days

    Scans a directory for subdirectories with numeric names matching the date format,
    and deletes those created before the specified number of days ago.

    Args:
        directory: Directory path to scan for old subdirectories
        keep_days: Number of days to keep (subdirectories older than this will be deleted)
        subdirectory_name_format: Date format string for subdirectory names (default: '%Y%m%d')

    Example:
        Suppose directory `test` has subdirectories:
        test/
        - 20251001
        - 20251002
        - 20251003
        - ...
        - 20251010

        Calling delete_old_directory('test', keep_days=7) will delete subdirectories
        created before 7 days ago (e.g., if today is 20251010, it deletes 20251001-20251003).
    """
    old_time = datetime.now() - timedelta(days=keep_days)
    date = old_time.strftime(subdirectory_name_format)
    # logger.info(f'delete old directory in "{directory}" created before {date}')
    for file in os.listdir(directory):
        adir = os.path.join(directory, file)
        if file.isdigit() and os.path.isdir(adir):
            if file < date:
                try:
                    shutil.rmtree(adir)
                    logger.info(f'deleted old dir: {adir}')
                except Exception as ex:
                    logger.error(f'delete old dir {adir} failed, ex={ex!r}')


def get_partition(path: str) -> str:
    """Get the mount point (partition) for a given path

    Finds the longest matching mount point for the given path by checking
    all disk partitions.

    Args:
        path: File system path

    Returns:
        Mount point string (e.g., '/', '/mnt/data', 'C:\\')
    """
    path = os.path.realpath(path)
    max_path_len = 0
    partition = ''
    for part in psutil.disk_partitions(all=all):
        if path.startswith(part.mountpoint):
            path_len = len(part.mountpoint)
            if path_len > max_path_len:
                max_path_len = path_len
                partition = part.mountpoint
    return partition


def disk_usage(path: str) -> dict[str, float]:
    """Get disk usage information for the partition containing the given path

    Args:
        path: File system path

    Returns:
        Dictionary containing:
            - 'partition': Mount point of the partition
            - 'free': Free space in GB (float)
            - 'total': Total space in GB (float)
            - 'ratio': Free space ratio (free/total, float)
            - 'unit': Unit string ('GB')
    """
    partition = get_partition(path)
    usage = psutil.disk_usage(partition)
    free = round(usage.free / 1024 / 1024 / 1024, 3) # GB
    total = round(usage.total / 1024 / 1024 / 1024, 3)
    return {
        'partition': partition,
        'free': free,
        'total': total,
        'ratio': round(free / total, 5),
        'unit': 'GB',
    }


def free_disk_usage(directory: str, keep_days: int = 7, delete_old_when_free_gb = 0.5, subdirectory_name_format: str = '%Y%m%d') -> bool:
    """Free up disk space by deleting old subdirectories

    Continuously deletes old subdirectories until free space is above the threshold.
    Uses delete_old_directory() to remove subdirectories older than keep_days.

    Args:
        directory: Directory path to clean up
        keep_days: Number of days to keep (subdirectories older than this will be deleted)
        delete_old_when_free_gb: Minimum free space threshold in GB (default: 0.5)
        subdirectory_name_format: Date format string for subdirectory names (default: '%Y%m%d')

    Returns:
        True if operation completed successfully, False otherwise
    """
    while 1:
        if keep_days == 0:
            break
        delete_old_directory(directory, keep_days=keep_days, subdirectory_name_format=subdirectory_name_format)
        du = disk_usage(directory)
        if du['free'] < delete_old_when_free_gb:
            keep_days -= 1
        else:
            break


def list_self_process():
    enum_process(PythonExePath, 'exe')


def enum_process(search: str = None, where: str = 'all', terminate: bool = False, kill: bool = False) -> None:
    if where == 'all' and search:
        search = search.lower()
    print(f'search {Fore.Cyan}{search}{Fore.Reset} in {Fore.Green}{where}{Fore.Reset}\n')
    self_pid = os.getpid()
    p: psutil.Process
    for p in psutil.process_iter():
        try:
            if self_pid == p.pid:
                continue
            name = p.name()
            exe = p.exe()
            cwd = p.cwd()
            cmdline = p.cmdline()
            # cmdline = ' '.join(f'"{it}"' if ' ' in it else it for it in p.cmdline())
            mem = p.memory_full_info()
            mem_values = {}
            for property in mem_properties:
                mem_values[property] = f'{getattr(mem, property, 0) / 1024 / 1024:.3f}M'
            if search:
                if where == 'pid':
                    search_pid = int(search)
                    if not (p.pid == search_pid or p.ppid() == search_pid):
                        continue
                else:
                    if where == 'all':
                        text: str = ' | '.join([name, exe, cwd, shlex.join(cmdline)])
                        text = text.lower()
                    elif where == 'name':
                        text = name
                    elif where == 'exe':
                        text = exe
                    elif where == 'cmd':
                        text = shlex.join(cmdline)
                    elif where == 'cwd':
                        text = cwd
                    if not search in text:
                        # print(f'{search} not in {text}')
                        continue
            print(f'pid={Fore.Cyan}{p.pid}{Fore.Reset}, ppid={p.ppid()}, name={Fore.Cyan}{name}{Fore.Reset}, \n\texe={Fore.DarkCyan}{exe}{Fore.Reset}'
                f', \n\tcwd={cwd}, \n\tcmd={cmdline}'
                f', \n\t{", ".join(f"{k}={v}" for k,v in mem_values.items())}')
            if terminate:
                print(f'try to terminate pid {Fore.Cyan}{p.pid}{Fore.Reset}')
                p.terminate()
            elif kill:
                print(f'try to kill pid {Fore.Cyan}{p.pid}{Fore.Reset}')
                p.kill()
        except Exception as ex:
            #traceback.print_exc()
            pass


def install_service(name: str, description: str, log_path: str, args: str='', run_as_user: str = None):
    '''only for Linux. run_as_user: 指定运行服务的用户，为 None 时自动取 SUDO_USER/USER'''
    # 未指定时：用 SUDO_USER 获取“真正”的当前用户（sudo 时 USER 会是 root）
    user_name = run_as_user if run_as_user else (os.getenv('SUDO_USER') or os.getenv('USER') or 'root')
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    service_txt = f'''# /etc/systemd/system/{name}.service
[Unit]
Description={description}
After=network.target

[Service]
ExecStart={PythonExePath} {ExePath} {args}
WorkingDirectory={ExeDir}
StandardOutput=file:{log_path}
StandardError=file:{log_path}
Restart=always
RestartSec=10
User={user_name}

[Install]
WantedBy=multi-user.target
'''
    print(service_txt)
    with open(f'/etc/systemd/system/{name}.service', 'wt', encoding='utf-8') as fout:
        fout.write(service_txt)
    with open(f'/etc/logrotate.d/{name}', 'wt', encoding='utf-8') as fout:
        fout.write(f'''# /etc/logrotate.d/{name}
{log_path} {{
    daily
    rotate 30
    compress
    delaycompress
    missingok
    create 0644 {user_name} {user_name}
    copytruncate
    postrotate
        systemctl restart {name}.service
    endscript
}}
''')
    cmds = [
        'sudo systemctl daemon-reload',
        f'sudo systemctl enable {name}.service',
        f'sudo systemctl start {name}.service',
        f'sudo systemctl status {name}.service',
    ]
    for cmd in cmds:
        print(f'run {Fore.Cyan}{cmd}{Fore.Reset}')
        os.system(cmd)


def install_cron_job(sh_name: str, log_name:str, cmd: str, at_hour: int = 4, at_minute: int = 0):
    '''only for Linux'''
    sh_content = f'''#!/bin/bash
CUR_DIR="$(pwd)"
SCRIPT_DIR="$(dirname "$0")"
SCRIPT_NAME="$(basename "$0")"
BASE_NAME="${{SCRIPT_NAME%.*}}"
echo "\\$0: $0"
echo "CUR_DIR: $CUR_DIR"
echo "SCRIPT_DIR: $SCRIPT_DIR"
echo "SCRIPT_NAME: $SCRIPT_NAME"
echo "BASE_NAME: $BASE_NAME"
echo "CurrentTime：$(date '+%Y-%m-%d %H:%M:%S')"
echo ""
cd "$SCRIPT_DIR"

{cmd}
'''
    with open(sh_name, 'wt', encoding='utf-8') as fout:
        fout.write(sh_content)
    os.chmod(sh_name, 0o755) # +x
    cur_dir = os.getcwd()
    cp: subprocess.CompletedProcess = subprocess.run(["crontab", "-l"], capture_output=True, text=True,
        # check=True, # if check is True, will raise CalledProcessError if returncode != 0
        )
    if cp.returncode != 0:
        if not cp.stderr.startswith('no crontab for'):
            print(f'run `crontab -l` failed, info={cp}')
            return
    crontab_lines = cp.stdout.split('\n')
    for line in crontab_lines:
        if line.startswith(f'{at_minute} {at_hour} * * * {cur_dir}/{sh_name}'):
            print(f'auto restart already setup, line="{line}", do nothing.')
            return
    new_job = f'{at_minute} {at_hour} * * * {cur_dir}/{sh_name} >> {cur_dir}/{log_name} 2>&1'
    new_crontab = f'{cp.stdout}\n{new_job}\n'
    cp: subprocess.CompletedProcess = subprocess.run(["crontab", "-"], input=new_crontab, capture_output=True, text=True)
    if cp.returncode != 0:
        print(f'run `crontab -` failed, info={cp}')
        return
    print(f"crontab updated. info={cp}")
    print('\ncrontab -l:')
    cp: subprocess.CompletedProcess = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    lines = cp.stdout.split('\n')
    for line in lines:
        if line and not line.startswith('#'):
            print(f'{line}')


def install_timer_service(service_name: str, service_description: str,
                          sh_content: str='',
                          at_hour: int = 4, at_minute: int = 0):
    '''only for Linux'''
    cwd = os.getcwd()
    if sh_content:
        with open(f'{service_name}.sh', 'wt', encoding='utf-8') as fout:
            fout.write(sh_content)
        os.chmod(f'{service_name}.sh', 0o755) # +x

    service_txt = f'''# /etc/systemd/system/{service_name}.service
[Unit]
Description={service_description}

[Service]
Type=oneshot
ExecStart=/bin/bash {cwd}/{service_name}.sh
WorkingDirectory={cwd}
StandardOutput=append:{cwd}/{service_name}.sh.log
StandardError=append:{cwd}/{service_name}.sh.log
'''
    with open(f'/etc/systemd/system/{service_name}.service', 'wt', encoding='utf-8') as fout:
        fout.write(service_txt)

    timer_txt = f'''# /etc/systemd/system/{service_name}.timer
[Unit]
Description={service_name} timer

[Timer]
Persistent=true
OnCalendar={at_hour:02d}:{at_minute:02d}:00

[Install]
WantedBy=timers.target
'''
    with open(f'/etc/systemd/system/{service_name}.timer', 'wt', encoding='utf-8') as fout:
        fout.write(timer_txt)

    cmds = [
        'sudo systemctl daemon-reload',
        f'sudo systemctl enable {service_name}.timer',
        f'sudo systemctl start {service_name}.timer',
        f'sudo systemctl status {service_name}.timer'
        # f'sudo systemctl list-timers {service_name}.timer'
    ]
    # if changed timer config, need reload and restart timer
    # sudo systemctl daemon-reload
    # sudo systemctl restart service_name.timer

    for cmd in cmds:
        print(f'run {Fore.Cyan}{cmd}{Fore.Reset}')
        os.system(cmd)


def uninstall_timed_service(service_name: str):
    '''only for Linux'''
    cmds = [
        f'sudo systemctl stop {service_name}.timer',
        f'sudo systemctl disable {service_name}.timer',
        f'sudo systemctl daemon-reload',
    ]
    for cmd in cmds:
        print(f'run {Fore.Cyan}{cmd}{Fore.Reset}')
        os.system(cmd)


def install_restart_docker_service(service_name: str, docker_compose_file: str, at_hour: int = 4, at_minute: int = 0):
    '''only for Linux'''
    ret = os.system('docker compose version')
    if ret == 0:
        docker_compose_cmd = 'docker compose'
    else:
        docker_compose_cmd = 'docker-compose'
    sh_content = f'''#!/bin/bash
CUR_DIR="$(pwd)"
SCRIPT_DIR="$(dirname "$0")"
SCRIPT_NAME="$(basename "$0")"
BASE_NAME="${{SCRIPT_NAME%.*}}"
echo "\\$0: $0"
echo "CUR_DIR: $CUR_DIR"
echo "SCRIPT_DIR: $SCRIPT_DIR"
echo "SCRIPT_NAME: $SCRIPT_NAME"
echo "BASE_NAME: $BASE_NAME"
echo "CurrentTime：$(date '+%Y-%m-%d %H:%M:%S')"
echo ""
cd "$SCRIPT_DIR"

PATH=/usr/local/sbin:/usr/local/bin:$PATH

echo "call env"
env
echo ""

echo "call nvidia-smi"
nvidia-smi
echo ""

echo "$(date '+%Y-%m-%d %H:%M:%S') call {docker_compose_cmd} down"
{docker_compose_cmd} -f "{docker_compose_file}" down
sleep 2
echo "$(date '+%Y-%m-%d %H:%M:%S') call {docker_compose_cmd} down again"
{docker_compose_cmd} -f "{docker_compose_file}" down
sleep 2
echo "$(date '+%Y-%m-%d %H:%M:%S') call {docker_compose_cmd} up -d"
{docker_compose_cmd} -f "{docker_compose_file}" up -d
echo "$(date '+%Y-%m-%d %H:%M:%S') call {docker_compose_cmd} up -d done"
'''
    install_timer_service(service_name=service_name, service_description=f'Restart {service_name} docker service',
                          sh_content=sh_content, at_hour=at_hour, at_minute=at_minute)


if __name__ == '__main__':
    # now =datetime.now()
    # install_cron_job(sh_name='auto-restart.sh', log_name='auto-restart.sh.log',
    #                cmd='echo "docker images"\ndocker images\necho ""',
    #                at_hour=now.hour, at_minute=now.minute+1)
    if len(sys.argv) != 5:
        print('Usage: python sys_util.py <service_name> <docker_compose_file> <at_hour> <at_minute>')
        print('Example: python sys_util.py restart-paddleocr-docker docker-compose-paddleocr.yaml 4 10')
        sys.exit(1)
    service_name = sys.argv[1]
    docker_compose_file = sys.argv[2]
    at_hour = int(sys.argv[3])
    at_minute = int(sys.argv[4])
    install_restart_docker_service(service_name=service_name,
                                   docker_compose_file=docker_compose_file,
                                   at_hour=at_hour,
                                   at_minute=at_minute)
