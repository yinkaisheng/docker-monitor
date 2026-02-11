#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author: yinkaisheng@foxmail.com
import os
import sys
import time
import io
import asyncio
import queue
import shlex
import locale
import threading
import subprocess
from enum import Enum
from typing import (Any, AsyncGenerator, Dict, Generator, List, Tuple, Union)

import psutil
from log_util import logger, log, Fore

monotonic_time = time.perf_counter

if sys.platform == 'win32':
    Mem1Name = 'wset'
    Mem2Name = "private"
elif sys.platform == 'linux':
    Mem1Name = 'rss'
    Mem2Name = "uss"
else:
    Mem1Name = 'rss'
    Mem2Name = "uss"
MemProperties = [Mem1Name, Mem2Name]


class ProcessSearchField(str, Enum):
    """Process search field enumeration"""
    ALL = 'all'
    PID = 'pid'
    NAME = 'name'
    EXE = 'exe'
    CMD = 'cmd'
    CWD = 'cwd'


class ProcessAction(str, Enum):
    """Process action enumeration"""
    NONE = 'none'
    TERMINATE = 'terminate'
    KILL = 'kill'


def list_processes(query: str = None,
                   search_field: Union[str, ProcessSearchField] = ProcessSearchField.ALL,
                   action: Union[str, ProcessAction] = ProcessAction.NONE) -> None:
    '''
    List process information and optionally perform actions

    Args:
        query: Search keyword, if None then list all processes except self
        search_field: Search field, options: 'all', 'pid', 'name', 'exe', 'cmd', 'cwd'
        action: Action to perform on matched processes, options: 'none', 'terminate', 'kill'
    '''
    # Compatible with old version string parameters
    if isinstance(search_field, str):
        search_field = ProcessSearchField(search_field)
    if isinstance(action, str):
        action = ProcessAction(action)

    if search_field == ProcessSearchField.ALL and query:
        query = query.lower()
    print(f'search {Fore.Cyan}{query}{Fore.Reset} in {Fore.Green}{search_field.value}{Fore.Reset}\n')
    self_pid = os.getpid()
    p: psutil.Process
    for p in psutil.process_iter():
        try:
            if self_pid == p.pid: # exclude self
                continue
            name = p.name()
            exe = p.exe()
            cwd = p.cwd()
            cmdline = p.cmdline()
            mem = p.memory_full_info()
            mem_values = {}
            for property in MemProperties:
                mem_values[property] = f'{getattr(mem, property, 0) / 1024 / 1024:.3f}M'
            if query:
                if search_field == ProcessSearchField.PID:
                    search_pid = int(query)
                    if not (p.pid == search_pid or p.ppid() == search_pid):
                        continue
                else:
                    if search_field == ProcessSearchField.ALL:
                        text: str = ' | '.join([name, exe, cwd, shlex.join(cmdline)])
                    elif search_field == ProcessSearchField.NAME:
                        text = name
                    elif search_field == ProcessSearchField.EXE:
                        text = exe
                    elif search_field == ProcessSearchField.CMD:
                        text = shlex.join(cmdline)
                    elif search_field == ProcessSearchField.CWD:
                        text = cwd
                    if query not in text.lower():
                        continue
            print(f'pid={Fore.Cyan}{p.pid}{Fore.Reset}, ppid={p.ppid()}, name={Fore.Cyan}{name}{Fore.Reset}'
                  f', \n\texe={Fore.DarkCyan}{exe}{Fore.Reset}'
                  f', \n\tcwd={cwd}, \n\tcmd={cmdline}'
                  f', \n\t{", ".join(f"{k}={v}" for k,v in mem_values.items())}')
            if action == ProcessAction.TERMINATE:
                print(f'try to terminate pid {Fore.Cyan}{p.pid}{Fore.Reset}')
                p.terminate()
            elif action == ProcessAction.KILL:
                print(f'try to kill pid {Fore.Cyan}{p.pid}{Fore.Reset}')
                p.kill()
        except Exception as ex:
            #traceback.print_exc()
            pass


def get_child_pids(pid: int = 0) -> List[int]:
    my_pid = pid or os.getpid()
    pids = []
    for proc in psutil.process_iter():
        try:
            if proc.ppid() == my_pid:
                pids.append(proc.pid)
        except Exception as ex:
            #traceback.print_exc()
            pass
    return pids


def process_str(proc: psutil.Process):
    exe = proc.exe()
    cmdline = proc.cmdline()
    cmdline_str = shlex.join(cmdline)
    mem = proc.memory_full_info()
    mem1 = f'{getattr(mem, Mem1Name, 0) / 1024 / 1024:.3f}M'
    mem2 = f'{getattr(mem, Mem2Name, 0) / 1024 / 1024:.3f}M'
    return (f'pid={Fore.Cyan}{proc.pid}{Fore.Reset}, ppid={proc.ppid()}'
            f', {Mem1Name}={mem1}, {Mem2Name}={mem2}'
            f', exe={Fore.DarkCyan}{exe}{Fore.Reset}, cmd={Fore.DarkCyan}{cmdline_str}{Fore.Reset}')


def find_self_processes(print_process: bool = False) -> List[psutil.Process]:
    my_pid = os.getpid()
    python_exe_path = os.path.realpath(sys.executable)
    script_path = os.path.realpath(sys.argv[0])
    procs = []
    proc: psutil.Process
    for proc in psutil.process_iter():
        if proc.pid == my_pid: # exclude self
            continue
        try:
            exe = proc.exe() # will be real path if python is a link
            if exe != python_exe_path:
                continue
            cmdline = proc.cmdline()
            if len(cmdline) >= 2:
                cwd = proc.cwd()
                proc_script_path = os.path.realpath(os.path.join(cwd, cmdline[1]))
                if proc_script_path == script_path:
                    procs.append(proc)
                    if print_process:
                        cmdline_str = shlex.join(cmdline)
                        mem = proc.memory_full_info()
                        mem1 = f'{getattr(mem, Mem1Name, 0) / 1024 / 1024:.3f}M'
                        mem2 = f'{getattr(mem, Mem2Name, 0) / 1024 / 1024:.3f}M'
                        print(f'pid={Fore.Cyan}{proc.pid}{Fore.Reset}, ppid={proc.ppid()}'
                          f', {Mem1Name}={mem1}, {Mem2Name}={mem2}'
                          f', exe={Fore.DarkCyan}{exe}{Fore.Reset}, cmd={Fore.DarkCyan}{cmdline_str}{Fore.Reset}')
        except Exception as ex:
            #traceback.print_exc()
            pass
    return procs


def stop_process(pids: List[int]):
    if sys.platform == 'win32':
        for pid in pids:
            cmdline = f'taskkill /f /pid {pid}'
            print(cmdline)
            os.system(cmdline)
    else:
        pidstr = ' '.join(str(it) for it in pids)
        cmdline = f'kill {pidstr}' # or kill -SIGTERM pid
        print(cmdline)
        os.system(cmdline)
        tick = monotonic_time()
        while True:
            time.sleep(0.1)
            has_running_process = False
            for pid in pids:
                try:
                    proc = psutil.Process(pid)
                    if proc.status() == 'running':
                        has_running_process = True
                        break
                except Exception as ex:
                    pass
            if has_running_process:
                if monotonic_time() - tick > 1:
                    cmdline = f'kill -9 {pidstr}' # or kill -SIGKILL pid
                    print(cmdline)
                    os.system(cmdline)
            else:
                break


def restart_self(exit_code: int = 0):
    argv = [sys.executable] + sys.argv
    # print(f'run {argv}')
    p = subprocess.Popen(argv, start_new_session=True)
    # print(f'new pid={p.pid}')
    sys.exit(exit_code)


def run_background_process(cmd: List[str], env:Dict[str,str] = None) -> int:
    '''if return 0, process is running, otherwise is failed'''
    if sys.platform == 'win32':
        proc = subprocess.Popen(cmd,
                                env=env,
                                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP|subprocess.CREATE_NEW_CONSOLE,
                                )
    else:
        try:
            os.setsid()
        except Exception as ex:
            logger.error(f'os.setsid failed: {ex!r}')

        proc = subprocess.Popen(cmd,
                                env=env,
                                start_new_session=True,
                                close_fds=True,
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                )
    if proc.poll() is None:
        return proc.pid
    return 0


def system(cmd: Union[str, List[str]], print_cmd: bool = False, print_return: bool = False) -> int:
    if isinstance(cmd, list):
        cmds = [f'"{it}"' if ' ' in it else it for it in cmd]
        cmd = ' '.join(cmds)
    if print_cmd:
        log(f'----{Fore.Magenta}process: {Fore.Cyan}{cmd}')
    start_tick = monotonic_time()
    exit_code = os.system(cmd)
    if print_return:
        fg_color = Fore.Red if exit_code else Fore.Green
        log(f'----{Fore.Magenta}process exit code: {fg_color}{exit_code}{Fore.Reset}'
            f', cost time: {monotonic_time() - start_tick:.3f} s')
    return exit_code


def run_cmd(cmd: Union[str, List[str]], input: str = None, text: bool = True, encoding: str = None,
        shell: bool = False, cwd: str = None, env: Dict[str, str] = None,
        print_cmd: bool = False, print_output: bool = False, print_return: bool = False,
        timeout: float = None) -> Dict[str, Any]:
    """Run command with input and timeout, return result as dictionary

    Similar to subprocess.run() but returns a dictionary instead of CompletedProcess.
    Supports input, timeout, and various output options.

    Args:
        cmd: Command to run, can be string or list of strings
        input: Input string to send to process stdin (optional)
        text: If True, use text mode; if False, use bytes mode
        encoding: Text encoding (defaults to system locale encoding)
        shell: If True, run command through shell
        cwd: Working directory for the command
        env: Environment variables dictionary
        print_cmd: If True, print the command before execution
        print_output: If True, print stdout and stderr
        print_return: If True, print exit code and execution time
        timeout: Maximum execution time in seconds (None for no timeout)

    Returns:
        Dictionary containing:
            - 'exit_code': Process exit code (int, None if exception occurred)
            - 'run_time': Execution time in seconds (float)
            - 'stdout': Standard output (str)
            - 'stderr': Standard error (str)
            - 'timeout': True if process was killed due to timeout (bool)
            - 'exception': Exception string if error occurred (str or None)
    """
    if print_cmd:
        log(f'----{Fore.Magenta}process: {Fore.Cyan}{cmd}')
    if not encoding:
        if sys.version_info >= (3, 11):
            encoding = locale.getencoding()
        else:
            encoding = locale.getpreferredencoding(False)
    stdin = subprocess.PIPE if input else None
    result = {}
    start_tick = monotonic_time()
    try:
        process = subprocess.Popen(cmd,
                    stdin=subprocess.PIPE,  # need for input
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=text, encoding=encoding,
                    shell=shell, env=env)
    except Exception as ex:
        logger.error(f'cmd={cmd!r} failed, ex={ex!r}')
        result['exception'] = repr(ex)
        return result
    with process:
        try:
            stdout, stderr = process.communicate(input=input, timeout=timeout)
            result['stdout'] = stdout
            result['stderr'] = stderr
            if print_output:
                print(f'{Fore.Cyan}stdout: \n{Fore.Reset}{stdout}')
                print(f'{Fore.Magenta}stderr: \n{Fore.Reset}{stderr}')
        except subprocess.TimeoutExpired as ex:
            process.kill()
            if subprocess._mswindows:
                ex.stdout, ex.stderr = process.communicate() # may raise exception
            else:
                process.wait()
            result['timeout'] = True
        except Exception as ex:  # Including KeyboardInterrupt, communicate handled that.
            process.kill()
            result['exception'] = repr(ex)
        exit_code = process.poll()
        run_time = round(monotonic_time() - start_tick, 3)
        result['exit_code'] = exit_code
        result['run_time'] = run_time
        if print_return:
            fg_color = Fore.Red if exit_code else Fore.Green
            log(f'----{Fore.Magenta}process({process.pid}) exit code: {fg_color}{exit_code}{Fore.Reset}'
                f', cost time: {run_time} s')
    return result


def run_cmd_iter(cmd: Union[str, List[str]], text: bool = True, encoding: str = None,
                 shell: bool = False, cwd: str = None, env: Dict[str, str] = None,
                 print_cmd: bool = False, print_return: bool = False,
                 timeout_interval: float = 1) -> Generator[Tuple[str, Any], None, None]:
    '''
    Run command and yield output in real-time as generator

    Executes a command and yields output line by line as it becomes available.
    Uses separate threads for stdout and stderr to enable real-time streaming.

    Note: When shell=True, the returned process is the shell process, not the command process,
    and timeout may not work as expected.

    Args:
        cmd: Command to run, can be string or list of strings
        text: If True, use text mode; if False, use bytes mode
        encoding: Text encoding (defaults to system locale encoding)
        shell: If True, run command through shell
        cwd: Working directory for the command
        env: Environment variables dictionary (PYTHONUNBUFFERED=1 is added on non-Windows)
        print_cmd: If True, print the command before execution
        print_return: If True, print exit code when process completes
        timeout_interval: Interval in seconds to check for output (yields 'timeout' if no output)

    Yields:
        Tuples of (output_type, value):
            - ('stdout', line): A line from stdout
            - ('stderr', line): A line from stderr
            - ('process', proc): The subprocess.Popen object
            - ('timeout', None): No output received within timeout_interval
            - ('exception', ex): Exception occurred
            - ('return', exit_code): Process completed with exit code

    Example::

        start_tick = time.perf_counter()
        killed = False
        for output_type, value in process_util.run_cmd_iter(sys.argv[1:]):
            since_start = time.perf_counter() - start_tick
            if output_type == 'stdout' or output_type == 'stderr':
                line: str = value
                print(f'{since_start:.3f} {Fore.DarkCyan}{output_type}{Fore.Reset} {value}', end='')
            if output_type == 'exception':
                ex: Exception = value
                print(f'{since_start:.3f} {Fore.DarkCyan}{output_type}{Fore.Reset} {ex!r}')
            elif output_type == 'process':
                proc: subprocess.Popen = value
                print(f'{since_start:.3f} {Fore.DarkCyan}{output_type}{Fore.Reset} {proc.pid}')
            elif output_type == 'return':
                exit_code: int = value
                print(f'{since_start:.3f} {Fore.DarkCyan}{output_type}{Fore.Reset} {value}')
            elif output_type == 'timeout':
                #print(f'{since_start:.3f} {Fore.DarkCyan}{output_type}{Fore.Reset} no output for 1 second')
                proc.stdin.write('2\n3\n') # must str
                proc.stdin.flush()
                pass
            if since_start >= 5 and not killed:
                print(f'{since_start:.3f} {Fore.Red} kill {proc.pid}')
                proc.kill()
                killed = True
    '''
    def get_output(stream: io.TextIOWrapper, que: queue.Queue, stdtype: str) -> None:
        while True:
            line = stream.readline()
            if line:
                que.put((stdtype, line))
            else:
                que.put(None)
                break

    if print_cmd:
        log(f'----{Fore.Magenta}process: {Fore.Cyan}{cmd}')
    if not encoding:
        if sys.version_info >= (3, 11):
            encoding = locale.getencoding()
        else:
            encoding = locale.getpreferredencoding(False)
    if sys.platform != 'win32':
        if env is None:
            env = {'PYTHONUNBUFFERED': '1'}
        elif 'PYTHONUNBUFFERED' not in env:
            env['PYTHONUNBUFFERED'] = '1'
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=text, encoding=encoding, shell=shell, cwd=cwd, env=env,
                                )
    except Exception as ex:
        yield 'exception', ex
        yield 'return', -1
        if print_return:
            log(f'----{Fore.Magenta}process exit code: -1, ex: {ex!r}')
        return
    yield 'process', proc
    out_que = queue.Queue()
    stdout_thread = threading.Thread(target=get_output, args=(proc.stdout, out_que, 'stdout'))
    stderr_thread = threading.Thread(target=get_output, args=(proc.stderr, out_que, 'stderr'))
    stdout_thread.start()
    stderr_thread.start()
    noneCount = 0
    while True:
        try:
            output = out_que.get(timeout=timeout_interval)
            if output is None:
                noneCount += 1
                if noneCount >= 2:
                    break
            else:
                yield output
        except queue.Empty as _:
            #if proc.poll() == None:
            yield 'timeout', None
    stdout_thread.join()
    stderr_thread.join()
    exit_code = proc.wait()
    yield 'return', exit_code
    if print_return:
        fg_color = Fore.Red if exit_code else Fore.Green
        log(f'----{Fore.Magenta}process({proc.pid}) exit code: {fg_color}{exit_code}')


class MonitoredCmdResult:
    def __init__(self, cmd: Union[str, List[str]], exitCode: int = -1):
        self.cmd = cmd
        self.pid = 0
        self.exit_code = exitCode
        self.exception: Exception = None
        self.stdouts: List[str] = []    # line ends with \n
        self.stdouts_timestamps: List[float] = []
        self.stderrs: List[str] = []    # line ends with \n
        self.stderrs_timestamps: List[float] = []
        self.stdout: str = ''
        self.stderr: str = ''
        self.is_exit_after_timeout = False
        self.is_exit_after_total_time = False


def run_cmd_monitored(cmd: Union[str, List[str]], inputs: List[str] = None, text: bool = True, encoding: str = None,
                   shell: bool = False, cwd: str = None, env: Dict[str, str] = None,
                   print_cmd: bool = False, print_output: bool = False, print_return: bool = False,
                   timeout_interval: float = 1, exit_after_timeout: float = 0,
                   exit_after_total_time: float = 0) -> MonitoredCmdResult:
    """Run command with monitoring, timeout control, and interactive input support

    Executes a command and monitors its output in real-time. Supports automatic termination
    based on output timeout or total execution time. Can send inputs to the process interactively.

    Args:
        cmd: Command to run, can be string or list of strings
        inputs: List of input strings to send to process stdin (sent when 'timeout' events occur)
        text: If True, use text mode; if False, use bytes mode
        encoding: Text encoding (defaults to system locale encoding)
        shell: If True, run command through shell
        cwd: Working directory for the command
        env: Environment variables dictionary
        print_cmd: If True, print the command before execution
        print_output: If True, print stdout and stderr in real-time
        print_return: If True, print exit code when process completes
        timeout_interval: Interval in seconds to check for output
        exit_after_timeout: If > 0, terminate process if no output for this many seconds
        exit_after_total_time: If > 0, terminate process after this many seconds total

    Returns:
        MonitoredCmdResult object containing:
            - exit_code: Process exit code
            - stdout: Complete stdout output (concatenated string from stdouts)
            - stderr: Complete stderr output (concatenated string from stderrs)
            - stdouts: List of stdout lines (each line ends with \n), each line corresponds to an element in stdouts_timestamps
            - stdouts_timestamps: List of timestamps (float) corresponding to stdout lines, same length as stdouts
            - stderrs: List of stderr lines (each line ends with \n), each line corresponds to an element in stderrs_timestamps
            - stderrs_timestamps: List of timestamps (float) corresponding to stderr lines, same length as stderrs
            - is_exit_after_timeout: True if terminated due to output timeout
            - is_exit_after_total_time: True if terminated due to total time limit
            - exception: Exception if one occurred
    """
    mc_result = MonitoredCmdResult(cmd)
    terminated = False
    terminate_time = 0
    killed = False
    start_time = monotonic_time()
    last_output_time = start_time
    for output_type, value in run_cmd_iter(cmd, text=text, encoding=encoding, shell=shell, cwd=cwd, env=env,
                                          timeout_interval=timeout_interval, print_cmd=print_cmd, print_return=print_return):
        now = monotonic_time()
        since_start = now - start_time
        if output_type == 'stdout':
            last_output_time = now
            mc_result.stdouts.append(value)
            mc_result.stdouts_timestamps.append(since_start)
            if print_output:
                print(f'{since_start:.3f} {Fore.DarkCyan}{output_type}{Fore.Reset} {value}', end='')
        elif output_type == 'stderr':
            last_output_time = now
            mc_result.stderrs.append(value)
            mc_result.stderrs_timestamps.append(since_start)
            if print_output:
                print(f'{since_start:.3f} {Fore.DarkCyan}{output_type}{Fore.Reset} {value}', end='')
        elif output_type == 'process':
            proc: subprocess.Popen = value
            mc_result.pid = proc.pid
            if print_output:
                print(f'{since_start:.3f} {Fore.DarkCyan}{output_type}{Fore.Reset} pid: {proc.pid}')
        elif output_type == 'return':
            mc_result.exit_code = value
            if print_output:
                print(f'{since_start:.3f} {Fore.DarkCyan}{output_type}{Fore.Reset} {value}')
        elif output_type == 'timeout':
            if exit_after_timeout > 0 and now - last_output_time >= exit_after_timeout:
                if not terminated:
                    print(f'{since_start:.3f} {Fore.DarkCyan}no output for {exit_after_timeout}s{Fore.Reset}, {Fore.Red}terminate pid: {proc.pid}')
                    try:
                        proc.terminate()
                        terminated = True
                        terminate_time = now
                        mc_result.is_exit_after_timeout = True
                    except Exception as ex:
                        print(f'{since_start:.3f} pid {mc_result.pid} terminate failed {ex!r}')
                else:
                    if not killed and now - terminate_time >= 1:
                        print(f'{since_start:.3f} {Fore.DarkCyan}no output for {exit_after_timeout}s{Fore.Reset}, {Fore.Red}kill pid: {proc.pid}')
                        try:
                            proc.kill()
                            killed = True
                            mc_result.is_exit_after_timeout = True
                        except Exception as ex:
                            print(f'{since_start:.3f} pid {mc_result.pid} kill failed {ex!r}')
            if inputs:
                input_str = inputs.pop(0)
                proc.stdin.write(input_str if input_str.endswith('\n') else input_str + '\n') # can't write bytes
                proc.stdin.flush()
        elif output_type == 'exception':
            mc_result.exception = value
        if exit_after_total_time > 0 and since_start >= exit_after_total_time:
            if not terminated:
                print(f'{since_start:.3f} {Fore.DarkCyan}run timeout after {exit_after_total_time}s{Fore.Reset}, {Fore.Red}terminate pid: {proc.pid}')
                try:
                    proc.terminate()
                    terminated = True
                    terminate_time = now
                    mc_result.is_exit_after_total_time = True
                except Exception as ex:
                    print(f'{since_start:.3f} pid {mc_result.pid} terminate failed {ex!r}')
            else:
                if not killed and now - terminate_time >= 1:
                    print(f'{since_start:.3f} {Fore.DarkCyan}run timeout after {exit_after_total_time}s{Fore.Reset}, {Fore.Red}kill pid: {proc.pid}')
                    try:
                        proc.kill()
                        killed = True
                        mc_result.is_exit_after_total_time = True
                    except Exception as ex:
                        print(f'{since_start:.3f} pid {mc_result.pid} kill failed {ex!r}')
    sep = '' if text else b''
    mc_result.stdout = sep.join(mc_result.stdouts)
    mc_result.stderr = sep.join(mc_result.stderrs)
    return mc_result


async def a_run_cmd_iter(cmd: Union[str, List[str]], text: bool = True, encoding: str = None,
                    cwd: str = None, env: Dict[str, str] = None,
                    print_cmd: bool = False, print_return: bool = False,
                    timeout_interval: float = 1) -> AsyncGenerator[Tuple[str, Any], None]:
    """Run command asynchronously and yield output in real-time as async generator

    Async version of run_cmd_iter. Executes a command and yields output line by line
    as it becomes available using asyncio.

    Note:
        - When cmd is a string, it uses create_subprocess_shell (PID is shell process, not command process)
        - When cmd is a list, it uses create_subprocess_exec (PID is command process)
        - Timeout may not work correctly when using shell mode

    Args:
        cmd: Command to run, can be string or list of strings
        text: If True, decode output as text; if False, return bytes
        encoding: Text encoding for decoding (defaults to system locale encoding)
        cwd: Working directory for the command
        env: Environment variables dictionary (PYTHONUNBUFFERED=1 is added on non-Windows)
        print_cmd: If True, print the command before execution
        print_return: If True, print exit code when process completes
        timeout_interval: Interval in seconds to check for output (yields 'timeout' if no output)

    Yields:
        Tuples of (output_type, value):
            - ('stdout', line): A line from stdout (decoded if text=True)
            - ('stderr', line): A line from stderr (decoded if text=True)
            - ('process', proc): The asyncio.subprocess.Process object
            - ('timeout', None): No output received within timeout_interval
            - ('exception', ex): Exception occurred
            - ('return', exit_code): Process completed with exit code
    """

    def find_last_ascii_pos(data: bytearray) -> int:
        for i in range(len(data) - 1, -1, -1):
            byte_val = data[i]
            # ASCII character (0x00-0x7F): safe to cut after
            if byte_val <= 0x7F:
                return i
        return -1

    async def a_get_output(stream: asyncio.StreamReader, que: asyncio.Queue, stdtype: str) -> None:
        # async for line in stream:
        #     # readline has 64 kb memory limit, may hang if output is too long, e.g. 200000 chars
        #     await que.put((stdtype, line))
        # await que.put(None)

        size_16_kb = 16*1024
        buffer = bytearray()
        while True:
            bytes = await stream.read(size_16_kb) # read 16 kb, avoid hanging if output > 64 kb and no newline
            if not bytes:
                if buffer:
                    await que.put((stdtype, buffer))
                await que.put(None)
                break
            buffer.extend(bytes)
            while True:
                ln_pos = buffer.find(b'\n')
                if ln_pos == -1:
                    break
                line = buffer[:ln_pos+1]
                await que.put((stdtype, line))
                buffer = buffer[ln_pos+1:]
            # If buffer is too large, find a safe cut point to avoid UTF-8 character splitting
            if len(buffer) >= size_16_kb:
                cut_pos = find_last_ascii_pos(buffer)
                if cut_pos > 0:
                    output_chunk = buffer[:cut_pos]
                    buffer = buffer[cut_pos:]
                    await que.put((stdtype, output_chunk))
                elif len(buffer) > size_16_kb * 4:
                    await que.put((stdtype, buffer)) # output partial buffer if no ascii character
                    buffer = bytearray()

    if sys.platform != 'win32':
        if env is None:
            env = {'PYTHONUNBUFFERED': '1'}
        elif 'PYTHONUNBUFFERED' not in env:
            env['PYTHONUNBUFFERED'] = '1'

    try:
        if isinstance(cmd, list):
            if print_cmd:
                log(f'----{Fore.Magenta}asyncio.create_subprocess_exec: {Fore.Cyan}{cmd}')
            process = await asyncio.create_subprocess_exec(*cmd,
                                                           stdin=asyncio.subprocess.PIPE,
                                                           stdout=asyncio.subprocess.PIPE,
                                                           stderr=asyncio.subprocess.PIPE,
                                                           cwd=cwd,
                                                           env=env,
                                                           #shell=False,  # only accept False
                                                           #text=False,  # only accept False
                                                           )
        elif isinstance(cmd, str):
            if print_cmd:
                log(f'----{Fore.Magenta}asyncio.create_subprocess_shell: {Fore.Cyan}{cmd}')
            process = await asyncio.create_subprocess_shell(cmd,
                                                            stdin=asyncio.subprocess.PIPE,
                                                            stdout=asyncio.subprocess.PIPE,
                                                            stderr=asyncio.subprocess.PIPE,
                                                            cwd=cwd,
                                                            env=env,
                                                            #shell=False,  # only accept False
                                                            #text=False,  # only accept False
                                                            )
    except Exception as ex:
        yield 'exception', ex
        yield 'return', -1
        log(f'----{Fore.Magenta}process exit code -1, ex={ex!r}')
        return
    yield 'process', process
    out_que = asyncio.Queue()
    stdout_task = asyncio.create_task(a_get_output(process.stdout, out_que, 'stdout'))
    stderr_task = asyncio.create_task(a_get_output(process.stderr, out_que, 'stderr'))
    if not encoding:
        if sys.version_info >= (3, 11):
            encoding = locale.getencoding()
        else:
            encoding = locale.getpreferredencoding(False)
    none_count = 0
    while True:
        try:
            output = await asyncio.wait_for(out_que.get(), timeout=timeout_interval)
            if output is None: # get first None from stdout or stderr
                none_count += 1
                if none_count >= 2:
                    break
                else:
                    continue
            if text:
                output_type, line = output
                yield output_type, line.decode(encoding, errors='ignore')
            else:
                yield output
        except asyncio.TimeoutError as ex:
            yield 'timeout', None
    await asyncio.sleep(0.001)
    assert out_que.empty(), 'expected queue is empty'
    await asyncio.gather(stdout_task, stderr_task)
    exit_code = await process.wait()
    yield 'return', exit_code
    if print_return:
        fg_color = Fore.Red if exit_code else Fore.Green
        log(f'----{Fore.Magenta}process({process.pid}) exit code: {fg_color}{exit_code}')


async def a_run_cmd_monitored(cmd: Union[str, List[str]], inputs: List[bytes] = None, text: bool = True,
                        encoding: str = None, cwd: str = None, env: Dict[str, str] = None,
                        print_cmd: bool = False, print_output: bool = False, print_return: bool = False,
                        timeout_interval: float = 1, exit_after_timeout: float = 0,
                        exit_after_total_time: float = 0) -> MonitoredCmdResult:
    """Run command asynchronously with monitoring, timeout control, and interactive input support

    Async version of run_cmd_monitored. Executes a command and monitors its output in real-time.
    Supports automatic termination based on output timeout or total execution time.
    Can send inputs to the process interactively.

    Note:
        - When cmd is a string, it uses create_subprocess_shell (PID is shell process, not command process)
        - When cmd is a list, it uses create_subprocess_exec (PID is command process)
        - Timeout may not work correctly when using shell mode

    Args:
        cmd: Command to run, can be string or list of strings
        inputs: List of input bytes to send to process stdin (sent when 'timeout' events occur)
        text: If True, decode output as text; if False, return bytes
        encoding: Text encoding for decoding (defaults to system locale encoding)
        cwd: Working directory for the command
        env: Environment variables dictionary
        print_cmd: If True, print the command before execution
        print_output: If True, print stdout and stderr in real-time
        print_return: If True, print exit code when process completes
        timeout_interval: Interval in seconds to check for output
        exit_after_timeout: If > 0, terminate process if no output for this many seconds
        exit_after_total_time: If > 0, terminate process after this many seconds total

    Returns:
        MonitoredCmdResult object containing:
            - exit_code: Process exit code
            - stdout: Complete stdout output (concatenated string from stdouts)
            - stderr: Complete stderr output (concatenated string from stderrs)
            - stdouts: List of stdout lines (each line ends with \n), each line corresponds to an element in stdouts_timestamps
            - stdouts_timestamps: List of timestamps (float) corresponding to stdout lines, same length as stdouts
            - stderrs: List of stderr lines (each line ends with \n), each line corresponds to an element in stderrs_timestamps
            - stderrs_timestamps: List of timestamps (float) corresponding to stderr lines, same length as stderrs
            - is_exit_after_timeout: True if terminated due to output timeout
            - is_exit_after_total_time: True if terminated due to total time limit
            - exception: Exception if one occurred
    """
    mc_result = MonitoredCmdResult(cmd)
    terminated = False
    terminate_time = 0
    killed = False
    start_tick = monotonic_time()
    last_output_time = start_tick
    async for output_type, value in a_run_cmd_iter(cmd, text=text, encoding=encoding, cwd=cwd, env=env,
                                                   print_cmd=print_cmd, print_return=print_return,
                                                   timeout_interval=timeout_interval):
        now = monotonic_time()
        since_start = now - start_tick
        if output_type == 'stdout':
            last_output_time = now
            mc_result.stdouts.append(value)
            mc_result.stdouts_timestamps.append(since_start)
            if print_output:
                print(f'{since_start:.3f} {Fore.DarkCyan}{output_type}{Fore.Reset} {value}', end='')
        elif output_type == 'stderr':
            last_output_time = now
            mc_result.stderrs.append(value)
            mc_result.stderrs_timestamps.append(since_start)
            if print_output:
                print(f'{since_start:.3f} {Fore.DarkCyan}{output_type}{Fore.Reset} {value}', end='')
        elif output_type == 'process':
            proc: asyncio.subprocess.Process = value
            mc_result.pid = proc.pid
            if print_output:
                print(f'{since_start:.3f} {Fore.DarkCyan}{output_type}{Fore.Reset} pid: {proc.pid}')
        elif output_type == 'return':
            mc_result.exit_code = value
            if print_output:
                print(f'{since_start:.3f} {Fore.DarkCyan}{output_type}{Fore.Reset} {value}')
        elif output_type == 'timeout':
            # proc is defined before 'timeout' type
            if exit_after_timeout > 0 and now - last_output_time >= exit_after_timeout:
                if not terminated:
                    print(f'{since_start:.3f} {Fore.DarkCyan}no output for {exit_after_timeout}s{Fore.Reset}, {Fore.Red}terminate pid: {proc.pid}')
                    try:
                        proc.terminate()
                        terminated = True
                        terminate_time = now
                        mc_result.is_exit_after_timeout = True
                    except Exception as ex:
                        print(f'{since_start:.3f} pid {mc_result.pid} terminate failed {ex!r}')
                else:
                    if not killed and now - terminate_time >= 1:
                        print(f'{since_start:.3f} {Fore.DarkCyan}no output for {exit_after_timeout}s{Fore.Reset}, {Fore.Red}kill pid: {proc.pid}')
                        try:
                            proc.kill()
                            killed = True
                            mc_result.is_exit_after_timeout = True
                        except Exception as ex:
                            print(f'{since_start:.3f} pid {mc_result.pid} kill failed {ex!r}')
            if inputs:
                input_bytes = inputs.pop(0)
                proc.stdin.write(input_bytes if input_bytes.endswith(b'\n') else input_bytes + b'\n')
                await proc.stdin.drain()
        elif output_type == 'exception':
            mc_result.exception = value
        if exit_after_total_time > 0 and since_start >= exit_after_total_time:
            if not terminated:
                print(f'{since_start:.3f} {Fore.DarkCyan}run timeout after {exit_after_total_time}s{Fore.Reset}, {Fore.Red}terminate pid: {proc.pid}')
                try:
                    proc.terminate()
                    terminated = True
                    terminate_time = now
                    mc_result.is_exit_after_total_time = True
                except Exception as ex:
                    print(f'{since_start:.3f} pid {mc_result.pid} terminate failed {ex!r}')
            else:
                if not killed and now - terminate_time >= 1:
                    print(f'{since_start:.3f} {Fore.DarkCyan}run timeout after {exit_after_total_time}s{Fore.Reset}, {Fore.Red}kill pid: {proc.pid}')
                    try:
                        proc.kill()
                        killed = True
                        mc_result.is_exit_after_total_time = True
                    except Exception as ex:
                        print(f'{since_start:.3f} pid {mc_result.pid} kill failed {ex!r}')
    sep = '' if text else b''
    mc_result.stdout = sep.join(mc_result.stdouts)
    mc_result.stderr = sep.join(mc_result.stderrs)
    return mc_result


if __name__ == '__main__':
    if sys.version_info >= (3, 11):
        encoding = locale.getencoding()
    else:
        encoding = locale.getpreferredencoding(False)
    print(f'encoding={encoding}')

    procs = find_self_processes()

    # list_processes(query='python', search_field=ProcessSearchField.EXE)

    # asyncio.run(a_run_cmd_monitored(['ping', 'www.baidu.com'], print_cmd=1, print_output=1, print_return=1))
    if len(sys.argv) > 1:
        asyncio.run(a_run_cmd_monitored(sys.argv[1:], print_cmd=1, print_output=1, print_return=1))