#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# created: 2025-07-18
# author: yinkaisheng@foxmail.com
import os
import sys
import time
import functools
from datetime import datetime

from log_util import log, Fore


def measure_time(run_times: int = 1, max_time: float = None):
    def inner(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # argstr = ','.join(repr(arg) for arg in args)
            # kwstr = ','.join('{}={}'.format(k, v) for k, v in kwargs.items())
            # instr = ','.join(s for s in (argstr, kwstr) if s)
            instr = ''
            print(f'call {Fore.Cyan}{func.__name__}({instr})')
            start = Tick.get_tick()
            if max_time is None:
                for i in range(run_times):
                    ret = func(*args, **kwargs)
            else:
                for i in range(run_times):
                    ret = func(*args, **kwargs)
                    if Tick.get_tick() - start >= max_time:
                        break
            total = Tick.get_tick() - start
            realRunTimes = i + 1
            avg = total / realRunTimes
            print(
                f'{Fore.Cyan}{func.__name__}{Fore.Reset} real run times {Fore.DarkGreen}{realRunTimes}{Fore.Reset}'
                f', cost {Fore.DarkGreen}{total:.6f}{Fore.Reset}s, avg cost {Fore.DarkGreen}{avg:.6f}{Fore.Reset}s\n')
            return ret
        return wrapper
    return inner


class Tick:
    get_tick = time.perf_counter
    _offset_tick = get_tick()

    @staticmethod
    def process_tick() -> float:
        return round(Tick.get_tick() - Tick._offset_tick, 6)

    def __init__(self):
        self.reset()

    def reset(self):
        self.start_tick = self.get_tick()
        self.last_tick = None

    def update(self) -> None:
        self.last_tick = self.get_tick()
        # return self.last_tick

    def since_start(self) -> float:
        self.last_tick = self.get_tick()
        return round(self.last_tick - self.start_tick, 6)

    def since_last(self) -> float:
        now = self.get_tick()
        cost = round(now - (self.last_tick or self.start_tick), 6)
        self.last_tick = now
        return cost

    def check_interval(self, interval: float) -> bool:
        if self.last_tick is None:
            self.last_tick = self.get_tick()
            return True
        else:
            now = self.get_tick()
            if now - self.last_tick >= interval:
                self.last_tick = now
                return True
            else:
                return False

    def reset_interval(self):
        self.last_tick = None

    def __str__(self):
        return f'elapsed(last={self.since_last():.6f},total={self.last_tick - self.start_tick:.6f})'

    def __repr__(self):
        return f'<{self.__class__.__name__} at 0x{id(self):08} {self}>'


def timestamp_to_datetime(ts: int) -> datetime:
    if ts <= 32536799999: # max timestamp on Windows, datetime(3001, 1, 19, 7, 59, 58, 999999), Linux is larger
        pass
    elif ts <= 32536799999_000:
        ts = ts / 1000
    else:
        ts = ts / 1000000
    return datetime.fromtimestamp(ts)


def timestamp_to_str(ts: int, strip_end: int = 0) -> str:
    if strip_end == 0:
        return timestamp_to_datetime(ts).strftime("%Y-%m-%d %H:%M:%S.%f")
    return timestamp_to_datetime(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:strip_end]


def milliseconds_since_epoch() -> int:
    return int(time.time() * 1000)


def dateTime_from_epoch_msec(milliseconds_since_epoch: int) -> datetime:
    return datetime.fromtimestamp(milliseconds_since_epoch / 1000)