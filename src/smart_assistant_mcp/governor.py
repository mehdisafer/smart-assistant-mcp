from __future__ import annotations

import threading
import math
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable

import psutil

from .common import RuntimeFault, utc_now


class Pressure(IntEnum):
    NORMAL = 0
    PRESSURE = 1
    HIGH = 2
    CRITICAL = 3
    EMERGENCY = 4


@dataclass(frozen=True)
class Sample:
    available_gib: float
    total_gib: float = 32.0
    cpu_pct: float = 0.0
    disk_free_gib: float = 100.0
    commit_pct: float | None = None
    vram_pct: float | None = None


def windows_commit_pct() -> float | None:
    import os
    if os.name != 'nt':
        return None
    import ctypes
    class PerformanceInfo(ctypes.Structure):
        _fields_ = [('cb', ctypes.c_uint32)] + [(n, ctypes.c_size_t) for n in
                    ('CommitTotal','CommitLimit','CommitPeak','PhysicalTotal','PhysicalAvailable',
                     'SystemCache','KernelTotal','KernelPaged','KernelNonpaged','PageSize')] + [
                    ('HandleCount',ctypes.c_uint32),('ProcessCount',ctypes.c_uint32),('ThreadCount',ctypes.c_uint32)]
    info = PerformanceInfo()
    info.cb = ctypes.sizeof(info)
    if not ctypes.windll.psapi.GetPerformanceInfo(ctypes.byref(info), info.cb):
        return None
    return 100 * info.CommitTotal / info.CommitLimit if info.CommitLimit else None


class Governor:
    """One bounded admission controller. It never suspends or kills external workloads."""
    def __init__(self, disk_path: str, config: dict | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.config = {'reserve_gib': 4.0, 'recovery_seconds': 60.0,
                       'max_sample_age_seconds': 5.0, 'max_leases': 32,
                       'max_heavy_leases': 2, 'disk_min_gib': 20.0,
                       'sample_seconds': 1.0, 'gpu_sample_seconds': 10.0,
                       'gpu_max_age_seconds': 30.0,
                       'gpu_pressure_pct': 70.0, 'gpu_high_pct': 85.0,
                       'gpu_critical_pct': 92.0,
                       'l0_max_gib': 0.03, 'l1_max_gib': 0.12,
                       'l0_min_free_gib': 0.35, 'l1_min_free_gib': 0.75,
                       'emergency_commit_stop_pct': 99.0,
                       'max_l0_leases': 24, 'max_l1_leases': 12,
                       **(config or {})}
        self.disk_path, self.clock = disk_path, clock
        self.lock = threading.RLock()
        self.level = Pressure.NORMAL
        self.sample: Sample | None = None
        self.sample_at = float('-inf')
        self.recovery_since: float | None = None
        self.leases: dict[str, tuple[float, int, float]] = {}
        self.lease_lanes: dict[str, str] = {}
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.last_error: str | None = None
        self.last_vram_pct: float | None = None
        self.last_gpu_at = float('-inf')
        self.last_gpu_error: str | None = None

    @staticmethod
    def classify(s: Sample) -> Pressure:
        ram = next((state for threshold, state in [(2, Pressure.EMERGENCY), (4, Pressure.CRITICAL),
                    (6, Pressure.HIGH), (8, Pressure.PRESSURE)] if s.available_gib < threshold), Pressure.NORMAL)
        commit = Pressure.NORMAL
        if s.commit_pct is not None:
            commit = next((level for threshold, level in [(97, Pressure.EMERGENCY), (92, Pressure.CRITICAL),
                          (87, Pressure.HIGH), (80, Pressure.PRESSURE)] if s.commit_pct >= threshold), Pressure.NORMAL)
        cpu = Pressure.HIGH if s.cpu_pct >= 97 else Pressure.PRESSURE if s.cpu_pct >= 90 else Pressure.NORMAL
        disk = Pressure.CRITICAL if s.disk_free_gib < 2 else Pressure.HIGH if s.disk_free_gib < 10 else Pressure.NORMAL
        return max(ram, commit, cpu, disk)

    def observe(self, sample: Sample):
        with self.lock:
            numeric = (sample.available_gib, sample.total_gib, sample.cpu_pct, sample.disk_free_gib)
            optional = (sample.commit_pct, sample.vram_pct)
            valid = all(type(x) in (int, float) and math.isfinite(x) and x >= 0 for x in numeric)
            valid = valid and all(x is None or (type(x) in (int, float) and math.isfinite(x) and 0 <= x <= 100) for x in optional)
            valid = valid and sample.total_gib > 0 and sample.available_gib <= sample.total_gib and sample.cpu_pct <= 100
            if not valid:
                self.sample = None
                self.sample_at = float('-inf')
                self.recovery_since = None
                self.last_error = 'INVALID_TELEMETRY'
                raise RuntimeFault('INVALID_TELEMETRY', 'Resource sample is not finite or is out of range.')
            now, candidate = self.clock(), self.classify(sample)
            self.sample, self.sample_at, self.last_error = sample, now, None
            if candidate >= self.level:
                self.level, self.recovery_since = candidate, None
            else:
                enough_headroom = (candidate != Pressure.NORMAL or sample.available_gib >= 10)
                if not enough_headroom:
                    self.recovery_since = None
                elif self.recovery_since is None:
                    self.recovery_since = now
                elif now - self.recovery_since >= self.config['recovery_seconds']:
                    self.level, self.recovery_since = candidate, None

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        # Prime admission synchronously with cheap host telemetry. GPU sampling stays out-of-band.
        # This prevents a freshly started service from rejecting safe calls as STALE_TELEMETRY.
        try:
            psutil.cpu_percent(None)
            memory=psutil.virtual_memory()
            self.observe(Sample(memory.available / 2**30, memory.total / 2**30,
                                psutil.cpu_percent(None), psutil.disk_usage(self.disk_path).free / 2**30,
                                windows_commit_pct(), None))
        except Exception as exc:
            with self.lock:
                self.last_error=type(exc).__name__
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._loop, name='mcp-resource-sampler', daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3)

    @staticmethod
    def nvidia_vram_pct() -> float | None:
        """Read aggregate NVIDIA VRAM pressure. This is sampled out-of-band, never per tool call."""
        import os
        from pathlib import Path
        flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0) if os.name == 'nt' else 0
        if os.name == 'nt':
            candidates = [
                Path(os.environ.get('WINDIR', r'C:\Windows')) / 'System32' / 'nvidia-smi.exe',
                Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'NVIDIA Corporation' / 'NVSMI' / 'nvidia-smi.exe',
            ]
        else:
            candidates = [Path('/usr/bin/nvidia-smi'), Path('/usr/local/bin/nvidia-smi')]
        executable = next((p for p in candidates if p.is_file()), None)
        if executable is None:
            raise FileNotFoundError('nvidia-smi executable not found in approved system locations')
        completed = subprocess.run(
            [str(executable), '--query-gpu=memory.total,memory.used', '--format=csv,noheader,nounits'],
            capture_output=True, text=True, timeout=2, check=True, creationflags=flags)
        ratios = []
        for line in completed.stdout.splitlines():
            if not line.strip():
                continue
            total, used = (float(x.strip()) for x in line.split(',')[:2])
            if total <= 0:
                continue
            ratios.append(100.0 * used / total)
        return max(ratios) if ratios else None

    def _loop(self):
        psutil.cpu_percent(None)
        next_gpu = float('-inf')
        while not self.stop_event.is_set():
            try:
                now = self.clock()
                if now >= next_gpu:
                    try:
                        vram = self.nvidia_vram_pct()
                        with self.lock:
                            self.last_vram_pct = vram
                            self.last_gpu_at = now if vram is not None else float('-inf')
                            self.last_gpu_error = None if vram is not None else 'NO_NVIDIA_GPU_SAMPLE'
                    except Exception as exc:
                        with self.lock:
                            self.last_gpu_error = type(exc).__name__
                    next_gpu = now + self.config['gpu_sample_seconds']
                with self.lock:
                    vram = self.last_vram_pct if (
                        self.last_vram_pct is not None and
                        now - self.last_gpu_at <= self.config['gpu_max_age_seconds']) else None
                memory = psutil.virtual_memory()
                self.observe(Sample(memory.available / 2**30, memory.total / 2**30,
                                    psutil.cpu_percent(None), psutil.disk_usage(self.disk_path).free / 2**30,
                                    windows_commit_pct(), vram))
            except Exception as exc:
                with self.lock:
                    self.last_error = type(exc).__name__
            self.stop_event.wait(self.config['sample_seconds'])

    @staticmethod
    def infer_lane(gib: float, priority: int, writes: bool) -> str:
        if priority >= 3:
            return 'L4'
        if priority >= 2 or gib > 0.12:
            return 'L3'
        if writes:
            return 'L2'
        return 'L0' if gib <= 0.03 else 'L1'

    def _decision(self, gib: float, priority: int, writes: bool, lane: str | None = None) -> tuple[bool, str]:
        s = self.sample
        if s is None or self.clock() - self.sample_at > self.config['max_sample_age_seconds']:
            return False, 'STALE_TELEMETRY'
        if len(self.leases) >= self.config['max_leases']:
            return False, 'CONCURRENCY_LIMIT'
        if writes and s.disk_free_gib < self.config['disk_min_gib']:
            return False, 'DISK_PRESSURE'
        lane = lane or self.infer_lane(gib, priority, writes)
        if lane not in {'L0','L1','L2','L3','L4'}:
            return False, 'INVALID_LANE'

        commit = s.commit_pct or 0.0
        outstanding = sum(max(0.0, estimate - observed) for estimate, _, observed in self.leases.values())
        lane_counts = {name: sum(1 for value in self.lease_lanes.values() if value == name)
                       for name in ('L0','L1','L2','L3','L4')}

        # Fast path: keep observability/small reads alive during system pressure.
        # These paths are read-only, tightly bounded and preserve a smaller emergency floor.
        if lane == 'L0':
            if writes or gib > self.config['l0_max_gib']:
                return False, 'LANE_PROFILE_MISMATCH'
            if lane_counts['L0'] >= self.config['max_l0_leases']:
                return False, 'FASTPATH_CONCURRENCY_LIMIT'
            if commit >= self.config['emergency_commit_stop_pct']:
                return False, 'COMMIT_EXHAUSTION'
            if s.available_gib - outstanding - gib < self.config['l0_min_free_gib']:
                return False, 'FASTPATH_MEMORY_FLOOR'
            return True, 'FASTPATH_L0'

        if lane == 'L1':
            if writes or gib > self.config['l1_max_gib']:
                return False, 'LANE_PROFILE_MISMATCH'
            if lane_counts['L1'] >= self.config['max_l1_leases']:
                return False, 'FASTPATH_CONCURRENCY_LIMIT'
            if commit >= self.config['emergency_commit_stop_pct']:
                return False, 'COMMIT_EXHAUSTION'
            if s.available_gib - outstanding - gib < self.config['l1_min_free_gib']:
                return False, 'FASTPATH_MEMORY_FLOOR'
            return True, 'FASTPATH_L1'

        # Mutations and compute remain conservative under pressure.
        if lane == 'L2':
            if self.level >= Pressure.CRITICAL:
                return False, 'RESOURCE_PRESSURE'
        elif lane == 'L3':
            if self.level >= Pressure.HIGH:
                return False, 'RESOURCE_PRESSURE'
        elif lane == 'L4':
            if self.level != Pressure.NORMAL:
                return False, 'BACKGROUND_DEFERRED'

        if priority >= 2 and sum(1 for _, p, _ in self.leases.values() if p >= 2) >= self.config['max_heavy_leases']:
            return False, 'HEAVY_CONCURRENCY_LIMIT'
        if s.available_gib - outstanding - gib < self.config['reserve_gib']:
            return False, 'MEMORY_RESERVATION'
        return True, 'AVAILABLE'

    def acquire(self, key: str, gib: float = 0.02, priority: int = 1, writes=False, lane: str | None = None):
        if (type(gib) not in (int,float) or not math.isfinite(gib) or not 0 < gib <= 32 or
                type(priority) is not int or not 0 <= priority <= 4 or
                (lane is not None and lane not in {'L0','L1','L2','L3','L4'})):
            raise RuntimeFault('INVALID_PROFILE', 'Invalid resource profile.')
        with self.lock:
            if key in self.leases:
                raise RuntimeFault('DUPLICATE_LEASE', 'Resource lease already exists.')
            effective_lane = lane or self.infer_lane(gib, priority, writes)
            allowed, reason = self._decision(gib, priority, writes, effective_lane)
            if not allowed:
                raise RuntimeFault(reason, 'Operation not admitted; retry after resource pressure clears.', True)
            self.leases[key] = (gib, priority, 0.0)
            self.lease_lanes[key] = effective_lane

    def restore(self, key: str, gib: float, priority: int, observed=0.0, lane: str | None = None):
        """Reattach an already running owned execution, not a new admission."""
        with self.lock:
            self.leases[key] = (gib, priority, observed)
            self.lease_lanes[key] = lane or self.infer_lane(gib, priority, True)

    def observed(self, key: str, gib: float):
        with self.lock:
            if key in self.leases:
                estimate, priority, _ = self.leases[key]
                if type(gib) not in (int,float) or not math.isfinite(gib) or gib < 0:
                    raise RuntimeFault('INVALID_PROFILE', 'Observed resident memory must be finite and nonnegative.')
                self.leases[key] = (estimate, priority, gib)

    def lease_keys(self):
        with self.lock:
            return list(self.leases)

    def release(self, key: str):
        with self.lock:
            self.leases.pop(key, None)
            self.lease_lanes.pop(key, None)

    @contextmanager
    def lease(self, key, gib=0.02, priority=1, writes=False, lane=None):
        self.acquire(key, gib, priority, writes, lane)
        try:
            yield
        finally:
            self.release(key)

    def status(self) -> dict:
        with self.lock:
            vram = self.sample.vram_pct if self.sample else None
            if vram is None:
                gpu_pressure = 'UNKNOWN'
            elif vram >= self.config['gpu_critical_pct']:
                gpu_pressure = 'CRITICAL'
            elif vram >= self.config['gpu_high_pct']:
                gpu_pressure = 'HIGH'
            elif vram >= self.config['gpu_pressure_pct']:
                gpu_pressure = 'PRESSURE'
            else:
                gpu_pressure = 'NORMAL'
            return {'at': utc_now(), 'pressure': self.level.name,
                    'gpu_pressure': gpu_pressure,
                    'sample_age_seconds': None if self.sample is None else round(self.clock() - self.sample_at, 3),
                    'gpu_sample_age_seconds': None if self.last_vram_pct is None else round(self.clock() - self.last_gpu_at, 3),
                    'sample': vars(self.sample) if self.sample else None,
                    'lease_count': len(self.leases),
                    'lease_lanes': {name: sum(1 for value in self.lease_lanes.values() if value == name)
                                    for name in ('L0','L1','L2','L3','L4')},
                    'fast_path': {'l0_min_free_gib': self.config['l0_min_free_gib'],
                                  'l1_min_free_gib': self.config['l1_min_free_gib'],
                                  'commit_stop_pct': self.config['emergency_commit_stop_pct']},
                    'reserved_remaining_gib': round(sum(max(0, e-o) for e, _, o in self.leases.values()), 3),
                    'last_error': self.last_error, 'last_gpu_error': self.last_gpu_error,
                    'mode': 'admission_control_not_arbitrary_preemption'}
