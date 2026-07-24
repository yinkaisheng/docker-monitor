import os
import sys
import time
import re
import json
import asyncio
import shutil
from typing import List, Dict, Any, Optional, Tuple

import process_util as putil
from log_util import logger

# Constants
CONTAINER_ID_SHORT_LENGTH = 12  # Length of short container ID for display
MAX_CONCURRENT_GPU_SEARCH = 10  # Maximum concurrent searches for GPU processes
DAVINCI_DEVICE_RE = re.compile(r'/dev/davinci(\d+)')
DOCKER_CGROUP_ID_RE = re.compile(r'docker[-/]([0-9a-f]{64})', re.IGNORECASE)
DOCKER_CGROUP_SHORT_ID_RE = re.compile(r'docker[-/]([0-9a-f]{12})', re.IGNORECASE)
_accelerator_vendor_cache: Optional[str] = None
_pid_to_container_cache: Dict[int, str] = {}
_container_pid_sets_cache: Dict[str, set] = {}
_container_pid_sets_cache_key: Optional[Tuple[str, ...]] = None
_container_pid_sets_cache_time: float = 0
CONTAINER_PID_SETS_CACHE_TTL = 2.0  # Reuse docker top PID sets within this window
DOCKER_METADATA_CACHE_TTL = 2.0  # Share docker ps / inspect across concurrent API calls
_running_container_ids_cache: Optional[List[str]] = None
_running_container_ids_cache_time: float = 0
_inspect_all_cache_data: Optional[List[Dict[str, Any]]] = None
_inspect_all_cache_key: Optional[Tuple[str, ...]] = None
_inspect_all_cache_time: float = 0
_docker_metadata_lock: Optional[asyncio.Lock] = None
ACCELERATOR_SMI_SEARCH_DIRS = (
    '/usr/local/sbin',
    '/usr/local/bin',
    '/usr/sbin',
    '/usr/bin',
    '/sbin',
    '/bin',
)
_executable_path_cache: Dict[str, Optional[str]] = {}


def _resolve_executable(executable_name: str) -> Optional[str]:
    """Resolve accelerator CLI to an absolute path (handles sbin not in service PATH)."""
    if executable_name in _executable_path_cache:
        return _executable_path_cache[executable_name]

    found = shutil.which(executable_name)
    if not found:
        path_dirs = list(ACCELERATOR_SMI_SEARCH_DIRS)
        path_dirs.extend(os.environ.get('PATH', '').split(os.pathsep))
        seen = set()
        unique_dirs = []
        for directory in path_dirs:
            if directory and directory not in seen:
                seen.add(directory)
                unique_dirs.append(directory)
        found = shutil.which(executable_name, path=os.pathsep.join(unique_dirs))

    if not found:
        for directory in ACCELERATOR_SMI_SEARCH_DIRS:
            candidate = os.path.join(directory, executable_name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                found = candidate
                break

    _executable_path_cache[executable_name] = found
    if found:
        logger.debug(f'resolved {executable_name} -> {found}')
    else:
        logger.debug(f'failed to resolve executable: {executable_name}')
    return found


def detect_accelerator_vendor() -> Optional[str]:
    """Detect GPU/NPU vendor on the host: 'nvidia', 'ascend', or None."""
    global _accelerator_vendor_cache
    if _accelerator_vendor_cache is not None:
        return _accelerator_vendor_cache

    if os.path.exists('/dev/nvidia0') or _resolve_executable('nvidia-smi'):
        _accelerator_vendor_cache = 'nvidia'
    elif os.path.exists('/dev/davinci0') or _resolve_executable('npu-smi'):
        _accelerator_vendor_cache = 'ascend'
    else:
        _accelerator_vendor_cache = None

    if _accelerator_vendor_cache:
        logger.debug(f'detected accelerator vendor: {_accelerator_vendor_cache}')
    else:
        logger.debug('no nvidia-smi or npu-smi found, GPU/NPU monitoring disabled')
    return _accelerator_vendor_cache


def _extract_nvidia_gpu_devices(device_requests: List[Dict[str, Any]]) -> List[str]:
    """Extract NVIDIA GPU device IDs from DeviceRequests."""
    gpu_devices = []
    for dr in device_requests or []:
        if dr.get('Driver') != 'nvidia':
            continue
        device_ids = dr.get('DeviceIDs') or []
        count = dr.get('Count', 0)
        if not device_ids and count == -1:
            gpu_devices.append('all')
        elif device_ids:
            gpu_devices.extend(device_ids)
    return gpu_devices


def _extract_ascend_gpu_devices(host_config: Dict[str, Any], config: Dict[str, Any]) -> List[str]:
    """Extract Ascend NPU device IDs from docker inspect HostConfig/Config."""
    gpu_devices = []
    seen = set()

    def add_device_id(device_id: str) -> None:
        if device_id and device_id not in seen:
            seen.add(device_id)
            gpu_devices.append(device_id)

    for device in host_config.get('Devices') or []:
        path = device.get('PathOnHost') or device.get('PathInContainer') or ''
        match = DAVINCI_DEVICE_RE.search(path)
        if match:
            add_device_id(match.group(1))

    if not gpu_devices:
        for env_item in config.get('Env') or []:
            for env_name in ('ASCEND_VISIBLE_DEVICES', 'ASCEND_RT_VISIBLE_DEVICES'):
                prefix = f'{env_name}='
                if env_item.startswith(prefix):
                    value = env_item[len(prefix):]
                    for device_id in value.split(','):
                        add_device_id(device_id.strip())

    return gpu_devices


def _container_id_matches(candidate: str, docker_id: str) -> bool:
    """Check whether two docker container IDs refer to the same container."""
    candidate = candidate.lower()
    docker_id = docker_id.lower()
    return (
        candidate == docker_id
        or candidate.startswith(docker_id[:CONTAINER_ID_SHORT_LENGTH])
        or docker_id.startswith(candidate[:CONTAINER_ID_SHORT_LENGTH])
    )


def _find_container_id_from_proc_cgroup(pid: int) -> Optional[str]:
    """Find docker container ID from /proc/{pid}/cgroup."""
    cgroup_path = f'/proc/{pid}/cgroup'
    try:
        with open(cgroup_path, encoding='utf-8') as f:
            content = f.read()
    except OSError:
        return None

    match = DOCKER_CGROUP_ID_RE.search(content)
    if match:
        return match.group(1).lower()
    match = DOCKER_CGROUP_SHORT_ID_RE.search(content)
    if match:
        return match.group(1).lower()
    return None


def _merge_processes_into_container_info(
    container_gpu_info: Dict[str, Dict[str, Any]],
    container_id: str,
    processes: List[Dict[str, Any]],
) -> None:
    """Merge accelerator process records into a container's GPU usage summary."""
    if not processes:
        return

    if container_id not in container_gpu_info:
        container_gpu_info[container_id] = {
            'gpu_processes': [],
            'total_memory_mib': 0,
            'gpu_ids': set(),
        }

    existing_pids = {proc['pid'] for proc in container_gpu_info[container_id]['gpu_processes']}
    for process in processes:
        if process['pid'] in existing_pids:
            continue
        container_gpu_info[container_id]['gpu_processes'].append(process)
        if process.get('memory_mib'):
            container_gpu_info[container_id]['total_memory_mib'] += process['memory_mib']
        if process.get('gpu_id') is not None:
            container_gpu_info[container_id]['gpu_ids'].add(process['gpu_id'])
        existing_pids.add(process['pid'])


def _build_container_id_index(container_ids: List[str]) -> Dict[str, str]:
    """Map container ID variants (short/full) to a canonical ID (prefer longest match)."""
    id_index: Dict[str, str] = {}
    by_short_prefix: Dict[str, str] = {}
    for container_id in sorted(container_ids, key=len, reverse=True):
        short_prefix = container_id[:CONTAINER_ID_SHORT_LENGTH].lower()
        if short_prefix not in by_short_prefix:
            by_short_prefix[short_prefix] = container_id
        canonical = by_short_prefix[short_prefix]
        id_index[container_id.lower()] = canonical
        id_index[short_prefix] = canonical
    return id_index


def _resolve_container_id(candidate: str, id_index: Dict[str, str]) -> Optional[str]:
    candidate = candidate.lower()
    return id_index.get(candidate) or id_index.get(candidate[:CONTAINER_ID_SHORT_LENGTH])


def _proc_exists(pid: int) -> bool:
    return os.path.exists(f'/proc/{pid}')


def _is_running_container(container_id: str, container_ids: List[str]) -> bool:
    container_id = container_id.lower()
    short_prefix = container_id[:CONTAINER_ID_SHORT_LENGTH]
    for running_id in container_ids:
        running_id = running_id.lower()
        if (
            running_id == container_id
            or running_id.startswith(short_prefix)
            or container_id.startswith(running_id[:CONTAINER_ID_SHORT_LENGTH])
        ):
            return True
    return False


def _container_ids_cache_key(container_ids: List[str]) -> Tuple[str, ...]:
    return tuple(sorted({container_id[:CONTAINER_ID_SHORT_LENGTH].lower() for container_id in container_ids}))


def _split_cached_pid_mappings(
    pids: List[int],
    container_ids: List[str],
    id_index: Dict[str, str],
) -> Tuple[Dict[int, str], List[int]]:
    """Return cached PID mappings that are still valid, and PIDs that need lookup."""
    pid_to_container: Dict[int, str] = {}
    pids_to_lookup: List[int] = []

    for pid in pids:
        cached_container_id = _pid_to_container_cache.get(pid)
        if (
            cached_container_id
            and _proc_exists(pid)
            and _is_running_container(cached_container_id, container_ids)
        ):
            pid_to_container[pid] = _resolve_container_id(cached_container_id, id_index) or cached_container_id
            logger.debug(
                f'PID {pid} -> container {pid_to_container[pid][:CONTAINER_ID_SHORT_LENGTH]} (cache hit)'
            )
            continue

        if pid in _pid_to_container_cache:
            del _pid_to_container_cache[pid]
        pids_to_lookup.append(pid)

    return pid_to_container, pids_to_lookup


def _prune_pid_container_cache(container_ids: List[str]) -> None:
    """Remove cache entries whose process or container no longer exists."""
    stale_pids = [
        pid for pid, container_id in _pid_to_container_cache.items()
        if not _proc_exists(pid) or not _is_running_container(container_id, container_ids)
    ]
    for pid in stale_pids:
        del _pid_to_container_cache[pid]
    if stale_pids:
        logger.debug(f'pruned {len(stale_pids)} stale PID->container cache entries')


async def _get_container_pid_sets_cached(container_ids: List[str]) -> Dict[str, set]:
    """Return container PID sets, reusing a recent docker top snapshot when possible."""
    global _container_pid_sets_cache, _container_pid_sets_cache_key, _container_pid_sets_cache_time

    cache_key = _container_ids_cache_key(container_ids)
    now = time.perf_counter()
    if (
        _container_pid_sets_cache
        and _container_pid_sets_cache_key == cache_key
        and (now - _container_pid_sets_cache_time) <= CONTAINER_PID_SETS_CACHE_TTL
    ):
        logger.debug(f'reusing cached docker top PID sets for {len(_container_pid_sets_cache)} containers')
        return _container_pid_sets_cache

    pid_sets = await a_build_container_pid_sets(container_ids)
    _container_pid_sets_cache = pid_sets
    _container_pid_sets_cache_key = cache_key
    _container_pid_sets_cache_time = now
    return pid_sets


async def _lookup_pids_to_containers(
    pids: List[int],
    container_ids: List[str],
    id_index: Dict[str, str],
) -> Dict[int, str]:
    """Look up container ownership for PIDs not satisfied by cache."""
    pid_to_container: Dict[int, str] = {}
    unmapped_pids: List[int] = []

    for pid in pids:
        cgroup_container_id = _find_container_id_from_proc_cgroup(pid)
        if cgroup_container_id:
            resolved = _resolve_container_id(cgroup_container_id, id_index)
            if resolved:
                pid_to_container[pid] = resolved
                _pid_to_container_cache[pid] = resolved
                logger.debug(f'mapped PID {pid} to container {resolved[:CONTAINER_ID_SHORT_LENGTH]} via cgroup')
                continue
        unmapped_pids.append(pid)

    if unmapped_pids:
        pid_sets = await _get_container_pid_sets_cached(container_ids)
        for pid in unmapped_pids:
            for container_id, container_pids in pid_sets.items():
                if pid in container_pids:
                    resolved = id_index.get(container_id.lower(), container_id)
                    pid_to_container[pid] = resolved
                    _pid_to_container_cache[pid] = resolved
                    logger.debug(
                        f'mapped PID {pid} to container {container_id[:CONTAINER_ID_SHORT_LENGTH]} via docker top'
                    )
                    break

    return pid_to_container


def _parse_docker_top_pids(stdout: str) -> set:
    """Parse PIDs from `docker top -o pid` output; fallback for default table."""
    pids: set = set()
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line or line.upper() == 'PID':
            continue
        if line.isdigit():
            pids.add(int(line))
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            pids.add(int(parts[1]))
    return pids


async def a_build_container_pid_sets(container_ids: List[str]) -> Dict[str, set]:
    """Build host PID sets for each container via `docker top <cid> -o pid`."""
    pid_sets: Dict[str, set] = {}
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_GPU_SEARCH)

    async def fetch_container_pids(container_id: str) -> None:
        async with semaphore:
            result = await putil.a_run_cmd_monitored(
                ['docker', 'top', container_id, '-o', 'pid'],
                print_cmd=False,
                print_output=False,
                print_return=False,
            )
            pids: set = set()
            if result.exit_code == 0:
                pids = _parse_docker_top_pids(result.stdout)
            if not pids:
                logger.debug(
                    f'docker top -o pid returned no PIDs for container '
                    f'{container_id[:CONTAINER_ID_SHORT_LENGTH]}, trying full table output'
                )
                result = await putil.a_run_cmd_monitored(
                    ['docker', 'top', container_id],
                    print_cmd=False,
                    print_output=False,
                    print_return=False,
                )
                if result.exit_code == 0:
                    pids = _parse_docker_top_pids(result.stdout)
            pid_sets[container_id] = pids

    await asyncio.gather(*[fetch_container_pids(container_id) for container_id in container_ids])
    return pid_sets


async def a_map_pids_to_containers(pids: List[int], container_ids: List[str]) -> Dict[int, str]:
    """Map accelerator process PIDs to container IDs.

    Shared GPUs/NPUs require PID-level attribution: smi reports per-PID memory,
    then we determine which container owns each PID.

    Uses an in-memory PID->container cache: if both the PID (/proc) and container
    are still present, the cached mapping is reused; only new or invalidated PIDs
    trigger cgroup / docker top lookup.
    """
    if not pids or not container_ids:
        return {}

    _prune_pid_container_cache(container_ids)
    id_index = _build_container_id_index(container_ids)
    unique_pids = list(dict.fromkeys(pids))

    pid_to_container, pids_to_lookup = _split_cached_pid_mappings(unique_pids, container_ids, id_index)
    if pids_to_lookup:
        logger.debug(f'PID cache: {len(pid_to_container)} hit, {len(pids_to_lookup)} miss, looking up misses')
        pid_to_container.update(await _lookup_pids_to_containers(pids_to_lookup, container_ids, id_index))

    return pid_to_container


def find_docker_id_by_pid(pid: int) -> Optional[str]:
    """Synchronously find container ID by PID (for non-async scenarios)"""
    cp = putil.run_cmd(['docker', 'ps', '-q'])
    exit_code = cp.get('exit_code', 1)
    if exit_code != 0:
        logger.error(f'failed to get container list, PID {pid}, exit_code {exit_code}')
        return None
    docker_ids = [line.strip() for line in cp['stdout'].split('\n') if line.strip()]
    logger.debug(f'searching for PID {pid} in {len(docker_ids)} containers')
    for docker_id in docker_ids:
        cp = putil.run_cmd(f'docker top {docker_id} | grep {pid}', shell=True)
        if cp.get('exit_code', 1) == 0:
            logger.debug(f'found container {docker_id[:CONTAINER_ID_SHORT_LENGTH]} for PID {pid}')
            return docker_id
    logger.debug(f'container not found for PID {pid}')
    return None


def inspect_docker(docker_id: str) -> Dict[str, Any]:
    """Synchronously get container inspect information (for non-async scenarios)

    Args:
        docker_id: Container ID to inspect

    Returns:
        Dictionary containing container inspect data, or empty dict if failed
    """
    cp = putil.run_cmd(['docker', 'inspect', docker_id])
    if cp.get('exit_code', 1) != 0:
        logger.error(f'failed to inspect container {docker_id[:CONTAINER_ID_SHORT_LENGTH]}, exit_code: {cp.get("exit_code", -1)}, stderr: {cp.get("stderr", "")}')
        return {}
    try:
        data = json.loads(cp.get('stdout', ''))
        return data if isinstance(data, list) and len(data) > 0 else (data if isinstance(data, dict) else {})
    except json.JSONDecodeError as ex:
        stdout_len = len(cp.get('stdout', ''))
        logger.error(f'failed to parse container {docker_id[:CONTAINER_ID_SHORT_LENGTH]} inspect JSON: {ex!r}, stdout length: {stdout_len}')
        return {}
    except Exception as ex:
        logger.error(f'unexpected error inspecting container {docker_id[:CONTAINER_ID_SHORT_LENGTH]}: {ex!r}')
        return {}


async def _fetch_running_container_ids() -> List[str]:
    """Run docker ps -q without caching."""
    result = await putil.a_run_cmd_monitored(['docker', 'ps', '-q'])
    if result.exit_code != 0:
        logger.error(f'failed to get running container IDs, exit_code: {result.exit_code}, stderr: {result.stderr}')
        return []
    ids = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
    logger.debug(f'got running container ids: {len(ids)}{ids}')
    return ids


def _get_docker_metadata_lock() -> asyncio.Lock:
    global _docker_metadata_lock
    if _docker_metadata_lock is None:
        _docker_metadata_lock = asyncio.Lock()
    return _docker_metadata_lock


def _invalidate_inspect_cache_if_container_set_changed(container_ids: List[str]) -> None:
    global _inspect_all_cache_data, _inspect_all_cache_key, _inspect_all_cache_time
    cache_key = tuple(sorted(container_ids))
    if _inspect_all_cache_key != cache_key:
        _inspect_all_cache_data = None
        _inspect_all_cache_key = None
        _inspect_all_cache_time = 0


async def a_get_running_container_ids() -> List[str]:
    """Asynchronously get list of all running container IDs (cached, single-flight)."""
    global _running_container_ids_cache, _running_container_ids_cache_time

    now = time.perf_counter()
    if (
        _running_container_ids_cache is not None
        and (now - _running_container_ids_cache_time) <= DOCKER_METADATA_CACHE_TTL
    ):
        logger.debug(f'reusing cached running container ids ({len(_running_container_ids_cache)})')
        return _running_container_ids_cache

    async with _get_docker_metadata_lock():
        now = time.perf_counter()
        if (
            _running_container_ids_cache is not None
            and (now - _running_container_ids_cache_time) <= DOCKER_METADATA_CACHE_TTL
        ):
            logger.debug(f'reusing cached running container ids ({len(_running_container_ids_cache)})')
            return _running_container_ids_cache

        ids = await _fetch_running_container_ids()
        _running_container_ids_cache = ids
        _running_container_ids_cache_time = time.perf_counter()
        _invalidate_inspect_cache_if_container_set_changed(ids)
        return ids


async def a_inspect_docker(docker_id: str) -> Dict[str, Any]:
    """Asynchronously get inspect information for a single container (used when operating on a container individually)"""
    result = await putil.a_run_cmd_monitored(['docker', 'inspect', docker_id])
    if result.exit_code != 0:
        logger.error(f'failed to inspect container {docker_id[:CONTAINER_ID_SHORT_LENGTH]}'
                     f', exit_code: {result.exit_code}, stderr: {result.stderr}')
        return {}
    try:
        data = json.loads(result.stdout)
        return data[0] if isinstance(data, list) and len(data) > 0 else {}
    except json.JSONDecodeError as ex:
        logger.error(f'failed to parse container {docker_id[:CONTAINER_ID_SHORT_LENGTH]} inspect JSON: {ex!r}'
                     f', stdout length: {len(result.stdout)}')
        return {}


async def a_inspect_all_containers() -> List[Dict[str, Any]]:
    """Asynchronously get inspect information for all running containers at once (cached)."""
    global _inspect_all_cache_data, _inspect_all_cache_key, _inspect_all_cache_time

    container_ids = await a_get_running_container_ids()
    if not container_ids:
        logger.debug('no running containers')
        return []

    cache_key = tuple(sorted(container_ids))
    now = time.perf_counter()
    if (
        _inspect_all_cache_data is not None
        and _inspect_all_cache_key == cache_key
        and (now - _inspect_all_cache_time) <= DOCKER_METADATA_CACHE_TTL
    ):
        logger.debug(f'reusing cached inspect data for {len(_inspect_all_cache_data)} containers')
        return _inspect_all_cache_data

    async with _get_docker_metadata_lock():
        now = time.perf_counter()
        if (
            _inspect_all_cache_data is not None
            and _inspect_all_cache_key == cache_key
            and (now - _inspect_all_cache_time) <= DOCKER_METADATA_CACHE_TTL
        ):
            logger.debug(f'reusing cached inspect data for {len(_inspect_all_cache_data)} containers')
            return _inspect_all_cache_data

        container_ids = _running_container_ids_cache or await _fetch_running_container_ids()
        if not container_ids:
            return []

        cache_key = tuple(sorted(container_ids))
        cmd = ['docker', 'inspect'] + container_ids
        logger.debug(f'executing command to get inspect info for {len(container_ids)} containers')
        result = await putil.a_run_cmd_monitored(
            cmd,
            print_cmd=False,
            print_output=False,
            print_return=False
        )
        if result.exit_code != 0:
            logger.error(f'docker inspect command failed, exit_code: {result.exit_code}, stderr: {result.stderr}')
            return []

        try:
            data = json.loads(result.stdout)
            if isinstance(data, list):
                logger.debug(f'successfully parsed inspect info for {len(data)} containers')
                _inspect_all_cache_data = data
                _inspect_all_cache_key = cache_key
                _inspect_all_cache_time = time.perf_counter()
                return data
            logger.warning(f'docker inspect returned data is not a list type: {type(data)}')
            return []
        except json.JSONDecodeError as ex:
            logger.error(f'failed to parse docker inspect JSON: {ex!r}, stdout length: {len(result.stdout)}'
                         f', first 100 chars: {result.stdout[:100]}')
            return []


def extract_container_info(inspect_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract required fields from docker inspect data"""
    # Extract basic information
    container_id = inspect_data.get('Id', '')
    created = inspect_data.get('Created', '')
    args = inspect_data.get('Args', [])
    name = inspect_data.get('Name', '')
    # Remove leading slash from name (Docker name format is /name)
    if name.startswith('/'):
        name = name[1:]

    # Extract State information (remove Log)
    state = inspect_data.get('State', {})
    state.get('Health', {}).pop('Log', None)

    # Extract NetworkMode
    network_mode = inspect_data.get('HostConfig', {}).get('NetworkMode', '')

    # Extract PortBindings
    port_bindings = inspect_data.get('HostConfig', {}).get('PortBindings', {})

    # Extract Memory and MemorySwap (memory limits in bytes)
    host_config = inspect_data.get('HostConfig', {})
    config = inspect_data.get('Config', {})
    memory_limit = host_config.get('Memory', 0)  # Memory limit in bytes, 0 means unlimited
    memory_swap = host_config.get('MemorySwap', 0)  # Memory+Swap limit in bytes, 0 means unlimited

    # Extract GPU/NPU device IDs (NVIDIA DeviceRequests or Ascend davinci devices)
    device_requests = host_config.get('DeviceRequests')
    gpu_devices = _extract_nvidia_gpu_devices(device_requests)
    if not gpu_devices:
        gpu_devices = _extract_ascend_gpu_devices(host_config, config)

    # Extract Test field from Healthcheck (extract URL)
    healthcheck_test = None
    image = config.get('Image', '')
    healthcheck = config.get('Healthcheck')
    if healthcheck and 'Test' in healthcheck:
        test = healthcheck['Test']
        if isinstance(test, list) and len(test) > 0:
            # Convert Test array to string
            # Support three URL formats:
            # 1. ["CMD-SHELL", "curl -f http://localhost:9997/health || exit 1"] - with shell logic or operators
            # 2. ["CMD-SHELL", "curl -f http://localhost:9997/health"] - without logic or operators
            # 3. ["CMD", "curl", "-f", "http://localhost:9997/v1/chat/completions"] - URL scattered across multiple parameters
            test_str = ' '.join(str(item) for item in test)
            # Try to extract URL from Test (supports http:// and https://)
            # Regular expression explanation:
            # - https?:// matches http:// or https://
            # - [^\s\'"|&<>]+ matches URL characters until encountering space, quotes, pipe, &, <, > and other shell special characters
            #   This correctly handles case 1's "|| exit 1", URL will stop before |
            #   For cases 2 and 3, URL will stop when encountering space or string end
            url_match = re.search(r'https?://[^\s\'"|&<>]+', test_str)
            if url_match:
                healthcheck_test = url_match.group(0)
            else:
                # If URL not found, return entire Test command (for debugging)
                healthcheck_test = test_str

    # Extract Entrypoint
    entrypoint = config.get('Entrypoint')

    # Extract compose file path from Labels
    labels = config.get('Labels', {})
    compose_file = labels.get('com.docker.compose.project.config_files', '')

    return {
        'Id': container_id,
        'Created': created,
        'Args': args,
        'State': state,
        'Name': name,
        'PortBindings': port_bindings,
        'NetworkMode': network_mode,
        'Memory': memory_limit,  # Memory limit in bytes
        'MemorySwap': memory_swap,  # Memory+Swap limit in bytes
        'DeviceRequests': device_requests,
        'Image': image,
        'HealthcheckTest': healthcheck_test,
        'Entrypoint': entrypoint,
        'ComposeFile': compose_file,
        'GpuDevices': gpu_devices,  # GPU device ID list
    }


async def a_get_container_list() -> List[Dict[str, Any]]:
    """Asynchronously get information list of all running containers (optimization: get all container information at once)"""
    # Get inspect information for all containers at once to improve efficiency
    inspect_data_list = await a_inspect_all_containers()
    containers = []
    for inspect_data in inspect_data_list:
        if inspect_data:
            container_info = extract_container_info(inspect_data)
            if container_info:
                containers.append(container_info)
    return containers


async def a_get_containers_overview() -> Dict[str, Any]:
    """Fetch containers, GPU/NPU usage, and stats in parallel (shared docker metadata cache)."""
    containers, gpu_usage, stats = await asyncio.gather(
        a_get_container_list(),
        a_get_gpu_usage_by_containers(),
        a_get_container_stats(),
    )
    return {
        'containers': containers,
        'gpu_usage': gpu_usage,
        'stats': stats,
    }


async def a_get_container_healthcheck_url(container_id: str) -> Optional[str]:
    """Get container Healthcheck URL"""
    inspect_data = await a_inspect_docker(container_id)
    if not inspect_data:
        logger.warning(f'cannot get inspect info for container {container_id[:CONTAINER_ID_SHORT_LENGTH]}, cannot extract Healthcheck URL')
        return None
    container_info = extract_container_info(inspect_data)
    healthcheck_url = container_info.get('HealthcheckTest')
    if healthcheck_url:
        logger.debug(f'container {container_id[:CONTAINER_ID_SHORT_LENGTH]} Healthcheck URL: {healthcheck_url}')
    else:
        logger.debug(f'container {container_id[:CONTAINER_ID_SHORT_LENGTH]} has no Healthcheck configured or cannot extract URL')
    return healthcheck_url


async def a_get_container_compose_file(container_id: str) -> Optional[str]:
    """Get container compose file path"""
    inspect_data = await a_inspect_docker(container_id)
    if not inspect_data:
        logger.warning(f'cannot get inspect info for container {container_id[:CONTAINER_ID_SHORT_LENGTH]}, cannot extract Compose file path')
        return None
    container_info = extract_container_info(inspect_data)
    compose_file = container_info.get('ComposeFile')
    if compose_file:
        logger.debug(f'container {container_id[:CONTAINER_ID_SHORT_LENGTH]} Compose file: {compose_file}')
    else:
        logger.debug(f'container {container_id[:CONTAINER_ID_SHORT_LENGTH]} has no associated Compose file')
    return compose_file


async def a_find_docker_id_by_pid(pid: int, docker_ids: List[str] = None) -> Optional[str]:
    """Asynchronously find container ID by PID

    Args:
        pid: Process ID
        docker_ids: Container ID list, if None then automatically get
    """
    # If container list not provided, get it first
    if docker_ids is None:
        result = await putil.a_run_cmd_monitored(['docker', 'ps', '-q'], print_cmd=False, print_output=False, print_return=False)
        if result.exit_code != 0:
            logger.error(f'failed to get container list, cannot find container for PID {pid}, exit_code: {result.exit_code}')
            return None
        docker_ids = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]

    logger.debug(f'searching for PID {pid} in {len(docker_ids)} containers')

    cgroup_container_id = _find_container_id_from_proc_cgroup(pid)
    if cgroup_container_id:
        for docker_id in docker_ids:
            if _container_id_matches(cgroup_container_id, docker_id):
                logger.debug(f'found container {docker_id[:CONTAINER_ID_SHORT_LENGTH]} for PID {pid} via cgroup')
                return docker_id

    for docker_id in docker_ids:
        # Use docker top to find PID
        result = await putil.a_run_cmd_monitored(
            ['sh', '-c', f'docker top {docker_id} | grep -w {pid}'],
            print_cmd=False,
            print_output=False,
            print_return=False
        )
        if result.exit_code == 0:
            logger.debug(f'found container {docker_id[:CONTAINER_ID_SHORT_LENGTH]} for PID {pid} via docker top')
            return docker_id
    logger.debug(f'container not found for PID {pid}')
    return None


def parse_nvidia_smi_output(output: str) -> List[Dict[str, Any]]:
    """Parse nvidia-smi output and extract GPU process information

    Parses the Processes section of nvidia-smi output to extract GPU process details.

    Args:
        output: Raw nvidia-smi command output string

    Returns:
        List of dictionaries, each containing:
            - 'gpu_id': GPU device ID (int)
            - 'pid': Process ID (int)
            - 'process_name': Process name (str)
            - 'memory_mib': GPU memory usage in MiB (int)

    Example:
        Input line format:
        |    0   N/A  N/A         3605966      C   VLLM::Worker_TP0                      22062MiB |
    """
    processes = []
    lines = output.split('\n')

    # Find the start of Processes section
    processes_start = False
    for line in lines:
        if 'Processes:' in line:
            processes_start = True
            continue
        if not processes_start:
            continue

        # Skip separators and headers
        if '===' in line or 'PID' in line or 'GPU' in line and 'ID' in line:
            continue

        # Reach the end of Processes section
        if '---' in line and 'Processes' not in line:
            break

        # Parse process information line
        # Format: |    0   N/A  N/A         3605966      C   VLLM::Worker_TP0                      22062MiB |
        if '|' in line:
            # Use regex to parse more accurately
            # Match format: GPU_ID  GI  CI  PID  Type  Process_name  Memory
            # Example: |    0   N/A  N/A         3605966      C   VLLM::Worker_TP0                      22062MiB |
            match = re.search(r'\|\s*(\d+)\s+\S+\s+\S+\s+(\d+)\s+\S+\s+(.+?)\s+(\d+)MiB\s*\|', line)
            if match:
                try:
                    gpu_id = int(match.group(1))
                    pid = int(match.group(2))
                    process_name = match.group(3).strip()
                    memory_usage = int(match.group(4))

                    processes.append({
                        'gpu_id': gpu_id,
                        'pid': pid,
                        'process_name': process_name,
                        'memory_mib': memory_usage,
                    })
                except (ValueError, IndexError) as ex:
                    logger.debug(f'failed to parse nvidia-smi process line: {line[:100]}, error: {ex!r}')
                    continue

    logger.debug(f'parsed {len(processes)} GPU processes from nvidia-smi output')
    return processes


def _parse_npu_hbm_usage(output: str) -> Dict[int, Dict[str, int]]:
    """Parse NPU HBM usage lines from npu-smi info output."""
    hbm_usage: Dict[int, Dict[str, int]] = {}
    current_npu_id: Optional[int] = None

    for line in output.split('\n'):
        npu_match = re.search(r'^\|\s*(\d+)\s+\S+\s+\|\s*OK\b', line)
        if npu_match:
            current_npu_id = int(npu_match.group(1))
            continue

        if current_npu_id is None:
            continue

        hbm_match = re.search(r'(\d+)\/\s*(\d+)\s*\|?\s*$', line)
        if hbm_match and 'Bus-Id' not in line and 'HBM-Usage' not in line:
            hbm_usage[current_npu_id] = {
                'used_mb': int(hbm_match.group(1)),
                'total_mb': int(hbm_match.group(2)),
            }
            current_npu_id = None

    return hbm_usage


def parse_npu_smi_output(output: str) -> List[Dict[str, Any]]:
    """Parse npu-smi info output and extract NPU process information

    Parses the process section of npu-smi info output.

    Args:
        output: Raw npu-smi info command output string

    Returns:
        List of dictionaries with the same fields as parse_nvidia_smi_output.
        memory_mib stores npu-smi Process memory values (MB).

    Example:
        Input line format:
        | 0       0                 | 1217362       | VLLMWorker_TP            | 56934                   |
    """
    processes = []
    npu_hbm_usage = _parse_npu_hbm_usage(output)
    lines = output.split('\n')
    processes_start = False

    for line in lines:
        if 'Process id' in line and 'Process name' in line:
            processes_start = True
            continue
        if not processes_start:
            continue

        if 'No running processes found' in line:
            continue

        if '+=' in line:
            continue

        if '|' not in line:
            continue

        match = re.search(
            r'\|\s*(\d+)\s+\d+\s+\|\s*(\d+)\s+\|\s*([^|]+?)\|\s*(\d+)\s*\|',
            line
        )
        if match:
            try:
                gpu_id = int(match.group(1))
                process = {
                    'gpu_id': gpu_id,
                    'pid': int(match.group(2)),
                    'process_name': match.group(3).strip(),
                    'memory_mib': int(match.group(4)),
                }
                hbm_info = npu_hbm_usage.get(gpu_id)
                if hbm_info:
                    process['device_memory_used_mb'] = hbm_info['used_mb']
                    process['device_memory_total_mb'] = hbm_info['total_mb']
                processes.append(process)
            except (ValueError, IndexError) as ex:
                logger.debug(f'failed to parse npu-smi process line: {line[:100]}, error: {ex!r}')
                continue

    logger.debug(f'parsed {len(processes)} NPU processes from npu-smi output')
    return processes


async def a_get_gpu_usage_by_containers() -> Dict[str, Dict[str, Any]]:
    """Get GPU/NPU usage information and associate with container IDs

    Queries nvidia-smi or npu-smi to get accelerator processes, then maps each process
    PID to a container. Per-container memory is the sum of smi-reported memory for PIDs
    owned by that container. This PID-based attribution is required when multiple
    containers share the same GPU/NPU device.

    Returns:
        Dictionary mapping container IDs to GPU usage information:
        {
            'container_id': {
                'gpu_processes': [
                    {
                        'gpu_id': 0,
                        'pid': 3605966,
                        'process_name': 'VLLM::Worker_TP0',
                        'memory_mib': 22062
                    },
                    ...
                ],
                'total_memory_mib': 44124,  # Total GPU memory used by this container
                'gpu_ids': [0, 1]  # Sorted list of GPU device IDs used
            },
            ...
        }
    """
    vendor = detect_accelerator_vendor()
    if vendor == 'nvidia':
        nvidia_smi = _resolve_executable('nvidia-smi')
        if not nvidia_smi:
            logger.error('nvidia-smi not found in PATH or standard directories')
            return {}
        smi_cmd = [nvidia_smi]
        parse_output = parse_nvidia_smi_output
        tool_name = 'nvidia-smi'
    elif vendor == 'ascend':
        npu_smi = _resolve_executable('npu-smi')
        if not npu_smi:
            logger.error('npu-smi not found in PATH or standard directories')
            return {}
        smi_cmd = [npu_smi, 'info']
        parse_output = parse_npu_smi_output
        tool_name = 'npu-smi'
    else:
        return {}

    logger.debug(f'starting to get {tool_name} output')
    result = await putil.a_run_cmd_monitored(
        smi_cmd,
        print_cmd=False,
        print_output=False,
        print_return=False
    )

    if result.exit_code != 0:
        logger.error(f'{tool_name} command failed, exit_code: {result.exit_code}, stderr: {result.stderr}')
        return {}

    gpu_processes = parse_output(result.stdout)
    logger.debug(f'parsed {len(gpu_processes)} accelerator processes from {tool_name}')

    if not gpu_processes:
        return {}

    # Always search all running containers: multiple containers may share the same GPU/NPU,
    # so attribution must be done by PID (from smi) -> container, not by device id alone.
    container_ids = await a_get_running_container_ids()
    if not container_ids:
        logger.error('failed to get container list')
        return {}
    logger.debug(f'mapping {len(gpu_processes)} accelerator PIDs across {len(container_ids)} containers')

    find_start_time = time.perf_counter()
    unique_pids = list({process['pid'] for process in gpu_processes})
    pid_to_container = await a_map_pids_to_containers(unique_pids, container_ids)
    find_end_time = time.perf_counter()
    logger.debug(
        f'pid mapping completed, mapped {len(pid_to_container)}/{len(unique_pids)} PIDs, '
        f'time taken: {(find_end_time - find_start_time) * 1000:.2f}ms'
    )

    container_gpu_info: Dict[str, Dict[str, Any]] = {}

    for process in gpu_processes:
        container_id = pid_to_container.get(process['pid'])
        if container_id:
            _merge_processes_into_container_info(container_gpu_info, container_id, [process])
        else:
            logger.debug(
                f'pid {process["pid"]} (process: {process.get("process_name", "unknown")}) '
                f'not found in any container, skipped'
            )

    for container_id in container_gpu_info:
        container_gpu_info[container_id]['gpu_ids'] = sorted(list(container_gpu_info[container_id]['gpu_ids']))

    logger.debug(f'successfully associated GPU usage info for {len(container_gpu_info)} containers')
    return container_gpu_info


def parse_docker_stats_output(output: str) -> Dict[str, Dict[str, Any]]:
    """Parse docker stats --no-stream output

    Args:
        output: Output from docker stats --no-stream command

    Returns:
        Dictionary mapping container IDs to stats information:
        {
            'container_id': {
                'cpu_percent': 203.09,  # CPU usage percentage
                'mem_usage_bytes': 10857684992,  # Memory usage in bytes
                'mem_limit_bytes': 68719476736,  # Memory limit in bytes
                'mem_percent': 15.80,  # Memory usage percentage
                'net_io_rx': 204472320,  # Network I/O received in bytes
                'net_io_tx': 607256576,  # Network I/O transmitted in bytes
                'block_io_read': 5196906496,  # Block I/O read in bytes
                'block_io_write': 2956984320,  # Block I/O write in bytes
                'pids': 439  # Number of PIDs
            },
            ...
        }
    """
    stats: Dict[str, Dict[str, Any]] = {}
    lines = output.strip().split('\n')

    if len(lines) < 2:
        logger.warning('docker stats output has less than 2 lines, cannot parse')
        return stats

    # Skip header line (first line)
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue

        try:
            # Parse format: CONTAINER ID   NAME        CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
            # Example: 32869ef54f20   qwen3-32b   203.09%   10.11GiB / 64GiB    15.80%    195MB / 579MB     4.84GB / 2.82MB   439
            parts = line.split()
            if len(parts) < 8:
                logger.debug(f'skipping invalid stats line: {line[:100]}')
                continue

            container_id = parts[0]
            # Skip NAME (parts[1])
            cpu_percent_str = parts[2].rstrip('%')
            mem_usage_str = parts[3]  # e.g., "10.11GiB"
            mem_limit_str = parts[5]  # e.g., "64GiB"
            mem_percent_str = parts[6].rstrip('%')
            net_io_rx_str = parts[7]  # e.g., "195MB"
            net_io_tx_str = parts[9]  # e.g., "579MB"
            block_io_read_str = parts[10]  # e.g., "4.84GB"
            block_io_write_str = parts[12]  # e.g., "2.82MB"
            pids = int(parts[13]) if len(parts) > 13 else 0

            # Parse CPU percentage
            cpu_percent = float(cpu_percent_str) if cpu_percent_str else 0.0

            # Parse memory usage and limit (convert to bytes)
            def parse_size(size_str: str) -> int:
                """Parse size string like '10.11GiB', '64GiB', '195MB' to bytes"""
                if not size_str or size_str == '0B':
                    return 0
                size_str = size_str.upper()
                multipliers = {
                    'B': 1,
                    'KB': 1024,
                    'MB': 1024 ** 2,
                    'GB': 1024 ** 3,
                    'TB': 1024 ** 4,
                    'KIB': 1024,
                    'MIB': 1024 ** 2,
                    'GIB': 1024 ** 3,
                    'TIB': 1024 ** 4
                }
                for unit, multiplier in sorted(multipliers.items(), key=lambda x: -len(x[0])):
                    if size_str.endswith(unit):
                        number_str = size_str[:-len(unit)]
                        try:
                            number = float(number_str)
                            return int(number * multiplier)
                        except ValueError:
                            logger.warning(f'failed to parse number from size string: {size_str}')
                            return 0
                logger.warning(f'unknown size unit in: {size_str}')
                return 0

            mem_usage_bytes = parse_size(mem_usage_str)
            mem_limit_bytes = parse_size(mem_limit_str)
            mem_percent = float(mem_percent_str) if mem_percent_str else 0.0

            # Parse network I/O
            net_io_rx = parse_size(net_io_rx_str)
            net_io_tx = parse_size(net_io_tx_str)

            # Parse block I/O
            block_io_read = parse_size(block_io_read_str)
            block_io_write = parse_size(block_io_write_str)

            stats[container_id] = {
                'cpu_percent': cpu_percent,
                'mem_usage_bytes': mem_usage_bytes,
                'mem_limit_bytes': mem_limit_bytes,
                'mem_percent': mem_percent,
                'net_io_rx': net_io_rx,
                'net_io_tx': net_io_tx,
                'block_io_read': block_io_read,
                'block_io_write': block_io_write,
                'pids': pids
            }

        except (ValueError, IndexError) as ex:
            logger.warning(f'failed to parse docker stats line: {line[:100]}, error: {ex!r}')
            continue

    logger.debug(f'parsed stats for {len(stats)} containers')
    return stats


async def a_get_container_stats(container_ids: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
    """Get container stats using docker stats --no-stream

    Args:
        container_ids: Optional list of container IDs. If None, get stats for all running containers.

    Returns:
        Dictionary mapping container IDs to stats information (same format as parse_docker_stats_output)
    """
    # Get container IDs if not provided
    if container_ids is None:
        container_ids = await a_get_running_container_ids()
        if not container_ids:
            logger.debug('no running containers for stats')
            return {}

    if not container_ids:
        return {}

    # Build command: docker stats --no-stream id1 id2 id3 ...
    cmd = ['docker', 'stats', '--no-stream'] + container_ids
    logger.debug(f'executing docker stats for {len(container_ids)} containers')
    result = await putil.a_run_cmd_monitored(
        cmd,
        print_cmd=False,
        print_output=False,
        print_return=False
    )

    if result.exit_code != 0:
        logger.error(f'docker stats command failed, exit_code: {result.exit_code}, stderr: {result.stderr}')
        return {}

    # Parse output
    stats = parse_docker_stats_output(result.stdout)
    logger.debug(f'successfully parsed stats for {len(stats)} containers')
    return stats


if __name__ == '__main__':
    if len(sys.argv) == 1:
        pid = input('Enter pid: ')
        pid = int(pid)
    else:
        pid = int(sys.argv[1])
    docker_id = find_docker_id_by_pid(pid)
    if docker_id:
        print(f'Docker id: {docker_id}')
        inspect = inspect_docker(docker_id)
        print(f'Inspect: {json.dumps(inspect, indent=2, ensure_ascii=False)}')
    else:
        print('Docker id not found')
