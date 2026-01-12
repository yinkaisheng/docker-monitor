import os
import sys
import time
import re
import json
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

import process_util as putil
from log_util import logger

# Constants
CONTAINER_ID_SHORT_LENGTH = 12  # Length of short container ID for display
MAX_CONCURRENT_GPU_SEARCH = 10  # Maximum concurrent searches for GPU processes


def find_docker_id_by_pid(pid: int) -> str|None:
    """Synchronously find container ID by PID (for non-async scenarios)"""
    cp = putil.run_cmd(['docker', 'ps', '-q'])
    if cp.get('exit_code', 1) != 0:
        logger.error(f'failed to get container list, cannot find container for PID {pid}, exit_code: {cp.get("exit_code")}')
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


def inspect_docker(docker_id: str) -> dict:
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
    except json.JSONDecodeError as e:
        stdout_len = len(cp.get('stdout', ''))
        logger.error(f'failed to parse container {docker_id[:CONTAINER_ID_SHORT_LENGTH]} inspect JSON: {e!r}, stdout length: {stdout_len}')
        return {}
    except Exception as e:
        logger.error(f'unexpected error inspecting container {docker_id[:CONTAINER_ID_SHORT_LENGTH]}: {e!r}')
        return {}


def describe_docker(inpsect: dict) -> str:
    config = inpsect['Config']
    state = inpsect['State']
    state.pop('Health', None)
    labels = config['Labels']
    config_files = labels.get('com.docker.compose.project.config_files', '')
    service = labels.get('com.docker.compose.service', '')
    print(f'Image: {config['Image']}')
    print(f'Service: {service}')
    print(f'Name: {inpsect['Name']}')
    print(f'ConfigFile: {config_files}')
    print(f'Created: {inpsect['Created']}')
    print(f'Path: {inpsect['Path']}')
    print(f'Args: {inpsect['Args']}')
    print(f'State: {json.dumps(state, indent=2, ensure_ascii=False)}')


async def a_get_running_container_ids() -> List[str]:
    """Asynchronously get list of all running container IDs"""
    result = await putil.a_run_cmd_monitored(['docker', 'ps', '-q'], print_cmd=False, print_output=False, print_return=False)
    if result.exit_code != 0:
        logger.error(f'failed to get running container IDs, exit_code: {result.exit_code}, stderr: {result.stderr}')
        return []
    ids = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
    logger.debug(f'got running container ids: {len(ids)}{ids}')
    return ids


async def a_inspect_docker(docker_id: str) -> Dict[str, Any]:
    """Asynchronously get inspect information for a single container (used when operating on a container individually)"""
    result = await putil.a_run_cmd_monitored(['docker', 'inspect', docker_id], print_cmd=False, print_output=False, print_return=False)
    if result.exit_code != 0:
        logger.error(f'failed to inspect container {docker_id[:CONTAINER_ID_SHORT_LENGTH]}, exit_code: {result.exit_code}, stderr: {result.stderr}')
        return {}
    try:
        data = json.loads(result.stdout)
        return data[0] if isinstance(data, list) and len(data) > 0 else {}
    except json.JSONDecodeError as e:
        logger.error(f'failed to parse container {docker_id[:CONTAINER_ID_SHORT_LENGTH]} inspect JSON: {e!r}, stdout length: {len(result.stdout)}')
        return {}


async def a_inspect_all_containers() -> List[Dict[str, Any]]:
    """Asynchronously get inspect information for all running containers at once (optimization: only one call needed)"""
    # First get all running container IDs
    container_ids = await a_get_running_container_ids()
    if not container_ids:
        logger.debug('no running containers')
        return []

    # Call docker inspect once to get all container information
    # Build command: docker inspect id1 id2 id3 ...
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
            return data
        else:
            logger.warning(f'docker inspect returned data is not a list type: {type(data)}')
            return []
    except json.JSONDecodeError as e:
        logger.error(f'failed to parse docker inspect JSON: {e!r}, stdout length: {len(result.stdout)}, first 100 chars: {result.stdout[:100]}')
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
    memory_limit = host_config.get('Memory', 0)  # Memory limit in bytes, 0 means unlimited
    memory_swap = host_config.get('MemorySwap', 0)  # Memory+Swap limit in bytes, 0 means unlimited

    # Extract DeviceRequests (GPU information)
    device_requests = inspect_data.get('HostConfig', {}).get('DeviceRequests', [])
    '''
    "DeviceRequests": [
        {
            "Driver": "nvidia",
            "Count": -1,
            "DeviceIDs": null,
            "Capabilities": [
                [
                    "gpu"
                ]
            ],
            "Options": null
        }
    ]
    or
    "DeviceRequests": [
        {
            "Driver": "nvidia",
            "Count": 0,
            "DeviceIDs": [
                "0",
                "1"
            ],
            "Capabilities": [
                [
                    "gpu"
                ]
            ],
            "Options": null
        }
    ]
    '''
    gpu_devices = []
    if device_requests:
        for dr in device_requests:
            driver = dr.get('Driver')
            device_ids = dr.get('DeviceIDs', [])
            count = dr.get('Count', 0)
            if driver == 'nvidia':
                if not device_ids and count == -1:
                    gpu_devices.append('all')
                elif device_ids:
                    gpu_devices.extend(device_ids)

    # Extract Test field from Healthcheck (extract URL)
    healthcheck_test = None
    config = inspect_data.get('Config', {})
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
    for docker_id in docker_ids:
        # Use docker top to find PID
        result = await putil.a_run_cmd_monitored(
            ['sh', '-c', f'docker top {docker_id} | grep {pid}'],
            print_cmd=False,
            print_output=False,
            print_return=False
        )
        if result.exit_code == 0:
            logger.debug(f'found container {docker_id[:CONTAINER_ID_SHORT_LENGTH]} for PID {pid}')
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
                except (ValueError, IndexError) as e:
                    logger.debug(f'failed to parse nvidia-smi process line: {line[:100]}, error: {e!r}')
                    continue

    logger.debug(f'parsed {len(processes)} GPU processes from nvidia-smi output')
    return processes


async def a_get_gpu_usage_by_containers(use_gpu_container_ids: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
    """Get GPU usage information and associate with container IDs

    Queries nvidia-smi to get GPU processes, then finds which Docker containers they belong to.
    Uses concurrent searches to improve performance.

    Args:
        use_gpu_container_ids: Optional list of container IDs that use GPU. If provided, only search
                              in these containers (optimization). If None, search in all running containers.

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
    # Get nvidia-smi output
    logger.debug('starting to get nvidia-smi output')
    result = await putil.a_run_cmd_monitored(
        ['nvidia-smi'],
        print_cmd=False,
        print_output=False,
        print_return=False
    )

    if result.exit_code != 0:
        logger.error(f'nvidia-smi command failed, exit_code: {result.exit_code}, stderr: {result.stderr}')
        return {}

    # Parse nvidia-smi output
    gpu_processes = parse_nvidia_smi_output(result.stdout)
    logger.debug(f'parsed {len(gpu_processes)} GPU processes')

    # Get container list - use provided list if available, otherwise get all containers
    if use_gpu_container_ids is not None:
        docker_ids = use_gpu_container_ids
        logger.debug(f'using provided GPU container IDs list ({len(docker_ids)} containers) for optimization')
    else:
        result = await putil.a_run_cmd_monitored(['docker', 'ps', '-q'], print_cmd=False, print_output=False, print_return=False)
        if result.exit_code != 0:
            logger.error(f'failed to get container list, exit_code: {result.exit_code}')
            return {}
        docker_ids = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
        logger.debug(f'got {len(docker_ids)} running containers')

    # Concurrently find container IDs for PIDs
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_GPU_SEARCH)

    async def find_container_with_semaphore(pid: int) -> Tuple[int, Optional[str]]:
        """Find function with semaphore control"""
        async with semaphore:
            container_id = await a_find_docker_id_by_pid(pid, docker_ids)
            return (pid, container_id)

    # Concurrently execute all PID searches
    logger.debug(f'starting concurrent search for {len(gpu_processes)} PIDs to find containers (concurrency: {MAX_CONCURRENT_GPU_SEARCH})')
    find_start_time = time.perf_counter()
    pid_container_tasks = [find_container_with_semaphore(process['pid']) for process in gpu_processes]
    pid_container_results = await asyncio.gather(*pid_container_tasks)
    find_end_time = time.perf_counter()
    logger.debug(f'pid search completed, time taken: {(find_end_time - find_start_time) * 1000:.2f}ms')

    # Build PID to container ID mapping
    pid_to_container = {pid: container_id for pid, container_id in pid_container_results}

    # Associate container IDs by PID
    container_gpu_info: Dict[str, Dict[str, Any]] = {}

    for process in gpu_processes:
        pid = process['pid']
        container_id = pid_to_container.get(pid)

        if container_id:
            if container_id not in container_gpu_info:
                container_gpu_info[container_id] = {
                    'gpu_processes': [],
                    'total_memory_mib': 0,
                    'gpu_ids': set()
                }

            container_gpu_info[container_id]['gpu_processes'].append(process)
            if process['memory_mib']:
                container_gpu_info[container_id]['total_memory_mib'] += process['memory_mib']
            if process['gpu_id'] is not None:
                container_gpu_info[container_id]['gpu_ids'].add(process['gpu_id'])
        else:
            logger.debug(f'pid {pid} (process: {process.get("process_name", "unknown")}) not found in any container')

    # Convert gpu_ids from set to list
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

        except (ValueError, IndexError) as e:
            logger.warning(f'failed to parse docker stats line: {line[:100]}, error: {e!r}')
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
        describe_docker(inspect[0])
    else:
        print('Docker id not found')
