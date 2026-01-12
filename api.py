import os
import sys
import time
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

from fastapi import APIRouter, Body, File, Form, HTTPException, Query, Request, Response, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import ValidationError

try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

import models
import fastapi_util as futil
import time_util as tutil
import sys_util as sutil
import docker_util as dutil
import process_util as putil
import httpx
from log_util import logger, remove_color_of_shell_text


router = APIRouter()
_thread_executor: ThreadPoolExecutor|None = None
# Docker Compose command format: ['docker', 'compose'] or ['docker-compose']
_compose_cmd: list[str]|None = None
# Restart password cache (username -> password_hash)
_restart_passwords: dict[str, str] | None = None
# GPU container IDs cache (for optimization)
_gpu_container_ids_cache: list[str] | None = None
_gpu_container_ids_cache_time: float = 0
GPU_CONTAINER_IDS_CACHE_TTL = 2.0  # Cache TTL in seconds
# HTTP request API configuration: whether to block local/private IP addresses (default False, allow local IP access)
HTTP_REQUEST_BLOCK_LOCAL_IP = False


def get_thread_executor() -> ThreadPoolExecutor:
    global _thread_executor
    if _thread_executor is None:
        _thread_executor = ThreadPoolExecutor(max_workers=1)
    return _thread_executor


def get_restart_password_hash(username: str = 'admin') -> str:
    """Get restart password hash value for a specific user (read from key.json file)

    The key.json file should contain a JSON object mapping usernames to bcrypt hash values.
    You can use the generate_password_hash.py script to generate and manage user passwords.

    Args:
        username: Username to get password hash for (default: 'admin')

    Returns:
        str: Password hash value, returns empty string if file does not exist, read fails, or user not found
    """
    global _restart_passwords

    # If already read, return cached hash value
    if _restart_passwords is not None:
        return _restart_passwords.get(username, '')

    # Read key.json file
    key_file_path = os.path.join(os.path.dirname(__file__), 'key.json')
    _restart_passwords = {}

    try:
        if os.path.exists(key_file_path):
            with open(key_file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    logger.warning(f'Password file is empty: {key_file_path}')
                    return ''

                # Try to parse as JSON (new format)
                try:
                    _restart_passwords = json.loads(content)
                    logger.info(f'Successfully read restart password file with {len(_restart_passwords)} user(s)')
                except json.JSONDecodeError:
                    # Old format: single hash value, treat as admin user
                    logger.info('Detected old format password file, treating as admin user')
                    _restart_passwords = {'admin': content}
                    # Optionally migrate the file (but don't do it automatically to avoid breaking things)

                return _restart_passwords.get(username, '')
        else:
            logger.warning(f'Password file does not exist: {key_file_path}')
            return ''
    except Exception as e:
        logger.error(f'Failed to read password file: {e!r}')
        _restart_passwords = {}
        return ''


def verify_password(password: str, password_hash: str) -> bool:
    """Verify if password matches hash value

    Args:
        password: Plain text password entered by user
        password_hash: Stored password hash value (bcrypt format)

    Returns:
        bool: Returns True if password matches, otherwise False
    """
    if not HAS_BCRYPT:
        logger.error('bcrypt library not installed, cannot verify password. Please run: pip install bcrypt')
        return False

    try:
        # bcrypt automatically handles salt in hash value
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception as e:
        logger.error(f'Password verification process error: {e!r}')
        return False


async def get_compose_cmd() -> list[str]:
    """Get docker compose command format supported by the system

    Detection order:
    1. First try 'docker compose' (Docker Compose V2, as a docker subcommand)
    2. If failed, try 'docker-compose' (Docker Compose V1, standalone command)

    Returns:
        list[str]: Compose command format, e.g. ['docker', 'compose'] or ['docker-compose']
    """
    global _compose_cmd

    # If already detected, return directly
    if _compose_cmd is not None:
        return _compose_cmd

    # First try 'docker compose' (V2)
    logger.info('Detecting docker compose command format, trying docker compose (V2)...')
    result = await putil.a_run_cmd_monitored(
        ['docker', 'compose', 'version'],
        print_cmd=False,
        print_output=False,
        print_return=False
    )

    if result.exit_code == 0:
        _compose_cmd = ['docker', 'compose']
        logger.info('Detected docker compose (V2) is available')
        return _compose_cmd

    # If failed, try 'docker-compose' (V1)
    logger.info('docker compose (V2) not available, trying docker-compose (V1)...')
    result = await putil.a_run_cmd_monitored(
        ['docker-compose', 'version'],
        print_cmd=False,
        print_output=False,
        print_return=False
    )

    if result.exit_code == 0:
        _compose_cmd = ['docker-compose']
        logger.info('Detected docker-compose (V1) is available')
        return _compose_cmd

    # If both are unavailable, default to 'docker compose' and log warning
    logger.warning('Unable to detect available docker compose command, defaulting to docker compose')
    _compose_cmd = ['docker', 'compose']
    return _compose_cmd


@router.get("/health")
async def health() -> Response:
    """Health check."""
    return Response(status_code=200)

@router.get("/version", summary='Get version information', description='Get version information')
async def handle_version(request: Request):
    import version

    return {
        'git_data': version.GitDate,
        'git_hash': version.GitCommit,
    }

@router.get("/status", summary='Get server status', description='Get server status information')
async def handle_status(request: Request):
    import serverinfo # serverinfo.py is dynamically generated by docker_monitor_server.py when the server starts

    status = {
        'start_time': serverinfo.StartTime,
        'pid': os.getpid(),
    }
    return status


@router.get("/api/containers", response_model=models.ResponseModel,
            summary='Get container information list',
            description='Get detailed information of all running containers')
async def get_containers(request: Request):
    """Get container information list API"""
    global _gpu_container_ids_cache, _gpu_container_ids_cache_time

    logger.info('client={request.client.host}:{request.client.port}')
    containers = await dutil.a_get_container_list()
    logger.info(f'containers={json.dumps(containers, ensure_ascii=False)}')

    # Extract container IDs that use GPU (for optimization)
    gpu_container_ids = []
    for container in containers:
        gpu_ids = container.get('GpuDevices', None)
        if gpu_ids:
            gpu_container_ids.append(container.get('Id', ''))

    # Update cache
    _gpu_container_ids_cache = gpu_container_ids
    _gpu_container_ids_cache_time = time.perf_counter()
    logger.debug(f'cached {len(gpu_container_ids)} GPU container IDs for optimization')

    ret = {
        'code': 0,
        'message': 'success',
        'data': containers
    }
    logger.info(f'ret={json.dumps(ret, ensure_ascii=False)}')
    return ret


@router.get("/api/gpu/usage", response_model=models.ResponseModel,
            summary='Get GPU usage information (associated with containers)',
            description='Get GPU usage information and associate with container IDs')
async def get_gpu_usage():
    """Get GPU usage information and associate with container IDs"""
    global _gpu_container_ids_cache, _gpu_container_ids_cache_time

    logger.info('client={request.client.host}:{request.client.port}')

    # Check if cache is valid (within 2 seconds)
    use_gpu_container_ids = None
    current_time = time.perf_counter()
    if (_gpu_container_ids_cache is not None and
        (current_time - _gpu_container_ids_cache_time) <= GPU_CONTAINER_IDS_CACHE_TTL):
        use_gpu_container_ids = _gpu_container_ids_cache
        logger.debug(f'using cached GPU container IDs ({len(use_gpu_container_ids)} containers) for optimization')
    else:
        logger.debug('GPU container IDs cache expired or not available, querying all containers')

    gpu_usage = await dutil.a_get_gpu_usage_by_containers(use_gpu_container_ids=use_gpu_container_ids)
    ret = {
        'code': 0,
        'message': 'success',
        'data': gpu_usage
    }
    logger.info(f'ret={json.dumps(ret, ensure_ascii=False)}')
    return ret


@router.get("/api/containers/stats", response_model=models.ResponseModel,
            summary='Get container stats (CPU, memory usage)',
            description='Get real-time container stats including CPU and memory usage')
async def get_container_stats():
    """Get container stats including CPU and memory usage"""
    logger.info('client={request.client.host}:{request.client.port}')

    # Get all running container IDs (we can optimize later if needed)
    container_ids = await dutil.a_get_running_container_ids()
    if not container_ids:
        return {
            'code': 0,
            'message': 'success',
            'data': {}
        }

    # Get container stats
    stats = await dutil.a_get_container_stats(container_ids)
    ret = {
        'code': 0,
        'message': 'success',
        'data': stats
    }
    logger.info(f'ret={json.dumps(ret, ensure_ascii=False)}')
    return ret


@router.post("/api/request", response_model=models.ResponseModel,
             summary='Generic HTTP request API',
             description='''Make arbitrary HTTP requests through backend,
support GET, POST and other methods, support custom headers and payload''')
async def make_http_request(request: Request, req_data: models.HttpRequestModel = Body(...)):
    """Generic HTTP request API, allows frontend to make HTTP requests through backend

    Security restrictions (controlled by HTTP_REQUEST_BLOCK_LOCAL_IP variable):
    - Local/private IP address access control (127.0.0.1, localhost, 10.x.x.x, 172.16-31.x.x, 192.168.x.x)
      - Default allows local IP access (HTTP_REQUEST_BLOCK_LOCAL_IP=False)
      - Set to True to block local/private addresses
    - Request timeout limit: 30 seconds
    - All requests are logged

    Args:
        request: FastAPI Request object
        req_data: HTTP request parameters, including method, url, headers, payload

    Returns:
        Dictionary containing status code, response content, and response headers
    """
    import ipaddress
    from urllib.parse import urlparse

    try:
        method = req_data.method.upper()
        url = req_data.url.strip()
        headers = req_data.headers or {}
        payload = req_data.payload

        # Log request information
        client_ip = request.client.host if request.client else 'unknown'
        logger.info(f'HTTP request from {client_ip}: method={method}, url={url}')

        # Validate HTTP method
        allowed_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        if method not in allowed_methods:
            return {
                'code': 1,
                'message': f'Unsupported HTTP method: {method}, supported methods: {", ".join(allowed_methods)}',
                'data': None
            }

        # Parse URL
        try:
            parsed_url = urlparse(url)
        except Exception as e:
            return {
                'code': 2,
                'message': f'Invalid URL format: {str(e)}',
                'data': None
            }

        # Security validation: check hostname
        hostname = parsed_url.hostname
        if not hostname:
            return {
                'code': 3,
                'message': 'URL missing hostname',
                'data': None
            }

        # Security validation: block local/private addresses if configured
        if HTTP_REQUEST_BLOCK_LOCAL_IP:
            # Check if it's a local/private address or localhost
            is_local = False
            try:
                # Try to parse as IP address
                ip = ipaddress.ip_address(hostname)
                # Check if it's a private IP or loopback address
                if ip.is_private or ip.is_loopback:
                    is_local = True
            except ValueError:
                # Not an IP address, check if it's a localhost-related domain name
                localhost_names = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
                if hostname.lower() in localhost_names:
                    is_local = True
                # Check if it's an internal domain (.local, .internal, etc.)
                elif any(hostname.lower().endswith(suffix) for suffix in ['.local', '.internal', '.lan']):
                    is_local = True

            if is_local:
                logger.warning(f'Blocked request to local/private address: {url} from {client_ip}')
                return {
                    'code': 4,
                    'message': 'Access to local/private addresses or localhost is blocked for security reasons',
                    'data': None
                }

        # Validate protocol (only allow HTTP and HTTPS)
        if parsed_url.scheme not in ['http', 'https']:
            return {
                'code': 5,
                'message': f'Unsupported protocol: {parsed_url.scheme}, only http and https are supported',
                'data': None
            }

        # Prepare request parameters
        request_kwargs = {
            'timeout': 30.0,  # 30 second timeout
            'follow_redirects': True,  # Follow redirects
        }

        # Set request headers
        if headers:
            request_kwargs['headers'] = headers

        # Set request body
        if payload is not None:
            if method in ['GET', 'HEAD', 'OPTIONS']:
                logger.warning(f'Method {method} should not have payload, ignoring it')
            else:
                # If payload is dict or list, convert to JSON
                if isinstance(payload, (dict, list)):
                    import json as json_module
                    request_kwargs['json'] = payload
                    # Ensure Content-Type is application/json
                    if 'Content-Type' not in request_kwargs.get('headers', {}):
                        if 'headers' not in request_kwargs:
                            request_kwargs['headers'] = {}
                        request_kwargs['headers']['Content-Type'] = 'application/json'
                else:
                    # String type payload
                    request_kwargs['content'] = str(payload)

        # Make HTTP request
        try:
            async with httpx.AsyncClient() as client:
                # Call corresponding method function
                http_method = getattr(client, method.lower())
                response = await http_method(url, **request_kwargs)

                # Get response content
                try:
                    # Try to get text content
                    response_text = response.text
                except Exception:
                    # If text cannot be retrieved, use byte content
                    response_text = response.content.decode('utf-8', errors='replace')

                # Get actual request headers (including auto-added headers like content-length)
                request_headers = dict(response.request.headers) if hasattr(response, 'request') and response.request else dict(request_kwargs.get('headers', {}))

                # Build response data
                result = {
                    'code': 0,
                    'message': 'success',
                    'data': {
                        'url': url,
                        'status_code': response.status_code,
                        'response': response_text,
                        'request_headers': request_headers,
                        'response_headers': dict(response.headers),
                        'method': method
                    }
                }

                logger.info(f'HTTP request completed: {method} {url} -> {response.status_code}')
                return result

        except httpx.TimeoutException:
            logger.warning(f'HTTP request timeout: {method} {url}')
            return {
                'code': 6,
                'message': 'Request timeout (exceeded 30 seconds)',
                'data': {'url': url, 'method': method}
            }
        except httpx.ConnectError as e:
            logger.warning(f'HTTP connection error: {method} {url} - {str(e)}')
            return {
                'code': 7,
                'message': f'Connection failed: {str(e)}',
                'data': {'url': url, 'method': method}
            }
        except httpx.HTTPError as e:
            logger.warning(f'HTTP error: {method} {url} - {str(e)}')
            return {
                'code': 8,
                'message': f'HTTP request error: {str(e)}',
                'data': {'url': url, 'method': method}
            }
        except Exception as e:
            logger.error(f'Unexpected error in HTTP request: {method} {url} - {e!r}')
            return {
                'code': 9,
                'message': f'Request failed: {str(e)}',
                'data': {'url': url, 'method': method}
            }

    except Exception as e:
        logger.error(f'HTTP request API error: {e!r}')
        raise HTTPException(status_code=500, detail=f'HTTP request API error: {str(e)}')


@router.get("/api/containers/{container_id}/healthcheck", response_model=models.ResponseModel,
            summary='Healthcheck test API',
            description='Test container Healthcheck URL')
async def test_healthcheck(container_id: str):
    """Healthcheck test API, input docker id, get Healthcheck URL and access it to return response"""
    try:
        # Get Healthcheck URL
        healthcheck_url = await dutil.a_get_container_healthcheck_url(container_id)
        if not healthcheck_url:
            return {
                'code': 1,
                'message': 'Container does not have Healthcheck configured or unable to extract URL',
                'data': None
            }

        # Access URL
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(healthcheck_url)
                return {
                    'code': 0,
                    'message': 'success',
                    'data': {
                        'url': healthcheck_url,
                        'status_code': response.status_code,
                        'response': response.text,
                        'headers': dict(response.headers)
                    }
                }
        except httpx.TimeoutException:
            return {
                'code': 2,
                'message': 'Healthcheck URL request timeout',
                'data': {'url': healthcheck_url}
            }
        except Exception as e:
            return {
                'code': 3,
                'message': f'Failed to access Healthcheck URL: {str(e)}',
                'data': {'url': healthcheck_url}
            }
    except Exception as e:
        logger.error(f'healthcheck test failed: {e!r}')
        raise HTTPException(status_code=500, detail=f'Healthcheck test failed: {str(e)}')


@router.post("/api/containers/{container_id}/restart", response_model=models.ResponseModel,
             summary='Restart docker container',
             description='Restart specified container (via docker compose)')
async def restart_container(request: Request, container_id: str,
                            username: str = Body('admin', embed=True),
                            password: str = Body(..., embed=True)):
    """Restart docker API, input docker id, get compose file path, execute docker compose down and up

    Args:
        request: FastAPI request object
        container_id: Container ID
        password: Restart password (obtained from request body)
        username: Username for authentication (default: 'admin', obtained from request body)
    """
    logger.info(f'client={request.client.host}:{request.client.port}, container_id={container_id}, username={username}')

    # Verify password (using bcrypt hash comparison)
    if not HAS_BCRYPT:
        logger.error('bcrypt library not installed, cannot verify password')
        return {
            'code': 500,
            'message': 'Server configuration error: bcrypt library not installed, please run: pip install bcrypt',
            'data': None
        }

    password_hash = get_restart_password_hash(username)
    if not password_hash:
        logger.error(f'Password file not configured for user "{username}", rejecting restart request')
        return {
            'code': 401,
            'message': f'Password verification failed: user "{username}" not found or password not configured',
            'data': None
        }

    if not verify_password(password, password_hash):
        logger.warning(f'Password verification failed for user "{username}", client IP: {request.client.host}')
        return {
            'code': 401,
            'message': 'Password verification failed',
            'data': None
        }

    logger.info('Password verified, starting container restart')

    try:
        # Get compose file path
        compose_file = await dutil.a_get_container_compose_file(container_id)
        if not compose_file:
            return {
                'code': 1,
                'message': 'Container does not have an associated compose file',
                'data': None
            }

        # Check if compose file exists
        if not os.path.exists(compose_file):
            return {
                'code': 1,
                'message': f'Compose file does not exist: {compose_file}',
                'data': {'compose_file': compose_file}
            }

        # Get compose file directory
        compose_dir = os.path.dirname(compose_file)
        compose_filename = os.path.basename(compose_file)

        # Get compose command format supported by system
        compose_cmd = await get_compose_cmd()

        # Build compose commands (V1 and V2 formats are the same)
        down_cmd = compose_cmd + ['-f', compose_file, 'down']
        up_cmd = compose_cmd + ['-f', compose_file, 'up', '-d']

        # Execute docker compose down
        compose_cmd_str = ' '.join(compose_cmd)
        logger.info(f'executing {compose_cmd_str} down, directory: {compose_dir}, file: {compose_filename}')
        result_down = await putil.a_run_cmd_monitored(
            down_cmd,
            cwd=compose_dir,
            print_cmd=True,
            print_output=True,
            print_return=True
        )

        if result_down.exit_code != 0:
            return {
                'code': 2,
                'message': f'{compose_cmd_str} down execution failed, exit code: {result_down.exit_code}',
                'data': {
                    'compose_file': compose_file,
                    'stdout': result_down.stdout,
                    'stderr': result_down.stderr
                }
            }

        # Execute docker compose up -d
        logger.info(f'executing {compose_cmd_str} up -d, directory: {compose_dir}, file: {compose_filename}')
        result_up = await putil.a_run_cmd_monitored(
            up_cmd,
            cwd=compose_dir,
            print_cmd=True,
            print_output=True,
            print_return=True
        )

        if result_up.exit_code != 0:
            return {
                'code': 3,
                'message': f'{compose_cmd_str} up -d execution failed, exit code: {result_up.exit_code}',
                'data': {
                    'compose_file': compose_file,
                    'stdout': result_up.stdout,
                    'stderr': result_up.stderr
                }
            }

        return {
            'code': 0,
            'message': 'success',
            'data': {
                'compose_file': compose_file,
                'down_stdout': result_down.stdout,
                'up_stdout': result_up.stdout
            }
        }
    except Exception as e:
        logger.error(f'failed to restart container: {e!r}')
        raise HTTPException(status_code=500, detail=f'Failed to restart container: {str(e)}')


@router.post("/api/containers/{container_id}/restart/stream", summary='Restart docker container (SSE stream)',
             description='''Restart specified container (via docker compose),
use SSE to return execution steps and command output in real-time''')
async def restart_container_stream(request: Request, container_id: str,
                                   username: str = Body('admin', embed=True),
                                   password: str = Body(..., embed=True)):
    """SSE stream version of restart docker API, returns execution steps and command output in real-time

    Args:
        request: FastAPI request object
        container_id: Container ID
        password: Restart password (obtained from request body)
        username: Username for authentication (default: 'admin', obtained from request body)
    """
    logger.info(f'client={request.client.host}:{request.client.port}, container_id={container_id}, username={username}')

    async def generate_restart_stream():
        try:
            # Verify password (using bcrypt hash comparison)
            if not HAS_BCRYPT:
                yield f"data: {json.dumps({'type': 'error', 'data': 'Server configuration error: bcrypt library not installed, please run: pip install bcrypt'}, ensure_ascii=False)}\n\n"
                return

            password_hash = get_restart_password_hash(username)
            if not password_hash:
                yield f"data: {json.dumps({'type': 'error', 'data': f'Password verification failed: user \"{username}\" not found or password not configured'}, ensure_ascii=False)}\n\n"
                return

            if not verify_password(password, password_hash):
                logger.warning(f'Password verification failed for user "{username}", client IP: {request.client.host}')
                yield f"data: {json.dumps({'type': 'error', 'data': 'Password verification failed'}, ensure_ascii=False)}\n\n"
                return

            yield f"data: {json.dumps({'type': 'step', 'step': 'password_verified', 'message': 'Password verified'}, ensure_ascii=False)}\n\n"

            # Get compose file path
            yield f"data: {json.dumps({'type': 'step', 'step': 'checking_compose', 'message': 'Checking Compose file...'}, ensure_ascii=False)}\n\n"
            compose_file = await dutil.a_get_container_compose_file(container_id)
            if not compose_file:
                yield f"data: {json.dumps({'type': 'error', 'data': 'Container does not have an associated compose file'}, ensure_ascii=False)}\n\n"
                return

            # Check if compose file exists
            if not os.path.exists(compose_file):
                yield f"data: {json.dumps({'type': 'error', 'data': f'Compose file does not exist: {compose_file}'}, ensure_ascii=False)}\n\n"
                return

            yield f"data: {json.dumps({'type': 'step', 'step': 'compose_found', 'message': f'Found Compose file: {compose_file}'}, ensure_ascii=False)}\n\n"

            # Get compose file directory
            compose_dir = os.path.dirname(compose_file)
            compose_filename = os.path.basename(compose_file)

            # Get compose command format supported by system
            compose_cmd = await get_compose_cmd()
            compose_cmd_str = ' '.join(compose_cmd)

            # Build compose commands (V1 and V2 formats are the same)
            down_cmd = compose_cmd + ['-f', compose_file, 'down']
            up_cmd = compose_cmd + ['-f', compose_file, 'up', '-d']

            # Execute docker compose down
            yield f"data: {json.dumps({'type': 'step', 'step': 'down_start', 'message': f'Starting execution: {compose_cmd_str} down', 'command': ' '.join(down_cmd)}, ensure_ascii=False)}\n\n"
            logger.info(f'executing {compose_cmd_str} down, directory: {compose_dir}, file: {compose_filename}')

            down_exit_code = None
            down_stdout = []
            down_stderr = []

            async for output_type, value in putil.a_run_cmd_iter(
                down_cmd,
                cwd=compose_dir,
                print_cmd=False,
                print_return=False,
                timeout_interval=1
            ):
                if output_type == 'stdout':
                    down_stdout.append(value)
                    yield f"data: {json.dumps({'type': 'output', 'step': 'down', 'stream': 'stdout', 'data': value}, ensure_ascii=False)}\n\n"
                elif output_type == 'stderr':
                    down_stderr.append(value)
                    yield f"data: {json.dumps({'type': 'output', 'step': 'down', 'stream': 'stderr', 'data': value}, ensure_ascii=False)}\n\n"
                elif output_type == 'return':
                    down_exit_code = value
                    break
                elif output_type == 'exception':
                    yield f"data: {json.dumps({'type': 'error', 'data': f'Exception occurred while executing command: {value!r}'}, ensure_ascii=False)}\n\n"
                    return

            if down_exit_code != 0:
                yield f"data: {json.dumps({'type': 'error', 'data': f'{compose_cmd_str} down execution failed, exit code: {down_exit_code}', 'exit_code': down_exit_code, 'stdout': ''.join(down_stdout), 'stderr': ''.join(down_stderr)}, ensure_ascii=False)}\n\n"
                return

            yield f"data: {json.dumps({'type': 'step', 'step': 'down_completed', 'message': f'{compose_cmd_str} down completed successfully', 'exit_code': down_exit_code}, ensure_ascii=False)}\n\n"

            # Execute docker compose up -d
            yield f"data: {json.dumps({'type': 'step', 'step': 'up_start', 'message': f'Starting execution: {compose_cmd_str} up -d', 'command': ' '.join(up_cmd)}, ensure_ascii=False)}\n\n"
            logger.info(f'executing {compose_cmd_str} up -d, directory: {compose_dir}, file: {compose_filename}')

            up_exit_code = None
            up_stdout = []
            up_stderr = []

            async for output_type, value in putil.a_run_cmd_iter(
                up_cmd,
                cwd=compose_dir,
                print_cmd=False,
                print_return=False,
                timeout_interval=1
            ):
                if output_type == 'stdout':
                    up_stdout.append(value)
                    yield f"data: {json.dumps({'type': 'output', 'step': 'up', 'stream': 'stdout', 'data': value}, ensure_ascii=False)}\n\n"
                elif output_type == 'stderr':
                    up_stderr.append(value)
                    yield f"data: {json.dumps({'type': 'output', 'step': 'up', 'stream': 'stderr', 'data': value}, ensure_ascii=False)}\n\n"
                elif output_type == 'return':
                    up_exit_code = value
                    break
                elif output_type == 'exception':
                    yield f"data: {json.dumps({'type': 'error', 'data': f'Exception occurred while executing command: {value!r}'}, ensure_ascii=False)}\n\n"
                    return

            if up_exit_code != 0:
                yield f"data: {json.dumps({'type': 'error', 'data': f'{compose_cmd_str} up -d execution failed, exit code: {up_exit_code}', 'exit_code': up_exit_code, 'stdout': ''.join(up_stdout), 'stderr': ''.join(up_stderr)}, ensure_ascii=False)}\n\n"
                return

            yield f"data: {json.dumps({'type': 'step', 'step': 'up_completed', 'message': f'{compose_cmd_str} up -d completed successfully', 'exit_code': up_exit_code}, ensure_ascii=False)}\n\n"

            # Return success result
            yield f"data: {json.dumps({'type': 'success', 'data': {'compose_file': compose_file, 'down_exit_code': down_exit_code, 'up_exit_code': up_exit_code, 'down_stdout': ''.join(down_stdout), 'up_stdout': ''.join(up_stdout)}}, ensure_ascii=False)}\n\n"

        except Exception as e:
            logger.error(f'failed to restart container: {e!r}')
            yield f"data: {json.dumps({'type': 'error', 'data': f'Failed to restart container: {str(e)}'}, ensure_ascii=False)}\n\n"

    return StreamingResponse(
        generate_restart_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@router.get("/api/containers/{container_id}/logs", summary='View container logs in real-time',
            description='Use SSE to return container logs in real-time')
async def stream_container_logs(container_id: str, lines: int = 50, remove_color: bool = True):
    """Real-time display of docker logs -f xxxx functionality, use SSE to return log output in real-time

    Args:
        container_id: Container ID or container name (supports using name, ID changes after restart but name remains the same)
        lines: Number of initial lines to display, default 50 lines. Set to 0 to indicate unlimited (display all historical logs)
    """
    async def generate_logs():
        try:
            # Build docker logs command
            # If lines > 0, use -n parameter to limit initial lines; if lines = 0, no limit (display all historical logs)
            # Use container name instead of ID, because ID changes after restart but name remains the same
            cmd = ['docker', 'logs']
            if lines > 0:
                cmd.extend(['-n', str(lines)])
            cmd.extend(['-f', container_id])

            logger.debug(f'getting logs for container {container_id[:12] if len(container_id) > 12 else container_id}, initial lines: {lines if lines > 0 else "all"}')

            # Use a_run_cmd_iter to get logs in real-time
            async for output_type, value in putil.a_run_cmd_iter(
                cmd,
                print_cmd=False,
                print_return=False,
                timeout_interval=1
            ):
                if output_type == 'stdout':
                    # Send SSE format data (normal log output)
                    if remove_color:
                        value = remove_color_of_shell_text(value)
                    yield f"data: {json.dumps({'type': 'log', 'data': value}, ensure_ascii=False)}\n\n"
                elif output_type == 'stderr':
                    # stderr is also treated as normal log, because many applications (such as Python logging) output logs to stderr
                    # Real errors should be Docker command execution failures, not log output inside the container
                    if remove_color:
                        value = remove_color_of_shell_text(value)
                    yield f"data: {json.dumps({'type': 'log', 'data': value}, ensure_ascii=False)}\n\n"
                elif output_type == 'return':
                    yield f"data: {json.dumps({'type': 'end', 'exit_code': value}, ensure_ascii=False)}\n\n"
                    break
                elif output_type == 'exception':
                    # This is a real error (Docker command execution failed)
                    yield f"data: {json.dumps({'type': 'error', 'data': f'Exception: {value!r}'}, ensure_ascii=False)}\n\n"
                    break
        except Exception as e:
            logger.error(f'failed to get container logs: {e!r}')
            yield f"data: {json.dumps({'type': 'error', 'data': f'Failed to get container logs: {str(e)}'}, ensure_ascii=False)}\n\n"

    return StreamingResponse(
        generate_logs(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
