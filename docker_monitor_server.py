import os
import sys
from datetime import datetime

import sys_util as sutil
import fastapi_util as futil
from log_util import logger, config_logger, log, Fore


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--install', default=False, action='store_true', help='install as service[False]')
    parser.add_argument('-p', '--process', default=False, action='store_true', help='show self process[False]')
    parser.add_argument('-n', '--nostdout', default=False, action='store_true', help='no log to stdout[False]')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='host[0.0.0.0]')
    parser.add_argument('--port', type=int, default=9949, help='port[9949]')
    parser.add_argument('--log-level', type=str, default='info', help='log level[info]')

    args = parser.parse_args()

    os.chdir(sutil.ExeDir)

    if args.install:
        if sys.platform == 'linux':
            service_log_path = os.path.join(sutil.ExeDir, 'logs', 'stdout-docker-monitor.log')
            sutil.install_service('docker-monitor', 'Docker Monitor Service', service_log_path,
                args=f'--host {args.host} --port {args.port} --nostdout')
        else:
            print('install as service only support linux')
        sys.exit(0)
    elif args.process:
        sutil.list_self_process()
        sys.exit(0)


    import uvicorn
    from app import app

    log_dir = './logs'
    log_to_stdout = not args.nostdout
    config_logger(logger, log_level=args.log_level, log_dir=log_dir, log_file='docker-monitor.log',
                  backup_count=14, log_to_stdout=log_to_stdout)
    if not log_to_stdout:
        log(f'pid {os.getpid()} command: {sutil.PythonExePath} {sys.argv} \nstarts server, config=\n{Fore.Cyan}{args}{Fore.Reset}')
    logger.info(f'pid {os.getpid()} command: {sutil.PythonExePath} {sys.argv} \nstarts server, config=\n{args}')
    with open('serverinfo.py', 'wt', encoding='utf-8') as fout:
        fout.write(f'StartTime = "{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}"\n')
    futil.setup_log_router(app, log_dir)
    futil.setup_file_server_router(app, '/dm', './static')

    uvicorn.run(app, host=args.host, port=args.port,
                log_config=futil.get_uvicorn_logging_config())
