#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
from datetime import datetime

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

from log_util import logger


def get_uvicorn_logging_config() -> dict:
    """Get uvicorn logging config with custom format.

    Returns:
        dict: uvicorn LOGGING_CONFIG dict, or None if uvicorn not installed.

    Usage::
        config = get_uvicorn_logging_config()
        uvicorn.run(app, log_config=config)
    """
    try:
        from uvicorn.config import LOGGING_CONFIG
        LOGGING_CONFIG["formatters"]["default"]["fmt"] = (
            '%(asctime)s.%(msecs)03d %(levelprefix)s %(message)s')
        LOGGING_CONFIG["formatters"]["access"]["fmt"] = (
            '%(asctime)s.%(msecs)03d %(levelprefix)s '
            '%(client_addr)s - "%(request_line)s" %(status_code)s')
        LOGGING_CONFIG["formatters"]["default"]["datefmt"] = (
            '%Y-%m-%d %H:%M:%S')
        LOGGING_CONFIG["formatters"]["access"]["datefmt"] = (
            '%Y-%m-%d %H:%M:%S')
        return LOGGING_CONFIG
    except ImportError:
        return None


def file_size_to_str(size_in_bytes: int) -> str:
    if size_in_bytes >= 1073741824:  # 1024**3
        return f'{size_in_bytes / 1073741824:.3f} GB'
    elif size_in_bytes >= 1048576:  # 1024**2
        return f'{size_in_bytes / 1048576:.3f} MB'
    elif size_in_bytes >= 1024:
        return f'{size_in_bytes / 1024:.3f} KB'
    elif size_in_bytes > 1:
        return f'{size_in_bytes} Bytes'
    else:
        return f'{size_in_bytes} Byte'


def get_route_sub_path(local_abs_dir: str, sub_path: str) -> str:
    """Resolve and validate a sub path within an absolute directory.

    Prevents path traversal attacks by ensuring the resolved path
    stays within the allowed directory.

    Args:
        local_abs_dir: Absolute path of the allowed directory.
        sub_path: Relative sub path to resolve.

    Returns:
        str: Resolved absolute path.

    Raises:
        HTTPException 400: If the resolved path escapes local_abs_dir.
    """
    norm_sub_path = os.path.normpath(os.path.join(local_abs_dir, sub_path))
    if not norm_sub_path.startswith(local_abs_dir):
        raise HTTPException(
            status_code=400,
            detail=f'Invalid path: `{sub_path}` is not allowed',
        )
    return norm_sub_path


def setup_log_router(app: FastAPI, log_dir: str, include_in_schema: bool = False):
    log_dir = os.path.abspath(log_dir)

    @app.get('/logs/{sub_path:path}', include_in_schema=include_in_schema,
             summary='list logs files in web page',
             description='''Generate logs page, support to download log files.''')
    async def get_logs(req: Request, sub_path: str = '', sort: str = None, reverse: int = None, output: str =''):
        logger.info(f'client={req.client.host}:{req.client.port}, url.path={req.url.path}, sub_path={sub_path}')
        return serve_directory_for_download('/logs', log_dir, sub_path,
                                            show_create_directory=False,
                                            show_upload=False,
                                            sort=sort, reverse=reverse, output=output)


def setup_file_server_router(app: FastAPI, mount_path: str, local_dir: str,
                             allow_create_directory: bool = False,
                             allow_upload: bool = False,
                             include_in_schema: bool = False):
    '''Register file server routes for a mount path.

    Serves files from local_dir under the given URL mount_path.
    When mount_path is '/', files are served at the root.

    Args:
        app: FastAPI application instance.
        mount_path: URL path starting with '/' (e.g. '/files' or '/').
        local_dir: Local directory to serve.
        allow_create_directory: Enable directory creation via POST.
        allow_upload: Enable file upload via POST.
        include_in_schema: Show routes in OpenAPI schema.

    Example:
        setup_file_server_router(app, '/files', './local_path')
    '''
    local_dir = os.path.abspath(local_dir)
    logger.info(f'mount_path={mount_path}, local_dir={local_dir}'
                f', allow_create_directory={allow_create_directory}, allow_upload={allow_upload}')
    if mount_path == '/':
        # When mount_path is '/', route_prefix must be '' to avoid '//' in route patterns.
        route_prefix = ''
    else:
        mount_path = mount_path.rstrip('/')
        route_prefix = mount_path

    @app.get(f'{route_prefix}/{{sub_path:path}}', include_in_schema=include_in_schema,
             summary=f'list files of `{mount_path}` in web page',
             description='''Generate files page, support to create directory, upload or download files.''')
    async def get_files(req: Request, sub_path: str = '', sort: str = None, reverse: int = None, output: str =''):
        logger.info(f'client={req.client.host}:{req.client.port}, url.path={req.url.path}'
                    f', mount_path={mount_path}, sub_path={sub_path}')
        return serve_directory_for_download(mount_path, local_dir, sub_path,
                                            show_create_directory=allow_create_directory,
                                            show_upload=allow_upload,
                                            sort=sort,
                                            reverse=reverse,
                                            output=output)

    if allow_create_directory:
        @app.post(f'/create/dir{route_prefix}', include_in_schema=include_in_schema,
                  summary=f'create sub directory in `{mount_path}`',
                  description=f'''Create a directory in {mount_path}.''')
        async def create_dir(req: Request, new_dir: str = Form(..., examples=["dir1", "dir2/dir3"])):
            logger.info(f'client={req.client.host}:{req.client.port}, url.path={req.url.path}'
                        f', mount_path={mount_path}, new_dir={new_dir}')
            if not new_dir:
                raise HTTPException(status_code=400, detail="New directory name is required")
            sub_dir = get_route_sub_path(local_dir, new_dir)
            if not os.path.exists(sub_dir):
                os.makedirs(sub_dir)
                return RedirectResponse(url=f'{route_prefix}/{new_dir}', status_code=302)
            else:
                raise HTTPException(status_code=400, detail="Directory already exists")

    if allow_upload:
        @app.post(f'{route_prefix}/{{sub_path:path}}', include_in_schema=include_in_schema,
                  summary=f'upload files to `{mount_path}`',
                  description=f'''Upload a file to `{mount_path}` and refresh the files page.''')
        async def upload_file(req: Request, sub_path: str = '',
                              file: UploadFile = File(...)) -> str:
            logger.info(f'client={req.client.host}:{req.client.port}, url.path={req.url.path}'
                        f', mount_path={mount_path}, sub_path={sub_path}'
                        f', content-length={req.headers.get("content-length")}')
            sub_dir =get_route_sub_path(local_dir, sub_path)
            if not os.path.exists(sub_dir):
                raise HTTPException(status_code=404, detail="Path not found")
            data = await file.read()
            file_path = os.path.join(sub_dir, file.filename)
            with open(file_path, 'wb') as fout:
                fout.write(data)
            return RedirectResponse(url=f'{route_prefix}/{sub_path}?sort=time&reverse=1', status_code=302)


def _fmt_time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def serve_directory_for_download(mount_path: str,
                                 local_dir:str,
                                 sub_path: str = '',
                                 show_create_directory: bool = False,
                                 show_upload: bool = False,
                                 sort: str = None,
                                 reverse: int = None,
                                 output: str = 'html'):
    """Serve directory contents as HTML page or JSON for file browsing and download

    Generates a web page or JSON response listing files and directories.
    Supports file download, directory creation and file upload (if enabled).

    Args:
        mount_path: URL mount path, must start with '/' (e.g. '/' or '/files')
        local_dir: Local directory path to serve
        sub_path: Subdirectory path within local_dir, such as '', 'subdir', or 'subdir/subsubdir'
        show_create_directory: If True, show directory creation UI
        show_upload: If True, show file upload UI
        sort: Sort field ('name', 'size', 'time') or None
        reverse: If 1, reverse sort order
        output: Output format ('html' or 'json')

    Returns:
        HTMLResponse or JSONResponse with directory listing
    """
    sub_path = sub_path.strip('/')  # Normalize sub_path to avoid trailing slashes
    # mount_path starts with '/' and does not end with '/' except when it equals '/'
    # when mount_path is '/', sub_path is empty ""
    dir_or_file_path = get_route_sub_path(local_dir, sub_path)
    if not os.path.exists(dir_or_file_path):
        raise HTTPException(status_code=404, detail="Path not found")

    if os.path.isfile(dir_or_file_path):
        return FileResponse(dir_or_file_path)

    dirs: list[tuple[os.DirEntry, os.stat_result]] = []
    files: list[tuple[os.DirEntry, os.stat_result]] = []
    with os.scandir(dir_or_file_path) as it:
        for entry in it:
            try:
                if entry.is_file():
                    files.append((entry, entry.stat()))
                else:
                    dirs.append((entry, entry.stat()))
            except Exception as ex:
                logger.error(f'entry={entry} maybe a broken link, error={ex!r}')
    reverse = bool(reverse)
    if not sort or sort == 'name':
        dirs.sort(key=lambda x: x[0].name, reverse=reverse)
        files.sort(key=lambda x: x[0].name, reverse=reverse)
    elif sort == 'size':
        dirs.sort(key=lambda x: x[1].st_size, reverse=reverse)
        files.sort(key=lambda x: x[1].st_size, reverse=reverse)
    elif sort == 'time':
        dirs.sort(key=lambda x: x[1].st_mtime, reverse=reverse)
        files.sort(key=lambda x: x[1].st_mtime, reverse=reverse)

    if output == 'json':
        result = { 'dirs': [entry.name for entry, _ in dirs],
                   'files': [{
                       "name": entry.name,
                       "size": stat.st_size,
                       "modify_time": _fmt_time(stat.st_mtime),
                       } for entry, stat in files] }
        return result

    if sub_path:
        parts = sub_path.split('/')
        parent_path = mount_path
        parents: list[str] = []
        parents.append(f'<a href="{mount_path}">{mount_path}{"" if mount_path == "/" else "/"}</a>')
        for part in parts[:-1]:
            if parent_path[-1] == '/':
                parents.append(f'<a href="{parent_path}{part}">{part}/</a>')
                parent_path = f'{parent_path}{part}'
            else:
                parents.append(f'<a href="{parent_path}/{part}">{part}/</a>')
                parent_path = f'{parent_path}/{part}'
        ancestor_link_block = '<p>Go to ' + ' '.join(parents) + '</p>'
    else:
        ancestor_link_block = ''

    current_path = f'{"" if mount_path == "/" else mount_path}/{sub_path}'
    current_path_ends_with_slash = current_path if current_path.endswith('/') else current_path + '/'
    json_url = f'{current_path}?output=json'
    forms = []
    forms_table = ''

    # show create directory form
    if show_create_directory:
        create_directory_form = f'''
<form method="post" action="/create/dir{current_path}">
    <input type="text" name="new_dir" placeholder="Enter directory name">
    <button type="submit">Create Directory</button>
</form>
'''
        forms.append(create_directory_form)

    # show upload file form
    if show_upload:
        upload_file_form = f'''
<form method="post" action="{current_path}" enctype="multipart/form-data">
    <input type="file" name="file">
    <button type="submit">Upload File</button> Note: Uploading a file with the same name will overwrite the existing one.
</form>
'''
        forms.append(upload_file_form)

    if forms:
        forms_table = (
            '<table>\n'
            + '\n'.join(f'<tr><td>{form}</td></tr>' for form in forms)
            + '\n</table>\n<hr>'
        )


    html = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>%s</title>
<style>
body {
    background-color: rgb(240,240,240);
}
table {
    border-collapse: collapse;
    font-size: 18px;
}
th, td {
    border: 1px solid #ccc;
    padding: 4px;
}
</style>
</head>
<body>
You can access <a href="%s">%s</a> to get json data.
%s
%s
<table>
    <tr>
    <th>Name</th>
    <th>Size</th>
    <th>Modify Time</th>
    </tr>
%s
</table>
</body>
</html>
'''

    dir_file_rows = []
    if sub_path and sub_path != '/':
        if sub_path[-1] != '/':
            sub_path += '/'
        dir_file_rows.append(
f'''    <tr>
        <td><a href="{current_path_ends_with_slash}..">..</a></td>
        <td>Dir</td>
        <td></td>
    </tr>''')

    for entry, stat in dirs:
        dir_file_rows.append(
f'''    <tr>
        <td><a href="{current_path_ends_with_slash}{entry.name}">{entry.name}</a></td>
        <td>Dir</td>
        <td>{_fmt_time(stat.st_mtime)}</td>
    </tr>''')

    for entry, stat in files:
        dir_file_rows.append(
f'''    <tr>
        <td><a href="{current_path_ends_with_slash}{entry.name}" target="_blank">{entry.name}</a></td>
        <td>{file_size_to_str(stat.st_size)}</td>
        <td>{_fmt_time(stat.st_mtime)}</td>
    </tr>''')

    html = html % (current_path, json_url, json_url,
                   ancestor_link_block,
                   forms_table,
                   '\n'.join(dir_file_rows))
    return HTMLResponse(content=html, status_code=200)


if __name__ == '__main__':
    import uvicorn
    from log_util import config_logger

    config_logger(logger, log_level='info', log_dir='logs',
                  log_file='file_server.log', backup_count=15,
                  log_to_stdout=True)
    logger.info(f'server pid {os.getpid()} starts')
    app = FastAPI()
    setup_file_server_router(app,
                             mount_path='files',
                             local_dir='.',
                             allow_create_directory=True,
                             allow_upload=True)
    setup_log_router(app, 'logs')
    log_config = get_uvicorn_logging_config()
    uvicorn.run(app, lifespan='off', host='0.0.0.0', port=8281,
                workers=1, log_level='info', log_config=log_config)
