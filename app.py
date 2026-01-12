import os
import sys
import time
import asyncio
from datetime import datetime
from typing import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi_offline import FastAPIOffline
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

import sys_util as sutil
from log_util import logger


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:

    # ---- above is start
    yield # yield between start and stop
    # ---- below is stop


from api import router
app = FastAPIOffline(lifespan=lifespan)

# Configure CORS cross-origin support
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins, production environment should specify specific domains
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all request headers
)

app.include_router(router)


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.perf_counter()
    response = await call_next(request)
    process_time = time.perf_counter() - start_time
    response.headers['X-Process-Time'] = f'{process_time:.6f}'
    return response


@app.exception_handler(Exception)
async def custom_exception_handler(request: Request, ex: Exception):
    logger.error(f'pid={os.getpid()}, {request.method} {request.url}, {ex!r}\n{sutil.get_exception_stack()}')
    return JSONResponse(
        status_code=500 if not isinstance(ex, HTTPException) else ex.status_code,
        content={'error_code': -1, 'message': 'An error occurred while processing your request.', 'data': None},
    )
