# Docker容器监控服务

一个基于FastAPI的Docker容器监控服务，提供容器信息查看、健康检查、重启和实时日志查看功能。

**English documentation:** [README.md](README.md) · **采集实现说明:** [docs/implementation.md](docs/implementation.md)

## 功能特性

### 服务端API功能

1. **获取容器信息列表接口** (`GET /api/containers`)
   - 获取所有运行中容器的详细信息
   - 提取的字段包括：
     - `Id`: Docker容器ID
     - `Created`: 创建时间
     - `Args`: 启动参数
     - `State`: 容器状态（已删除Log信息）
     - `Name`: 容器名称
     - `PortBindings`: 端口绑定信息
     - `DeviceRequests`: 设备请求（NVIDIA GPU 通过此字段配置）
     - `Image`: 镜像名字
     - `HealthcheckTest`: Healthcheck中的URL（如果有）
     - `Entrypoint`: 入口点
     - `ComposeFile`: Compose文件路径（如果有）
     - `GpuDevices`: 使用的显卡/NPU序号列表（NVIDIA 来自 `DeviceRequests`；Ascend 来自 `/dev/davinci*` 设备挂载或 `ASCEND_VISIBLE_DEVICES` 环境变量）

2. **Healthcheck测试接口** (`GET /api/containers/{container_id}/healthcheck`)
   - 输入一个docker id
   - 自动提取容器的Healthcheck URL
   - 在后端访问该URL并返回原始响应
   - 返回状态码、响应内容和响应头

3. **通用HTTP请求接口** (`POST /api/request`)
   - 通过后端发起任意HTTP请求，支持GET、POST、PUT、DELETE等方法
   - 支持自定义请求头和请求体
   - 返回原始响应（状态码、响应内容、响应头）
   - **安全限制**：
     - 内网IP地址访问控制（可通过`HTTP_REQUEST_BLOCK_LOCAL_IP`变量配置）
       - 默认允许访问内网IP（`HTTP_REQUEST_BLOCK_LOCAL_IP=False`）
       - 设置为`True`时禁止访问内网地址（127.0.0.1, localhost, 私有IP段）
     - 只支持HTTP和HTTPS协议
     - 请求超时限制为30秒
     - 记录所有请求日志
   - 请求体格式：
     ```json
     {
       "method": "GET",
       "url": "http://example.com/api",
       "headers": {"Content-Type": "application/json"},
       "payload": "请求体内容（可选）"
     }
     ```

4. **Restart 容器接口** (`POST /api/containers/{container_name}/restart`)
   - 路径参数为**容器名称**（前端列表已有，直接传入）
   - **需要密码验证**：密码保存在项目根目录的 `key.json` 文件中
   - 执行 `docker restart <容器名>`，**同步等待**命令完成（约 3 秒）后返回
   - 请求体格式：`{"username": "admin", "password": "密码"}`

5. **DownUp docker接口** (`POST /api/containers/{container_id}/downup`)
   - 输入一个docker id
   - **需要密码验证**：密码保存在项目根目录的 `key.json` 文件中
   - 自动获取容器的compose文件路径
   - 执行 `docker compose down` 和 `docker compose up -d`
   - 返回执行结果
   - 请求体格式：`{"password": "密码"}`

6. **DownUp docker接口（SSE流式）** (`POST /api/containers/{container_id}/downup/stream`)
   - 输入一个docker id
   - **需要密码验证**：密码保存在项目根目录的 `key.json` 文件中
   - 使用SSE（Server-Sent Events）实时返回执行步骤和命令输出
   - 实时显示每个命令的执行过程和输出结果
   - 适合长时间执行的场景，用户可以实时看到进度
   - 请求体格式：`{"password": "密码"}`
   - 响应格式（SSE流）：
     - `{"type": "step", "step": "password_verified", "message": "密码验证通过"}`
     - `{"type": "step", "step": "checking_compose", "message": "正在检查Compose文件..."}`
     - `{"type": "step", "step": "down_start", "message": "开始执行: docker compose down", "command": "..."}`
     - `{"type": "output", "step": "down", "stream": "stdout", "data": "命令输出..."}`
     - `{"type": "step", "step": "down_completed", "message": "docker compose down 执行成功", "exit_code": 0}`
     - `{"type": "step", "step": "up_start", "message": "开始执行: docker compose up -d", "command": "..."}`
     - `{"type": "output", "step": "up", "stream": "stdout", "data": "命令输出..."}`
     - `{"type": "step", "step": "up_completed", "message": "docker compose up -d 执行成功", "exit_code": 0}`
     - `{"type": "success", "data": {...}}` 或 `{"type": "error", "data": "错误信息"}`

7. **实时日志查看接口** (`GET /api/containers/{container_id}/logs`)
   - 使用SSE（Server-Sent Events）实时返回容器日志
   - 相当于执行 `docker logs -f {container_id}`
   - 支持实时流式输出

8. **获取 GPU/NPU 使用信息接口** (`GET /api/gpu/usage`)
   - 自动检测 NVIDIA（`nvidia-smi`）或华为 Ascend（`npu-smi info`）
   - 返回各容器的加速器进程、显存占用及设备序号

9. **获取容器资源统计接口** (`GET /api/containers/stats`)
   - 调用 `docker stats --no-stream` 获取 CPU、内存、网络、磁盘 I/O

10. **容器聚合概览接口** (`GET /api/containers/overview`)
   - 一次返回容器列表、GPU/NPU 显存、CPU/内存统计
   - 前端**首次加载**仍分步请求以快速显示列表；**自动刷新及之后的手动刷新**使用本接口

> 容器字段（GPU 序号、显存、内存等）的采集实现细节见 [docs/implementation.md](docs/implementation.md)。

### 前端主页功能

- **容器列表展示**
  - 显示容器的ID、名称、创建时间、Compose文件路径、显卡序号、Entrypoint信息
  - 支持表格形式展示，便于查看
  - 注意：由于docker ps命令只列出运行中的容器，因此不显示状态列
  - 表格单元格支持自动换行显示，不会截断长文本
  - 支持在表头拖拽调整列宽，调整后的列宽会自动保存到浏览器本地存储

- **自动刷新功能**
  - 可配置刷新时间间隔（5-300秒）
  - 支持手动刷新按钮
  - 显示最后更新时间

- **实时日志查看**
  - 点击"查看日志"按钮可弹出窗口
  - 使用SSE实时显示容器日志
  - 支持错误日志高亮显示
  - 自动滚动到最新日志

- **容器重启功能**
  - 如果容器有关联的compose文件，显示"重启"按钮
  - 点击重启后会弹出密码输入框，需要输入正确的密码才能继续
  - 密码验证通过后使用SSE流式接口执行compose down和up
  - 重启过程中弹出日志窗口，实时显示执行步骤和命令输出
  - 可以实时查看每个命令的执行过程和输出结果
  - 重启按钮在重启过程中会被禁用，防止重复点击
  - 重启完成后不会自动打开容器日志查看窗口（用户可手动查看）
  - 密码错误时会显示错误提示并重新弹出密码输入框

## 安装和运行

### 依赖要求

- Python 3.10+（已在 Python 3.12 测试）
- Docker
- Docker Compose（用于重启功能）
- **GPU/NPU 监控（可选）**：主机需安装对应厂商工具之一
  - NVIDIA：`nvidia-smi`（或存在 `/dev/nvidia0`）
  - 华为 Ascend：`npu-smi`（或存在 `/dev/davinci0`）
  - 程序启动时自动检测，无需手动配置

### 安装依赖

```bash
python -m pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/
python -m pip install fastapi fastapi-offline uvicorn[standard] httpx psutil bcrypt
python gen_git_commit.py   # 生成 version.py
python docker_monitor_server.py --host 0.0.0.0 --port 9949
```

**注意**: `bcrypt` 是密码验证功能必需的库，用于安全地存储和验证密码。

### 运行服务

也可使用 uvicorn 直接运行：

```bash
uvicorn app:app --host 0.0.0.0 --port 9949
```

### 配置密码（重启功能）

重启功能需要密码保护，密码使用 **bcrypt** 进行哈希存储（不是明文）。

**首次配置密码：**

1. 使用工具脚本生成密码hash值：
```bash
# 交互式输入密码（推荐，密码不会显示在屏幕上）
python generate_password_hash.py --interactive

# 或者直接指定密码（不推荐，密码会出现在命令行历史中）
python generate_password_hash.py --password "你的密码"
```

2. 脚本会自动将hash值保存到 `key.json` 文件中

3. **重要**: `key.json` 文件包含密码hash值，请妥善保管，不要将其提交到版本控制系统！

**更新密码：**

如果需要更改密码，重新运行 `generate_password_hash.py` 脚本即可。

### 访问服务

- 前端页面: http://localhost:9949/dm/index.html
- API文档: http://localhost:9949/docs
- 健康检查: http://localhost:9949/health

## API接口说明

### 0. 容器聚合概览（推荐）

**请求**
```
GET /api/containers/overview
GET /api/containers/overview?debug=true
```

**响应**
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "containers": [ /* 同 /api/containers 的 data 数组 */ ],
    "gpu_usage": { /* 同 /api/gpu/usage 的 data 对象 */ },
    "stats": { /* 同 /api/containers/stats 的 data 对象 */ }
  }
}
```

### 1. 获取容器列表

**请求**
```
GET /api/containers
```

**响应**
```json
{
  "code": 0,
  "message": "success",
  "data": [
    {
      "Id": "efb99eb8f0dcbd0a0b5ebd7d6191e1e0e337233e694d7f7748e852fda1b0911f",
      "Created": "2025-12-30T14:43:04.099262022Z",
      "Args": ["serve", "/models/Qwen/Qwen3-32B-AWQ", ...],
      "State": {
        "Status": "running",
        "Running": true,
        ...
      },
      "Name": "/qwen3-32b",
      "PortBindings": {
        "9997/tcp": [{"HostIp": "", "HostPort": "9999"}]
      },
      "DeviceRequests": [...],
      "Image": "sha256:ee2917e260bb5037ca93944bfcb845a8f867674c63de2284d28c541f1eaf3f08",
      "HealthcheckTest": "http://localhost:9997/health",
      "Entrypoint": ["vllm", "serve", ...],
      "ComposeFile": "/mnt/sdb/llm_install/docker-compose-qwen3-32b.yaml",
      "GpuDevices": ["0", "1"]
    }
  ]
}
```

### 2. Healthcheck测试

**请求**
```
GET /api/containers/{container_id}/healthcheck
```

**响应**
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "url": "http://localhost:9997/health",
    "status_code": 200,
    "response": "OK",
    "headers": {...}
  }
}
```

### 3. 通用HTTP请求

**请求**
```
POST /api/request
Content-Type: application/json

{
  "method": "GET",
  "url": "http://example.com/api",
  "headers": {
    "Content-Type": "application/json",
    "Authorization": "Bearer token"
  },
  "payload": "请求体内容（可选，GET请求通常不需要）"
}
```

**响应（成功）**
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "url": "http://example.com/api",
    "status_code": 200,
    "response": "响应内容",
    "headers": {
      "Content-Type": "application/json",
      ...
    },
    "method": "GET"
  }
}
```

**响应（错误）**
```json
{
  "code": 4,
  "message": "出于安全考虑，禁止访问内网地址或localhost",
  "data": null
}
```

**支持的HTTP方法**
- GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS

**安全限制**
- 内网IP地址访问控制（可通过`HTTP_REQUEST_BLOCK_LOCAL_IP`变量配置）
  - 默认允许访问内网IP（`HTTP_REQUEST_BLOCK_LOCAL_IP=False`）
  - 设置为`True`时禁止访问内网地址（127.0.0.1, localhost, 10.x.x.x, 172.16-31.x.x, 192.168.x.x）
  - 禁止访问私有IP段和.local/.internal域名（仅在`HTTP_REQUEST_BLOCK_LOCAL_IP=True`时生效）
- 只支持HTTP和HTTPS协议
- 请求超时限制为30秒
- 所有请求都会记录日志

**配置说明**
- 在`api.py`文件中可以修改`HTTP_REQUEST_BLOCK_LOCAL_IP`变量来控制是否禁止访问内网IP
- 默认值为`False`，表示允许访问内网IP地址
- 如果设置为`True`，则会阻止访问内网地址，提高安全性

**注意事项**
- payload可以是字符串、字典或列表
- 如果payload是字典或列表，会自动转换为JSON格式
- GET、HEAD、OPTIONS方法不需要payload，如果提供了会被忽略

### 4. Restart 容器（docker restart）

**请求**（路径中的 `{container_name}` 为容器名称，由前端从列表传入）
```
POST /api/containers/{container_name}/restart
Content-Type: application/json

{
  "username": "admin",
  "password": "密码"
}
```

**响应（成功）**
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "container_name": "容器名",
    "stdout": "容器名"
  }
}
```

**说明**：接口直接使用传入的容器名执行 `docker restart <容器名>`，同步等待完成（约 3 秒）后返回。

**响应（密码错误）**
```json
{
  "code": 401,
  "message": "密码验证失败",
  "data": null
}
```

### 5. DownUp 容器（docker compose down + up）

**请求**
```
POST /api/containers/{container_id}/downup
Content-Type: application/json

{
  "password": "密码"
}
```

**响应（成功）**
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "compose_file": "/path/to/docker-compose.yml",
    "down_stdout": "...",
    "up_stdout": "..."
  }
}
```

**响应（密码错误）**
```json
{
  "code": 401,
  "message": "密码验证失败",
  "data": null
}
```

### 6. DownUp 容器（SSE流式）

**请求**
```
POST /api/containers/{container_id}/downup/stream
Content-Type: application/json

{
  "password": "密码"
}
```

**响应格式**（SSE流）
```
data: {"type": "step", "step": "password_verified", "message": "密码验证通过"}

data: {"type": "step", "step": "checking_compose", "message": "正在检查Compose文件..."}

data: {"type": "step", "step": "compose_found", "message": "找到Compose文件: /path/to/docker-compose.yml"}

data: {"type": "step", "step": "down_start", "message": "开始执行: docker compose down", "command": "docker compose -f ... down"}

data: {"type": "output", "step": "down", "stream": "stdout", "data": "命令输出行1\n"}

data: {"type": "output", "step": "down", "stream": "stderr", "data": "错误输出（如果有）\n"}

data: {"type": "step", "step": "down_completed", "message": "docker compose down 执行成功", "exit_code": 0}

data: {"type": "step", "step": "up_start", "message": "开始执行: docker compose up -d", "command": "docker compose -f ... up -d"}

data: {"type": "output", "step": "up", "stream": "stdout", "data": "命令输出行1\n"}

data: {"type": "step", "step": "up_completed", "message": "docker compose up -d 执行成功", "exit_code": 0}

data: {"type": "success", "data": {"compose_file": "...", "down_exit_code": 0, "up_exit_code": 0, ...}}
```

**错误响应**
```
data: {"type": "error", "data": "错误信息"}
```

**事件类型说明**：
- `step`: 执行步骤信息（密码验证、检查文件、开始执行命令、命令完成等）
- `output`: 命令实时输出（stdout或stderr）
- `success`: 所有步骤执行成功
- `error`: 执行过程中发生错误

### 7. 实时日志（SSE）

**请求**
```
GET /api/containers/{container_id}/logs
```

**响应格式**（SSE流）
```
data: {"type": "log", "data": "日志内容\n"}

data: {"type": "error", "data": "错误信息\n"}

data: {"type": "end", "exit_code": 0}
```

### 8. 获取 GPU/NPU 使用信息

**请求**
```
GET /api/gpu/usage
```

**响应**（字段说明见 [docs/implementation.md](docs/implementation.md)）
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "c0bfefa6064b": {
      "gpu_processes": [
        {
          "gpu_id": 0,
          "pid": 1217362,
          "process_name": "VLLMWorker_TP",
          "memory_mib": 56934
        }
      ],
      "total_memory_mib": 113868,
      "gpu_ids": [0, 1]
    }
  }
}
```

### 9. 获取容器资源统计

**请求**
```
GET /api/containers/stats
```

**响应**
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "32869ef54f20": {
      "cpu_percent": 203.09,
      "mem_usage_bytes": 10857684992,
      "mem_limit_bytes": 68719476736,
      "mem_percent": 15.80,
      "net_io_rx": 204472320,
      "net_io_tx": 607256576,
      "block_io_read": 5196906496,
      "block_io_write": 2956984320,
      "pids": 439
    }
  }
}
```

## 项目结构

```
docker-monitor/
├── app.py                  # FastAPI应用主文件
├── api.py                  # API路由定义
├── docker_util.py          # Docker相关工具函数
├── process_util.py         # 异步进程执行工具
├── docker_monitor_server.py # 服务器启动脚本
├── models.py               # 数据模型定义
├── fastapi_util.py         # FastAPI工具函数
├── sys_util.py             # 系统工具函数
├── log_util.py             # 日志工具
├── generate_password_hash.py # 密码hash生成工具脚本
├── key.json                 # 密码hash值文件（不要提交到版本控制）
├── static/                 # 前端静态文件目录
│   ├── index.html          # 前端HTML页面
│   ├── style.css           # 样式文件
│   └── app.js              # JavaScript逻辑文件
├── README.md               # 英文文档
├── README-cn.md            # 中文文档（本文档）
├── docs/
│   └── implementation.md   # 容器信息采集实现说明
└── 前端功能描述.md          # 前端功能详细说明
```

## 技术实现

- 所有 Docker 命令与 HTTP 请求均为异步执行（`asyncio` + `process_util`）
- 实时日志与 DownUp 进度通过 SSE（`StreamingResponse`）推送
- 容器基础信息、GPU/NPU 显存、CPU/内存等资源字段的采集逻辑见 **[docs/implementation.md](docs/implementation.md)**

## 注意事项

1. **权限要求**: 需要Docker执行权限，确保运行用户有权限执行docker命令
2. **Compose文件**: 重启功能需要容器有关联的compose文件（通过Labels中的`com.docker.compose.project.config_files`获取）
3. **密码保护**: 重启功能需要密码验证，密码使用 **bcrypt** 进行哈希存储（不是明文），hash值保存在项目根目录的 `key.json` 文件中。如果文件不存在或为空，重启功能将被禁用。使用 `generate_password_hash.py` 脚本生成密码hash值。
4. **Healthcheck URL**: 自动从Healthcheck的Test命令中提取URL，如果无法提取则返回整个Test命令
5. **日志流**: 实时日志查看使用SSE，断开连接后需要重新连接

## 开发说明

### 代码规范

- 所有函数都包含详细的文档字符串
- 使用类型提示提高代码可读性
- 错误处理完善，记录详细日志

### 扩展功能

如需添加新功能，可以：
1. 在 `docker_util.py` 中添加新的工具函数
2. 在 `api.py` 中添加新的API路由
3. 在前端HTML中添加新的UI元素和交互逻辑

## 问题排查

### 常见问题

1. **无法获取容器列表**
   - 检查Docker服务是否运行
   - 检查是否有执行docker命令的权限

2. **Healthcheck测试失败**
   - 检查容器是否配置了Healthcheck
   - 检查Healthcheck URL是否可访问

3. **重启失败**
   - 检查容器是否有关联的compose文件
   - 检查compose文件路径是否正确
   - 检查是否有执行compose命令的权限
   - 检查密码是否正确（密码hash保存在 `key.json` 文件中）
   - 检查 `key.json` 文件是否存在且包含有效的bcrypt hash值
   - 检查是否安装了 `bcrypt` 库：`pip install bcrypt`
   - 如果密码验证失败，使用 `generate_password_hash.py` 重新生成hash值

4. **日志无法显示**
   - 检查容器是否在运行
   - 检查网络连接是否正常
   - 查看浏览器控制台是否有错误

5. **GPU/NPU 显存信息不显示**
   - 确认主机已安装 `nvidia-smi`（NVIDIA）或 `npu-smi`（Ascend），且监控服务有执行权限
   - Ascend 容器需挂载 `/dev/davinci*` 设备（或通过环境变量指定可见 NPU）
   - 容器刚启动时进程可能尚未注册，等待自动刷新后再查看
   - 详细采集逻辑见 [容器信息采集实现](docs/implementation.md)

## 许可证

本项目采用MIT许可证。

