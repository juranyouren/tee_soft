# TEE软件监控仪表板

## 功能概述

这是一个专为TEE软件系统设计的监控仪表板，提供以下核心功能：

### 🖥️ 系统资源监控
- **CPU监控**: 实时CPU使用率，多核心显示，负载平均值
- **内存监控**: 内存使用率、缓存、交换分区状态
- **磁盘监控**: 磁盘使用率、I/O统计
- **网络监控**: 网络速度、连接数、流量统计
- **进程监控**: 资源占用最高的进程列表

### 🧪 API功能测试
- **自动化测试**: 定时执行TEE API接口测试
- **端点覆盖**: 支持所有主要TEE API端点
- **性能测试**: 并发测试、负载测试、响应时间统计
- **功能验证**: 加密功能、风险评估等核心功能验证
- **错误处理**: 异常情况处理测试

### 📊 实时数据展示
- **WebSocket**: 实时数据推送，无需刷新页面
- **图表展示**: 使用Chart.js绘制实时性能图表
- **告警系统**: 资源使用率超标自动告警
- **历史数据**: 保存和展示历史监控数据

## 架构设计

```
dashboard/
├── __init__.py          # 包初始化
├── config.py           # 配置管理
├── main.py            # 主应用程序
├── monitors.py        # 系统监控模块
├── api_tester.py      # API测试模块
├── run_dashboard.py   # 启动脚本
├── templates/         # HTML模板
│   └── dashboard.html
├── static/           # 静态资源
│   ├── css/
│   └── js/
└── README.md         # 说明文档
```

## 快速开始

### 1. 环境要求

```bash
Python 3.7+
pip install flask flask-socketio psutil requests
```

### 2. 启动仪表板

```bash
# 方法1: 直接运行主程序
cd dashboard
python main.py

# 方法2: 使用启动脚本
python dashboard/run_dashboard.py
```

### 3. 访问仪表板

打开浏览器访问: http://127.0.0.1:8080

## 配置说明

### 环境变量配置

```bash
# Dashboard配置
export DASHBOARD_HOST="127.0.0.1"
export DASHBOARD_PORT="8080"
export DASHBOARD_DEBUG="false"

# TEE服务器配置
export TEE_SERVER_URL="http://localhost:5000"
export TEE_API_TIMEOUT="30"

# 日志配置
export LOG_LEVEL="INFO"
```

### 监控配置

在 `config.py` 中可以调整以下参数：

```python
SYSTEM_MONITOR = {
    'enabled': True,
    'interval_seconds': 5,          # 监控数据收集间隔
    'cpu_alert_threshold': 80.0,    # CPU告警阈值
    'memory_alert_threshold': 85.0, # 内存告警阈值
    'disk_alert_threshold': 90.0,   # 磁盘告警阈值
}
```

### API测试配置

```python
API_TEST = {
    'enabled': True,
    'test_interval_seconds': 30,    # 测试执行间隔
    'timeout_seconds': 15,          # 请求超时时间
    'retry_attempts': 3,            # 重试次数
}
```

## 功能特性

### 实时监控面板

1. **概览卡片**: 显示CPU、内存、磁盘使用率和API成功率
2. **性能图表**: 实时更新的系统资源使用趋势图
3. **进程列表**: 显示资源占用最高的进程
4. **网络监控**: 网络速度和连接状态

### API测试面板

1. **测试统计**: 显示通过/失败测试数量和平均响应时间
2. **测试结果**: 详细的测试执行结果和错误信息
3. **手动测试**: 支持手动执行特定API端点测试
4. **测试历史**: 保存和查看历史测试记录

### 告警和通知

1. **阈值告警**: 资源使用率超过预设阈值时触发告警
2. **API异常**: API测试失败时生成告警
3. **告警冷却**: 防止同一告警重复触发
4. **告警清除**: 支持手动清除告警记录

## API接口

### 系统监控API

- `GET /api/overview` - 获取系统概览
- `GET /api/system/metrics` - 获取系统指标
- `GET /api/system/alerts` - 获取系统告警
- `DELETE /api/system/alerts` - 清除系统告警

### API测试API

- `GET /api/tests/results` - 获取测试结果
- `GET /api/tests/statistics` - 获取测试统计
- `POST /api/tests/run` - 运行手动测试
- `POST /api/tests/clear` - 清除测试历史

### WebSocket事件

- `system_update` - 系统指标更新
- `api_test_update` - API测试结果更新
- `request_refresh` - 请求数据刷新

## 技术栈

- **后端**: Python, Flask, Flask-SocketIO
- **前端**: HTML5, CSS3, JavaScript, Bootstrap 5
- **图表**: Chart.js
- **监控**: psutil
- **通信**: WebSocket, RESTful API

## 监控指标

### 系统指标

- CPU使用率 (总体和各核心)
- CPU频率和负载平均值
- 内存使用率、缓存、交换分区
- 磁盘使用率、I/O统计
- 网络速度、连接数
- 进程信息和资源占用

### API指标

- 请求成功率
- 平均响应时间
- 并发性能
- 错误率统计
- 端点可用性

## 故障排除

### 常见问题

1. **无法连接TEE服务器**
   - 检查TEE_SERVER_URL配置
   - 确认TEE服务器是否运行
   - 检查网络连接

2. **监控数据不更新**
   - 检查WebSocket连接状态
   - 确认系统监控是否启用
   - 查看浏览器控制台错误

3. **告警不触发**
   - 检查告警阈值配置
   - 确认告警功能是否启用
   - 查看后台日志

### 日志查看

```bash
# 查看dashboard日志
tail -f logs/dashboard.log

# 查看详细调试信息
export LOG_LEVEL="DEBUG"
python dashboard/main.py
```

## 扩展开发

### 添加新的监控指标

1. 在 `monitors.py` 中添加数据收集逻辑
2. 在前端添加对应的显示组件
3. 更新WebSocket数据推送

### 添加新的API测试

1. 在 `api_tester.py` 中添加测试用例
2. 在配置中添加端点信息
3. 更新前端测试结果显示

## 许可证

本项目采用MIT许可证。 