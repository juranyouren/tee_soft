# TEE软件系统测试指南

## 🎯 概述

本指南为TEE (Trusted Execution Environment) 软件系统提供完整的测试方案，包括客户端交互测试、Dashboard监控验证和系统功能测试。

## 🏗️ 测试架构

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   测试客户端    │────│   TEE服务器     │────│   Dashboard     │
│(test_system.py) │    │   (main.py)     │    │ (dashboard.py)  │
│   ./test/       │    │   Port: 5000    │    │   Port: 5001    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  │
                         ┌─────────────────┐
                         │   浏览器界面    │
                         │ localhost:5001  │
                         └─────────────────┘
```

## 🚀 快速开始

### 方式1: 一键启动测试环境 (推荐)

```bash
# 运行一键启动脚本
python test/start_test_environment.py
```

选择菜单选项:
- `1` - 启动完整测试环境
- `2` - 启动环境 + 运行系统测试
- `3` - 启动环境 + 运行监控演示

### 方式2: 手动启动各组件

```bash
# 终端1: 启动TEE服务器
python main.py

# 终端2: 启动Dashboard
python start_dashboard.py

# 终端3: 运行测试
python test/test_system.py
```

## 🧪 测试功能详解

### 1. 服务健康检查
- ✅ TEE服务器连通性测试
- ✅ Dashboard服务响应测试
- ✅ 基础API端点验证

### 2. 客户端交互测试
模拟真实客户端场景:
- **正常用户登录**: 标准浏览器、正常IP地址
- **可疑用户活动**: 异常IP、可疑用户代理
- **移动端用户**: 移动设备特征、不同地理位置

### 3. 加密功能验证
- 🔐 SM4对称加密测试
- 🔐 SM2公钥保护验证
- 🔐 数据完整性检查
- 🔐 密钥协商流程测试

### 4. Dashboard监控测试
- 📊 实时系统资源监控
- 📊 通讯流量统计
- 📊 加密操作统计
- 📊 风险评估可视化

### 5. 持续监控演示
- 🔄 持续发送测试请求
- 🔄 实时数据更新观察
- 🔄 Dashboard界面动态效果

## 📊 Dashboard功能展示

在浏览器中访问 `http://localhost:5001` 查看:

### 主界面功能
- **系统概览**: CPU、内存、磁盘使用率实时监控
- **通讯抽象**: 客户端与服务器交互可视化
- **加密状态**: 加密操作实时统计
- **风险评估**: 实时风险分析结果

### 实时数据展示
- **通讯流量图**: 入站/出站请求可视化
- **加密操作图**: 加密/解密操作统计
- **性能指标**: 响应时间、成功率监控
- **安全事件**: 高风险请求警报

## 🎮 测试场景

### 场景1: 正常业务流量测试
```bash
# 启动环境
python test/start_test_environment.py

# 选择: 2 (启动环境 + 系统测试)
# 观察Dashboard显示正常的用户活动
```

### 场景2: 高风险活动监控
```bash
# 运行持续监控演示
python test/test_system.py --demo

# 观察Dashboard中的风险警报和统计变化
```

### 场景3: 性能压力测试
```bash
# 运行60秒持续监控
python test/start_test_environment.py

# 选择: 3 (监控演示)
# 输入演示时长: 60
```

## 🔍 详细测试命令

### 基础测试命令
```bash
# 完整系统测试
python test/test_system.py

# 快速健康检查
python test/test_system.py --quick

# 持续监控演示
python test/test_system.py --demo

# 查看帮助
python test/test_system.py --help
```

### 独立功能测试
```bash
# 测试密钥协商协议
python examples/key_agreement_demo.py

# 测试核心功能
python examples/demo.py

# 测试Dashboard功能
python examples/demo_dashboard.py
```

## 📁 测试文件结构

```
tee_software/
├── test/                          # 测试目录
│   ├── test_system.py            # 综合系统测试
│   ├── start_test_environment.py # 一键启动脚本
│   └── TESTING_GUIDE.md          # 本测试指南
├── main.py                       # TEE服务器主程序
├── start_dashboard.py            # Dashboard启动脚本
├── dashboard.py                  # Dashboard主程序
└── examples/                     # 功能演示
    ├── key_agreement_demo.py     # 密钥协商演示
    ├── demo.py                   # 核心功能演示
    └── demo_dashboard.py         # Dashboard演示
```

## 📈 预期测试结果

### 成功指标
- ✅ 所有健康检查通过
- ✅ 客户端请求正确处理
- ✅ 加密功能正常工作
- ✅ Dashboard实时数据更新
- ✅ 风险评估准确响应

### Dashboard展示效果
- 📊 系统资源图表实时更新
- 📊 通讯统计数字动态变化
- 📊 加密操作计数器增加
- 📊 不同风险级别的请求分类显示

## 🐛 故障排除

### 常见问题

**问题1: 端口占用**
```bash
# 检查端口使用情况
netstat -an | findstr :5000
netstat -an | findstr :5001

# 或使用PowerShell
Get-NetTCPConnection -LocalPort 5000,5001
```

**问题2: 服务启动失败**
```bash
# 检查日志
type logs\tee_server.log
type logs\dashboard.log
type logs\system_test.log
```

**问题3: 依赖包问题**
```bash
# 安装依赖
pip install -r requirements.txt

# 检查Python版本 (推荐3.8+)
python --version
```

### 调试模式
```bash
# 启用详细日志
set PYTHONPATH=%PYTHONPATH%;%CD%
python main.py --debug

# 或修改config.py中的日志级别
```

## 🎯 测试重点

### 1. 客户端交互验证
- [ ] 不同类型客户端请求处理正确
- [ ] 风险评估逻辑准确
- [ ] 响应时间在合理范围内

### 2. Dashboard监控验证
- [ ] 实时数据更新正常
- [ ] 图表显示准确
- [ ] 用户界面响应流畅

### 3. 安全功能验证
- [ ] 加密/解密操作成功
- [ ] 密钥管理安全
- [ ] 数据传输保护有效

### 4. 性能验证
- [ ] 系统资源使用合理
- [ ] 响应时间满足要求
- [ ] 并发处理能力充足

## 📝 测试报告

测试完成后，系统会生成详细报告包括:
- 📊 测试用例通过率
- 📊 性能指标统计
- 📊 错误日志分析
- 📊 改进建议

## 💡 进阶测试

### 自定义测试场景
1. 修改 `test/test_system.py` 中的测试数据
2. 添加新的测试用例
3. 调整监控演示参数

### 集成测试
1. 与外部系统集成测试
2. 数据库连接测试
3. 网络安全测试

## 🔧 开发者测试

### 单元测试
```bash
# 运行核心功能单元测试
python -m pytest test/ -v
```

### API测试
```bash
# 测试REST API端点
python test/test_api.py
```

### 压力测试
```bash
# 运行压力测试
python test/performance_test.py
```

---

## 📞 技术支持

如遇到问题或需要技术支持，请:
1. 查看日志文件 (`logs/` 目录)
2. 运行快速诊断: `python test/test_system.py --quick`
3. 查看详细文档: `docs/` 目录

**祝测试顺利！** 🎉 