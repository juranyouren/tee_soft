# TEE软件测试套件

本目录包含TEE (Trusted Execution Environment) 软件系统的完整测试套件。

## 📁 文件说明

| 文件 | 用途 | 描述 |
|------|------|------|
| `test_system.py` | 综合系统测试 | 完整的TEE系统功能测试客户端 |
| `start_test_environment.py` | 一键启动脚本 | 自动启动测试环境和服务 |
| `TESTING_GUIDE.md` | 详细测试指南 | 完整的测试文档和使用说明 |
| `README.md` | 本文件 | 测试套件概览 |

## 🚀 快速开始

### 一键启动测试环境
```bash
python test/start_test_environment.py
```

### 直接运行系统测试
```bash
python test/test_system.py
```

### 快速健康检查
```bash
python test/test_system.py --quick
```

## 📖 详细文档

查看 [`TESTING_GUIDE.md`](./TESTING_GUIDE.md) 获取完整的测试指南，包括：
- 详细的测试架构说明
- 各种测试场景的使用方法
- 故障排除和调试技巧
- Dashboard功能展示说明

## 🎯 测试目标

- ✅ 验证TEE服务器核心功能
- ✅ 测试Dashboard监控系统
- ✅ 模拟客户端交互场景
- ✅ 验证加密和安全功能
- ✅ 监控系统性能表现

## 🔧 依赖要求

- Python 3.8+
- TEE服务器 (localhost:5000)
- Dashboard服务 (localhost:5001)
- 相关Python依赖包 (参见 requirements.txt)

## 📞 问题反馈

如遇到测试问题，请：
1. 查看 `logs/system_test.log` 日志文件
2. 运行快速诊断：`python test/test_system.py --quick`
3. 参考详细测试指南进行故障排除 