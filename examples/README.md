# TEE软件示例和演示程序

本目录包含TEE软件的各种示例、演示和测试程序，帮助用户理解和使用TEE软件的各项功能。

## 📁 文件说明

### 🚀 核心演示
- **`demo.py`** - TEE软件核心功能完整演示
  - 展示完整的TEE处理流程
  - 包含用户注册、风险评估、加密响应等
  - **使用**: `python examples/demo.py`

### 📊 监控演示
- **`demo_dashboard.py`** - Dashboard监控系统演示
  - 演示实时监控功能
  - 展示通讯抽象和加密可视化
  - **使用**: `python examples/demo_dashboard.py`
  - **前置条件**: 需要TEE服务器和Dashboard都在运行

### 🔐 加密算法演示
- **`crypto_demo.py`** - 基础加密功能演示
  - 展示AES加密和RSA签名
  - 密钥生成和管理示例
  - **使用**: `python examples/crypto_demo.py`

- **`sm_crypto_demo.py`** - 国密算法完整演示
  - SM2椭圆曲线加密算法
  - SM3密码杂凑算法
  - SM4分组密码算法
  - **使用**: `python examples/sm_crypto_demo.py`

### 🔑 密钥管理演示
- **`client_key_demo.py`** - 客户端密钥协商演示
  - 客户端密钥生成和管理
  - 与TEE服务器的密钥交换
  - **使用**: `python examples/client_key_demo.py`

- **`key_agreement_demo.py`** - 🔐 **密钥协商协议详细演示** (新增)
  - 完整的密钥协商过程演示
  - SM2/SM3/SM4算法详细展示
  - ECDH密钥交换和KDF密钥派生
  - 安全通信和性能分析
  - **使用**: `python examples/key_agreement_demo.py`
  - **特色**: 最详细的密钥协商教学演示 ⭐

### 🧪 测试程序
- **`simple_test.py`** - 简单功能测试
  - 基础功能验证
  - 快速测试TEE服务器连接
  - **使用**: `python examples/simple_test.py`

## 🎯 使用指南

### 快速开始
1. **启动TEE服务器**:
   ```bash
   python main.py
   ```

2. **运行核心演示**:
   ```bash
   python examples/demo.py
   ```

3. **运行密钥协商详细演示** (推荐):
   ```bash
   python examples/key_agreement_demo.py
   ```

4. **启动Dashboard**:
   ```bash
   python start_dashboard.py
   ```

5. **运行Dashboard演示**:
   ```bash
   python examples/demo_dashboard.py
   ```

### 学习路径

#### 🔰 初学者路径
1. `simple_test.py` - 验证环境和基础连接
2. `crypto_demo.py` - 了解基础加密概念
3. **`key_agreement_demo.py` - 深入理解密钥协商机制** ⭐
4. `demo.py` - 理解完整TEE处理流程

#### 🔧 开发者路径
1. `sm_crypto_demo.py` - 深入学习国密算法
2. **`key_agreement_demo.py` - 掌握核心安全协议** ⭐
3. `client_key_demo.py` - 理解客户端密钥管理
4. `demo_dashboard.py` - 监控和调试工具使用

#### 📊 运维路径
1. `demo_dashboard.py` - 监控系统使用
2. **`key_agreement_demo.py` - 理解安全协议运行机制** ⭐
3. `demo.py` - 完整系统验证
4. 结合Dashboard进行实时监控

## 🔧 环境要求

### 基础依赖
```bash
pip install -r requirements.txt
```

### 核心依赖包
- `gmssl>=3.2.2` - 国密算法支持
- `flask>=2.3.3` - Web框架
- `flask-socketio>=5.3.6` - 实时通讯
- `cryptography>=41.0.7` - 加密算法
- `psutil>=5.9.5` - 系统监控

## 📝 运行示例

### 运行所有演示
```bash
# 1. 启动TEE服务器
python main.py &

# 2. 启动Dashboard
python start_dashboard.py &

# 3. 运行各种演示
python examples/simple_test.py
python examples/crypto_demo.py
python examples/sm_crypto_demo.py
python examples/key_agreement_demo.py  # 推荐：最详细的演示
python examples/demo.py
python examples/demo_dashboard.py
```

### 单独运行演示
```bash
# 仅测试加密功能
python examples/sm_crypto_demo.py

# 仅测试基础连接
python examples/simple_test.py

# 密钥协商详细演示 (推荐学习)
python examples/key_agreement_demo.py

# 完整功能演示
python examples/demo.py
```

## 🚨 注意事项

1. **端口占用**: 确保端口5000和5001未被占用
2. **依赖安装**: 运行前确保所有依赖已正确安装
3. **环境变量**: 某些演示可能需要特定的环境变量
4. **执行顺序**: Dashboard演示需要先启动TEE服务器和Dashboard
5. **日志输出**: 演示过程会产生详细日志，注意查看
6. **密钥协商演示**: `key_agreement_demo.py`可独立运行，不需要启动服务器

## 🎓 学习资源

- 📖 [项目主文档](../README.md)
- 📚 [完整项目文档](../docs/) - 所有技术文档
- 🔐 **[密钥协商协议详解](../docs/key_agreement_protocol.md) - 理论基础** ⭐
- 📊 [Dashboard使用指南](../docs/DASHBOARD_README.md)
- 🚀 [快速开始指南](../docs/QUICK_START_DASHBOARD.md)
- 🏗️ [项目组织结构](../docs/PROJECT_ORGANIZATION.md)
- 📋 [项目状态说明](../docs/PROJECT_STATUS.md)

## 🤝 贡献指南

如果您想添加新的示例或改进现有示例：
1. 在`examples/`目录下创建新文件
2. 遵循现有的命名约定
3. 添加详细的注释和文档
4. 更新本README文件
5. 提交Pull Request

欢迎贡献更多有用的示例！ 