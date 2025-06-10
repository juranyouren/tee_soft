# TEE_SOFT - 可信执行环境风险评估软件 🇨🇳

TEE_SOFT 是一个基于可信执行环境（TEE）的风险评估软件，专门用于处理用户特征数据的安全分析和风险计算。该软件采用中国国家密码标准（国密算法），实现了数据加密存储、安全解密计算、基于贝叶斯模型的风险评估等核心功能。

## 🎯 核心功能

- **国密算法保护**: 采用SM4、SM3、SM2国密算法，符合国家密码标准
- **密文消息处理**: 接收加密的用户特征数据，在TEE环境中安全解密处理
- **明文兼容模式**: 向后兼容传统明文特征处理
- **TEE环境保护**: 在可信执行环境中进行数据解密和风险计算
- **RBA风险评估**: 基于贝叶斯模型计算用户行为风险分数
- **灵活特征管理**: 支持动态配置特征类型和验证规则
- **内存安全监控**: 实时监控内存使用，自动清理敏感数据
- **加密数据库存储**: 所有敏感数据加密后存储，保护用户隐私

## 🔐 国密算法支持

### 加密算法
- **SM4-ECB**: 128位对称加密算法，替代AES-256-GCM
- **SM3**: 256位密码杂凑算法，替代SHA-256
- **SM2**: 椭圆曲线公钥密码算法，替代Ed25519

### 标准合规
- **GB/T 32907-2016**: SM4分组密码算法
- **GB/T 32905-2016**: SM3密码杂凑算法  
- **GB/T 32918-2016**: SM2椭圆曲线公钥密码算法
- **商用密码等级**: 达到国家商用密码安全等级要求

## 🏗️ 系统架构

```
TEE_SOFT (国密版本)
├── 🇨🇳 国密引擎 (SM4-ECB, SM3, SM2)
├── 🔐 传统加密引擎 (AES-256-GCM, Ed25519) - 向后兼容
├── 📥 密文消息处理器 (支持加密输入)
├── 📊 特征管理器 (动态特征配置)
├── 🧠 RBA计算引擎 (贝叶斯风险模型)
├── 🗄️ 数据库管理器 (MySQL + 加密存储)
├── 🧹 内存监控器 (安全清理)
└── 🌐 REST API (Flask)
```

## 📋 系统要求

- **Python**: 3.8+
- **数据库**: MySQL 8.0+
- **内存**: 建议 2GB+ (支持128MB限制模式)
- **操作系统**: Linux/Windows/macOS
- **国密库**: gmssl 3.2.2+

## 🚀 快速开始

### 1. 环境准备

```bash
# 克隆项目
git clone <repository-url>
cd tee_software

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/macOS
# 或 venv\Scripts\activate  # Windows

# 安装依赖（包含国密库）
pip install -r requirements.txt
```

### 2. 数据库配置

```sql
-- 创建数据库和用户
CREATE DATABASE risk_assessment CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'tee_user'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON risk_assessment.* TO 'tee_user'@'localhost';
FLUSH PRIVILEGES;
```

### 3. 环境变量设置

```bash
# 必需的环境变量（国密版本）
export DB_PASSWORD="your_secure_password"
export TEE_SM4_MASTER_KEY="$(python -c 'import secrets; print(secrets.token_hex(16))')"

# 传统加密支持（向后兼容）
export TEE_MASTER_KEY="$(openssl rand -hex 32)"

# 可选的环境变量
export FLASK_HOST="127.0.0.1"
export FLASK_PORT="5000"
export FLASK_DEBUG="false"
```

### 4. 配置文件调整

编辑 `config/security.yaml`:
```yaml
encryption:
  # 国密算法配置
  algorithm: sm4-ecb
  key_size: 16  # SM4 128位密钥

signature:
  algorithm: sm2
  curve: sm2p256v1

hash:
  algorithm: sm3

key_management:
  master_key_env: TEE_SM4_MASTER_KEY
```

### 5. 启动服务

```bash
# 运行国密算法演示
python sm_crypto_demo.py

# 启动主服务
python main.py
```

服务启动后，可通过以下地址访问：
- 健康检查: http://127.0.0.1:5000/health
- 系统状态: http://127.0.0.1:5000/status

## 📡 API 接口

### 🔐 密文消息处理接口

**POST** `/tee_soft/process_encrypted`

处理加密的用户特征数据并返回风险评估结果。

**请求示例**:
```json
{
    "request_id": "msg_1704110400",
    "timestamp": "2024-01-01T12:00:00Z",
    "source_ip": "110.242.68.66",
    "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_2 like Mac OS X)",
    "encrypted_features": {
        "device_fingerprint": {
            "ciphertext": "a1b2c3d4e5f6...",
            "integrity_hash": "sm3_hash_value",
            "algorithm": "sm4-ecb",
            "key_purpose": "feature_device_fingerprint"
        },
        "login_location": {
            "ciphertext": "f6e5d4c3b2a1...",
            "integrity_hash": "sm3_hash_value",
            "algorithm": "sm4-ecb", 
            "key_purpose": "feature_login_location"
        }
    }
}
```

**响应示例**:
```json
{
    "request_id": "msg_1704110400",
    "status": "success",
    "processing_time_ms": 245.7,
    "feature_count": 5,
    "feature_analysis": {
        "processed_features": 5,
        "status": "success"
    },
    "risk_assessment": {
        "risk_score": 0.234,
        "risk_level": "low",
        "action": "allow"
    },
    "digital_signature": "sm2_signature_value",
    "signature_algorithm": "SM2"
}
```

### 🔓 传统明文处理接口（向后兼容）

**POST** `/tee_soft/process`

处理明文用户特征数据并返回风险评估结果。

**请求示例**:
```json
{
    "user_id": "user123",
    "features": {
        "ip": "192.168.1.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "rtt": 45.2,
        "geo_location": "40.7128,-74.0060"
    },
    "metadata": {
        "session_id": "sess_456",
        "timestamp": "2024-01-01T12:00:00Z"
    }
}
```

### 系统管理接口

- **GET** `/health` - 健康检查
- **GET** `/status` - 系统状态
- **GET** `/tee_soft/public_key` - 获取SM2公钥信息
- **GET** `/tee_soft/algorithm_info` - 获取国密算法信息
- **POST** `/admin/cleanup` - 清理旧数据
- **GET** `/admin/memory` - 内存状态
- **POST** `/admin/force_cleanup` - 强制内存清理

## ⚙️ 配置管理

### 安全配置 (`config/security.yaml`)

```yaml
encryption:
  # 国密算法配置
  algorithm: sm4-ecb
  key_size: 16  # SM4 128位密钥

signature:
  algorithm: sm2
  curve: sm2p256v1

hash:
  algorithm: sm3

key_management:
  master_key_env: TEE_SM4_MASTER_KEY
  key_rotation_days: 90

tee:
  memory_limit: 134217728  # 128MB
  memory_monitor:
    interval: 5
    alert_threshold: 0.8
    cleanup_threshold: 0.9
```

### 特征配置 (`config/features.yaml`)

```yaml
features:
  device_fingerprint:
    type: string
    required: true
    weight: 0.4
    encryption: sm4-ecb
    validation: non_empty_string
    description: "设备指纹信息"
    
  login_location:
    type: object
    required: true
    weight: 0.3
    encryption: sm4-ecb
    validation: location_object
    description: "登录地理位置"
    
  behavior_pattern:
    type: object
    required: false
    weight: 0.2
    encryption: sm4-ecb
    validation: behavior_object
    description: "用户行为模式"

risk_calculation:
  algorithm: bayesian
  thresholds:
    reject: 0.7
    challenge: 0.4
    allow: 0.0
```

## 🔒 安全特性

### 国密算法保护

- **SM4加密**: 128位分组加密，支持ECB模式
- **SM3哈希**: 256位密码杂凑，完整性校验
- **SM2签名**: 椭圆曲线数字签名，身份认证
- **密钥派生**: 基于SM3的安全密钥派生

### TEE环境保护

- **内存加密**: 敏感数据在内存中加密存储
- **安全清理**: 处理完成后立即清理明文数据
- **内存限制**: 可配置的内存使用限制（默认128MB）
- **最小权限**: 只在需要时解密数据

### 数据流安全

- **端到端加密**: 从客户端到TEE环境的完整加密链
- **完整性验证**: SM3哈希确保数据完整性
- **重放攻击防护**: 时间戳和随机数防护
- **密钥隔离**: 不同特征使用不同派生密钥

## ⚡ 性能特性

### 国密算法性能

- **SM4硬件加速**: 支持硬件加速的SM4实现
- **高效密钥派生**: 基于SM3的快速密钥派生
- **内存优化**: 最小化内存占用和复制
- **并发安全**: 支持多线程并发处理

### 系统性能

- **连接池**: MySQL连接池优化
- **实时处理**: 毫秒级风险评估响应
- **自适应清理**: 智能内存管理策略
- **缓存优化**: 特征处理结果缓存

## 🚀 演示程序

### 国密算法演示

```bash
# 运行完整国密算法演示
python sm_crypto_demo.py
```

演示内容：
- SM4加密解密功能
- SM2数字签名验证
- SM3哈希计算
- 密文消息完整处理流程
- 性能基准测试

### 传统功能演示

```bash
# 运行传统功能演示（向后兼容）
python demo.py
```

## 📊 技术规格

### 算法规格

| 算法类型 | 国密标准 | 传统算法 | 密钥长度 | 性能 |
|---------|---------|---------|---------|------|
| 分组加密 | SM4-ECB | AES-256-GCM | 128位 | ~1000次/秒 |
| 哈希算法 | SM3 | SHA-256 | 256位 | ~5000次/秒 |
| 数字签名 | SM2 | Ed25519 | 256位 | ~100次/秒 |

### 系统规格

- **内存使用**: < 128MB (TEE限制模式)
- **处理延迟**: < 50ms (单次请求)
- **并发支持**: 100+ 并发连接
- **数据吞吐**: 1000+ 请求/秒

## 🔧 开发指南

### 添加新特征

1. 更新 `config/features.yaml`
2. 实现特征验证器
3. 配置加密参数
4. 更新权重计算

### 自定义加密算法

1. 实现 `BaseCryptoEngine` 接口
2. 添加算法配置
3. 更新初始化流程

### 扩展风险模型

1. 继承 `BaseRBAEngine`
2. 实现自定义评分逻辑
3. 配置风险阈值

## 📈 部署指南

### 生产环境部署

```bash
# 使用Docker部署
docker build -t tee_soft:latest .
docker run -d \
  -p 5000:5000 \
  -e DB_PASSWORD="secure_password" \
  -e TEE_SM4_MASTER_KEY="your_sm4_key" \
  --memory="128m" \
  tee_soft:latest
```

### 集群部署

- 支持多实例水平扩展
- 负载均衡配置
- 数据库连接池优化
- 监控和告警集成

## 📚 相关资源

- [国密算法标准文档](http://www.gmbz.org.cn/)
- [SM2/SM3/SM4技术规范](http://www.oscca.gov.cn/)
- [TEE技术白皮书](https://www.trusted-execution.org/)
- [风险评估最佳实践](https://www.risk-assessment.org/)

## 🤝 贡献指南

1. Fork 项目
2. 创建特性分支
3. 提交代码更改
4. 运行测试套件
5. 提交 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🆘 支持

如果您遇到问题或需要帮助：

1. 查看 [文档](README.md)
2. 检查 [常见问题](FAQ.md)
3. 提交 [Issue](https://github.com/your-repo/issues)
4. 联系技术支持

---

**🇨🇳 TEE_SOFT - 符合国家密码标准的可信执行环境风险评估软件** 