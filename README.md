# TEE_SOFT - 可信执行环境风险评估软件

TEE_SOFT 是一个基于可信执行环境（TEE）的风险评估软件，专门用于处理用户特征数据的安全分析和风险计算。该软件实现了数据加密存储、安全解密计算、基于贝叶斯模型的风险评估等核心功能。

## 🎯 核心功能

- **安全特征处理**: 接收用户特征哈希值，进行加密存储和安全处理
- **TEE环境保护**: 在可信执行环境中进行数据解密和风险计算
- **RBA风险评估**: 基于贝叶斯模型计算用户行为风险分数
- **灵活特征管理**: 支持动态配置特征类型和验证规则
- **内存安全监控**: 实时监控内存使用，自动清理敏感数据
- **加密数据库存储**: 所有敏感数据加密后存储，保护用户隐私

## 🏗️ 系统架构

```
TEE_SOFT
├── 🔐 加密引擎 (AES-256-GCM, Ed25519)
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

# 安装依赖
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
# 必需的环境变量
export DB_PASSWORD="your_secure_password"
export TEE_MASTER_KEY="$(openssl rand -hex 32)"

# 可选的环境变量
export FLASK_HOST="127.0.0.1"
export FLASK_PORT="5000"
export FLASK_DEBUG="false"
```

### 4. 配置文件调整

编辑 `config/database.yaml`:
```yaml
database:
  mysql:
    host: "localhost"
    port: 3306
    database: "risk_assessment"
    user: "tee_user"
    # password 将从环境变量 DB_PASSWORD 读取
```

### 5. 启动服务

```bash
python main.py
```

服务启动后，可通过以下地址访问：
- 健康检查: http://127.0.0.1:5000/health
- 系统状态: http://127.0.0.1:5000/status

## 📡 API 接口

### 主要处理接口

**POST** `/tee_soft/process`

处理用户特征数据并返回风险评估结果。

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

**响应示例**:
```json
{
    "success": true,
    "result": {
        "risk_score": 0.234,
        "action": "ALLOW",
        "stored": true,
        "record_id": 12345,
        "timestamp": 1704110400.0
    }
}
```

### 系统管理接口

- **GET** `/health` - 健康检查
- **GET** `/status` - 系统状态
- **GET** `/tee_soft/public_key` - 获取公钥信息
- **POST** `/admin/cleanup` - 清理旧数据
- **GET** `/admin/memory` - 内存状态
- **POST** `/admin/force_cleanup` - 强制内存清理

## ⚙️ 配置管理

### 特征配置 (`config/features.yaml`)

```yaml
features:
  ip:
    type: string
    required: true
    weight: 0.4
    encryption: aes-256-gcm
    validation: ipv4_or_ipv6
    description: "用户IP地址"
    
  user_agent:
    type: string
    required: true
    weight: 0.3
    encryption: aes-256-gcm
    validation: non_empty_string
    description: "浏览器用户代理字符串"
    
  # 可以轻松添加新特征
  custom_feature:
    type: string
    required: false
    weight: 0.1
    encryption: aes-256-gcm
    validation: non_empty_string
    description: "自定义特征"

risk_calculation:
  algorithm: bayesian
  thresholds:
    reject: 0.7
    challenge: 0.4
    allow: 0.0
```

### 安全配置 (`config/security.yaml`)

```yaml
encryption:
  algorithm: aes-256-gcm
  key_size: 32
  nonce_size: 12
  tag_size: 16

tee:
  memory_limit: 134217728  # 128MB
  memory_monitor:
    interval: 5
    alert_threshold: 0.8
    cleanup_threshold: 0.9

key_management:
  master_key_env: "TEE_MASTER_KEY"
  key_rotation_hours: 24
```

## 🔒 安全特性

### 数据加密
- **算法**: AES-256-GCM (认证加密)
- **密钥管理**: HKDF-SHA256 密钥派生
- **数字签名**: Ed25519

### TEE保护
- **内存加密**: 敏感数据在内存中加密
- **安全清理**: 处理完成后立即清理明文数据
- **最小权限**: 只在需要时解密数据

### 隐私保护
- **加密存储**: 数据库中只存储加密数据
- **哈希处理**: 特征值计算安全哈希
- **访问控制**: 严格的API访问控制

## 📊 内存管理

### 监控模式
- **实时监控**: 每5秒检查一次内存使用
- **自动报警**: 使用率超过80%时报警
- **自动清理**: 使用率超过90%时强制清理

### 限制模式
```bash
# 128MB限制模式
export TEE_MEMORY_LIMIT=134217728

# 无限制模式
export TEE_MEMORY_LIMIT=0
```

## 🔧 开发和调试

### 开发模式

```bash
export FLASK_DEBUG=true
python main.py
```

### 日志查看

```bash
# 查看应用日志
tail -f logs/tee_soft.log

# 查看审计日志
tail -f logs/tee_audit.log
```

### 数据库查询

```sql
-- 查看风险日志
SELECT user_id, risk_score, action, created_at 
FROM risk_logs 
ORDER BY created_at DESC 
LIMIT 10;

-- 查看特征统计
SELECT feature_name, COUNT(*) as count 
FROM feature_history 
GROUP BY feature_name;
```

## 🧪 测试

### 功能测试

```bash
# 健康检查
curl http://127.0.0.1:5000/health

# 处理请求测试
curl -X POST http://127.0.0.1:5000/tee_soft/process \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "test_user",
    "features": {
      "ip": "192.168.1.1",
      "user_agent": "Mozilla/5.0...",
      "rtt": 25.5
    }
  }'
```

### 压力测试

```bash
# 使用 ab 进行压力测试
ab -n 1000 -c 10 -T application/json -p test_data.json \
   http://127.0.0.1:5000/tee_soft/process
```

## 🐛 故障排除

### 常见问题

1. **数据库连接失败**
   ```
   检查 DB_PASSWORD 环境变量
   确认 MySQL 服务运行状态
   验证数据库用户权限
   ```

2. **内存使用过高**
   ```
   检查 /admin/memory 接口
   执行 /admin/force_cleanup
   调整 memory_limit 配置
   ```

3. **加密失败**
   ```
   检查 TEE_MASTER_KEY 环境变量
   确认密钥格式正确（64位十六进制）
   ```

### 日志级别调整

```python
# 在 main.py 中调整日志级别
logging.basicConfig(level=logging.DEBUG)  # 详细日志
logging.basicConfig(level=logging.WARNING)  # 只显示警告和错误
```

## 🔄 生产部署

### 使用 Gunicorn

```bash
# 安装 gunicorn
pip install gunicorn

# 启动服务
gunicorn -w 4 -b 0.0.0.0:5000 main:app
```

### Docker 部署

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY . .

RUN pip install -r requirements.txt

EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "main:app"]
```

### 系统服务配置

```ini
# /etc/systemd/system/tee-soft.service
[Unit]
Description=TEE Software
After=network.target

[Service]
Type=simple
User=tee-user
WorkingDirectory=/opt/tee_software
Environment=DB_PASSWORD=your_password
Environment=TEE_MASTER_KEY=your_master_key
ExecStart=/opt/tee_software/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 main:app
Restart=always

[Install]
WantedBy=multi-user.target
```

## 📄 许可证

本项目采用 MIT 许可证。详见 LICENSE 文件。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📞 支持

如有问题，请通过以下方式联系：
- 提交 GitHub Issue
- 邮件联系: support@example.com

---

**TEE_SOFT** - 保护数据隐私，确保安全计算 🔒 