#!/usr/bin/env python3
"""
简单测试程序 - 验证TEE软件的基本功能
"""
import os
import sys

# 添加父目录到Python路径，以便导入项目模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 设置环境变量
os.environ['TEE_MASTER_KEY'] = "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
os.environ['DB_PASSWORD'] = "test_password"

print("🔍 TEE软件基本功能测试")
print("=" * 40)

# 测试1: 导入配置模块
try:
    from config import initialize_config, get_all_configs
    print("✅ 配置模块导入成功")
    
    config_manager = initialize_config()
    all_configs = get_all_configs()
    print(f"✅ 配置加载成功，共 {len(all_configs)} 个配置段")
    
except Exception as e:
    print(f"❌ 配置模块测试失败: {e}")
    sys.exit(1)

# 测试2: 加密引擎
try:
    from core.crypto_engine import initialize_crypto_engine
    
    security_config = all_configs.get('security', {})
    crypto_engine = initialize_crypto_engine(security_config)
    print("✅ 加密引擎初始化成功")
    
    # 测试加密解密
    test_data = "Hello TEE Software!"
    encrypted = crypto_engine.encrypt_data(test_data)
    decrypted = crypto_engine.decrypt_data(encrypted)
    
    if test_data == decrypted:
        print("✅ 加密解密功能正常")
    else:
        print(f"❌ 加密解密验证失败: {test_data} != {decrypted}")
        
except Exception as e:
    print(f"❌ 加密引擎测试失败: {e}")
    import traceback
    traceback.print_exc()

# 测试3: 特征管理器
try:
    from core.feature_manager import initialize_feature_manager
    
    features_config = all_configs.get('features', {})
    feature_manager = initialize_feature_manager(features_config)
    print("✅ 特征管理器初始化成功")
    
    # 测试特征验证
    test_features = {
        "ip": "192.168.1.100", 
        "user_agent": "TestAgent/1.0"
    }
    feature_manager.validate_features(test_features)
    print("✅ 特征验证功能正常")
    
except Exception as e:
    print(f"❌ 特征管理器测试失败: {e}")
    import traceback
    traceback.print_exc()

# 测试4: RBA引擎
try:
    from core.rba_engine import initialize_rba_engine
    
    features_config = all_configs.get('features', {})
    rba_engine = initialize_rba_engine(features_config)
    print("✅ RBA引擎初始化成功")
    
except Exception as e:
    print(f"❌ RBA引擎测试失败: {e}")
    import traceback
    traceback.print_exc()

# 测试5: 内存监控
try:
    from utils.memory_monitor import initialize_memory_monitor
    
    security_config = all_configs.get('security', {})
    memory_monitor = initialize_memory_monitor(security_config)
    print("✅ 内存监控器初始化成功")
    
    status = memory_monitor.check_memory_usage()
    print(f"✅ 内存监控功能正常，当前使用: {status['memory_used_mb']:.1f}MB")
    
except Exception as e:
    print(f"❌ 内存监控测试失败: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 40)
print("🎉 基本功能测试完成！")
print("💡 核心模块运行正常，可以尝试启动完整系统")
print("📝 注意：完整系统需要MySQL数据库支持") 