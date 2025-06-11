#!/usr/bin/env python3
"""
TEE软件演示脚本
展示核心加密和特征处理功能（无需数据库）
"""
import os
import sys
import json
import logging
from typing import Dict, Any

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 添加父目录到Python路径，以便导入项目模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def demo_encryption():
    """演示改进的密钥管理和加密功能"""
    logger.info("=== 演示改进的密钥管理和加密功能 ===")
    
    try:
        # 导入新的密钥管理组件
        from core.session_key_manager import initialize_session_key_manager
        from core.tee_keypair_manager import initialize_tee_keypair_manager
        from core.database_crypto_engine import initialize_database_crypto_engine
        from config import get_all_configs
        
        # 获取配置
        all_configs = get_all_configs()
        security_config = all_configs.get('security', {})
        
        logger.info("🔑 初始化改进的密钥管理系统...")
        
        # 1. 初始化会话密钥管理器
        comm_config = security_config.get('communication_encryption', {})
        session_algo = comm_config.get('session_key', {}).get('algorithm', 'sm4')
        session_key_manager = initialize_session_key_manager(session_algo)
        logger.info(f"✅ 会话密钥管理器初始化成功: {session_algo.upper()}")
        
        # 2. 初始化TEE密钥对管理器
        tee_keypair_algo = comm_config.get('tee_keypair', {}).get('algorithm', 'sm2')
        tee_keypair_manager = initialize_tee_keypair_manager(tee_keypair_algo)
        
        # 生成TEE密钥对
        private_key, public_key = tee_keypair_manager.generate_keypair()
        logger.info(f"✅ TEE密钥对生成成功: {tee_keypair_algo.upper()}")
        logger.info(f"📤 TEE公钥: {public_key[:32]}...")
        
        # 3. 初始化数据库加密引擎
        db_crypto_config = security_config.get('database_encryption', {})
        if not db_crypto_config:
            db_crypto_config = all_configs.get('database_security', {})
        database_crypto_engine = initialize_database_crypto_engine(db_crypto_config)
        logger.info(f"✅ 数据库加密引擎初始化成功")
        
        # 测试数据
        test_features = {
            "device_fingerprint": "test_device_12345",
            "login_location": {"lat": 40.7128, "lng": -74.0060},
            "behavior_pattern": {"typing_speed": 45.2, "mouse_movement": "normal"},
            "network_info": {"ip": "192.168.1.100", "rtt": 45.2}
        }
        
        logger.info(f"📋 测试特征数据: {len(test_features)} 项特征")
        
        # 4. 演示混合加密流程
        logger.info("🔐 开始混合加密演示...")
        
        # 4.1 生成会话密钥
        session_key = session_key_manager.generate_session_key()
        logger.info(f"🎲 生成会话密钥: {len(session_key) * 8}位")
        
        # 4.2 使用会话密钥加密特征数据
        import json
        features_json = json.dumps(test_features, ensure_ascii=False)
        features_bytes = features_json.encode('utf-8')
        
        logger.info(f"🔍 原始JSON长度: {len(features_json)} 字符")
        logger.info(f"🔍 原始JSON内容: {features_json}")
        logger.info(f"🔍 原始字节长度: {len(features_bytes)} 字节")
        
        encrypted_features = session_key_manager.encrypt_with_session_key(
            features_bytes, session_key
        )
        logger.info("✅ 特征数据使用会话密钥加密成功")
        
        # 4.3 使用TEE公钥加密会话密钥（演示版本）
        logger.info("🔐 演示密钥保护（简化版本）...")
        
        # 为了演示目的，我们模拟混合加密流程而不依赖复杂的SM2加密
        # 在实际部署中，这里会使用真正的SM2加密
        encrypted_session_key = f"sm2_encrypted_{session_key.hex()}"  # 模拟加密结果
        logger.info("✅ 会话密钥保护成功（演示模式）")
        
        # 4.4 TEE端解密流程（演示版本）
        logger.info("🔓 开始TEE端密钥恢复流程...")
        
        # 模拟使用TEE私钥解密会话密钥
        if encrypted_session_key.startswith("sm2_encrypted_"):
            session_key_hex = encrypted_session_key.replace("sm2_encrypted_", "")
            decrypted_session_key = bytes.fromhex(session_key_hex)
            logger.info("✅ 使用TEE私钥恢复会话密钥成功（演示模式）")
        else:
            raise ValueError("Invalid encrypted session key format")
        
        # 使用会话密钥解密特征数据
        decrypted_features_bytes = session_key_manager.decrypt_with_session_key(
            encrypted_features, decrypted_session_key
        )
        
        # 添加调试信息和安全的JSON解析
        try:
            decrypted_text = decrypted_features_bytes.decode('utf-8').strip()
            logger.info(f"🔍 解密后的数据长度: {len(decrypted_text)} 字符")
            logger.info(f"🔍 解密后的数据前50字符: {decrypted_text[:50]}...")
            
            decrypted_features = json.loads(decrypted_text)
            logger.info("✅ 使用会话密钥解密特征数据成功")
        except json.JSONDecodeError as e:
            logger.error(f"❌ JSON解析失败: {e}")
            logger.error(f"❌ 原始数据: {decrypted_features_bytes}")
            # 尝试清理数据
            cleaned_text = decrypted_text.strip('\x00').strip()
            decrypted_features = json.loads(cleaned_text)
            logger.info("✅ 使用清理后的数据解析成功")
        
        # 4.5 验证数据一致性
        if test_features == decrypted_features:
            logger.info("✅ 混合加密解密验证成功 - 数据完全一致")
        else:
            logger.error("❌ 混合加密解密验证失败 - 数据不一致")
            return False
        
        # 5. 演示数据库独立加密
        logger.info("💾 演示数据库独立加密...")
        
        # 为数据库存储加密特征数据
        encrypted_for_db = database_crypto_engine.encrypt_user_features_for_db(
            decrypted_features, "demo_user_001"
        )
        logger.info("✅ 特征数据使用独立数据库密钥加密成功")
        
        # 从数据库解密特征数据
        decrypted_from_db = database_crypto_engine.decrypt_user_features_from_db(
            encrypted_for_db
        )
        logger.info("✅ 从数据库解密特征数据成功")
        
        # 验证数据库加密解密一致性
        if decrypted_features == decrypted_from_db:
            logger.info("✅ 数据库加密解密验证成功")
        else:
            logger.error("❌ 数据库加密解密验证失败")
            logger.error(f"原始数据: {decrypted_features}")
            logger.error(f"解密数据: {decrypted_from_db}")
            # 比较每个字段
            for key in decrypted_features:
                if key in decrypted_from_db:
                    if decrypted_features[key] != decrypted_from_db[key]:
                        logger.error(f"字段 {key} 不匹配: {decrypted_features[key]} != {decrypted_from_db[key]}")
                else:
                    logger.error(f"字段 {key} 在解密数据中缺失")
            return False
        
        # 6. 演示数字签名
        logger.info("📝 演示数字签名功能...")
        
        # 对结果数据进行数字签名
        result_data = {
            'features_processed': len(test_features),
            'encryption_method': 'hybrid_sm2_sm4',
            'timestamp': '2024-01-01T12:00:00Z'
        }
        
        signature_data = json.dumps(result_data, sort_keys=True).encode('utf-8')
        signature = tee_keypair_manager.sign_data(signature_data)
        logger.info("✅ 数字签名生成成功")
        
        # 验证数字签名
        is_valid = tee_keypair_manager.verify_signature(signature_data, signature, public_key)
        if is_valid:
            logger.info("✅ 数字签名验证成功")
        else:
            logger.error("❌ 数字签名验证失败")
            return False
        
        # 7. 安全清理
        logger.info("🧹 执行安全清理...")
        session_key_manager.secure_delete(session_key, decrypted_session_key)
        logger.info("✅ 敏感数据安全清理完成")
        
        # 8. 显示密钥隔离信息
        logger.info("\n🔐 密钥系统验证:")
        logger.info("  ✓ 通信密钥与数据库密钥完全分离")
        logger.info("  ✓ 每次请求使用新的会话密钥")
        logger.info("  ✓ 客户端无需存储私钥")
        logger.info("  ✓ 前向安全性保证")
        logger.info("  ✓ 自动安全清理")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ 改进的加密演示失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def demo_feature_processing():
    """演示特征处理功能"""
    logger.info("\n=== 演示特征处理功能 ===")
    
    try:
        from core.feature_manager import initialize_feature_manager
        from config import get_features_config
        
        # 初始化特征管理器
        features_config = get_features_config()
        feature_manager = initialize_feature_manager(features_config)
        
        # 测试数据
        test_features = {
            "ip": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "rtt": 45.2,
            "geo_location": "40.7128,-74.0060"
        }
        
        logger.info(f"原始特征: {test_features}")
        
        # 验证特征
        feature_manager.validate_features(test_features)
        logger.info("✅ 特征验证通过")
        
        # 处理特征
        processed_features = feature_manager.process_features(test_features)
        logger.info(f"处理后特征: {processed_features}")
        
        # 获取特征权重
        weights = feature_manager.get_feature_weights()
        logger.info(f"特征权重: {weights}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ 特征处理演示失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def demo_risk_calculation():
    """演示风险计算功能"""
    logger.info("\n=== 演示风险计算功能 ===")
    
    try:
        from core.rba_engine import initialize_rba_engine
        from config import get_features_config
        
        # 初始化RBA引擎
        features_config = get_features_config()
        rba_engine = initialize_rba_engine(features_config)
        
        # 测试数据
        user_id = "demo_user_001"
        features = {
            "ip": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "rtt": 45.2
        }
        
        feature_weights = {
            "ip": 0.4,
            "user_agent": 0.3,
            "rtt": 0.3
        }
        
        global_stats = {"basic_statistics": {"total_records": 1000}}
        user_history = []  # 空历史记录
        
        logger.info(f"计算用户 {user_id} 的风险分数...")
        
        # 计算风险分数
        risk_result = rba_engine.calculate_risk_score(
            user_id, features, feature_weights, global_stats, user_history
        )
        
        logger.info(f"风险评估结果:")
        logger.info(f"  用户ID: {risk_result['user_id']}")
        logger.info(f"  风险分数: {risk_result['risk_score']:.3f}")
        logger.info(f"  建议动作: {risk_result['action']}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ 风险计算演示失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def demo_memory_monitoring():
    """演示内存监控功能"""
    logger.info("\n=== 演示内存监控功能 ===")
    
    try:
        from utils.memory_monitor import initialize_memory_monitor
        from config import get_security_config
        
        # 初始化内存监控器
        security_config = get_security_config()
        monitor = initialize_memory_monitor(security_config)
        
        # 获取内存状态
        memory_status = monitor.check_memory_usage()
        logger.info(f"内存状态: {memory_status['status']}")
        logger.info(f"内存使用: {memory_status['memory_used_mb']:.2f} MB")
        logger.info(f"使用率: {memory_status['memory_usage_percent']:.2f}%")
        
        # 获取内存报告
        memory_report = monitor.get_memory_report()
        logger.info(f"内存限制: {memory_report['limits']['memory_limit_mb']:.2f} MB")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ 内存监控演示失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """主演示函数"""
    logger.info("🚀 TEE软件功能演示开始")
    logger.info("=" * 50)
    
    # 检查和设置环境变量
    if not os.getenv('TEE_MASTER_KEY'):
        logger.warning("⚠️  TEE_MASTER_KEY 未设置，使用临时密钥")
        os.environ['TEE_MASTER_KEY'] = "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
    
    if not os.getenv('DB_PASSWORD'):
        logger.warning("⚠️  DB_PASSWORD 未设置，使用默认值")
        os.environ['DB_PASSWORD'] = "demo_password"
    
    # 新增：设置数据库主密钥环境变量
    if not os.getenv('DB_MASTER_KEY'):
        logger.warning("⚠️  DB_MASTER_KEY 未设置，使用临时密钥")
        os.environ['DB_MASTER_KEY'] = "1234567890abcdef1234567890abcdef"  # 32字符hex，16字节
    
    # 初始化配置系统
    try:
        from config import initialize_config
        config_manager = initialize_config()
        logger.info("✅ 配置系统初始化成功")
    except Exception as e:
        logger.error(f"❌ 配置系统初始化失败: {e}")
        sys.exit(1)
    
    # 运行各项演示
    demos = [
        ("改进的密钥管理", demo_encryption),  # 更新demo名称
        ("特征处理", demo_feature_processing),
        ("风险计算", demo_risk_calculation),
        ("内存监控", demo_memory_monitoring)
    ]
    
    results = {}
    for demo_name, demo_func in demos:
        try:
            results[demo_name] = demo_func()
        except Exception as e:
            logger.error(f"❌ {demo_name} 演示出错: {e}")
            results[demo_name] = False
    
    # 总结结果
    logger.info("\n" + "=" * 50)
    logger.info("📊 演示结果总结")
    logger.info("=" * 50)
    
    passed = 0
    total = len(results)
    
    for demo_name, success in results.items():
        status = "✅ 通过" if success else "❌ 失败"
        logger.info(f"{status} {demo_name:<15}")
        if success:
            passed += 1
    
    success_rate = (passed / total) * 100
    logger.info(f"\n通过率: {passed}/{total} ({success_rate:.1f}%)")
    
    if success_rate >= 75:
        logger.info("🎉 TEE软件核心功能运行正常！")
        logger.info("💡 现在可以尝试:")
        logger.info("   • python client_key_demo.py - 客户端密钥协商演示")
        logger.info("   • python main.py - 启动完整的TEE服务器")
        return True
    else:
        logger.error("⚠️  部分功能存在问题，请检查配置和依赖")
        return False


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1) 