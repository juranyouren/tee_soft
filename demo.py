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

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def demo_encryption():
    """演示加密功能"""
    logger.info("=== 演示加密功能 ===")
    
    try:
        from core.crypto_engine import initialize_crypto_engine
        from config import get_security_config
        
        # 初始化加密引擎
        security_config = get_security_config()
        crypto_engine = initialize_crypto_engine(security_config)
        
        # 测试数据
        test_data = {
            "ip": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "rtt": 45.2
        }
        
        logger.info(f"原始数据: {test_data}")
        
        # 加密数据
        encrypted_data = crypto_engine.encrypt_features(test_data)
        logger.info("✅ 数据加密成功")
        
        # 解密数据
        decrypted_data = crypto_engine.decrypt_features(encrypted_data)
        logger.info(f"解密数据: {decrypted_data}")
        
        # 验证数据一致性
        if test_data == decrypted_data:
            logger.info("✅ 加密解密验证成功")
        else:
            logger.error("❌ 加密解密验证失败")
            
        return True
        
    except Exception as e:
        logger.error(f"❌ 加密演示失败: {e}")
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
    
    # 检查环境变量
    if not os.getenv('TEE_MASTER_KEY'):
        logger.warning("⚠️  TEE_MASTER_KEY 未设置，使用临时密钥")
        os.environ['TEE_MASTER_KEY'] = "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
    
    if not os.getenv('DB_PASSWORD'):
        logger.warning("⚠️  DB_PASSWORD 未设置，使用默认值")
        os.environ['DB_PASSWORD'] = "demo_password"
    
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
        ("加密功能", demo_encryption),
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
        logger.info(f"{status} {demo_name}")
        if success:
            passed += 1
    
    success_rate = (passed / total) * 100
    logger.info(f"\n通过率: {passed}/{total} ({success_rate:.1f}%)")
    
    if success_rate >= 75:
        logger.info("🎉 TEE软件核心功能运行正常！")
        logger.info("💡 您现在可以尝试运行完整的系统（需要MySQL数据库）")
        return True
    else:
        logger.error("⚠️  部分功能存在问题，请检查配置和依赖")
        return False


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1) 