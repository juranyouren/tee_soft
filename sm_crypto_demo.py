#!/usr/bin/env python3
"""
国密算法演示程序
展示TEE软件的国密算法改进：
1. 输入密文消息，解密后得到明文
2. 使用SM4、SM3、SM2国密算法替代原有算法
"""
import os
import json
import time
from typing import Dict, Any, List
from datetime import datetime, timezone

# 设置演示环境变量
os.environ['TEE_SM4_MASTER_KEY'] = 'a1b2c3d4e5f6789012345678901234567890abcdef123456789012345678901234'

from core.sm_crypto_engine import initialize_sm_crypto_engine, get_sm_crypto_engine
from core.feature_manager import initialize_feature_manager, get_feature_manager
from core.rba_engine import initialize_rba_engine, get_rba_engine
from core.tee_processor import initialize_tee_processor, get_tee_processor
from config import get_all_configs


def print_header(title: str):
    """打印格式化的标题"""
    print("\n" + "="*80)
    print(f"🇨🇳 {title}")
    print("="*80)


def print_section(title: str):
    """打印章节标题"""
    print(f"\n📍 {title}")
    print("-" * 50)


def demo_sm_algorithms():
    """演示国密算法基础功能"""
    print_header("国密算法基础功能演示")
    
    # 初始化配置
    config = {
        'encryption': {
            'algorithm': 'sm4-cbc',
            'key_size': 128
        },
        'key_management': {
            'master_key_env': 'TEE_SM4_MASTER_KEY'
        }
    }
    
    # 初始化国密加密引擎
    crypto_engine = initialize_sm_crypto_engine(config)
    
    print_section("算法信息")
    algo_info = crypto_engine.get_algorithm_info()
    for key, value in algo_info.items():
        print(f"  {key}: {value}")
    
    print_section("SM2公钥信息")
    public_key_info = crypto_engine.get_public_key_info()
    for key, value in public_key_info.items():
        print(f"  {key}: {value}")
    
    # 演示SM4加密解密
    print_section("SM4加密解密演示")
    
    test_data = {
        "message": "这是一条敏感信息，使用国密SM4算法加密保护",
        "user_id": "user_12345",
        "sensitive_info": {
            "credit_card": "6222 **** **** 1234",
            "phone": "138****5678"
        }
    }
    
    print(f"📝 原始明文数据:")
    print(json.dumps(test_data, ensure_ascii=False, indent=2))
    
    # SM4加密
    print(f"\n🔐 SM4加密中...")
    encrypted_result = crypto_engine.encrypt_data(test_data, "test_message")
    
    print(f"✅ SM4加密完成:")
    print(f"  算法: {encrypted_result['algorithm']}")
    print(f"  密钥用途: {encrypted_result['key_purpose']}")
    print(f"  数据长度: {encrypted_result['data_length']} 字节")
    print(f"  密文长度: {len(encrypted_result['ciphertext'])} 字符")
    print(f"  完整性哈希: {encrypted_result['integrity_hash'][:32]}...")
    
    # SM4解密
    print(f"\n🔓 SM4解密中...")
    decrypted_data = crypto_engine.decrypt_data(encrypted_result)
    
    print(f"✅ SM4解密完成:")
    print(json.dumps(decrypted_data, ensure_ascii=False, indent=2))
    
    # 验证数据一致性
    data_match = json.dumps(test_data, sort_keys=True) == json.dumps(decrypted_data, sort_keys=True)
    print(f"\n🔍 数据一致性验证: {'✅ 通过' if data_match else '❌ 失败'}")
    
    # 演示SM2数字签名
    print_section("SM2数字签名演示")
    
    signature_data = {
        "risk_score": 0.75,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": "user_12345"
    }
    
    print(f"📝 待签名数据:")
    print(json.dumps(signature_data, ensure_ascii=False, indent=2))
    
    # SM2签名
    print(f"\n✍️  SM2签名中...")
    signature = crypto_engine.sign_data(signature_data)
    print(f"✅ SM2签名完成:")
    print(f"  签名长度: {len(signature)} 字符")
    print(f"  签名: {signature[:64]}...")
    
    # SM2验证
    print(f"\n🔍 SM2签名验证中...")
    is_valid = crypto_engine.verify_signature(signature_data, signature)
    print(f"✅ 签名验证: {'✅ 有效' if is_valid else '❌ 无效'}")
    
    # 演示SM3哈希
    print_section("SM3哈希演示")
    
    feature_value = "user_behavior_pattern_12345"
    feature_name = "login_pattern"
    
    hash_result = crypto_engine.hash_feature_value(feature_value, feature_name)
    print(f"📝 特征值: {feature_value}")
    print(f"📝 特征名: {feature_name}")
    print(f"🔍 SM3哈希结果: {hash_result}")
    
    return crypto_engine


def demo_encrypted_message_processing():
    """演示密文消息处理"""
    print_header("密文消息处理演示")
    
    # 初始化配置管理器
    from config import initialize_config
    initialize_config()
    
    # 初始化所有组件
    all_configs = get_all_configs()
    
    # 修改配置使用国密算法
    all_configs['security']['encryption']['algorithm'] = 'sm4-cbc'
    all_configs['security']['key_management']['master_key_env'] = 'TEE_SM4_MASTER_KEY'
    
    # 初始化组件
    crypto_engine = initialize_sm_crypto_engine(all_configs['security'])
    feature_manager = initialize_feature_manager(all_configs['features'])
    rba_engine = initialize_rba_engine(all_configs['features'])
    tee_processor = initialize_tee_processor(all_configs)
    
    print_section("模拟客户端：创建加密消息")
    
    # 模拟客户端特征数据
    client_features = {
        "device_fingerprint": "mobile_ios_safari_15.2_iphone13",
        "login_location": {
            "country": "China",
            "city": "Beijing",
            "ip_range": "110.242.68.0/24"
        },
        "behavior_pattern": {
            "login_time": "09:30:00",
            "typical_duration": 1800,
            "frequency": "daily"
        },
        "biometric_score": 0.95,
        "transaction_amount": 5000.00
    }
    
    print(f"📱 客户端原始特征数据:")
    print(json.dumps(client_features, ensure_ascii=False, indent=2))
    
    # 客户端加密特征数据
    print(f"\n🔐 客户端加密特征数据...")
    encrypted_features = crypto_engine.encrypt_features(client_features)
    
    print(f"✅ 特征数据加密完成 ({len(encrypted_features)} 个特征)")
    for feature_name, encrypted_data in encrypted_features.items():
        print(f"  {feature_name}: {encrypted_data['algorithm']} (长度: {encrypted_data['data_length']} 字节)")
    
    # 构造加密消息
    encrypted_message = {
        "request_id": f"msg_{int(time.time())}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": "110.242.68.66",
        "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_2 like Mac OS X)",
        "encrypted_features": encrypted_features
    }
    
    print(f"\n📦 构造的加密消息:")
    message_summary = {
        "request_id": encrypted_message["request_id"],
        "timestamp": encrypted_message["timestamp"],
        "source_ip": encrypted_message["source_ip"],
        "encrypted_features_count": len(encrypted_features)
    }
    print(json.dumps(message_summary, ensure_ascii=False, indent=2))
    
    print_section("TEE环境：处理加密消息")
    
    # TEE处理器处理加密消息
    print(f"🏭 TEE处理器开始处理加密消息...")
    start_time = time.time()
    
    processing_result = tee_processor.process_encrypted_message(encrypted_message)
    
    processing_time = time.time() - start_time
    print(f"⏱️  处理耗时: {processing_time*1000:.2f} 毫秒")
    
    print_section("TEE处理结果")
    
    # 显示处理结果
    result_summary = {
        "request_id": processing_result["request_id"],
        "status": processing_result["status"],
        "processing_time_ms": processing_result["processing_time_ms"],
        "feature_count": processing_result["feature_count"],
        "signature_algorithm": processing_result["signature_algorithm"]
    }
    
    print(f"📊 处理结果摘要:")
    print(json.dumps(result_summary, ensure_ascii=False, indent=2))
    
    print(f"\n🔍 特征分析结果:")
    feature_analysis = processing_result["feature_analysis"]
    print(f"  分析的特征数: {feature_analysis['processed_features']}")
    print(f"  处理状态: {feature_analysis['status']}")
    
    print(f"\n⚠️  风险评估结果:")
    risk_assessment = processing_result["risk_assessment"]
    print(f"  风险分数: {risk_assessment['risk_score']:.3f}")
    print(f"  风险等级: {risk_assessment['risk_level']}")
    print(f"  建议行动: {risk_assessment['action']}")
    
    print(f"\n💾 内存使用情况:")
    memory_usage = processing_result["memory_usage"]
    print(f"  进程内存: {memory_usage['process_memory_mb']:.2f} MB")
    print(f"  系统可用内存: {memory_usage['available_memory_mb']:.2f} MB")
    
    print_section("数字签名验证")
    
    # 验证处理结果的数字签名
    signature = processing_result.pop('digital_signature')
    is_signature_valid = crypto_engine.verify_signature(processing_result, signature)
    
    print(f"🔍 验证TEE处理结果签名...")
    print(f"✅ 签名验证: {'✅ 有效' if is_signature_valid else '❌ 无效'}")
    print(f"📝 签名算法: SM2")
    print(f"📝 签名长度: {len(signature)} 字符")
    
    return processing_result


def demo_response_encryption():
    """演示响应加密"""
    print_header("响应加密演示")
    
    tee_processor = get_tee_processor()
    
    # 模拟处理结果
    response_data = {
        "user_id": "user_12345",
        "risk_assessment": {
            "risk_score": 0.25,
            "risk_level": "low",
            "action": "allow"
        },
        "recommendations": [
            "用户行为正常，建议继续监控",
            "设备指纹匹配，风险较低"
        ],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    print(f"📊 待加密的响应数据:")
    print(json.dumps(response_data, ensure_ascii=False, indent=2))
    
    # 加密响应
    print(f"\n🔐 加密响应数据...")
    encrypted_response = tee_processor.encrypt_response(response_data)
    
    print(f"✅ 响应加密完成:")
    encryption_info = encrypted_response["encryption_info"]
    print(f"  算法: {encryption_info['algorithm']}")
    print(f"  密钥派生: {encryption_info['key_derivation']}")
    print(f"  数字签名: {encryption_info['signature']}")
    print(f"  加密时间: {encryption_info['timestamp']}")
    
    # 解密验证
    print(f"\n🔓 解密验证...")
    crypto_engine = get_sm_crypto_engine()
    decrypted_response = crypto_engine.decrypt_data(encrypted_response["encrypted_response"])
    
    print(f"✅ 解密验证成功:")
    print(json.dumps(decrypted_response, ensure_ascii=False, indent=2))
    
    # 验证数据一致性
    data_match = json.dumps(response_data, sort_keys=True) == json.dumps(decrypted_response, sort_keys=True)
    print(f"\n🔍 数据一致性验证: {'✅ 通过' if data_match else '❌ 失败'}")


def demo_performance_comparison():
    """演示性能对比"""
    print_header("国密算法性能测试")
    
    crypto_engine = get_sm_crypto_engine()
    
    # 测试数据
    test_datasets = [
        {"name": "小数据", "data": "测试消息123", "iterations": 1000},
        {"name": "中等数据", "data": {"user": "test", "features": list(range(100))}, "iterations": 500},
        {"name": "大数据", "data": {"features": {f"feature_{i}": f"value_{i}" for i in range(1000)}}, "iterations": 100}
    ]
    
    print_section("性能测试结果")
    
    for test in test_datasets:
        print(f"\n📊 {test['name']} 测试 (迭代次数: {test['iterations']})")
        
        # SM4加密性能测试
        start_time = time.time()
        for _ in range(test['iterations']):
            encrypted = crypto_engine.encrypt_data(test['data'], "performance_test")
        encrypt_time = time.time() - start_time
        
        # SM4解密性能测试
        start_time = time.time()
        for _ in range(test['iterations']):
            decrypted = crypto_engine.decrypt_data(encrypted)
        decrypt_time = time.time() - start_time
        
        # SM2签名性能测试
        start_time = time.time()
        for _ in range(min(test['iterations'], 100)):  # 签名操作相对较慢
            signature = crypto_engine.sign_data(test['data'])
        sign_time = time.time() - start_time
        sign_iterations = min(test['iterations'], 100)
        
        # SM2验证性能测试
        start_time = time.time()
        for _ in range(sign_iterations):
            verified = crypto_engine.verify_signature(test['data'], signature)
        verify_time = time.time() - start_time
        
        print(f"  SM4加密: {encrypt_time*1000/test['iterations']:.3f} ms/次")
        print(f"  SM4解密: {decrypt_time*1000/test['iterations']:.3f} ms/次")
        print(f"  SM2签名: {sign_time*1000/sign_iterations:.3f} ms/次")
        print(f"  SM2验证: {verify_time*1000/sign_iterations:.3f} ms/次")


def main():
    """主函数"""
    print_header("TEE软件国密算法改进演示")
    
    print("""
🎯 本演示程序展示以下改进：
  1. 📥 输入密文消息，TEE环境解密后处理
  2. 🇨🇳 使用国密算法替代原有加密算法
     • SM4-ECB 替代 AES-256-GCM
     • SM3 替代 SHA-256  
     • SM2 替代 Ed25519
  3. 🔐 端到端的加密通信流程
  4. ⚡ 高性能的国密算法实现
    """)
    
    try:
        # 1. 国密算法基础演示
        crypto_engine = demo_sm_algorithms()
        
        # 2. 密文消息处理演示
        processing_result = demo_encrypted_message_processing()
        
        # 3. 响应加密演示
        demo_response_encryption()
        
        # 4. 性能测试
        demo_performance_comparison()
        
        print_header("演示完成")
        print("""
✅ 国密算法改进演示完成！

🔒 安全特性：
  • 符合国家密码标准 (GB/T 32907, GB/T 32905, GB/T 32918)
  • 商用密码安全等级
  • 端到端加密保护
  • 数字签名保证完整性

⚡ 性能优势：
  • SM4硬件加速支持
  • 高效的密钥派生
  • 内存安全管理
  • 实时处理能力

🏭 应用场景：
  • 金融支付系统
  • 政务服务平台  
  • 企业内部系统
  • 物联网设备认证
        """)
        
    except Exception as e:
        print(f"\n❌ 演示过程中发生错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main() 