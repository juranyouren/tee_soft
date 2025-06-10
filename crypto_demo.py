#!/usr/bin/env python3
"""
TEE软件加密方法演示程序
展示项目中使用的各种加密技术和安全特性
"""
import os
import json
import time
from typing import Dict, Any
from core.crypto_engine import CryptoEngine


def print_header(title: str):
    """打印格式化的标题"""
    print("\n" + "="*60)
    print(f"🔐 {title}")
    print("="*60)


def print_section(title: str):
    """打印章节标题"""
    print(f"\n📍 {title}")
    print("-" * 40)


def demo_basic_encryption():
    """演示基本的加密解密功能"""
    print_header("TEE软件加密方法演示")
    
    # 模拟配置
    config = {
        'encryption': {
            'algorithm': 'aes-256-gcm',
            'nonce_size': 12
        },
        'key_management': {
            'master_key_env': 'TEE_DEMO_MASTER_KEY'
        }
    }
    
    # 设置演示用的主密钥
    demo_master_key = os.urandom(32).hex()
    os.environ['TEE_DEMO_MASTER_KEY'] = demo_master_key
    print(f"🔑 演示主密钥: {demo_master_key[:16]}...")
    
    # 初始化加密引擎
    crypto_engine = CryptoEngine(config)
    
    print_section("1. 基本数据加密/解密")
    
    # 测试不同类型的数据
    test_data = [
        "Hello, TEE World!",
        {"user_id": "user123", "action": "login", "timestamp": time.time()},
        ["ip_address", "user_agent", "device_fingerprint"],
        12345,
        {"complex": {"nested": {"data": "with multiple levels"}}}
    ]
    
    for i, data in enumerate(test_data, 1):
        print(f"\n🔹 测试数据 {i}: {data}")
        print(f"   数据类型: {type(data).__name__}")
        
        # 加密
        encrypted = crypto_engine.encrypt_data(data, f"test_purpose_{i}")
        print(f"   ✅ 加密成功")
        print(f"   📦 密文长度: {len(encrypted['ciphertext'])} 字符")
        print(f"   🎲 随机数: {encrypted['nonce'][:16]}...")
        print(f"   🏷️ 认证标签: {encrypted['tag'][:16]}...")
        
        # 解密
        decrypted = crypto_engine.decrypt_data(encrypted)
        print(f"   ✅ 解密成功")
        print(f"   📋 解密结果: {decrypted}")
        print(f"   ✔️ 数据一致性: {'通过' if data == decrypted else '失败'}")


def demo_feature_encryption():
    """演示特征数据加密"""
    print_section("2. 特征数据加密/解密")
    
    config = {
        'encryption': {'algorithm': 'aes-256-gcm', 'nonce_size': 12},
        'key_management': {'master_key_env': 'TEE_DEMO_MASTER_KEY'}
    }
    crypto_engine = CryptoEngine(config)
    
    # 模拟用户特征数据
    user_features = {
        'ip': {'address': '192.168.1.100', 'version': 4, 'is_private': True},
        'user_agent': {
            'browser': 'Chrome',
            'version': '120.0',
            'os': 'Windows',
            'is_mobile': False
        },
        'geo_location': {'latitude': 39.9042, 'longitude': 116.4074, 'region': 'China'},
        'device_fingerprint': {
            'screen_resolution': '1920x1080',
            'timezone': 'Asia/Shanghai',
            'language': 'zh-CN'
        },
        'rtt': {'value': 45.2, 'category': 'excellent'}
    }
    
    print("🔹 原始特征数据:")
    for feature_name, feature_value in user_features.items():
        print(f"   {feature_name}: {feature_value}")
    
    # 加密所有特征
    print("\n🔐 加密特征数据...")
    encrypted_features = crypto_engine.encrypt_features(user_features)
    
    print("✅ 特征加密完成:")
    for feature_name, encrypted_data in encrypted_features.items():
        print(f"   {feature_name}:")
        print(f"     算法: {encrypted_data['algorithm']}")
        print(f"     密文: {encrypted_data['ciphertext'][:32]}...")
        print(f"     随机数: {encrypted_data['nonce']}")
    
    # 解密所有特征
    print("\n🔓 解密特征数据...")
    decrypted_features = crypto_engine.decrypt_features(encrypted_features)
    
    print("✅ 特征解密完成:")
    verification_passed = True
    for feature_name, decrypted_value in decrypted_features.items():
        original_value = user_features[feature_name]
        is_match = original_value == decrypted_value
        verification_passed &= is_match
        
        print(f"   {feature_name}: {'✔️' if is_match else '❌'}")
        if not is_match:
            print(f"     原始: {original_value}")
            print(f"     解密: {decrypted_value}")
    
    print(f"\n🎯 整体验证结果: {'✅ 通过' if verification_passed else '❌ 失败'}")


def demo_digital_signature():
    """演示数字签名功能"""
    print_section("3. 数字签名验证")
    
    config = {
        'encryption': {'algorithm': 'aes-256-gcm', 'nonce_size': 12},
        'key_management': {'master_key_env': 'TEE_DEMO_MASTER_KEY'}
    }
    crypto_engine = CryptoEngine(config)
    
    # 测试数据
    test_messages = [
        "重要的风险评估结果",
        {"risk_score": 0.85, "action": "CHALLENGE", "user_id": "user123"},
        {"features": ["ip", "user_agent"], "timestamp": time.time()}
    ]
    
    for i, message in enumerate(test_messages, 1):
        print(f"\n🔹 消息 {i}: {message}")
        
        # 生成数字签名
        signature = crypto_engine.sign_data(message)
        print(f"   📝 数字签名: {signature[:32]}...")
        
        # 验证签名
        is_valid = crypto_engine.verify_signature(message, signature)
        print(f"   ✅ 签名验证: {'通过' if is_valid else '失败'}")
        
        # 测试篡改检测
        if isinstance(message, dict):
            tampered_message = message.copy()
            tampered_message['tampered'] = True
        else:
            tampered_message = str(message) + " [篡改]"
        
        is_tampered_valid = crypto_engine.verify_signature(tampered_message, signature)
        print(f"   🛡️ 篡改检测: {'检测到篡改' if not is_tampered_valid else '未检测到篡改'}")


def demo_key_derivation():
    """演示密钥派生功能"""
    print_section("4. 密钥派生机制")
    
    config = {
        'encryption': {'algorithm': 'aes-256-gcm', 'nonce_size': 12},
        'key_management': {'master_key_env': 'TEE_DEMO_MASTER_KEY'}
    }
    crypto_engine = CryptoEngine(config)
    
    # 演示不同用途的密钥派生
    key_purposes = [
        "feature_ip",
        "feature_user_agent", 
        "feature_geo_location",
        "database_encryption",
        "session_key",
        "audit_log"
    ]
    
    print("🔹 从主密钥派生不同用途的子密钥:")
    derived_keys = {}
    
    for purpose in key_purposes:
        key = crypto_engine.derive_key(purpose)
        derived_keys[purpose] = key
        print(f"   {purpose}: {key.hex()[:16]}...")
    
    # 验证密钥的确定性和唯一性
    print("\n🔍 密钥特性验证:")
    
    # 确定性测试 - 相同目的应该产生相同密钥
    key1 = crypto_engine.derive_key("test_purpose")
    key2 = crypto_engine.derive_key("test_purpose")
    print(f"   确定性: {'✅ 通过' if key1 == key2 else '❌ 失败'}")
    
    # 唯一性测试 - 不同目的应该产生不同密钥
    unique_keys = set(key.hex() for key in derived_keys.values())
    print(f"   唯一性: {'✅ 通过' if len(unique_keys) == len(derived_keys) else '❌ 失败'}")


def demo_security_features():
    """演示安全特性"""
    print_section("5. 安全特性演示")
    
    config = {
        'encryption': {'algorithm': 'aes-256-gcm', 'nonce_size': 12},
        'key_management': {'master_key_env': 'TEE_DEMO_MASTER_KEY'}
    }
    crypto_engine = CryptoEngine(config)
    
    print("🔹 安全特性清单:")
    
    # 1. 认证加密 (AES-GCM)
    print("   ✅ AES-256-GCM 认证加密")
    print("     - 提供机密性、完整性、认证性")
    print("     - 防止密文篡改和伪造")
    
    # 2. 密钥派生 (HKDF)
    print("   ✅ HKDF-SHA256 密钥派生")
    print("     - 从主密钥安全派生子密钥")
    print("     - 不同用途使用不同密钥")
    
    # 3. 数字签名 (Ed25519)
    print("   ✅ Ed25519 数字签名")
    print("     - 高性能椭圆曲线签名")
    print("     - 防篡改和身份认证")
    
    # 4. 安全随机数
    print("   ✅ 密码学安全随机数")
    print("     - 使用操作系统级随机数生成器")
    print("     - 每次加密使用唯一随机数")
    
    # 5. 特征隔离
    print("   ✅ 特征数据隔离加密")
    print("     - 每个特征使用独立密钥")
    print("     - 防止交叉关联分析")
    
    # 6. 安全内存清理
    print("   ✅ 安全内存清理")
    print("     - 处理完成后清零敏感数据")
    print("     - 防止内存泄露攻击")
    
    # 演示公钥信息
    print("\n🔹 公钥信息 (用于签名验证):")
    public_key_info = crypto_engine.get_public_key_info()
    for key, value in public_key_info.items():
        if key == 'public_key_pem':
            print(f"   {key}: {value[:64]}...")
        else:
            print(f"   {key}: {value}")


def main():
    """主演示程序"""
    try:
        # 运行所有演示
        demo_basic_encryption()
        demo_feature_encryption()
        demo_digital_signature()
        demo_key_derivation()
        demo_security_features()
        
        print_header("演示总结")
        print("🎉 TEE软件加密方法演示完成！")
        print("\n🔐 使用的加密技术:")
        print("   • AES-256-GCM: 认证加密，提供机密性和完整性")
        print("   • HKDF-SHA256: 密钥派生，从主密钥生成子密钥")
        print("   • Ed25519: 数字签名，提供身份认证和防篡改")
        print("   • 密码学安全随机数: 确保加密的随机性")
        
        print("\n🛡️ 安全特性:")
        print("   • 每个特征使用独立的加密密钥")
        print("   • 支持数据完整性验证")
        print("   • 防止密文篡改和重放攻击")
        print("   • 符合TEE(可信执行环境)安全要求")
        print("   • 支持密钥轮换和安全清理")
        
        print("\n📈 性能优势:")
        print("   • AES-GCM硬件加速支持")
        print("   • Ed25519高性能签名算法")
        print("   • 最小化内存占用")
        print("   • 支持并发加密操作")
        
    except Exception as e:
        print(f"\n❌ 演示过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # 清理环境变量
        if 'TEE_DEMO_MASTER_KEY' in os.environ:
            del os.environ['TEE_DEMO_MASTER_KEY']


if __name__ == "__main__":
    main() 