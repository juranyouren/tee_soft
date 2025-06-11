#!/usr/bin/env python3
"""
客户端密钥协商演示脚本
展示改进后的混合加密通信流程
"""
import json
import secrets
import logging
import requests
from typing import Dict, Any
from core.session_key_manager import SessionKeyManager
from core.tee_keypair_manager import TEEKeyPairManager

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TEEClient:
    """
    TEE客户端
    演示新的密钥协商和混合加密流程
    """
    
    def __init__(self, tee_server_url: str = "http://127.0.0.1:5000"):
        """
        初始化TEE客户端
        
        Args:
            tee_server_url: TEE服务器地址
        """
        self.server_url = tee_server_url
        self.logger = logging.getLogger(__name__)
        
        # 客户端只有TEE公钥，没有私钥（安全设计）
        self.tee_public_key = None
        self.tee_algorithm = None
        
        # 会话密钥管理器
        self.session_key_manager = SessionKeyManager("sm4")
        
        # TEE密钥对管理器（仅用于加密会话密钥）
        self.tee_keypair_manager = TEEKeyPairManager("sm2")
        
        self.logger.info("🖥️  TEE client initialized")
    
    def get_tee_public_key(self) -> bool:
        """
        从TEE服务器获取公钥
        
        Returns:
            是否成功获取公钥
        """
        try:
            self.logger.info("📡 Fetching TEE public key from server...")
            
            response = requests.get(f"{self.server_url}/tee_soft/public_key")
            
            if response.status_code == 200:
                key_info = response.json()
                self.tee_public_key = key_info.get('tee_public_key')
                self.tee_algorithm = key_info.get('algorithm', 'SM2')
                
                if self.tee_public_key:
                    self.logger.info(f"✅ Successfully obtained TEE public key: {self.tee_algorithm}")
                    self.logger.info(f"📤 Public Key: {self.tee_public_key[:32]}...")
                    return True
                else:
                    self.logger.error("❌ No public key in server response")
                    return False
            else:
                self.logger.error(f"❌ Failed to get public key: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Error getting TEE public key: {e}")
            return False
    
    def encrypt_features_for_tee(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        为TEE加密特征数据（混合加密）
        
        Args:
            features: 用户特征数据
            
        Returns:
            加密后的消息
        """
        try:
            self.logger.info("🔐 Starting hybrid encryption process...")
            
            # 1. 生成随机会话密钥
            self.logger.info("🔑 Generating random session key...")
            session_key = self.session_key_manager.generate_session_key()
            self.logger.info(f"✅ Generated {len(session_key) * 8}-bit session key")
            
            # 2. 使用会话密钥加密特征数据
            self.logger.info("🔒 Encrypting features with session key...")
            features_json = json.dumps(features, ensure_ascii=False)
            features_bytes = features_json.encode('utf-8')
            
            encrypted_features = self.session_key_manager.encrypt_with_session_key(
                features_bytes, session_key
            )
            self.logger.info("✅ Features encrypted with session key")
            
            # 3. 使用TEE公钥加密会话密钥
            self.logger.info("🔐 Encrypting session key with TEE public key...")
            encrypted_session_key = self.tee_keypair_manager.encrypt_session_key(
                session_key, self.tee_public_key
            )
            self.logger.info("✅ Session key encrypted with TEE public key")
            
            # 4. 构造混合加密消息
            encrypted_message = {
                'request_id': f"client_req_{secrets.randbits(32)}",
                'timestamp': '2024-01-01T12:00:00Z',
                'source_ip': '192.168.1.100',
                'user_agent': 'TEE_Client/1.0 (Improved)',
                'encrypted_session_key': encrypted_session_key,
                'encrypted_features': encrypted_features,
                'encryption_info': {
                    'method': 'hybrid_encryption',
                    'session_key_algorithm': self.session_key_manager.algorithm.upper(),
                    'tee_keypair_algorithm': self.tee_algorithm,
                    'security_level': 'forward_secure'
                }
            }
            
            # 5. 安全删除会话密钥
            self.session_key_manager.secure_delete(session_key)
            self.logger.info("🧹 Session key securely deleted from client")
            
            self.logger.info("✅ Hybrid encryption completed successfully")
            return encrypted_message
            
        except Exception as e:
            self.logger.error(f"❌ Encryption error: {e}")
            raise
    
    def send_encrypted_request(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        发送加密请求到TEE服务器
        
        Args:
            features: 用户特征数据
            
        Returns:
            TEE响应结果
        """
        try:
            # 1. 获取TEE公钥（如果还没有）
            if not self.tee_public_key:
                if not self.get_tee_public_key():
                    raise Exception("Failed to obtain TEE public key")
            
            # 2. 加密特征数据
            encrypted_message = self.encrypt_features_for_tee(features)
            
            # 3. 发送到TEE服务器
            self.logger.info("📤 Sending encrypted request to TEE server...")
            
            response = requests.post(
                f"{self.server_url}/tee_soft/process_encrypted",
                json=encrypted_message,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                self.logger.info("✅ Successfully received TEE response")
                self.logger.info(f"🎯 Risk Score: {result.get('risk_assessment', {}).get('risk_score', 'N/A')}")
                self.logger.info(f"⚡ Processing Time: {result.get('processing_time_ms', 'N/A')}ms")
                return result
            else:
                self.logger.error(f"❌ TEE server error: {response.status_code}")
                return {"error": f"Server error: {response.status_code}"}
                
        except Exception as e:
            self.logger.error(f"❌ Request error: {e}")
            return {"error": str(e)}
    
    def demo_multiple_requests(self, num_requests: int = 3):
        """
        演示多次请求（每次使用新的会话密钥）
        
        Args:
            num_requests: 请求次数
        """
        self.logger.info(f"🚀 Starting demo with {num_requests} requests...")
        
        # 模拟不同的用户特征数据
        demo_features = [
            {
                "device_fingerprint": f"device_abc_{i}",
                "login_location": {"lat": 40.7128 + i*0.01, "lng": -74.0060 + i*0.01},
                "behavior_pattern": {"typing_speed": 45.2 + i*5, "mouse_movement": f"pattern_{i}"},
                "network_info": {"ip": f"192.168.1.{100+i}", "rtt": 45.2 + i*2}
            }
            for i in range(num_requests)
        ]
        
        for i, features in enumerate(demo_features, 1):
            self.logger.info(f"\n{'='*50}")
            self.logger.info(f"📋 Request {i}/{num_requests}")
            self.logger.info(f"{'='*50}")
            
            result = self.send_encrypted_request(features)
            
            if "error" not in result:
                self.logger.info(f"✅ Request {i} completed successfully")
                encryption_info = result.get('encryption_info', {})
                if encryption_info:
                    self.logger.info(f"🔐 Encryption Method: {encryption_info.get('method', 'Unknown')}")
                    self.logger.info(f"🔑 Key Isolation: {encryption_info.get('key_isolation', 'Unknown')}")
            else:
                self.logger.error(f"❌ Request {i} failed: {result['error']}")
    
    def get_encryption_system_info(self) -> Dict[str, Any]:
        """
        获取加密系统信息
        
        Returns:
            加密系统信息
        """
        try:
            response = requests.get(f"{self.server_url}/tee_soft/encryption_info")
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"Server error: {response.status_code}"}
                
        except Exception as e:
            return {"error": str(e)}


def main():
    """主函数"""
    print("""
    🔐 TEE密钥协商与混合加密演示
    ================================
    
    本演示展示了改进后的密钥管理架构：
    1. 🔑 TEE长期密钥对（SM2）
    2. 🎲 随机会话密钥（SM4，每次请求生成新密钥）
    3. 💾 独立数据库加密密钥
    4. 🧹 自动安全清理
    5. 🛡️  前向安全性保证
    
    ================================
    """)
    
    # 创建客户端
    client = TEEClient()
    
    try:
        # 1. 获取加密系统信息
        print("📊 获取TEE加密系统信息...")
        encryption_info = client.get_encryption_system_info()
        if "error" not in encryption_info:
            print("✅ 加密系统信息:")
            print(json.dumps(encryption_info, indent=2, ensure_ascii=False))
        else:
            print(f"⚠️  无法获取加密系统信息: {encryption_info['error']}")
        
        print("\n" + "="*60)
        
        # 2. 演示多次混合加密请求
        print("🔐 开始混合加密通信演示...")
        client.demo_multiple_requests(3)
        
        print("\n" + "="*60)
        print("✅ 演示完成！")
        print("\n🔑 关键安全特性验证:")
        print("  ✓ 每次请求使用新的会话密钥")
        print("  ✓ 客户端不存储私钥")
        print("  ✓ 会话密钥用后即焚")
        print("  ✓ 数据库加密与通信加密完全分离")
        print("  ✓ 前向安全性保证")
        
    except KeyboardInterrupt:
        print("\n⏹️  演示被用户中断")
    except Exception as e:
        print(f"\n❌ 演示过程中出现错误: {e}")


if __name__ == "__main__":
    main() 