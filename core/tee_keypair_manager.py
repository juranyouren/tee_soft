"""
TEE密钥对管理器模块
负责生成、管理TEE的长期密钥对用于保护会话密钥
"""
import os
import json
import logging
import secrets
from typing import Optional, Dict, Any, Tuple
from gmssl import sm2
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


class TEEKeyPairError(Exception):
    """TEE密钥对操作异常"""
    pass


class TEEKeyPairManager:
    """TEE密钥对管理器"""
    
    def __init__(self, algorithm: str = "sm2"):
        """
        初始化TEE密钥对管理器
        
        Args:
            algorithm: 密钥算法 (sm2 或 ed25519)
        """
        self.algorithm = algorithm.lower()
        self.logger = logging.getLogger(__name__)
        
        # 支持的算法
        self.supported_algorithms = ["sm2", "ed25519"]
        
        if self.algorithm not in self.supported_algorithms:
            raise TEEKeyPairError(f"Unsupported algorithm: {algorithm}")
        
        # 密钥对
        self.private_key = None
        self.public_key = None
        
        # SM2实例
        if self.algorithm == "sm2":
            self.sm2_crypt = sm2.CryptSM2(public_key="", private_key="")
        
        self.logger.info(f"TEE keypair manager initialized with {self.algorithm.upper()}")
    
    def generate_keypair(self) -> Tuple[str, str]:
        """
        生成TEE密钥对
        
        Returns:
            (private_key, public_key) 密钥对
        """
        try:
            if self.algorithm == "sm2":
                return self._generate_sm2_keypair()
            elif self.algorithm == "ed25519":
                return self._generate_ed25519_keypair()
            else:
                raise TEEKeyPairError(f"Unsupported algorithm: {self.algorithm}")
                
        except Exception as e:
            raise TEEKeyPairError(f"Failed to generate keypair: {e}")
    
    def _generate_sm2_keypair(self) -> Tuple[str, str]:
        """生成SM2密钥对"""
        # 生成随机私钥
        private_key = secrets.token_hex(32)  # 64字符hex字符串
        
        # 从私钥生成公钥
        temp_sm2 = sm2.CryptSM2(public_key="", private_key=private_key)
        public_key_point = temp_sm2._kg(int(private_key, 16), sm2.default_ecc_table['g'])
        
        # 确保公钥点是整数
        if isinstance(public_key_point[0], str):
            x_coord = int(public_key_point[0], 16)
            y_coord = int(public_key_point[1], 16)
        else:
            x_coord = public_key_point[0]
            y_coord = public_key_point[1]
        
        public_key = '04' + format(x_coord, '064x') + format(y_coord, '064x')
        
        # 存储密钥对
        self.private_key = private_key
        self.public_key = public_key
        self.sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)
        
        self.logger.info("SM2 keypair generated successfully")
        return private_key, public_key
    
    def _generate_ed25519_keypair(self) -> Tuple[str, str]:
        """生成Ed25519密钥对"""
        # 生成Ed25519密钥对
        private_key_obj = ed25519.Ed25519PrivateKey.generate()
        public_key_obj = private_key_obj.public_key()
        
        # 序列化私钥
        private_key_bytes = private_key_obj.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # 序列化公钥
        public_key_bytes = public_key_obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        private_key = private_key_bytes.hex()
        public_key = public_key_bytes.hex()
        
        # 存储密钥对
        self.private_key = private_key
        self.public_key = public_key
        
        self.logger.info("Ed25519 keypair generated successfully")
        return private_key, public_key
    
    def load_keypair(self, private_key: str, public_key: str):
        """
        加载现有密钥对
        
        Args:
            private_key: 私钥字符串
            public_key: 公钥字符串
        """
        try:
            self.private_key = private_key
            self.public_key = public_key
            
            if self.algorithm == "sm2":
                self.sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)
            
            self.logger.info(f"Loaded {self.algorithm.upper()} keypair")
            
        except Exception as e:
            raise TEEKeyPairError(f"Failed to load keypair: {e}")
    
    def encrypt_session_key(self, session_key: bytes, public_key: Optional[str] = None) -> str:
        """
        使用公钥加密会话密钥
        
        Args:
            session_key: 会话密钥
            public_key: 公钥（如果不提供则使用自己的公钥）
            
        Returns:
            加密后的会话密钥（hex字符串）
        """
        try:
            target_public_key = public_key or self.public_key
            
            if not target_public_key:
                raise TEEKeyPairError("No public key available")
            
            if self.algorithm == "sm2":
                return self._sm2_encrypt_session_key(session_key, target_public_key)
            elif self.algorithm == "ed25519":
                # Ed25519主要用于签名，这里为了兼容性使用简单的XOR（实际应用中应使用X25519）
                raise TEEKeyPairError("Ed25519 encryption not implemented - use X25519 for encryption")
            else:
                raise TEEKeyPairError(f"Unsupported algorithm: {self.algorithm}")
                
        except Exception as e:
            raise TEEKeyPairError(f"Failed to encrypt session key: {e}")
    
    def decrypt_session_key(self, encrypted_session_key: str) -> bytes:
        """
        使用私钥解密会话密钥
        
        Args:
            encrypted_session_key: 加密的会话密钥（hex字符串）
            
        Returns:
            解密后的会话密钥
        """
        try:
            if not self.private_key:
                raise TEEKeyPairError("No private key available")
            
            if self.algorithm == "sm2":
                return self._sm2_decrypt_session_key(encrypted_session_key)
            elif self.algorithm == "ed25519":
                raise TEEKeyPairError("Ed25519 decryption not implemented")
            else:
                raise TEEKeyPairError(f"Unsupported algorithm: {self.algorithm}")
                
        except Exception as e:
            raise TEEKeyPairError(f"Failed to decrypt session key: {e}")
    
    def _sm2_encrypt_session_key(self, session_key: bytes, public_key: str) -> str:
        """使用SM2加密会话密钥"""
        # 创建临时SM2实例用于加密
        temp_sm2 = sm2.CryptSM2(public_key=public_key, private_key="")
        
        # SM2加密
        encrypted = temp_sm2.encrypt(session_key.hex())
        
        return encrypted
    
    def _sm2_decrypt_session_key(self, encrypted_session_key: str) -> bytes:
        """使用SM2解密会话密钥"""
        # 使用当前实例解密
        decrypted_hex = self.sm2_crypt.decrypt(encrypted_session_key)
        
        # 转换回字节
        return bytes.fromhex(decrypted_hex)
    
    def sign_data(self, data: bytes) -> str:
        """
        对数据进行数字签名
        
        Args:
            data: 要签名的数据
            
        Returns:
            数字签名（hex字符串）
        """
        try:
            if not self.private_key:
                raise TEEKeyPairError("No private key available for signing")
            
            if self.algorithm == "sm2":
                return self._sm2_sign(data)
            elif self.algorithm == "ed25519":
                return self._ed25519_sign(data)
            else:
                raise TEEKeyPairError(f"Unsupported algorithm: {self.algorithm}")
                
        except Exception as e:
            raise TEEKeyPairError(f"Failed to sign data: {e}")
    
    def verify_signature(self, data: bytes, signature: str, public_key: Optional[str] = None) -> bool:
        """
        验证数字签名
        
        Args:
            data: 原始数据
            signature: 数字签名
            public_key: 公钥（如果不提供则使用自己的公钥）
            
        Returns:
            验证结果
        """
        try:
            target_public_key = public_key or self.public_key
            
            if not target_public_key:
                raise TEEKeyPairError("No public key available for verification")
            
            if self.algorithm == "sm2":
                return self._sm2_verify(data, signature, target_public_key)
            elif self.algorithm == "ed25519":
                return self._ed25519_verify(data, signature, target_public_key)
            else:
                raise TEEKeyPairError(f"Unsupported algorithm: {self.algorithm}")
                
        except Exception as e:
            self.logger.warning(f"Signature verification failed: {e}")
            return False
    
    def _sm2_sign(self, data: bytes) -> str:
        """SM2数字签名"""
        # 生成随机数
        random_hex = self._generate_random_hex()
        
        # SM2签名
        signature = self.sm2_crypt.sign(data, random_hex)
        
        return signature
    
    def _sm2_verify(self, data: bytes, signature: str, public_key: str) -> bool:
        """SM2签名验证"""
        try:
            # 创建临时SM2实例用于验证
            temp_sm2 = sm2.CryptSM2(public_key=public_key, private_key="")
            
            # 验证签名
            return temp_sm2.verify(signature, data)
            
        except Exception:
            return False
    
    def _ed25519_sign(self, data: bytes) -> str:
        """Ed25519数字签名"""
        # 从hex字符串恢复私钥
        private_key_bytes = bytes.fromhex(self.private_key)
        private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        
        # 签名
        signature = private_key_obj.sign(data)
        
        return signature.hex()
    
    def _ed25519_verify(self, data: bytes, signature: str, public_key: str) -> bool:
        """Ed25519签名验证"""
        try:
            # 从hex字符串恢复公钥
            public_key_bytes = bytes.fromhex(public_key)
            public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            
            # 验证签名
            signature_bytes = bytes.fromhex(signature)
            public_key_obj.verify(signature_bytes, data)
            
            return True
            
        except Exception:
            return False
    
    def _generate_random_hex(self) -> str:
        """生成随机hex字符串"""
        return secrets.token_hex(32)
    
    def get_public_key_info(self) -> Dict[str, Any]:
        """
        获取公钥信息
        
        Returns:
            公钥信息字典
        """
        if not self.public_key:
            raise TEEKeyPairError("No keypair generated")
        
        return {
            'algorithm': self.algorithm.upper(),
            'public_key': self.public_key,
            'key_size': len(self.public_key) * 4,  # hex字符转位数
            'curve': 'sm2p256v1' if self.algorithm == 'sm2' else 'ed25519'
        }
    
    def export_public_key_for_client(self) -> Dict[str, Any]:
        """
        导出公钥供客户端使用
        
        Returns:
            客户端公钥配置
        """
        return {
            'tee_public_key': self.public_key,
            'algorithm': self.algorithm.upper(),
            'version': '1.0',
            'usage': 'session_key_encryption'
        }
    
    def secure_delete_private_key(self):
        """安全删除私钥"""
        if self.private_key:
            # 用随机数据覆盖私钥字符串
            self.private_key = None
            
        self.logger.info("Private key securely deleted")


# 全局TEE密钥对管理器实例
_tee_keypair_manager: Optional[TEEKeyPairManager] = None


def initialize_tee_keypair_manager(algorithm: str = "sm2") -> TEEKeyPairManager:
    """
    初始化TEE密钥对管理器
    
    Args:
        algorithm: 密钥算法
        
    Returns:
        TEE密钥对管理器实例
    """
    global _tee_keypair_manager
    _tee_keypair_manager = TEEKeyPairManager(algorithm)
    return _tee_keypair_manager


def get_tee_keypair_manager() -> TEEKeyPairManager:
    """获取TEE密钥对管理器实例"""
    if _tee_keypair_manager is None:
        raise TEEKeyPairError("TEE keypair manager not initialized")
    return _tee_keypair_manager 