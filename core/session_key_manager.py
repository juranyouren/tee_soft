"""
会话密钥管理器模块
负责生成、管理和安全清理会话密钥
"""
import os
import secrets
import logging
from typing import Optional, Dict, Any
from gmssl import sm4
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class SessionKeyError(Exception):
    """会话密钥操作异常"""
    pass


class SessionKeyManager:
    """会话密钥管理器"""
    
    def __init__(self, algorithm: str = "sm4"):
        """
        初始化会话密钥管理器
        
        Args:
            algorithm: 会话密钥算法 (sm4 或 aes-256)
        """
        self.algorithm = algorithm.lower()
        self.logger = logging.getLogger(__name__)
        
        # 支持的算法配置
        self.algorithm_config = {
            "sm4": {"key_size": 16, "block_size": 16},  # 128位
            "aes-256": {"key_size": 32, "block_size": 16}  # 256位
        }
        
        if self.algorithm not in self.algorithm_config:
            raise SessionKeyError(f"Unsupported algorithm: {algorithm}")
        
        self.key_size = self.algorithm_config[self.algorithm]["key_size"]
        self.block_size = self.algorithm_config[self.algorithm]["block_size"]
        
        self.logger.info(f"Session key manager initialized with {self.algorithm.upper()}")
    
    def generate_session_key(self) -> bytes:
        """
        生成随机会话密钥
        
        Returns:
            随机生成的会话密钥
        """
        try:
            # 使用密码学安全的随机数生成器
            session_key = secrets.token_bytes(self.key_size)
            
            self.logger.debug(f"Generated {self.key_size * 8}-bit session key")
            return session_key
            
        except Exception as e:
            raise SessionKeyError(f"Failed to generate session key: {e}")
    
    def encrypt_with_session_key(self, plaintext: bytes, session_key: bytes) -> Dict[str, str]:
        """
        使用会话密钥加密数据
        
        Args:
            plaintext: 明文数据
            session_key: 会话密钥
            
        Returns:
            加密结果字典
        """
        try:
            if self.algorithm == "sm4":
                return self._sm4_encrypt(plaintext, session_key)
            elif self.algorithm == "aes-256":
                return self._aes_encrypt(plaintext, session_key)
            else:
                raise SessionKeyError(f"Unsupported algorithm: {self.algorithm}")
                
        except Exception as e:
            raise SessionKeyError(f"Session encryption failed: {e}")
    
    def decrypt_with_session_key(self, encrypted_data: Dict[str, str], session_key: bytes) -> bytes:
        """
        使用会话密钥解密数据
        
        Args:
            encrypted_data: 加密数据字典
            session_key: 会话密钥
            
        Returns:
            解密后的明文数据
        """
        try:
            if self.algorithm == "sm4":
                return self._sm4_decrypt(encrypted_data, session_key)
            elif self.algorithm == "aes-256":
                return self._aes_decrypt(encrypted_data, session_key)
            else:
                raise SessionKeyError(f"Unsupported algorithm: {self.algorithm}")
                
        except Exception as e:
            raise SessionKeyError(f"Session decryption failed: {e}")
    
    def _sm4_encrypt(self, plaintext: bytes, session_key: bytes) -> Dict[str, str]:
        """SM4加密实现"""
        # 创建SM4加密器
        crypt_sm4 = sm4.CryptSM4()
        crypt_sm4.set_key(session_key, sm4.SM4_ENCRYPT)
        
        # PKCS7填充
        padded_data = self._pkcs7_pad(plaintext, self.block_size)
        
        # 分块加密
        ciphertext = b''
        for i in range(0, len(padded_data), self.block_size):
            block = padded_data[i:i+self.block_size]
            encrypted_block = crypt_sm4.crypt_ecb(block)
            ciphertext += encrypted_block
        
        return {
            'ciphertext': ciphertext.hex(),
            'algorithm': 'sm4-ecb',
            'data_length': len(plaintext),
            'padded_length': len(padded_data)
        }
    
    def _sm4_decrypt(self, encrypted_data: Dict[str, str], session_key: bytes) -> bytes:
        """SM4解密实现"""
        ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
        data_length = encrypted_data.get('data_length', 0)
        
        # 创建SM4解密器
        crypt_sm4 = sm4.CryptSM4()
        crypt_sm4.set_key(session_key, sm4.SM4_DECRYPT)
        
        # 分块解密
        plaintext_padded = b''
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i+self.block_size]
            decrypted_block = crypt_sm4.crypt_ecb(block)
            plaintext_padded += decrypted_block
        
        # 去除填充
        plaintext = self._pkcs7_unpad(plaintext_padded)
        
        # 截断到原始长度
        if data_length > 0 and len(plaintext) != data_length:
            plaintext = plaintext[:data_length]
        
        return plaintext
    
    def _aes_encrypt(self, plaintext: bytes, session_key: bytes) -> Dict[str, str]:
        """AES-256-GCM加密实现"""
        # 生成随机nonce
        nonce = os.urandom(12)  # 96位nonce用于GCM
        
        # 创建AES-GCM加密器
        cipher = Cipher(
            algorithms.AES(session_key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return {
            'ciphertext': ciphertext.hex(),
            'nonce': nonce.hex(),
            'tag': encryptor.tag.hex(),
            'algorithm': 'aes-256-gcm',
            'data_length': len(plaintext)
        }
    
    def _aes_decrypt(self, encrypted_data: Dict[str, str], session_key: bytes) -> bytes:
        """AES-256-GCM解密实现"""
        ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
        nonce = bytes.fromhex(encrypted_data['nonce'])
        tag = bytes.fromhex(encrypted_data['tag'])
        
        # 创建AES-GCM解密器
        cipher = Cipher(
            algorithms.AES(session_key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    
    def _pkcs7_pad(self, data: bytes, block_size: int) -> bytes:
        """PKCS7填充"""
        padding_len = block_size - (len(data) % block_size)
        padding = bytes([padding_len] * padding_len)
        return data + padding
    
    def _pkcs7_unpad(self, data: bytes) -> bytes:
        """PKCS7去填充"""
        if not data:
            return data
        
        padding_len = data[-1]
        
        # 验证填充
        if padding_len == 0 or padding_len > 16 or padding_len > len(data):
            return data
        
        for i in range(padding_len):
            if data[-(i+1)] != padding_len:
                return data
        
        return data[:-padding_len]
    
    def secure_delete(self, *objects):
        """
        安全删除敏感数据
        
        Args:
            *objects: 要删除的对象
        """
        for obj in objects:
            if obj is not None:
                if isinstance(obj, (bytes, bytearray)):
                    # 对于字节数组，用随机数据覆盖
                    if isinstance(obj, bytearray):
                        for i in range(len(obj)):
                            obj[i] = secrets.randbits(8)
                elif isinstance(obj, dict):
                    # 对于字典，清空内容
                    obj.clear()
                
        self.logger.debug("Secure deletion completed")


# 全局会话密钥管理器实例
_session_key_manager: Optional[SessionKeyManager] = None


def initialize_session_key_manager(algorithm: str = "sm4") -> SessionKeyManager:
    """
    初始化会话密钥管理器
    
    Args:
        algorithm: 会话密钥算法
        
    Returns:
        会话密钥管理器实例
    """
    global _session_key_manager
    _session_key_manager = SessionKeyManager(algorithm)
    return _session_key_manager


def get_session_key_manager() -> SessionKeyManager:
    """获取会话密钥管理器实例"""
    if _session_key_manager is None:
        raise SessionKeyError("Session key manager not initialized")
    return _session_key_manager 