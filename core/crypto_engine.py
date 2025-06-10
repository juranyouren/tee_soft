"""
加密引擎模块
用于处理数据的加密和解密，实现TEE安全特性
"""
import os
import hashlib
import json
import logging
from typing import Dict, Any, Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class CryptoError(Exception):
    """加密操作异常"""
    pass


class CryptoEngine:
    """加密引擎"""
    
    def __init__(self, config: Dict):
        """
        初始化加密引擎
        
        Args:
            config: 安全配置
        """
        self.config = config
        self.encryption_config = config['encryption']
        self.key_config = config['key_management']
        self.logger = logging.getLogger(__name__)
        
        # 初始化主密钥
        self.master_key = self._initialize_master_key()
        
        # 生成签名密钥对
        self.signing_key = ed25519.Ed25519PrivateKey.generate()
        self.verify_key = self.signing_key.public_key()
        
        self.logger.info("Crypto engine initialized successfully")
    
    def _initialize_master_key(self) -> bytes:
        """初始化主密钥"""
        master_key_env = self.key_config.get('master_key_env', 'TEE_MASTER_KEY')
        master_key_hex = os.getenv(master_key_env)
        
        if master_key_hex:
            try:
                return bytes.fromhex(master_key_hex)
            except ValueError:
                self.logger.warning("Invalid master key format in environment variable")
        
        # 生成新的主密钥
        master_key = os.urandom(32)  # 256 bits
        self.logger.warning(f"Generated new master key. Please save it to environment variable {master_key_env}")
        self.logger.info(f"Master key (save this): {master_key.hex()}")
        
        return master_key
    
    def derive_key(self, purpose: str, info: Optional[bytes] = None) -> bytes:
        """
        从主密钥派生子密钥
        
        Args:
            purpose: 密钥用途
            info: 附加信息
            
        Returns:
            派生的密钥
        """
        salt = hashlib.sha256(purpose.encode()).digest()
        
        if info is None:
            info = purpose.encode()
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            info=info,
            backend=default_backend()
        )
        
        return hkdf.derive(self.master_key)
    
    def encrypt_data(self, plaintext: Any, key_purpose: str = "default") -> Dict[str, str]:
        """
        加密数据
        
        Args:
            plaintext: 明文数据
            key_purpose: 密钥用途
            
        Returns:
            加密结果字典，包含密文、随机数、标签等
        """
        try:
            # 将数据转换为JSON字符串
            if isinstance(plaintext, str):
                data = plaintext.encode('utf-8')
            else:
                data = json.dumps(plaintext, ensure_ascii=False).encode('utf-8')
            
            # 派生加密密钥
            encryption_key = self.derive_key(f"encrypt_{key_purpose}")
            
            # 生成随机数
            nonce = os.urandom(self.encryption_config['nonce_size'])
            
            # 使用AES-256-GCM加密
            cipher = Cipher(
                algorithms.AES(encryption_key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            # 获取认证标签
            tag = encryptor.tag
            
            return {
                'ciphertext': ciphertext.hex(),
                'nonce': nonce.hex(),
                'tag': tag.hex(),
                'algorithm': 'aes-256-gcm',
                'key_purpose': key_purpose
            }
            
        except Exception as e:
            raise CryptoError(f"Encryption failed: {e}")
    
    def decrypt_data(self, encrypted_data: Dict[str, str]) -> Any:
        """
        解密数据
        
        Args:
            encrypted_data: 加密数据字典
            
        Returns:
            解密后的原始数据
        """
        try:
            # 提取加密组件
            ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
            nonce = bytes.fromhex(encrypted_data['nonce'])
            tag = bytes.fromhex(encrypted_data['tag'])
            key_purpose = encrypted_data.get('key_purpose', 'default')
            
            # 派生解密密钥
            decryption_key = self.derive_key(f"encrypt_{key_purpose}")
            
            # 使用AES-256-GCM解密
            cipher = Cipher(
                algorithms.AES(decryption_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
            
            # 尝试解析为JSON，失败则返回字符串
            try:
                plaintext_str = plaintext_bytes.decode('utf-8')
                return json.loads(plaintext_str)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return plaintext_bytes.decode('utf-8', errors='replace')
            
        except Exception as e:
            raise CryptoError(f"Decryption failed: {e}")
    
    def encrypt_features(self, features: Dict[str, Any]) -> Dict[str, Dict]:
        """
        加密特征数据
        
        Args:
            features: 特征数据字典
            
        Returns:
            加密后的特征数据
        """
        encrypted_features = {}
        
        for feature_name, feature_value in features.items():
            try:
                encrypted_features[feature_name] = self.encrypt_data(
                    feature_value, 
                    key_purpose=f"feature_{feature_name}"
                )
            except Exception as e:
                self.logger.error(f"Failed to encrypt feature {feature_name}: {e}")
                raise CryptoError(f"Feature encryption failed for {feature_name}")
        
        return encrypted_features
    
    def decrypt_features(self, encrypted_features: Dict[str, Dict]) -> Dict[str, Any]:
        """
        解密特征数据
        
        Args:
            encrypted_features: 加密的特征数据
            
        Returns:
            解密后的特征数据
        """
        decrypted_features = {}
        
        for feature_name, encrypted_data in encrypted_features.items():
            try:
                decrypted_features[feature_name] = self.decrypt_data(encrypted_data)
            except Exception as e:
                self.logger.error(f"Failed to decrypt feature {feature_name}: {e}")
                # 在生产环境中，可能需要更严格的错误处理
                decrypted_features[feature_name] = None
        
        return decrypted_features
    
    def hash_feature_value(self, feature_value: Any, feature_name: str = "") -> str:
        """
        计算特征值的哈希
        
        Args:
            feature_value: 特征值
            feature_name: 特征名称（用于加盐）
            
        Returns:
            SHA-256哈希值
        """
        if isinstance(feature_value, str):
            data = feature_value.encode('utf-8')
        else:
            data = json.dumps(feature_value, ensure_ascii=False, sort_keys=True).encode('utf-8')
        
        # 使用特征名称作为盐值
        salt = feature_name.encode('utf-8')
        salted_data = salt + data
        
        return hashlib.sha256(salted_data).hexdigest()
    
    def sign_data(self, data: Any) -> str:
        """
        对数据进行数字签名
        
        Args:
            data: 要签名的数据
            
        Returns:
            Ed25519签名的十六进制字符串
        """
        try:
            if isinstance(data, str):
                message = data.encode('utf-8')
            else:
                message = json.dumps(data, ensure_ascii=False, sort_keys=True).encode('utf-8')
            
            signature = self.signing_key.sign(message)
            return signature.hex()
            
        except Exception as e:
            raise CryptoError(f"Signing failed: {e}")
    
    def verify_signature(self, data: Any, signature_hex: str) -> bool:
        """
        验证数字签名
        
        Args:
            data: 原始数据
            signature_hex: 签名的十六进制字符串
            
        Returns:
            验证结果
        """
        try:
            if isinstance(data, str):
                message = data.encode('utf-8')
            else:
                message = json.dumps(data, ensure_ascii=False, sort_keys=True).encode('utf-8')
            
            signature = bytes.fromhex(signature_hex)
            self.verify_key.verify(signature, message)
            return True
            
        except (InvalidSignature, Exception):
            return False
    
    def secure_delete(self, data: Any):
        """
        安全删除敏感数据
        
        Args:
            data: 要删除的数据
        """
        if isinstance(data, bytes):
            # 用随机数据覆盖内存
            for i in range(len(data)):
                data = data[:i] + os.urandom(1) + data[i+1:]
        elif isinstance(data, str):
            # 字符串无法直接修改，只能设置为None并触发垃圾回收
            data = None
        elif isinstance(data, (list, dict)):
            # 递归清理容器类型
            if isinstance(data, list):
                for i in range(len(data)):
                    self.secure_delete(data[i])
                data.clear()
            else:
                for key in list(data.keys()):
                    self.secure_delete(data[key])
                data.clear()
    
    def rotate_keys(self):
        """轮换密钥"""
        self.logger.info("Starting key rotation...")
        
        # 生成新的签名密钥对
        old_signing_key = self.signing_key
        self.signing_key = ed25519.Ed25519PrivateKey.generate()
        self.verify_key = self.signing_key.public_key()
        
        # 安全删除旧密钥
        self.secure_delete(old_signing_key)
        
        self.logger.info("Key rotation completed")
    
    def get_public_key_info(self) -> Dict[str, str]:
        """
        获取公钥信息（用于外部验证）
        
        Returns:
            公钥信息
        """
        public_key_bytes = self.verify_key.public_key_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return {
            'algorithm': 'Ed25519',
            'public_key': public_key_bytes.hex(),
            'key_size': len(public_key_bytes) * 8
        }


# 全局加密引擎实例
crypto_engine = None


def initialize_crypto_engine(config: Dict) -> CryptoEngine:
    """
    初始化加密引擎
    
    Args:
        config: 安全配置
        
    Returns:
        加密引擎实例
    """
    global crypto_engine
    crypto_engine = CryptoEngine(config)
    return crypto_engine


def get_crypto_engine() -> CryptoEngine:
    """获取加密引擎实例"""
    if crypto_engine is None:
        raise CryptoError("Crypto engine not initialized")
    return crypto_engine


def secure_compare(a: str, b: str) -> bool:
    """
    安全字符串比较（防止时序攻击）
    
    Args:
        a: 字符串A
        b: 字符串B
        
    Returns:
        比较结果
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    
    return result == 0 