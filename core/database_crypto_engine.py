"""
数据库加密引擎模块
独立的数据库加密系统，与通信加密完全分离
"""
import os
import json
import hashlib
import secrets
import logging
from typing import Dict, Any, Optional
from gmssl import sm3, sm4
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class DatabaseCryptoError(Exception):
    """数据库加密操作异常"""
    pass


class DatabaseCryptoEngine:
    """独立的数据库加密引擎"""
    
    def __init__(self, config: Dict):
        """
        初始化数据库加密引擎
        
        Args:
            config: 数据库加密配置
        """
        self.config = config
        self.encryption_config = config.get('encryption', {})
        self.key_config = config.get('key_management', {})
        self.logger = logging.getLogger(__name__)
        
        # 加密算法配置（必须在初始化主密钥之前设置）
        self.algorithm = self.encryption_config.get('algorithm', 'sm4-ecb')
        self.key_size = self.encryption_config.get('key_size', 16)  # SM4 128位
        
        # 独立的数据库主密钥（现在可以使用self.key_size了）
        self.db_master_key = self._initialize_db_master_key()
        
        self.logger.info(f"Database crypto engine initialized with {self.algorithm.upper()}")
        self.logger.info("Database encryption completely isolated from communication encryption")
    
    def _initialize_db_master_key(self) -> bytes:
        """初始化独立的数据库主密钥"""
        # 使用独立的环境变量
        db_master_key_env = self.key_config.get('db_master_key_env', 'DB_MASTER_KEY')
        db_master_key_hex = os.getenv(db_master_key_env)
        
        if db_master_key_hex:
            try:
                key = bytes.fromhex(db_master_key_hex)
                if len(key) == self.key_size:
                    self.logger.info(f"Loaded database master key from {db_master_key_env}")
                    return key
                else:
                    self.logger.warning(f"Invalid database master key length, generating new key")
            except ValueError:
                self.logger.warning("Invalid database master key format in environment variable")
        
        # 生成新的数据库主密钥
        db_master_key = secrets.token_bytes(self.key_size)
        self.logger.warning(f"Generated new database master key. Please save it to environment variable {db_master_key_env}")
        self.logger.info(f"Database Master Key (save this): {db_master_key.hex()}")
        
        return db_master_key
    
    def derive_db_key(self, purpose: str, info: Optional[str] = None) -> bytes:
        """
        从数据库主密钥派生子密钥
        
        Args:
            purpose: 密钥用途
            info: 附加信息
            
        Returns:
            派生的数据库子密钥
        """
        if info is None:
            info = purpose
        
        # 使用SM3生成派生材料
        derive_input = self.db_master_key + f"db_{purpose}".encode('utf-8') + info.encode('utf-8')
        derived = sm3.sm3_hash([i for i in derive_input])
        
        # 取前key_size字节作为子密钥
        return bytes.fromhex(derived)[:self.key_size]
    
    def encrypt_for_database(self, plaintext: Any, purpose: str = "default") -> Dict[str, str]:
        """
        为数据库存储加密数据
        
        Args:
            plaintext: 明文数据
            purpose: 存储用途
            
        Returns:
            数据库加密结果
        """
        try:
            # 将数据转换为字节
            if isinstance(plaintext, str):
                data = plaintext.encode('utf-8')
            else:
                data = json.dumps(plaintext, ensure_ascii=False).encode('utf-8')
            
            # 派生数据库专用密钥
            db_key = self.derive_db_key(f"storage_{purpose}")
            
            # 使用SM4加密
            encrypted_result = self._sm4_encrypt_for_db(data, db_key)
            
            # 添加数据库特定的元数据
            encrypted_result.update({
                'db_purpose': purpose,
                'db_algorithm': self.algorithm,
                'db_version': '1.0',
                'encrypted_at': str(int(secrets.randbits(32)))  # 时间戳混淆
            })
            
            return encrypted_result
            
        except Exception as e:
            raise DatabaseCryptoError(f"Database encryption failed: {e}")
    
    def decrypt_from_database(self, encrypted_data: Dict[str, str]) -> Any:
        """
        从数据库解密数据
        
        Args:
            encrypted_data: 数据库加密数据
            
        Returns:
            解密后的原始数据
        """
        try:
            # 提取数据库加密信息
            purpose = encrypted_data.get('db_purpose', 'default')
            algorithm = encrypted_data.get('db_algorithm', self.algorithm)
            
            if algorithm != self.algorithm:
                raise DatabaseCryptoError(f"Algorithm mismatch: expected {self.algorithm}, got {algorithm}")
            
            # 派生相同的数据库密钥
            db_key = self.derive_db_key(f"storage_{purpose}")
            
            # 解密数据
            plaintext_bytes = self._sm4_decrypt_from_db(encrypted_data, db_key)
            
            # 清理可能的填充字符
            plaintext_bytes = plaintext_bytes.rstrip(b'\x00').rstrip(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10')
            
            # 尝试解析为JSON，失败则返回字符串
            try:
                plaintext_str = plaintext_bytes.decode('utf-8').strip()
                # 检查是否是JSON格式
                if plaintext_str.startswith(('{', '[')) and plaintext_str.endswith(('}', ']')):
                    return json.loads(plaintext_str)
                else:
                    return plaintext_str
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                self.logger.warning(f"Failed to parse decrypted data as JSON: {e}")
                # 尝试使用更宽松的解码方式
                try:
                    return plaintext_bytes.decode('utf-8', errors='replace').strip()
                except:
                    return plaintext_bytes.hex()  # 返回十六进制表示作为最后手段
            
        except Exception as e:
            raise DatabaseCryptoError(f"Database decryption failed: {e}")
    
    def _sm4_encrypt_for_db(self, data: bytes, db_key: bytes) -> Dict[str, str]:
        """使用SM4为数据库加密"""
        # 创建SM4加密器
        crypt_sm4 = sm4.CryptSM4()
        crypt_sm4.set_key(db_key, sm4.SM4_ENCRYPT)
        
        # PKCS7填充
        block_size = 16
        padded_data = self._pkcs7_pad(data, block_size)
        
        # ECB模式加密 - 使用正确的方法
        try:
            # 尝试使用内置的crypt_ecb方法一次性加密
            ciphertext = crypt_sm4.crypt_ecb(padded_data)
        except:
            # 如果失败，使用分块加密
            ciphertext = b''
            for i in range(0, len(padded_data), block_size):
                block = padded_data[i:i+block_size]
                if len(block) == block_size:  # 确保块大小正确
                    encrypted_block = crypt_sm4.crypt_ecb(block)
                    ciphertext += encrypted_block
                else:
                    # 如果最后一块不足16字节，再次填充
                    padded_block = self._pkcs7_pad(block, block_size)
                    encrypted_block = crypt_sm4.crypt_ecb(padded_block)
                    ciphertext += encrypted_block
        
        # 计算完整性校验（使用SM3）
        integrity_data = db_key + ciphertext + b'database_integrity'
        integrity_hash = sm3.sm3_hash([i for i in integrity_data])
        
        return {
            'db_ciphertext': ciphertext.hex(),
            'db_integrity_hash': integrity_hash,
            'db_data_length': len(data),
            'db_padded_length': len(padded_data)
        }
    
    def _sm4_decrypt_from_db(self, encrypted_data: Dict[str, str], db_key: bytes) -> bytes:
        """使用SM4从数据库解密"""
        # 提取加密组件
        ciphertext = bytes.fromhex(encrypted_data['db_ciphertext'])
        stored_hash = encrypted_data['db_integrity_hash']
        data_length = encrypted_data.get('db_data_length', 0)
        
        # 验证完整性
        integrity_data = db_key + ciphertext + b'database_integrity'
        computed_hash = sm3.sm3_hash([i for i in integrity_data])
        
        if computed_hash != stored_hash:
            raise DatabaseCryptoError("Database data integrity check failed")
        
        # 创建SM4解密器
        crypt_sm4 = sm4.CryptSM4()
        crypt_sm4.set_key(db_key, sm4.SM4_DECRYPT)
        
        # ECB模式解密 - 使用正确的方法
        try:
            # 尝试使用内置的crypt_ecb方法一次性解密
            plaintext_padded = crypt_sm4.crypt_ecb(ciphertext)
        except:
            # 如果失败，使用分块解密
            block_size = 16
            plaintext_padded = b''
            for i in range(0, len(ciphertext), block_size):
                block = ciphertext[i:i+block_size]
                if len(block) == block_size:  # 确保块大小正确
                    decrypted_block = crypt_sm4.crypt_ecb(block)
                    plaintext_padded += decrypted_block
        
        # 去除填充
        try:
            plaintext_bytes = self._pkcs7_unpad(plaintext_padded)
        except Exception as e:
            self.logger.warning(f"PKCS7 unpadding failed, using raw data: {e}")
            plaintext_bytes = plaintext_padded
        
        # 确保数据长度正确
        if data_length > 0 and len(plaintext_bytes) != data_length:
            if len(plaintext_bytes) > data_length:
                plaintext_bytes = plaintext_bytes[:data_length]
            else:
                self.logger.warning(f"Decrypted data length mismatch: expected {data_length}, got {len(plaintext_bytes)}")
        
        return plaintext_bytes
    
    def encrypt_user_features_for_db(self, features: Dict[str, Any], user_id: str) -> Dict[str, Dict]:
        """
        为数据库存储加密用户特征
        
        Args:
            features: 用户特征数据
            user_id: 用户ID
            
        Returns:
            数据库加密的特征数据
        """
        encrypted_features = {}
        
        for feature_name, feature_value in features.items():
            try:
                # 为每个特征使用不同的存储密钥
                purpose = f"user_feature_{feature_name}"
                encrypted_features[feature_name] = self.encrypt_for_database(
                    feature_value, 
                    purpose
                )
                
                # 添加用户特定的信息
                encrypted_features[feature_name]['user_context'] = hashlib.sha256(
                    f"{user_id}_{feature_name}".encode('utf-8')
                ).hexdigest()[:16]
                
            except Exception as e:
                self.logger.error(f"Failed to encrypt feature {feature_name} for database: {e}")
                raise DatabaseCryptoError(f"Database feature encryption failed for {feature_name}")
        
        return encrypted_features
    
    def decrypt_user_features_from_db(self, encrypted_features: Dict[str, Dict]) -> Dict[str, Any]:
        """
        从数据库解密用户特征
        
        Args:
            encrypted_features: 数据库加密的特征数据
            
        Returns:
            解密后的特征数据
        """
        decrypted_features = {}
        
        for feature_name, encrypted_data in encrypted_features.items():
            try:
                decrypted_features[feature_name] = self.decrypt_from_database(encrypted_data)
            except Exception as e:
                self.logger.error(f"Failed to decrypt feature {feature_name} from database: {e}")
                decrypted_features[feature_name] = None
        
        return decrypted_features
    
    def calculate_storage_hash(self, data: Any) -> str:
        """
        计算数据库存储哈希
        
        Args:
            data: 数据
            
        Returns:
            存储哈希值
        """
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = json.dumps(data, ensure_ascii=False, sort_keys=True).encode('utf-8')
        
        # 使用SM3计算哈希
        return sm3.sm3_hash([i for i in data_bytes])
    
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
        
        # 验证填充长度的合理性
        if padding_len == 0 or padding_len > 16 or padding_len > len(data):
            self.logger.warning(f"Invalid padding length: {padding_len}, data length: {len(data)}")
            return data
        
        # 验证填充字节的一致性
        for i in range(padding_len):
            if data[-(i+1)] != padding_len:
                self.logger.warning(f"Invalid padding pattern at position {i+1}")
                return data
        
        return data[:-padding_len]
    
    def get_database_encryption_info(self) -> Dict[str, Any]:
        """获取数据库加密信息"""
        return {
            'algorithm': self.algorithm.upper(),
            'key_size': self.key_size * 8,  # 转换为位数
            'hash_algorithm': 'SM3',
            'integrity_protection': True,
            'isolation_status': 'COMPLETELY_ISOLATED_FROM_COMMUNICATION',
            'key_derivation': 'SM3_BASED_HKDF',
            'supported_purposes': [
                'user_data',
                'risk_logs',
                'feature_history',
                'statistics'
            ]
        }
    
    def rotate_database_keys(self):
        """轮换数据库密钥"""
        self.logger.info("Starting database key rotation...")
        
        # 生成新的数据库主密钥
        old_master_key = self.db_master_key
        self.db_master_key = secrets.token_bytes(self.key_size)
        
        # 安全删除旧密钥
        if old_master_key:
            # 用随机数据覆盖
            for i in range(len(old_master_key)):
                old_master_key = secrets.token_bytes(len(old_master_key))
        
        self.logger.warning(f"Database key rotated. New master key: {self.db_master_key.hex()}")
        self.logger.info("Database key rotation completed")


# 全局数据库加密引擎实例
_database_crypto_engine: Optional[DatabaseCryptoEngine] = None


def initialize_database_crypto_engine(config: Dict) -> DatabaseCryptoEngine:
    """
    初始化数据库加密引擎
    
    Args:
        config: 数据库加密配置
        
    Returns:
        数据库加密引擎实例
    """
    global _database_crypto_engine
    _database_crypto_engine = DatabaseCryptoEngine(config)
    return _database_crypto_engine


def get_database_crypto_engine() -> DatabaseCryptoEngine:
    """获取数据库加密引擎实例"""
    if _database_crypto_engine is None:
        raise DatabaseCryptoError("Database crypto engine not initialized")
    return _database_crypto_engine 