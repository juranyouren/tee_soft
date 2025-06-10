"""
国密加密引擎模块
使用SM2、SM3、SM4国密算法实现TEE安全特性
"""
import os
import json
import logging
import hashlib
from typing import Dict, Any, Optional
from gmssl import sm2, sm3, sm4
import secrets


class SMCryptoError(Exception):
    """国密加密操作异常"""
    pass


class SMCryptoEngine:
    """国密加密引擎"""
    
    def __init__(self, config: Dict):
        """
        初始化国密加密引擎
        
        Args:
            config: 安全配置
        """
        self.config = config
        self.encryption_config = config.get('encryption', {})
        self.key_config = config.get('key_management', {})
        self.logger = logging.getLogger(__name__)
        
        # 初始化SM4主密钥 (128位)
        self.master_key = self._initialize_master_key()
        
        # 生成SM2密钥对用于数字签名
        self.sm2_crypt = sm2.CryptSM2(public_key="", private_key="")
        self.private_key, self.public_key = self._generate_sm2_keypair()
        self.sm2_crypt = sm2.CryptSM2(public_key=self.public_key, private_key=self.private_key)
        
        self.logger.info("SM Crypto engine initialized successfully")
        self.logger.info(f"Using algorithms: SM4 (encryption), SM3 (hash), SM2 (signature)")
    
    def _initialize_master_key(self) -> bytes:
        """初始化SM4主密钥（128位）"""
        master_key_env = self.key_config.get('master_key_env', 'TEE_SM4_MASTER_KEY')
        master_key_hex = os.getenv(master_key_env)
        
        if master_key_hex:
            try:
                key = bytes.fromhex(master_key_hex)
                if len(key) == 16:  # SM4需要128位密钥
                    return key
                else:
                    self.logger.warning("Invalid SM4 master key length, generating new key")
            except ValueError:
                self.logger.warning("Invalid master key format in environment variable")
        
        # 生成新的SM4主密钥（128位）
        master_key = secrets.token_bytes(16)
        self.logger.warning(f"Generated new SM4 master key. Please save it to environment variable {master_key_env}")
        self.logger.info(f"SM4 Master key (save this): {master_key.hex()}")
        
        return master_key
    
    def _generate_sm2_keypair(self) -> tuple:
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
        
        return private_key, public_key
    
    def derive_sm4_key(self, purpose: str, info: Optional[str] = None) -> bytes:
        """
        从主密钥派生SM4子密钥
        
        Args:
            purpose: 密钥用途
            info: 附加信息
            
        Returns:
            派生的SM4密钥（128位）
        """
        if info is None:
            info = purpose
        
        # 使用SM3生成派生材料
        derive_input = self.master_key + purpose.encode('utf-8') + info.encode('utf-8')
        derived = sm3.sm3_hash([i for i in derive_input])
        
        # 取前128位作为SM4密钥
        return bytes.fromhex(derived)[:16]
    
    def encrypt_data(self, plaintext: Any, key_purpose: str = "default") -> Dict[str, str]:
        """
        使用SM4加密数据
        
        Args:
            plaintext: 明文数据
            key_purpose: 密钥用途
            
        Returns:
            加密结果字典
        """
        try:
            # 将数据转换为字节
            if isinstance(plaintext, str):
                data = plaintext.encode('utf-8')
            else:
                data = json.dumps(plaintext, ensure_ascii=False).encode('utf-8')
            
            # 派生SM4密钥
            sm4_key = self.derive_sm4_key(f"encrypt_{key_purpose}")
            
            # 创建SM4加密器，设置密钥
            crypt_sm4 = sm4.CryptSM4()
            crypt_sm4.set_key(sm4_key, sm4.SM4_ENCRYPT)
            
            # 对数据进行PKCS7填充
            block_size = 16
            padded_data = self._pkcs7_pad(data, block_size)
            
            # 使用ECB模式加密
            ciphertext = b''
            for i in range(0, len(padded_data), block_size):
                block = padded_data[i:i+block_size]
                encrypted_block = crypt_sm4.crypt_ecb(block)
                ciphertext += encrypted_block
            
            # 计算完整性校验（使用SM3）
            integrity_data = sm4_key + ciphertext
            integrity_hash = sm3.sm3_hash([i for i in integrity_data])
            
            return {
                'ciphertext': ciphertext.hex(),
                'integrity_hash': integrity_hash,
                'algorithm': 'sm4-ecb',
                'key_purpose': key_purpose,
                'data_length': len(data),
                'padded_length': len(padded_data)
            }
            
        except Exception as e:
            raise SMCryptoError(f"SM4 encryption failed: {e}")
    
    def decrypt_data(self, encrypted_data: Dict[str, str]) -> Any:
        """
        使用SM4解密数据
        
        Args:
            encrypted_data: 加密数据字典
            
        Returns:
            解密后的原始数据
        """
        try:
            # 提取加密组件
            ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
            stored_hash = encrypted_data['integrity_hash']
            key_purpose = encrypted_data.get('key_purpose', 'default')
            data_length = encrypted_data.get('data_length', 0)
            padded_length = encrypted_data.get('padded_length', 0)
            
            # 派生SM4密钥
            sm4_key = self.derive_sm4_key(f"encrypt_{key_purpose}")
            
            # 验证完整性
            integrity_data = sm4_key + ciphertext
            computed_hash = sm3.sm3_hash([i for i in integrity_data])
            
            if computed_hash != stored_hash:
                raise SMCryptoError("Data integrity check failed")
            
            # 创建SM4解密器，设置密钥
            crypt_sm4 = sm4.CryptSM4()
            crypt_sm4.set_key(sm4_key, sm4.SM4_DECRYPT)
            
            # 使用ECB模式解密
            block_size = 16
            plaintext_padded = b''
            for i in range(0, len(ciphertext), block_size):
                block = ciphertext[i:i+block_size]
                decrypted_block = crypt_sm4.crypt_ecb(block)
                plaintext_padded += decrypted_block
            
            # 移除padding并截断到原始长度
            plaintext_bytes = self._pkcs7_unpad(plaintext_padded)
            
            # 确保数据长度正确
            if data_length > 0 and len(plaintext_bytes) != data_length:
                self.logger.warning(f"Data length mismatch: expected {data_length}, got {len(plaintext_bytes)}")
                if len(plaintext_bytes) > data_length:
                    plaintext_bytes = plaintext_bytes[:data_length]
            
            # 尝试解析为JSON，失败则返回字符串
            try:
                plaintext_str = plaintext_bytes.decode('utf-8')
                return json.loads(plaintext_str)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return plaintext_bytes.decode('utf-8', errors='replace')
            
        except Exception as e:
            raise SMCryptoError(f"SM4 decryption failed: {e}")
    
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
        
        # 验证填充长度是否有效
        if padding_len == 0 or padding_len > 16 or padding_len > len(data):
            return data  # 如果填充无效，返回原数据
        
        # 验证所有填充字节是否相同
        for i in range(padding_len):
            if data[-(i+1)] != padding_len:
                return data  # 如果填充不一致，返回原数据
        
        return data[:-padding_len]
    
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
                raise SMCryptoError(f"Feature encryption failed for {feature_name}")
        
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
        使用SM3计算特征值的哈希
        
        Args:
            feature_value: 特征值
            feature_name: 特征名称（用于加盐）
            
        Returns:
            SM3哈希值
        """
        if isinstance(feature_value, str):
            data = feature_value.encode('utf-8')
        else:
            data = json.dumps(feature_value, ensure_ascii=False, sort_keys=True).encode('utf-8')
        
        # 使用特征名称作为盐值
        salt = feature_name.encode('utf-8')
        salted_data = salt + data
        
        return sm3.sm3_hash([i for i in salted_data])
    
    def sign_data(self, data: Any) -> str:
        """
        使用SM2对数据进行数字签名
        
        Args:
            data: 要签名的数据
            
        Returns:
            SM2签名的十六进制字符串
        """
        try:
            if isinstance(data, str):
                message = data.encode('utf-8')
            else:
                message = json.dumps(data, ensure_ascii=False, sort_keys=True).encode('utf-8')
            
            # 使用SM2签名 - 传入字节数据而不是hex字符串
            signature = self.sm2_crypt.sign(message, self._generate_random_hex())
            return signature
            
        except Exception as e:
            raise SMCryptoError(f"SM2 signing failed: {e}")
    
    def verify_signature(self, data: Any, signature: str) -> bool:
        """
        使用SM2验证数字签名
        
        Args:
            data: 原始数据
            signature: SM2签名字符串
            
        Returns:
            验证结果
        """
        try:
            if isinstance(data, str):
                message = data.encode('utf-8')
            else:
                message = json.dumps(data, ensure_ascii=False, sort_keys=True).encode('utf-8')
            
            # 使用SM2验证签名 - 传入字节数据
            return self.sm2_crypt.verify(signature, message)
            
        except Exception:
            return False
    
    def _generate_random_hex(self, length: int = 64) -> str:
        """生成随机十六进制字符串"""
        return secrets.token_hex(length // 2)
    
    def secure_delete(self, data: Any):
        """
        安全删除敏感数据
        
        Args:
            data: 要删除的数据
        """
        if isinstance(data, bytes):
            # 用随机数据覆盖内存
            for i in range(len(data)):
                data = data[:i] + secrets.token_bytes(1) + data[i+1:]
        elif isinstance(data, str):
            # 字符串无法直接修改
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
    
    def get_public_key_info(self) -> Dict[str, str]:
        """
        获取SM2公钥信息
        
        Returns:
            公钥信息
        """
        return {
            'algorithm': 'SM2',
            'public_key': self.public_key,
            'curve': 'sm2p256v1',
            'key_size': 256
        }
    
    def get_algorithm_info(self) -> Dict[str, str]:
        """获取算法信息"""
        return {
            'encryption': 'SM4-ECB',
            'hash': 'SM3',
            'signature': 'SM2',
            'key_size_sm4': '128 bits',
            'key_size_sm2': '256 bits',
            'standard': 'GB/T 32918 (SM2), GB/T 32905 (SM3), GB/T 32907 (SM4)',
            'security_level': 'Commercial level (国密商用密码)'
        }


# 全局国密加密引擎实例
_sm_crypto_engine: Optional[SMCryptoEngine] = None


def initialize_sm_crypto_engine(config: Dict) -> SMCryptoEngine:
    """
    初始化国密加密引擎
    
    Args:
        config: 安全配置
        
    Returns:
        国密加密引擎实例
    """
    global _sm_crypto_engine
    _sm_crypto_engine = SMCryptoEngine(config)
    return _sm_crypto_engine


def get_sm_crypto_engine() -> SMCryptoEngine:
    """获取国密加密引擎实例"""
    if _sm_crypto_engine is None:
        raise SMCryptoError("SM Crypto engine not initialized")
    return _sm_crypto_engine