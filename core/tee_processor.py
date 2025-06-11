"""
TEE处理器模块 - 改进版
支持分离式密钥管理和混合加密架构
"""
import json
import logging
import time
import gc
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timezone
from core.crypto_engine import get_crypto_engine, CryptoError, initialize_crypto_engine
from core.feature_manager import get_feature_manager, FeatureManagerError, initialize_feature_manager
from core.rba_engine import get_rba_engine, RBACalculationError, initialize_rba_engine
from utils.db_manager import get_db_manager, DatabaseError, initialize_database
from utils.memory_monitor import get_memory_status, cleanup_memory, initialize_memory_monitor, MemoryMonitor
from utils.validators import ValidationError
from config import get_all_configs
from .sm_crypto_engine import get_sm_crypto_engine, SMCryptoError

# 新增：导入改进的密钥管理组件
from .session_key_manager import (
    get_session_key_manager, 
    SessionKeyError, 
    initialize_session_key_manager
)
from .tee_keypair_manager import (
    get_tee_keypair_manager, 
    TEEKeyPairError, 
    initialize_tee_keypair_manager
)
from .database_crypto_engine import (
    get_database_crypto_engine, 
    DatabaseCryptoError, 
    initialize_database_crypto_engine
)


class TEEProcessorError(Exception):
    """TEE处理器异常"""
    pass


class TEEProcessor:
    """
    TEE处理器 - 改进版
    支持分离式密钥管理和混合加密架构
    """
    
    def __init__(self, config: Dict):
        """
        初始化TEE处理器
        
        Args:
            config: 处理器配置
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 传统组件
        self.crypto_engine = None
        self.feature_manager = None
        self.rba_engine = None
        self.db_manager = None
        self.memory_monitor = MemoryMonitor(config.get('memory', {}))
        
        # 新增：分离式密钥管理组件
        self.session_key_manager = None
        self.tee_keypair_manager = None
        self.database_crypto_engine = None
        
        # 初始化标志
        self._initialized = False
        
        # 统计信息
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'session_keys_processed': 0,
            'database_encryptions': 0,
            'start_time': time.time()
        }
        
        self.logger.info("TEE processor initializing with improved key management...")
    
    def initialize(self):
        """初始化所有组件"""
        try:
            # 获取所有配置
            all_configs = get_all_configs()
            
            # 初始化传统组件
            self.logger.info("Initializing legacy crypto engine...")
            self.crypto_engine = get_sm_crypto_engine()
            self.feature_manager = get_feature_manager()
            self.rba_engine = get_rba_engine()
            
            # 初始化数据库管理器
            self.logger.info("Initializing database manager...")
            self.db_manager = initialize_database(all_configs)
            
            # 新增：初始化改进的密钥管理组件
            self.logger.info("🔑 Initializing improved key management components...")
            
            # 1. 会话密钥管理器
            comm_config = all_configs.get('security', {}).get('communication_encryption', {})
            session_algo = comm_config.get('session_key', {}).get('algorithm', 'sm4')
            self.session_key_manager = initialize_session_key_manager(session_algo)
            
            # 2. TEE密钥对管理器
            tee_keypair_algo = comm_config.get('tee_keypair', {}).get('algorithm', 'sm2')
            self.tee_keypair_manager = initialize_tee_keypair_manager(tee_keypair_algo)
            
            # 生成TEE密钥对
            private_key, public_key = self.tee_keypair_manager.generate_keypair()
            self.logger.info(f"🔐 Generated TEE keypair: {tee_keypair_algo.upper()}")
            self.logger.info(f"📤 TEE Public Key: {public_key[:32]}...")
            
            # 3. 数据库加密引擎
            db_crypto_config = all_configs.get('security', {}).get('database_encryption', {})
            if not db_crypto_config:
                db_crypto_config = all_configs.get('database_security', {})
            self.database_crypto_engine = initialize_database_crypto_engine(db_crypto_config)
            
            self._initialized = True
            self.logger.info("✅ TEE processor initialized successfully with improved key management")
            self.logger.info("🔐 Key isolation: Communication ↔️ Database keys are completely separated")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize TEE processor: {e}")
            raise TEEProcessorError(f"Failed to initialize TEE processor: {e}")
    
    def process_hybrid_encrypted_message(self, encrypted_message: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理混合加密消息（新的改进接口）
        
        Args:
            encrypted_message: 包含混合加密数据的消息
                - encrypted_session_key: TEE公钥加密的会话密钥
                - encrypted_features: 会话密钥加密的特征数据
                
        Returns:
            处理结果，包含风险评估和特征分析
        """
        start_time = datetime.now(timezone.utc)
        request_id = encrypted_message.get('request_id', f"hybrid_req_{int(start_time.timestamp())}")
        
        self.logger.info(f"🔐 Processing hybrid encrypted message: {request_id}")
        self.stats['total_requests'] += 1
        
        # 用于安全清理的临时变量
        session_key = None
        decrypted_features = None
        validated_features = None
        
        try:
            # 1. 使用TEE私钥解密会话密钥
            encrypted_session_key = encrypted_message.get('encrypted_session_key')
            if not encrypted_session_key:
                raise TEEProcessorError("No encrypted session key found in message")
            
            self.logger.info("🔓 Decrypting session key with TEE private key...")
            session_key = self.tee_keypair_manager.decrypt_session_key(encrypted_session_key)
            self.stats['session_keys_processed'] += 1
            self.logger.info("✅ Session key decrypted successfully")
            
            # 2. 使用会话密钥解密特征数据
            encrypted_features_data = encrypted_message.get('encrypted_features')
            if not encrypted_features_data:
                raise TEEProcessorError("No encrypted features found in message")
            
            self.logger.info("🔍 Decrypting features with session key...")
            
            # 支持多种特征数据格式
            if isinstance(encrypted_features_data, dict):
                # 多个特征分别加密
                decrypted_features = {}
                for feature_name, encrypted_feature in encrypted_features_data.items():
                    feature_bytes = self.session_key_manager.decrypt_with_session_key(
                        encrypted_feature, session_key
                    )
                    # 解析JSON格式的特征数据
                    try:
                        decrypted_features[feature_name] = json.loads(feature_bytes.decode('utf-8'))
                    except json.JSONDecodeError:
                        decrypted_features[feature_name] = feature_bytes.decode('utf-8')
            else:
                # 整体加密的特征数据
                features_bytes = self.session_key_manager.decrypt_with_session_key(
                    encrypted_features_data, session_key
                )
                decrypted_features = json.loads(features_bytes.decode('utf-8'))
            
            self.logger.info(f"✅ Successfully decrypted {len(decrypted_features)} features")
            
            # 3. 验证和清理解密的特征数据
            validated_features = self._validate_features(decrypted_features)
            
            # 4. 特征处理和分析
            self.logger.info("🔍 Processing features...")
            feature_analysis = self.feature_manager.process_features(validated_features)
            
            # 5. 风险评估
            self.logger.info("⚠️  Conducting risk assessment...")
            risk_context = {
                'timestamp': start_time.isoformat(),
                'request_id': request_id,
                'source_ip': encrypted_message.get('source_ip', 'unknown'),
                'user_agent': encrypted_message.get('user_agent', 'unknown'),
                'encryption_method': 'hybrid_sm2_sm4'
            }
            
            risk_assessment = self.rba_engine.assess_risk(validated_features, risk_context)
            
            # 6. 使用独立密钥存储到数据库
            await_storage = self._store_with_database_encryption(
                validated_features, risk_assessment, request_id
            )
            
            # 7. 生成处理结果
            processing_result = {
                'request_id': request_id,
                'timestamp': start_time.isoformat(),
                'processing_time_ms': (datetime.now(timezone.utc) - start_time).total_seconds() * 1000,
                'status': 'success',
                'feature_count': len(validated_features),
                'feature_analysis': feature_analysis,
                'risk_assessment': risk_assessment,
                'memory_usage': self.memory_monitor.get_memory_info(),
                'encryption_info': {
                    'method': 'hybrid_encryption',
                    'session_key_algorithm': self.session_key_manager.algorithm.upper(),
                    'tee_keypair_algorithm': self.tee_keypair_manager.algorithm.upper(),
                    'database_algorithm': self.database_crypto_engine.algorithm.upper(),
                    'key_isolation': 'ENABLED'
                }
            }
            
            # 8. 对结果进行数字签名
            signature_data = json.dumps(processing_result, sort_keys=True).encode('utf-8')
            signature = self.tee_keypair_manager.sign_data(signature_data)
            processing_result['digital_signature'] = signature
            processing_result['signature_algorithm'] = self.tee_keypair_manager.algorithm.upper()
            
            self.stats['successful_requests'] += 1
            self.logger.info(f"✅ Successfully processed hybrid encrypted message: {request_id}")
            return processing_result
            
        except (SessionKeyError, TEEKeyPairError, DatabaseCryptoError) as e:
            self.logger.error(f"❌ Key management error: {e}")
            self.stats['failed_requests'] += 1
            return self._generate_error_response(request_id, f"Key management error: {e}", start_time)
        
        except Exception as e:
            self.logger.error(f"❌ Processing error: {e}")
            self.stats['failed_requests'] += 1
            return self._generate_error_response(request_id, f"Processing error: {e}", start_time)
        
        finally:
            # 9. 立即进行安全清理
            self.logger.info("🧹 Performing secure cleanup...")
            self._secure_cleanup_improved(session_key, decrypted_features, validated_features)
    
    def _store_with_database_encryption(self, features: Dict[str, Any], risk_assessment: Dict[str, Any], request_id: str) -> bool:
        """
        使用独立的数据库密钥加密并存储数据
        
        Args:
            features: 特征数据
            risk_assessment: 风险评估结果
            request_id: 请求ID
            
        Returns:
            存储是否成功
        """
        try:
            self.logger.info("💾 Storing data with independent database encryption...")
            
            # 为不同类型的数据使用不同的数据库存储密钥
            user_id = risk_assessment.get('user_id', 'anonymous')
            
            # 1. 加密用户特征数据
            encrypted_features = self.database_crypto_engine.encrypt_user_features_for_db(
                features, user_id
            )
            
            # 2. 加密风险评估结果
            encrypted_risk_data = self.database_crypto_engine.encrypt_for_database(
                risk_assessment, "risk_logs"
            )
            
            # 3. 存储到数据库
            if self.db_manager:
                storage_result = self.db_manager.store_risk_log(
                    user_id=user_id,
                    encrypted_features=encrypted_features,
                    risk_score=risk_assessment.get('risk_score', 0.0),
                    risk_level=risk_assessment.get('risk_level', 'unknown'),
                    metadata={
                        'request_id': request_id,
                        'encrypted_risk_data': encrypted_risk_data,
                        'database_encryption': 'INDEPENDENT_KEY_SYSTEM',
                        'storage_timestamp': datetime.now(timezone.utc).isoformat()
                    }
                )
                
                self.stats['database_encryptions'] += 1
                self.logger.info("✅ Data successfully stored with database encryption")
                return True
            else:
                self.logger.warning("⚠️  Database manager not available")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Database storage error: {e}")
            return False
    
    def _secure_cleanup_improved(self, *sensitive_objects):
        """
        改进的安全清理方法
        
        Args:
            *sensitive_objects: 需要安全清理的敏感对象
        """
        try:
            cleanup_count = 0
            
            for obj in sensitive_objects:
                if obj is not None:
                    if isinstance(obj, (bytes, bytearray)):
                        # 对字节数据进行安全覆盖
                        if isinstance(obj, bytearray):
                            for i in range(len(obj)):
                                obj[i] = 0
                        cleanup_count += 1
                    elif isinstance(obj, dict):
                        # 清空字典内容
                        obj.clear()
                        cleanup_count += 1
                    elif isinstance(obj, str):
                        # 字符串无法直接覆盖，但可以删除引用
                        del obj
                        cleanup_count += 1
            
            # 使用会话密钥管理器的安全删除功能
            if self.session_key_manager:
                self.session_key_manager.secure_delete(*sensitive_objects)
            
            # 强制垃圾回收
            gc.collect()
            
            self.logger.debug(f"🧹 Secure cleanup completed: {cleanup_count} objects cleaned")
            
        except Exception as e:
            # 3. 风险评估
            risk_context = context or {}
            risk_context.update({
                'timestamp': start_time.isoformat(),
                'request_id': request_id
            })
            
            risk_assessment = self.rba_engine.assess_risk(validated_features, risk_context)
            
            # 4. 生成处理结果
            processing_result = {
                'request_id': request_id,
                'timestamp': start_time.isoformat(),
                'processing_time_ms': (datetime.now(timezone.utc) - start_time).total_seconds() * 1000,
                'status': 'success',
                'feature_count': len(validated_features),
                'feature_analysis': feature_analysis,
                'risk_assessment': risk_assessment,
                'memory_usage': self.memory_monitor.get_memory_info()
            }
            
            # 5. 数字签名
            signature = self.crypto_engine.sign_data(processing_result)
            processing_result['digital_signature'] = signature
            processing_result['signature_algorithm'] = 'SM2'
            
            self.logger.info(f"✅ Successfully processed plaintext features: {request_id}")
            return processing_result
            
        except Exception as e:
            self.logger.error(f"❌ Processing error: {e}")
            return self._generate_error_response(request_id, f"Processing error: {e}", start_time)
    
    def encrypt_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        加密响应数据
        
        Args:
            response_data: 响应数据
            
        Returns:
            加密后的响应
        """
        try:
            encrypted_response = self.crypto_engine.encrypt_data(
                response_data, 
                key_purpose="response"
            )
            
            return {
                'encrypted_response': encrypted_response,
                'encryption_info': {
                    'algorithm': 'SM4-ECB',
                    'key_derivation': 'SM3-HKDF',
                    'signature': 'SM2',
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
            }
            
        except Exception as e:
            raise TEEProcessorError(f"Failed to encrypt response: {e}")
    
    def decrypt_request(self, encrypted_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        解密请求数据
        
        Args:
            encrypted_request: 加密的请求数据
            
        Returns:
            解密后的请求数据
        """
        try:
            if 'encrypted_data' in encrypted_request:
                decrypted_data = self.crypto_engine.decrypt_data(encrypted_request['encrypted_data'])
                return decrypted_data
            else:
                raise TEEProcessorError("No encrypted data found in request")
                
        except Exception as e:
            raise TEEProcessorError(f"Failed to decrypt request: {e}")
    
    def _validate_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        验证和清理特征数据
        
        Args:
            features: 原始特征数据
            
        Returns:
            验证后的特征数据
        """
        validated = {}
        
        for feature_name, feature_value in features.items():
            if feature_value is None:
                self.logger.warning(f"Skipping null feature: {feature_name}")
                continue
                
            # 基本验证
            if isinstance(feature_name, str) and len(feature_name) > 0:
                # 清理特征名称
                clean_name = feature_name.strip()
                if clean_name:
                    validated[clean_name] = feature_value
                    
        if not validated:
            raise TEEProcessorError("No valid features found after validation")
            
        self.logger.info(f"Validated {len(validated)} features")
        return validated
    
    def _secure_cleanup(self, *data_objects):
        """
        安全清理敏感数据
        
        Args:
            *data_objects: 要清理的数据对象
        """
        for data in data_objects:
            if data:
                self.crypto_engine.secure_delete(data)
    
    def _generate_error_response(self, request_id: str, error_message: str, start_time: datetime) -> Dict[str, Any]:
        """
        生成错误响应
        
        Args:
            request_id: 请求ID
            error_message: 错误消息
            start_time: 开始时间
            
        Returns:
            错误响应
        """
        error_response = {
            'request_id': request_id,
            'timestamp': start_time.isoformat(),
            'processing_time_ms': (datetime.now(timezone.utc) - start_time).total_seconds() * 1000,
            'status': 'error',
            'error': error_message,
            'memory_usage': self.memory_monitor.get_memory_info()
        }
        
        # 即使是错误响应也要签名
        try:
            signature = self.crypto_engine.sign_data(error_response)
            error_response['digital_signature'] = signature
            error_response['signature_algorithm'] = 'SM2'
        except Exception:
            pass  # 签名失败不应该阻止错误响应
            
        return error_response
    
    def get_processor_info(self) -> Dict[str, Any]:
        """获取处理器信息"""
        return {
            'processor_version': '2.0.0-SM',
            'algorithms': self.crypto_engine.get_algorithm_info(),
            'features_supported': self.feature_manager.get_supported_features(),
            'memory_info': self.memory_monitor.get_memory_info(),
            'processing_capabilities': {
                'encrypted_input': True,
                'plaintext_input': True,
                'encrypted_output': True,
                'digital_signature': True,
                'real_time_processing': True
            }
        }
    
    def get_status(self) -> Dict[str, Any]:
        """获取TEE处理器状态"""
        memory_status = get_memory_status()
        
        # 计算成功率
        success_rate = 0.0
        if self.stats['total_requests'] > 0:
            success_rate = self.stats['successful_requests'] / self.stats['total_requests']
        
        status = {
            'initialized': self._initialized,
            'uptime': time.time() - self.stats['start_time'],
            'total_requests': self.stats['total_requests'],
            'successful_requests': self.stats['successful_requests'],
            'failed_requests': self.stats['failed_requests'],
            'success_rate': success_rate,
            'memory_status': memory_status,
            'components': {
                'crypto_engine': self.crypto_engine is not None,
                'feature_manager': self.feature_manager is not None,
                'rba_engine': self.rba_engine is not None,
                'db_manager': self.db_manager is not None,
                'memory_monitor': self.memory_monitor is not None
            }
        }
        
        return status
    
    def get_public_key_info(self) -> Dict[str, Any]:
        """获取公钥信息"""
        if not self.crypto_engine:
            raise TEEProcessorError("Crypto engine not initialized")
        
        return self.crypto_engine.get_public_key_info()
    
    def cleanup_old_data(self, days: int = 90) -> Dict[str, Any]:
        """清理旧数据"""
        try:
            deleted_count = self.db_manager.cleanup_old_records(days)
            
            return {
                'success': True,
                'deleted_records': deleted_count,
                'cleanup_days': days,
                'timestamp': time.time()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'timestamp': time.time()
            }

    def process_encrypted_message(self, encrypted_message: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理加密消息（向后兼容旧版本）
        
        Args:
            encrypted_message: 包含加密特征数据的消息
            
        Returns:
            处理结果
        """
        # 检查是否为新的混合加密格式
        if 'encrypted_session_key' in encrypted_message:
            self.logger.info("🔄 Detected hybrid encryption format, using improved processor")
            return self.process_hybrid_encrypted_message(encrypted_message)
        
        # 使用传统处理方式（向后兼容）
        start_time = datetime.now(timezone.utc)
        request_id = encrypted_message.get('request_id', f"legacy_req_{int(start_time.timestamp())}")
        
        self.logger.info(f"🔒 Processing legacy encrypted message: {request_id}")
        self.stats['total_requests'] += 1
        
        try:
            # 使用传统SM加密引擎
            encrypted_features = encrypted_message.get('encrypted_features')
            if not encrypted_features:
                raise TEEProcessorError("No encrypted features found in message")
            
            decrypted_features = self.crypto_engine.decrypt_features(encrypted_features)
            validated_features = self._validate_features(decrypted_features)
            
            # 特征处理和风险评估
            feature_analysis = self.feature_manager.process_features(validated_features)
            
            risk_context = {
                'timestamp': start_time.isoformat(),
                'request_id': request_id,
                'source_ip': encrypted_message.get('source_ip', 'unknown'),
                'user_agent': encrypted_message.get('user_agent', 'unknown'),
                'encryption_method': 'legacy_sm_crypto'
            }
            
            risk_assessment = self.rba_engine.assess_risk(validated_features, risk_context)
            
            # 生成处理结果
            processing_result = {
                'request_id': request_id,
                'timestamp': start_time.isoformat(),
                'processing_time_ms': (datetime.now(timezone.utc) - start_time).total_seconds() * 1000,
                'status': 'success',
                'feature_count': len(validated_features),
                'feature_analysis': feature_analysis,
                'risk_assessment': risk_assessment,
                'memory_usage': self.memory_monitor.get_memory_info(),
                'encryption_info': {
                    'method': 'legacy_encryption',
                    'compatibility_mode': True
                }
            }
            
            # 数字签名
            signature = self.crypto_engine.sign_data(processing_result)
            processing_result['digital_signature'] = signature
            processing_result['signature_algorithm'] = 'SM2'
            
            # 安全清理
            self._secure_cleanup(decrypted_features, validated_features)
            
            self.stats['successful_requests'] += 1
            self.logger.info(f"✅ Successfully processed legacy encrypted message: {request_id}")
            return processing_result
            
        except SMCryptoError as e:
            self.logger.error(f"❌ Legacy cryptographic error: {e}")
            self.stats['failed_requests'] += 1
            return self._generate_error_response(request_id, f"Legacy cryptographic error: {e}", start_time)
        
        except Exception as e:
            self.logger.error(f"❌ Legacy processing error: {e}")
            self.stats['failed_requests'] += 1
            return self._generate_error_response(request_id, f"Legacy processing error: {e}", start_time)
    
    def process_plaintext_features(self, features: Dict[str, Any], context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        处理明文特征数据（向后兼容）
        
        Args:
            features: 明文特征数据
            context: 请求上下文
            
        Returns:
            处理结果
        """
        start_time = datetime.now(timezone.utc)
        request_id = f"plaintext_req_{int(start_time.timestamp())}"
        
        self.logger.info(f"🔓 Processing plaintext features: {request_id}")
        self.stats['total_requests'] += 1
        
        try:
            # 1. 验证和清理特征数据
            validated_features = self._validate_features(features)
            
            # 2. 特征处理和分析
            feature_analysis = self.feature_manager.process_features(validated_features)
            
            # 3. 风险评估
            risk_context = context or {}
            risk_context.update({
                'timestamp': start_time.isoformat(),
                'request_id': request_id,
                'encryption_method': 'plaintext'
            })
            
            risk_assessment = self.rba_engine.assess_risk(validated_features, risk_context)
            
            # 4. 生成处理结果
            processing_result = {
                'request_id': request_id,
                'timestamp': start_time.isoformat(),
                'processing_time_ms': (datetime.now(timezone.utc) - start_time).total_seconds() * 1000,
                'status': 'success',
                'feature_count': len(validated_features),
                'feature_analysis': feature_analysis,
                'risk_assessment': risk_assessment,
                'memory_usage': self.memory_monitor.get_memory_info(),
                'encryption_info': {
                    'method': 'plaintext',
                    'warning': 'Unencrypted data processing'
                }
            }
            
            # 数字签名
            if self.tee_keypair_manager:
                signature_data = json.dumps(processing_result, sort_keys=True).encode('utf-8')
                signature = self.tee_keypair_manager.sign_data(signature_data)
                processing_result['digital_signature'] = signature
                processing_result['signature_algorithm'] = self.tee_keypair_manager.algorithm.upper()
            elif self.crypto_engine:
                signature = self.crypto_engine.sign_data(processing_result)
                processing_result['digital_signature'] = signature
                processing_result['signature_algorithm'] = 'SM2'
            
            self.stats['successful_requests'] += 1
            self.logger.info(f"✅ Successfully processed plaintext features: {request_id}")
            return processing_result
            
        except Exception as e:
            self.logger.error(f"❌ Plaintext processing error: {e}")
            self.stats['failed_requests'] += 1
            return self._generate_error_response(request_id, f"Plaintext processing error: {e}", start_time)


# 全局TEE处理器实例
_tee_processor: Optional[TEEProcessor] = None


def initialize_tee_processor(config: Dict) -> TEEProcessor:
    """
    初始化TEE处理器
    
    Args:
        config: 处理器配置
        
    Returns:
        TEE处理器实例
    """
    global _tee_processor
    _tee_processor = TEEProcessor(config)
    _tee_processor.initialize()
    return _tee_processor


def get_tee_processor() -> TEEProcessor:
    """获取TEE处理器实例"""
    if _tee_processor is None:
        raise TEEProcessorError("TEE processor not initialized")
    return _tee_processor 