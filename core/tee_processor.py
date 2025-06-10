"""
TEE处理器模块
使用国密算法处理加密的用户特征数据
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


class TEEProcessorError(Exception):
    """TEE处理器异常"""
    pass


class TEEProcessor:
    """
    TEE处理器
    负责安全地处理加密的用户特征数据
    """
    
    def __init__(self, config: Dict):
        """
        初始化TEE处理器
        
        Args:
            config: 处理器配置
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.crypto_engine = None
        self.feature_manager = None
        self.rba_engine = None
        self.db_manager = None
        self.memory_monitor = MemoryMonitor(config.get('memory', {}))
        
        # 初始化标志
        self._initialized = False
        
        # 统计信息
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'start_time': time.time()
        }
        
        # 获取各个组件
        try:
            self.crypto_engine = get_sm_crypto_engine()
            self.feature_manager = get_feature_manager()
            self.rba_engine = get_rba_engine()
        except Exception as e:
            raise TEEProcessorError(f"Failed to initialize TEE processor components: {e}")
        
        self.logger.info("TEE processor initialized with SM algorithms")
    
    def initialize(self):
        """初始化所有组件"""
        try:
            # 获取所有配置
            all_configs = get_all_configs()
            
            # 初始化数据库管理器
            self.logger.info("Initializing database manager...")
            self.db_manager = initialize_database(all_configs)
            
            self._initialized = True
            self.logger.info("TEE processor initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize TEE processor: {e}")
            raise TEEProcessorError(f"Failed to initialize TEE processor: {e}")
    
    def process_encrypted_message(self, encrypted_message: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理加密消息的主要接口
        
        Args:
            encrypted_message: 包含加密特征数据的消息
            
        Returns:
            处理结果，包含风险评估和特征分析
        """
        start_time = datetime.now(timezone.utc)
        request_id = encrypted_message.get('request_id', f"req_{int(start_time.timestamp())}")
        
        self.logger.info(f"🔒 Processing encrypted message: {request_id}")
        
        try:
            # 1. 解密用户特征数据
            encrypted_features = encrypted_message.get('encrypted_features')
            if not encrypted_features:
                raise TEEProcessorError("No encrypted features found in message")
            
            self.logger.info("📥 Decrypting user features...")
            decrypted_features = self.crypto_engine.decrypt_features(encrypted_features)
            self.logger.info(f"✅ Successfully decrypted {len(decrypted_features)} features")
            
            # 2. 验证和清理解密的特征数据
            validated_features = self._validate_features(decrypted_features)
            
            # 3. 特征处理和分析
            self.logger.info("🔍 Processing features...")
            feature_analysis = self.feature_manager.process_features(validated_features)
            
            # 4. 风险评估
            self.logger.info("⚠️  Conducting risk assessment...")
            risk_context = {
                'timestamp': start_time.isoformat(),
                'request_id': request_id,
                'source_ip': encrypted_message.get('source_ip', 'unknown'),
                'user_agent': encrypted_message.get('user_agent', 'unknown')
            }
            
            risk_assessment = self.rba_engine.assess_risk(
                validated_features, 
                risk_context
            )
            
            # 5. 生成处理结果
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
            
            # 6. 对结果进行数字签名
            signature = self.crypto_engine.sign_data(processing_result)
            processing_result['digital_signature'] = signature
            processing_result['signature_algorithm'] = 'SM2'
            
            # 7. 安全清理敏感数据
            self._secure_cleanup(decrypted_features, validated_features)
            
            self.logger.info(f"✅ Successfully processed encrypted message: {request_id}")
            return processing_result
            
        except SMCryptoError as e:
            self.logger.error(f"❌ Cryptographic error: {e}")
            return self._generate_error_response(request_id, f"Cryptographic error: {e}", start_time)
        
        except Exception as e:
            self.logger.error(f"❌ Processing error: {e}")
            return self._generate_error_response(request_id, f"Processing error: {e}", start_time)
    
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
        
        try:
            # 1. 验证和清理特征数据
            validated_features = self._validate_features(features)
            
            # 2. 特征处理和分析
            feature_analysis = self.feature_manager.process_features(validated_features)
            
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