"""
TEE核心处理器
整合加密、特征管理、风险计算等模块，实现完整的TEE功能
"""
import logging
import time
import gc
from typing import Dict, Any, Optional, Tuple, List
from core.crypto_engine import get_crypto_engine, CryptoError, initialize_crypto_engine
from core.feature_manager import get_feature_manager, FeatureManagerError, initialize_feature_manager
from core.rba_engine import get_rba_engine, RBACalculationError, initialize_rba_engine
from utils.db_manager import get_db_manager, DatabaseError, initialize_database
from utils.memory_monitor import get_memory_status, cleanup_memory, initialize_memory_monitor
from utils.validators import ValidationError
from config import get_all_configs


class TEEProcessorError(Exception):
    """TEE处理器异常"""
    pass


class TEEProcessor:
    """TEE核心处理器"""
    
    def __init__(self):
        """初始化TEE处理器"""
        self.logger = logging.getLogger(__name__)
        self.crypto_engine = None
        self.feature_manager = None
        self.rba_engine = None
        self.db_manager = None
        self.memory_monitor = None
        
        # 初始化标志
        self._initialized = False
        
        # 统计信息
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'start_time': time.time()
        }
    
    def initialize(self):
        """初始化所有组件"""
        try:
            # 获取所有配置
            all_configs = get_all_configs()
            
            # 初始化加密引擎
            self.logger.info("Initializing crypto engine...")
            self.crypto_engine = initialize_crypto_engine(all_configs['security'])
            
            # 初始化特征管理器
            self.logger.info("Initializing feature manager...")
            self.feature_manager = initialize_feature_manager(all_configs['features'])
            
            # 初始化RBA引擎
            self.logger.info("Initializing RBA engine...")
            self.rba_engine = initialize_rba_engine(all_configs['features'])
            
            # 初始化数据库管理器
            self.logger.info("Initializing database manager...")
            self.db_manager = initialize_database(all_configs)
            
            # 初始化内存监控器
            self.logger.info("Initializing memory monitor...")
            self.memory_monitor = initialize_memory_monitor(all_configs['security'])
            
            self._initialized = True
            self.logger.info("TEE processor initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize TEE processor: {e}")
            raise TEEProcessorError(f"Failed to initialize TEE processor: {e}")
    
    def process_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理TEE请求
        
        Args:
            request_data: 请求数据
            
        Returns:
            处理结果
        """
        if not self._initialized:
            raise TEEProcessorError("TEE processor not initialized")
        
        request_start_time = time.time()
        self.stats['total_requests'] += 1
        
        try:
            # 1. 预处理和验证
            validated_data = self._preprocess_request(request_data)
            
            # 2. 特征处理
            processed_features = self._process_features(validated_data['features'])
            
            # 3. 加密特征数据
            encrypted_features = self._encrypt_features(processed_features)
            
            # 4. 获取历史数据和统计信息
            user_id = validated_data['user_id']
            user_history, global_stats = self._get_historical_data(user_id)
            
            # 5. 计算风险分数
            risk_result = self._calculate_risk(
                user_id, processed_features, user_history, global_stats
            )
            
            # 6. 存储结果
            storage_result = self._store_results(
                user_id, encrypted_features, risk_result, validated_data.get('metadata')
            )
            
            # 7. 清理敏感数据
            self._secure_cleanup(processed_features)
            
            # 8. 准备响应
            response = self._prepare_response(risk_result, storage_result)
            
            # 更新统计
            self.stats['successful_requests'] += 1
            processing_time = time.time() - request_start_time
            
            self.logger.info(f"Request processed successfully for user {user_id} "
                           f"in {processing_time:.3f}s, risk: {risk_result['risk_score']:.3f}")
            
            return response
            
        except Exception as e:
            self.stats['failed_requests'] += 1
            self.logger.error(f"Request processing failed: {e}")
            
            # 在异常情况下也要清理内存
            self._emergency_cleanup()
            
            raise TEEProcessorError(f"Request processing failed: {e}")
    
    def _preprocess_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """预处理和验证请求数据"""
        try:
            # 基本结构验证
            required_fields = ['user_id', 'features']
            for field in required_fields:
                if field not in request_data:
                    raise ValidationError(f"Missing required field: {field}")
            
            # 特征数据验证
            features = request_data['features']
            if not isinstance(features, dict) or not features:
                raise ValidationError("Features must be a non-empty dictionary")
            
            # 使用特征管理器验证
            self.feature_manager.validate_features(features)
            
            return {
                'user_id': str(request_data['user_id']),
                'features': features,
                'metadata': request_data.get('metadata', {}),
                'timestamp': time.time()
            }
            
        except (ValidationError, FeatureManagerError) as e:
            raise TEEProcessorError(f"Request validation failed: {e}")
    
    def _process_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """处理特征数据"""
        try:
            # 使用特征管理器处理
            processed_features = self.feature_manager.process_features(features)
            
            # 提取特征元数据
            feature_metadata = self.feature_manager.extract_feature_metadata(processed_features)
            
            # 添加元数据到处理结果
            processed_features['_metadata'] = feature_metadata
            
            return processed_features
            
        except FeatureManagerError as e:
            raise TEEProcessorError(f"Feature processing failed: {e}")
    
    def _encrypt_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """加密特征数据"""
        try:
            # 分离元数据（不加密）
            metadata = features.pop('_metadata', {})
            
            # 加密特征数据
            encrypted_features = self.crypto_engine.encrypt_features(features)
            
            # 添加元数据
            encrypted_features['_metadata'] = metadata
            
            return encrypted_features
            
        except CryptoError as e:
            raise TEEProcessorError(f"Feature encryption failed: {e}")
    
    def _get_historical_data(self, user_id: str) -> Tuple[List[Dict], Dict[str, Any]]:
        """获取历史数据和统计信息"""
        try:
            # 获取用户历史记录
            user_history = self.db_manager.get_user_history(user_id, limit=50)
            
            # 解密历史记录中的特征数据
            decrypted_history = []
            for record in user_history:
                if 'features' in record and record['features']:
                    try:
                        # 分离元数据
                        encrypted_features = record['features'].copy()
                        metadata = encrypted_features.pop('_metadata', {})
                        
                        # 解密特征数据
                        decrypted_features = self.crypto_engine.decrypt_features(encrypted_features)
                        
                        # 创建解密后的记录
                        decrypted_record = record.copy()
                        decrypted_record['features'] = decrypted_features
                        decrypted_record['features']['_metadata'] = metadata
                        
                        decrypted_history.append(decrypted_record)
                        
                    except Exception as e:
                        self.logger.warning(f"Failed to decrypt historical record {record.get('id')}: {e}")
                        continue
            
            # 获取全局统计信息
            global_stats = self.db_manager.get_global_statistics()
            
            return decrypted_history, global_stats
            
        except DatabaseError as e:
            raise TEEProcessorError(f"Failed to get historical data: {e}")
    
    def _calculate_risk(self, user_id: str, features: Dict[str, Any],
                       user_history: List[Dict], global_stats: Dict[str, Any]) -> Dict[str, Any]:
        """计算风险分数"""
        try:
            # 获取特征权重
            feature_weights = self.feature_manager.get_feature_weights()
            
            # 移除元数据
            clean_features = {k: v for k, v in features.items() if k != '_metadata'}
            
            # 计算风险分数
            risk_result = self.rba_engine.calculate_risk_score(
                user_id, clean_features, feature_weights, global_stats, user_history
            )
            
            return risk_result
            
        except RBACalculationError as e:
            raise TEEProcessorError(f"Risk calculation failed: {e}")
    
    def _store_results(self, user_id: str, encrypted_features: Dict[str, Any],
                      risk_result: Dict[str, Any], metadata: Optional[Dict]) -> Dict[str, Any]:
        """存储结果到数据库"""
        try:
            # 存储风险日志
            record_id = self.db_manager.store_risk_log(
                user_id=user_id,
                encrypted_features=encrypted_features,
                risk_score=risk_result['risk_score'],
                action=risk_result['action'],
                metadata=metadata
            )
            
            # 更新特征历史统计
            clean_features = {k: v for k, v in encrypted_features.items() if k != '_metadata'}
            for feature_name, encrypted_data in clean_features.items():
                if isinstance(encrypted_data, dict):
                    # 计算特征值哈希用于统计
                    feature_hash = self.crypto_engine.hash_feature_value(
                        encrypted_data, feature_name
                    )
                    self.db_manager.update_feature_history(feature_name, feature_hash)
            
            return {
                'stored': True,
                'record_id': record_id,
                'timestamp': time.time()
            }
            
        except DatabaseError as e:
            self.logger.error(f"Failed to store results: {e}")
            return {
                'stored': False,
                'error': str(e),
                'timestamp': time.time()
            }
    
    def _secure_cleanup(self, sensitive_data: Any):
        """安全清理敏感数据"""
        try:
            # 使用加密引擎的安全删除功能
            self.crypto_engine.secure_delete(sensitive_data)
            
            # 强制垃圾回收
            gc.collect()
            
        except Exception as e:
            self.logger.warning(f"Secure cleanup warning: {e}")
    
    def _emergency_cleanup(self):
        """紧急清理（异常情况下）"""
        try:
            # 清理内存
            cleanup_memory()
            
            # 强制垃圾回收
            gc.collect()
            
        except Exception as e:
            self.logger.error(f"Emergency cleanup failed: {e}")
    
    def _prepare_response(self, risk_result: Dict[str, Any], 
                         storage_result: Dict[str, Any]) -> Dict[str, Any]:
        """准备响应数据"""
        response = {
            'risk_score': risk_result['risk_score'],
            'action': risk_result['action'],
            'stored': storage_result['stored'],
            'timestamp': time.time()
        }
        
        # 添加存储信息
        if storage_result['stored']:
            response['record_id'] = storage_result.get('record_id')
        else:
            response['storage_error'] = storage_result.get('error')
        
        return response
    
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
tee_processor = None


def initialize_tee_processor() -> TEEProcessor:
    """
    初始化TEE处理器
    
    Returns:
        TEE处理器实例
    """
    global tee_processor
    tee_processor = TEEProcessor()
    tee_processor.initialize()
    return tee_processor


def get_tee_processor() -> TEEProcessor:
    """获取TEE处理器实例"""
    if tee_processor is None:
        raise TEEProcessorError("TEE processor not initialized")
    return tee_processor 