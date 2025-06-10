"""
特征管理器模块
负责特征数据的验证、处理和管理
"""
import re
import logging
import ipaddress
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse


class FeatureManagerError(Exception):
    """特征管理器异常"""
    pass


class FeatureManager:
    """特征管理器"""
    
    def __init__(self, config: Dict):
        """
        初始化特征管理器
        
        Args:
            config: 特征配置
        """
        self.config = config
        # 从配置中提取特征定义
        self.supported_features = config.get('features', {})
        self.risk_config = config.get('risk_calculation', {})
        self.malicious_indicators = config.get('malicious_indicators', {})
        self.logger = logging.getLogger(__name__)
        
        self.logger.info(f"Feature manager initialized with {len(self.supported_features)} features")
    
    def validate_features(self, features: Dict[str, Any]):
        """
        验证特征数据
        
        Args:
            features: 特征数据字典
            
        Raises:
            FeatureManagerError: 验证失败时抛出
        """
        if not isinstance(features, dict):
            raise FeatureManagerError("Features must be a dictionary")
        
        if not features:
            raise FeatureManagerError("Features cannot be empty")
        
        # 验证每个特征
        for feature_name, feature_value in features.items():
            self._validate_single_feature(feature_name, feature_value)
    
    def _validate_single_feature(self, feature_name: str, feature_value: Any):
        """验证单个特征"""
        # 检查特征是否支持
        if feature_name not in self.supported_features:
            raise FeatureManagerError(f"Unsupported feature: {feature_name}")
        
        feature_config = self.supported_features[feature_name]
        
        # 检查是否必需
        if feature_config.get('required', False) and (feature_value is None or feature_value == ""):
            raise FeatureManagerError(f"Required feature '{feature_name}' is missing or empty")
        
        # 跳过空值的非必需特征
        if feature_value is None or feature_value == "":
            return
        
        # 根据特征类型进行验证
        feature_type = feature_config.get('type', 'string')
        validation_type = feature_config.get('validation', '')
        
        # 基本类型验证
        self._validate_feature_type(feature_name, feature_value, feature_type)
        
        # 特定验证逻辑
        if validation_type == 'ipv4_or_ipv6':
            self._validate_ip_address(feature_name, feature_value)
        elif validation_type == 'non_empty_string':
            self._validate_non_empty_string(feature_name, feature_value)
        elif validation_type == 'positive_number':
            self._validate_positive_number(feature_name, feature_value)
        elif validation_type == 'geo_coordinates':
            self._validate_geo_coordinates(feature_name, feature_value)
        
        # 范围验证
        if 'range' in feature_config:
            self._validate_range(feature_name, feature_value, feature_config['range'])
    
    def _validate_feature_type(self, feature_name: str, feature_value: Any, expected_type: str):
        """验证特征类型"""
        if expected_type == 'string' and not isinstance(feature_value, str):
            raise FeatureManagerError(f"Feature '{feature_name}' must be a string")
        elif expected_type == 'float' and not isinstance(feature_value, (int, float)):
            raise FeatureManagerError(f"Feature '{feature_name}' must be a number")
        elif expected_type == 'int' and not isinstance(feature_value, int):
            raise FeatureManagerError(f"Feature '{feature_name}' must be an integer")
    
    def _validate_ip_address(self, feature_name: str, value: Any):
        """验证IP地址"""
        if not isinstance(value, str):
            raise FeatureManagerError(f"Feature '{feature_name}' must be a string")
        
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise FeatureManagerError(f"Feature '{feature_name}' is not a valid IP address")
    
    def _validate_non_empty_string(self, feature_name: str, value: Any):
        """验证非空字符串"""
        if not isinstance(value, str) or len(value.strip()) == 0:
            raise FeatureManagerError(f"Feature '{feature_name}' must be a non-empty string")
    
    def _validate_positive_number(self, feature_name: str, value: Any):
        """验证正数"""
        try:
            num_value = float(value)
            if num_value < 0:
                raise FeatureManagerError(f"Feature '{feature_name}' must be a positive number")
        except (TypeError, ValueError):
            raise FeatureManagerError(f"Feature '{feature_name}' must be a valid number")
    
    def _validate_geo_coordinates(self, feature_name: str, value: Any):
        """验证地理坐标格式 (latitude,longitude)"""
        if not isinstance(value, str):
            raise FeatureManagerError(f"Feature '{feature_name}' must be a string")
        
        try:
            parts = value.split(',')
            if len(parts) != 2:
                raise FeatureManagerError(f"Feature '{feature_name}' must be in format 'latitude,longitude'")
            
            lat, lon = map(float, parts)
            if not (-90 <= lat <= 90):
                raise FeatureManagerError(f"Invalid latitude in feature '{feature_name}': {lat}")
            if not (-180 <= lon <= 180):
                raise FeatureManagerError(f"Invalid longitude in feature '{feature_name}': {lon}")
                
        except (ValueError, AttributeError):
            raise FeatureManagerError(f"Invalid coordinates format in feature '{feature_name}'")
    
    def _validate_range(self, feature_name: str, value: Any, range_config: List):
        """验证数值范围"""
        try:
            num_value = float(value)
            min_val, max_val = range_config
            if not (min_val <= num_value <= max_val):
                raise FeatureManagerError(f"Feature '{feature_name}' must be between {min_val} and {max_val}")
        except (TypeError, ValueError, IndexError):
            raise FeatureManagerError(f"Invalid range validation for feature '{feature_name}'")
    
    def process_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理特征数据
        
        Args:
            features: 原始特征数据
            
        Returns:
            处理后的特征数据
        """
        processed_features = {}
        
        for feature_name, feature_value in features.items():
            if feature_name not in self.supported_features:
                continue  # 跳过不支持的特征
            
            try:
                processed_value = self._process_single_feature(feature_name, feature_value)
                processed_features[feature_name] = processed_value
            except Exception as e:
                self.logger.error(f"Failed to process feature '{feature_name}': {e}")
                raise FeatureManagerError(f"Feature processing failed for '{feature_name}': {e}")
        
        return processed_features
    
    def _process_single_feature(self, feature_name: str, feature_value: Any) -> Any:
        """处理单个特征"""
        if feature_value is None or feature_value == "":
            return feature_value
        
        feature_config = self.supported_features[feature_name]
        validation_type = feature_config.get('validation', '')
        
        # 根据验证类型处理特征
        if validation_type == 'ipv4_or_ipv6':
            return self._process_ip_address(feature_value)
        elif feature_name == 'user_agent':
            return self._process_user_agent(feature_value)
        elif feature_name == 'rtt':
            return self._process_rtt(feature_value)
        elif validation_type == 'geo_coordinates':
            return self._process_geo_location(feature_value)
        elif feature_name == 'device_fingerprint':
            return self._process_device_fingerprint(feature_value)
        else:
            return self._process_string(feature_value)
    
    def _process_ip_address(self, value: str) -> Dict[str, Any]:
        """处理IP地址"""
        try:
            ip = ipaddress.ip_address(value)
            return {
                'address': str(ip),
                'version': ip.version,
                'is_private': ip.is_private,
                'is_loopback': ip.is_loopback,
                'is_multicast': ip.is_multicast
            }
        except ValueError:
            return {'address': value, 'valid': False}
    
    def _process_user_agent(self, value: str) -> Dict[str, Any]:
        """处理User-Agent"""
        # 提取基本信息
        browser_patterns = {
            'Chrome': r'Chrome/(\d+)',
            'Firefox': r'Firefox/(\d+)',
            'Safari': r'Safari/(\d+)',
            'Edge': r'Edge/(\d+)',
            'Opera': r'Opera/(\d+)'
        }
        
        os_patterns = {
            'Windows': r'Windows NT ([\d.]+)',
            'macOS': r'Mac OS X ([\d_]+)',
            'Linux': r'Linux',
            'Android': r'Android ([\d.]+)',
            'iOS': r'iPhone OS ([\d_]+)'
        }
        
        result = {
            'original': value,
            'length': len(value),
            'browser': None,
            'browser_version': None,
            'os': None,
            'os_version': None,
            'is_mobile': 'Mobile' in value or 'Android' in value or 'iPhone' in value
        }
        
        # 检测浏览器
        for browser, pattern in browser_patterns.items():
            match = re.search(pattern, value)
            if match:
                result['browser'] = browser
                result['browser_version'] = match.group(1)
                break
        
        # 检测操作系统
        for os_name, pattern in os_patterns.items():
            match = re.search(pattern, value)
            if match:
                result['os'] = os_name
                if match.groups():
                    result['os_version'] = match.group(1)
                break
        
        return result
    
    def _process_rtt(self, value: Any) -> Dict[str, Any]:
        """处理RTT值"""
        try:
            rtt_value = float(value)
            return {
                'value': rtt_value,
                'unit': 'ms',
                'category': self._categorize_rtt(rtt_value)
            }
        except (TypeError, ValueError):
            return {'value': value, 'valid': False}
    
    def _categorize_rtt(self, rtt: float) -> str:
        """对RTT值进行分类"""
        if rtt < 50:
            return 'excellent'
        elif rtt < 100:
            return 'good'
        elif rtt < 200:
            return 'fair'
        elif rtt < 500:
            return 'poor'
        else:
            return 'very_poor'
    
    def _process_geo_location(self, value: str) -> Dict[str, Any]:
        """处理地理位置坐标"""
        try:
            parts = value.split(',')
            lat, lon = map(float, parts)
            
            result = {
                'latitude': lat,
                'longitude': lon,
                'region': self._get_region_from_coordinates(lat, lon),
                'valid': True
            }
            
            return result
            
        except (ValueError, AttributeError):
            return {
                'original': value,
                'valid': False
            }
    
    def _get_region_from_coordinates(self, lat: float, lon: float) -> str:
        """根据坐标获取大致区域"""
        # 简单的区域划分
        if 35 <= lat <= 55 and 73 <= lon <= 135:
            return 'China'
        elif 25 <= lat <= 49 and -125 <= lon <= -66:
            return 'USA'
        elif 36 <= lat <= 71 and -9 <= lon <= 40:
            return 'Europe'
        else:
            return 'Other'
    
    def _process_device_fingerprint(self, value: Any) -> Dict[str, Any]:
        """处理设备指纹"""
        if isinstance(value, dict):
            result = value.copy()
            
            # 处理屏幕分辨率
            if 'screen_resolution' in value:
                resolution = str(value['screen_resolution'])
                if 'x' in resolution:
                    try:
                        width, height = map(int, resolution.split('x'))
                        result['screen_area'] = width * height
                        result['aspect_ratio'] = round(width / height, 2)
                    except ValueError:
                        pass
            
            return result
        else:
            return {'original': str(value), 'valid': False}
    
    def _process_string(self, value: str) -> str:
        """处理字符串"""
        # 标准化字符串
        return value.strip()
    
    def extract_feature_metadata(self, processed_features: Dict[str, Any]) -> Dict[str, Any]:
        """提取特征元数据"""
        metadata = {
            'feature_count': len(processed_features),
            'feature_names': list(processed_features.keys()),
            'feature_types': {},
            'processing_timestamp': None
        }
        
        # 记录每个特征的类型
        for feature_name in processed_features.keys():
            if feature_name in self.supported_features:
                metadata['feature_types'][feature_name] = self.supported_features[feature_name].get('type', 'string')
        
        return metadata
    
    def get_supported_features(self) -> Dict[str, Any]:
        """获取支持的特征列表"""
        return self.supported_features.copy()
    
    def get_feature_weights(self) -> Dict[str, float]:
        """获取特征权重"""
        weights = {}
        for feature_name, feature_config in self.supported_features.items():
            weights[feature_name] = feature_config.get('weight', 0.1)
        return weights


# 全局特征管理器实例
_feature_manager: Optional[FeatureManager] = None


def initialize_feature_manager(config: Dict) -> FeatureManager:
    """
    初始化特征管理器
    
    Args:
        config: 特征配置
        
    Returns:
        特征管理器实例
    """
    global _feature_manager
    _feature_manager = FeatureManager(config)
    return _feature_manager


def get_feature_manager() -> FeatureManager:
    """获取特征管理器实例"""
    if _feature_manager is None:
        raise FeatureManagerError("Feature manager not initialized. Call initialize_feature_manager() first.")
    return _feature_manager