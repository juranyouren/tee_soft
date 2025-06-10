"""
输入验证工具模块
用于验证各种类型的特征数据
"""
import re
import ipaddress
from typing import Any, Dict, List, Optional


class ValidationError(Exception):
    """验证错误异常"""
    pass


class FeatureValidator:
    """特征验证器"""
    
    def __init__(self):
        self.validators = {
            'ipv4_or_ipv6': self._validate_ip,
            'non_empty_string': self._validate_non_empty_string,
            'positive_number': self._validate_positive_number,
            'geo_coordinates': self._validate_geo_coordinates,
            'email': self._validate_email,
            'url': self._validate_url,
            'phone': self._validate_phone,
        }
    
    def validate_feature(self, feature_name: str, feature_value: Any, 
                        validation_type: str, feature_config: Dict) -> bool:
        """
        验证单个特征
        
        Args:
            feature_name: 特征名称
            feature_value: 特征值
            validation_type: 验证类型
            feature_config: 特征配置
            
        Returns:
            验证结果
            
        Raises:
            ValidationError: 验证失败时抛出
        """
        try:
            # 检查是否为必需字段
            if feature_config.get('required', False) and not feature_value:
                raise ValidationError(f"Required feature '{feature_name}' is missing or empty")
            
            # 如果不是必需字段且值为空，则跳过验证
            if not feature_value and not feature_config.get('required', False):
                return True
            
            # 类型验证
            expected_type = feature_config.get('type', 'string')
            if not self._validate_type(feature_value, expected_type):
                raise ValidationError(f"Feature '{feature_name}' has invalid type. Expected: {expected_type}")
            
            # 特定验证
            if validation_type in self.validators:
                if not self.validators[validation_type](feature_value):
                    raise ValidationError(f"Feature '{feature_name}' failed {validation_type} validation")
            
            # 范围验证
            if 'range' in feature_config:
                if not self._validate_range(feature_value, feature_config['range']):
                    raise ValidationError(f"Feature '{feature_name}' is out of allowed range")
            
            # 长度验证
            if 'max_length' in feature_config:
                if len(str(feature_value)) > feature_config['max_length']:
                    raise ValidationError(f"Feature '{feature_name}' exceeds maximum length")
            
            return True
            
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"Validation error for feature '{feature_name}': {str(e)}")
    
    def _validate_type(self, value: Any, expected_type: str) -> bool:
        """验证数据类型"""
        type_mapping = {
            'string': str,
            'int': int,
            'float': (int, float),
            'bool': bool,
            'list': list,
            'dict': dict
        }
        
        expected_python_type = type_mapping.get(expected_type.lower())
        if expected_python_type is None:
            return True  # 未知类型跳过验证
        
        return isinstance(value, expected_python_type)
    
    def _validate_ip(self, ip_str: str) -> bool:
        """验证IP地址（IPv4或IPv6）"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def _validate_non_empty_string(self, value: str) -> bool:
        """验证非空字符串"""
        return isinstance(value, str) and len(value.strip()) > 0
    
    def _validate_positive_number(self, value: Any) -> bool:
        """验证正数"""
        try:
            num = float(value)
            return num >= 0
        except (ValueError, TypeError):
            return False
    
    def _validate_geo_coordinates(self, coords: str) -> bool:
        """验证地理坐标格式 (latitude,longitude)"""
        try:
            if not isinstance(coords, str):
                return False
            
            parts = coords.split(',')
            if len(parts) != 2:
                return False
            
            lat, lon = map(float, parts)
            return -90 <= lat <= 90 and -180 <= lon <= 180
        except (ValueError, AttributeError):
            return False
    
    def _validate_email(self, email: str) -> bool:
        """验证邮箱格式"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def _validate_url(self, url: str) -> bool:
        """验证URL格式"""
        pattern = r'^https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:\w*))?)?$'
        return re.match(pattern, url) is not None
    
    def _validate_phone(self, phone: str) -> bool:
        """验证电话号码格式"""
        # 简单的电话号码验证，支持国际格式
        pattern = r'^\+?[\d\s\-\(\)]{7,15}$'
        return re.match(pattern, phone) is not None
    
    def _validate_range(self, value: Any, range_config: List) -> bool:
        """验证数值范围"""
        try:
            num_value = float(value)
            min_val, max_val = range_config
            return min_val <= num_value <= max_val
        except (ValueError, TypeError, IndexError):
            return False


# 全局验证器实例
validator = FeatureValidator()


def validate_request_schema(request_data: Dict) -> bool:
    """
    验证请求数据的基本结构
    
    Args:
        request_data: 请求数据
        
    Returns:
        验证结果
        
    Raises:
        ValidationError: 验证失败时抛出
    """
    required_fields = ['user_id', 'features']
    
    for field in required_fields:
        if field not in request_data:
            raise ValidationError(f"Missing required field: {field}")
    
    if not isinstance(request_data['features'], dict):
        raise ValidationError("Features must be a dictionary")
    
    if not request_data['features']:
        raise ValidationError("Features dictionary cannot be empty")
    
    return True


def sanitize_input(value: str) -> str:
    """
    清理输入数据，防止注入攻击
    
    Args:
        value: 输入值
        
    Returns:
        清理后的值
    """
    if not isinstance(value, str):
        return str(value)
    
    # 移除潜在的危险字符
    dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '|', '`']
    cleaned = value
    
    for char in dangerous_chars:
        cleaned = cleaned.replace(char, '')
    
    return cleaned.strip() 