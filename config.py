"""
配置管理模块
负责加载和管理所有配置文件
"""
import os
import yaml
import logging
from typing import Dict, Any, Optional
from pathlib import Path


class ConfigurationError(Exception):
    """配置错误异常"""
    pass


class ConfigManager:
    """配置管理器"""
    
    def __init__(self, config_dir: str = "config"):
        """
        初始化配置管理器
        
        Args:
            config_dir: 配置文件目录
        """
        self.config_dir = Path(config_dir)
        self.configs = {}
        self.logger = logging.getLogger(__name__)
        self._load_all_configs()
    
    def _load_all_configs(self):
        """加载所有配置文件"""
        if not self.config_dir.exists():
            raise ConfigurationError(f"Configuration directory {self.config_dir} not found")
        
        config_files = {
            'features': 'features.yaml',
            'security': 'security.yaml', 
            'database': 'database.yaml'
        }
        
        for config_name, filename in config_files.items():
            file_path = self.config_dir / filename
            try:
                self.configs[config_name] = self._load_config_file(file_path)
                self.logger.info(f"Loaded {config_name} configuration from {filename}")
            except Exception as e:
                self.logger.error(f"Failed to load {config_name} configuration: {e}")
                raise ConfigurationError(f"Failed to load {config_name} configuration: {e}")
    
    def _load_config_file(self, file_path: Path) -> Dict[str, Any]:
        """加载单个配置文件"""
        if not file_path.exists():
            raise ConfigurationError(f"Configuration file {file_path} not found")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
            
            # 处理环境变量替换
            return self._process_env_vars(config_data)
            
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in {file_path}: {e}")
        except Exception as e:
            raise ConfigurationError(f"Error reading {file_path}: {e}")
    
    def _process_env_vars(self, config_data: Any) -> Any:
        """处理配置中的环境变量"""
        if isinstance(config_data, dict):
            return {k: self._process_env_vars(v) for k, v in config_data.items()}
        elif isinstance(config_data, list):
            return [self._process_env_vars(item) for item in config_data]
        elif isinstance(config_data, str) and config_data.startswith('${') and config_data.endswith('}'):
            # 环境变量格式: ${VAR_NAME:default_value}
            env_expr = config_data[2:-1]
            if ':' in env_expr:
                var_name, default_value = env_expr.split(':', 1)
                return os.getenv(var_name, default_value)
            else:
                var_name = env_expr
                env_value = os.getenv(var_name)
                if env_value is None:
                    raise ConfigurationError(f"Required environment variable {var_name} not set")
                return env_value
        else:
            return config_data
    
    def get_config(self, config_name: str) -> Dict[str, Any]:
        """获取指定配置"""
        if config_name not in self.configs:
            raise ConfigurationError(f"Configuration '{config_name}' not found")
        return self.configs[config_name]
    
    def get_all_configs(self) -> Dict[str, Dict[str, Any]]:
        """获取所有配置"""
        return self.configs.copy()
    
    def update_config(self, config_name: str, updates: Dict[str, Any]):
        """更新配置"""
        if config_name not in self.configs:
            raise ConfigurationError(f"Configuration '{config_name}' not found")
        
        self.configs[config_name].update(updates)
        self.logger.info(f"Updated {config_name} configuration")


# 全局配置管理器实例
_config_manager: Optional[ConfigManager] = None


def initialize_config(config_dir: str = "config") -> ConfigManager:
    """
    初始化配置管理器
    
    Args:
        config_dir: 配置文件目录
        
    Returns:
        配置管理器实例
    """
    global _config_manager
    _config_manager = ConfigManager(config_dir)
    return _config_manager


def get_config_manager() -> ConfigManager:
    """获取配置管理器实例"""
    if _config_manager is None:
        raise ConfigurationError("Configuration manager not initialized. Call initialize_config() first.")
    return _config_manager


def get_config(config_name: str) -> Dict[str, Any]:
    """获取指定配置"""
    return get_config_manager().get_config(config_name)


def get_all_configs() -> Dict[str, Dict[str, Any]]:
    """获取所有配置"""
    return get_config_manager().get_all_configs()


def get_features_config() -> Dict[str, Any]:
    """获取特征配置"""
    return get_config('features')


def get_security_config() -> Dict[str, Any]:
    """获取安全配置"""
    return get_config('security')


def get_database_config() -> Dict[str, Any]:
    """获取数据库配置"""
    return get_config('database') 