"""
Dashboard配置文件
"""
import os

class DashboardConfig:
    """Dashboard配置类"""
    
    # 基础配置
    HOST = os.getenv('DASHBOARD_HOST', '127.0.0.1')
    PORT = int(os.getenv('DASHBOARD_PORT', '8080'))
    DEBUG = os.getenv('DASHBOARD_DEBUG', 'false').lower() == 'true'
    SECRET_KEY = os.getenv('DASHBOARD_SECRET_KEY', 'tee_dashboard_secret_key_2024')
    
    # TEE服务器配置
    TEE_SERVER_URL = os.getenv('TEE_SERVER_URL', 'http://localhost:5000')
    
    # SocketIO配置
    SOCKETIO = {
        'cors_allowed_origins': "*",
        'async_mode': 'threading',
        'logger': False,
        'engineio_logger': False
    }
    
    # 系统监控配置
    SYSTEM_MONITOR = {
        'enabled': True,
        'interval_seconds': 5,  # 恢复更频繁的监控
        'history_size': 1000,  # 恢复详细的历史数据
        'cpu_alert_threshold': 80.0,
        'memory_alert_threshold': 85.0,
        'memory_limit_mb': 128,  # TEE软件内存限制
        'disk_alert_threshold': 90.0,
        'max_processes': 50,  # 增加显示的进程数量
        'cleanup_interval': 10,  # 更频繁的清理检查
        'process_monitor_enabled': True,
        'network_monitor_enabled': True,
        'detailed_memory_analysis': True,  # 详细内存分析
        'memory_optimization_enabled': True,  # 启用内存优化
        'tee_memory_tracking': True,  # TEE内存跟踪
    }
    
    # API测试配置
    API_TEST = {
        'enabled': True,
        'timeout_seconds': 15,
        'retry_attempts': 3,
        'test_interval_seconds': 30,
        'endpoints': [
            {'url': '/health', 'method': 'GET', 'name': '健康检查'},
            {'url': '/api/status', 'method': 'GET', 'name': '状态查询'},
            {'url': '/tee_soft/encrypt', 'method': 'POST', 'name': 'TEE加密'},
            {'url': '/tee_soft/decrypt', 'method': 'POST', 'name': 'TEE解密'},
            {'url': '/tee_soft/process', 'method': 'POST', 'name': 'TEE处理'},
        ],
        'test_data': {
            'encrypt': {
                'data': 'Hello TEE Software - Test Data',
                'algorithm': 'AES-256-GCM',
                'user_id': 'test_user_encrypt'
            },
            'decrypt': {
                'encrypted_data': '',
                'algorithm': 'AES-256-GCM',
                'user_id': 'test_user_decrypt'
            },
            'process': {
                'operation': 'encrypt',
                'data': 'Test data for TEE processing',
                'user_id': 'test_user_process',
                'features': {
                    'ip': '127.0.0.1',
                    'user_agent': 'TEE Dashboard Test Client',
                    'timestamp': None  # 将在运行时设置
                },
                'params': {
                    'algorithm': 'AES-256-GCM',
                    'key_size': 256,
                    'mode': 'test'
                }
            }
        }
    }
    
    # 性能配置
    PERFORMANCE = {
        'chart_update_interval': 2,  # 更快的图表更新
        'data_retention_hours': 48,  # 更长的数据保留时间
        'max_chart_points': 200,  # 更多图表数据点
        'memory_cleanup_interval': 60,  # TEE软件内存清理检查间隔
        'detailed_metrics': True,  # 详细指标
        'real_time_optimization': True,  # 实时优化
    }
    
    # 日志配置
    LOGGING = {
        'level': os.getenv('LOG_LEVEL', 'INFO'),
        'file': os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs', 'dashboard.log'),
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    }
    
    # 告警配置
    ALERTS = {
        'enabled': True,
        'cooldown_minutes': 5,  # 告警冷却时间
        'max_alerts': 100,  # 最大告警数量
        'notification_methods': ['log', 'websocket']  # 通知方式
    } 