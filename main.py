#!/usr/bin/env python3
"""
TEE软件主程序
提供Web API接口，整合所有TEE功能模块
"""
import os
import logging
import json
from datetime import datetime
from flask import Flask, request, jsonify, g
from werkzeug.exceptions import BadRequest, InternalServerError
from dotenv import load_dotenv

# 导入TEE模块
from config import initialize_config, get_all_configs
from core.tee_processor import initialize_tee_processor, get_tee_processor, TEEProcessorError
from utils.validators import ValidationError
from utils.memory_monitor import get_memory_status, cleanup_memory

# 加载环境变量
load_dotenv()

# 创建Flask应用
app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False  # 支持中文JSON

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/tee_soft.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


def initialize_application():
    """初始化应用程序"""
    try:
        # 创建日志目录
        os.makedirs('logs', exist_ok=True)
        
        # 初始化配置
        logger.info("Initializing configuration...")
        config_manager = initialize_config()
        all_configs = get_all_configs()
        logger.info(f"Configuration loaded successfully: {list(all_configs.keys())}")
        
        # 初始化TEE处理器
        logger.info("Initializing TEE processor...")
        tee_processor = initialize_tee_processor(all_configs)
        logger.info("TEE processor initialized successfully")
        
        logger.info("Application initialization completed")
        return True
        
    except Exception as e:
        logger.error(f"Application initialization failed: {e}")
        return False


@app.before_request
def before_request():
    """请求前处理"""
    g.request_start_time = datetime.utcnow()
    g.request_id = request.headers.get('X-Request-ID', 'unknown')
    
    # 记录请求信息
    logger.info(f"Request {g.request_id}: {request.method} {request.path}")


@app.after_request
def after_request(response):
    """请求后处理"""
    # 计算处理时间
    if hasattr(g, 'request_start_time'):
        duration = (datetime.utcnow() - g.request_start_time).total_seconds()
        response.headers['X-Response-Time'] = f"{duration:.3f}s"
    
    # 添加CORS头
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Request-ID'
    
    return response


@app.errorhandler(ValidationError)
def handle_validation_error(e):
    """处理验证错误"""
    logger.warning(f"Validation error: {e}")
    return jsonify({
        'error': 'validation_error',
        'message': str(e),
        'timestamp': datetime.utcnow().isoformat()
    }), 400


@app.errorhandler(TEEProcessorError)
def handle_tee_error(e):
    """处理TEE处理器错误"""
    logger.error(f"TEE processor error: {e}")
    return jsonify({
        'error': 'tee_processor_error',
        'message': str(e),
        'timestamp': datetime.utcnow().isoformat()
    }), 500


@app.errorhandler(Exception)
def handle_generic_error(e):
    """处理通用错误"""
    logger.error(f"Unexpected error: {e}", exc_info=True)
    return jsonify({
        'error': 'internal_server_error',
        'message': 'An unexpected error occurred',
        'timestamp': datetime.utcnow().isoformat()
    }), 500


@app.route('/health', methods=['GET'])
def health_check():
    """健康检查接口"""
    try:
        # 检查内存状态
        memory_status = get_memory_status()
        
        # 检查TEE处理器状态
        tee_processor = get_tee_processor()
        tee_status = tee_processor.get_status()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0',
            'memory': memory_status,
            'tee_processor': {
                'initialized': tee_status['initialized'],
                'total_requests': tee_status['total_requests'],
                'success_rate': tee_status.get('success_rate', 0.0)
            }
        })
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 503


@app.route('/status', methods=['GET'])
def get_status():
    """获取系统状态"""
    try:
        tee_processor = get_tee_processor()
        status = tee_processor.get_status()
        
        # 添加内存信息
        memory_status = get_memory_status()
        status['memory'] = memory_status
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Failed to get status: {e}")
        raise TEEProcessorError(f"Failed to get system status: {e}")


@app.route('/tee_soft/process', methods=['POST'])
def process_tee_request():
    """处理TEE请求"""
    try:
        # 验证请求格式
        if not request.is_json:
            raise ValidationError("Request must be JSON")
        
        request_data = request.get_json()
        if not request_data:
            raise ValidationError("Request body cannot be empty")
        
        # 处理请求
        tee_processor = get_tee_processor()
        result = tee_processor.process_request(request_data)
        
        logger.info(f"Request processed successfully for user {request_data.get('user_id', 'unknown')}")
        
        return jsonify({
            'success': True,
            'result': result,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except ValidationError as e:
        raise e  # 交给错误处理器处理
    except TEEProcessorError as e:
        raise e  # 交给错误处理器处理
    except Exception as e:
        logger.error(f"Unexpected error in process_tee_request: {e}")
        raise TEEProcessorError(f"Request processing failed: {e}")


@app.route('/tee_soft/process_encrypted', methods=['POST'])
def process_encrypted_request():
    """处理加密的TEE请求（支持混合加密）"""
    try:
        # 验证请求格式
        if not request.is_json:
            raise ValidationError("Request must be JSON")
        
        request_data = request.get_json()
        if not request_data:
            raise ValidationError("Request body cannot be empty")
        
        # 检测加密类型并处理
        tee_processor = get_tee_processor()
        
        # 新版本支持混合加密，旧版本向后兼容
        if 'encrypted_session_key' in request_data:
            logger.info("🔐 Processing hybrid encrypted request")
            result = tee_processor.process_hybrid_encrypted_message(request_data)
        else:
            logger.info("🔒 Processing legacy encrypted request")
            result = tee_processor.process_encrypted_message(request_data)
        
        logger.info(f"Encrypted request processed successfully: {request_data.get('request_id', 'unknown')}")
        
        return jsonify(result)
        
    except ValidationError as e:
        raise e  # 交给错误处理器处理
    except TEEProcessorError as e:
        raise e  # 交给错误处理器处理
    except Exception as e:
        logger.error(f"Unexpected error in encrypted request processing: {e}")
        raise TEEProcessorError(f"Failed to process encrypted request: {e}")


@app.route('/tee_soft/encryption_info', methods=['GET'])
def get_encryption_system_info():
    """获取加密系统详细信息"""
    try:
        tee_processor = get_tee_processor()
        
        # 获取加密系统信息
        try:
            encryption_info = tee_processor.get_encryption_info()
        except AttributeError:
            # 向后兼容
            encryption_info = {
                'communication_encryption': {
                    'note': 'Legacy system - detailed info not available'
                },
                'database_encryption': 'Legacy system',
                'key_isolation_status': 'UNKNOWN'
            }
        
        # 添加系统级别信息
        system_info = {
            'encryption_system': encryption_info,
            'supported_features': {
                'hybrid_encryption': hasattr(tee_processor, 'process_hybrid_encrypted_message'),
                'session_key_management': hasattr(tee_processor, 'session_key_manager'),
                'database_key_isolation': hasattr(tee_processor, 'database_crypto_engine'),
                'forward_secrecy': True,
                'key_rotation': True
            },
            'security_level': 'HIGH' if encryption_info.get('key_isolation_status') == 'ENABLED' else 'MEDIUM',
            'compliance': {
                'national_crypto_standards': True,
                'commercial_crypto_level': True,
                'algorithms': ['SM2', 'SM3', 'SM4']
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(system_info)
        
    except Exception as e:
        logger.error(f"Failed to get encryption system info: {e}")
        raise TEEProcessorError(f"Failed to get encryption system info: {e}")


@app.route('/tee_soft/algorithm_info', methods=['GET'])
def get_algorithm_info():
    """获取国密算法信息"""
    try:
        algorithm_info = {
            'encryption_algorithms': {
                'SM4': {
                    'name': 'SM4分组密码算法',
                    'standard': 'GB/T 32907-2016',
                    'key_size': 128,
                    'block_size': 128,
                    'mode': 'ECB',
                    'usage': ['数据加密', '会话密钥加密', '数据库存储加密']
                },
                'SM2': {
                    'name': 'SM2椭圆曲线公钥密码算法',
                    'standard': 'GB/T 32918-2016',
                    'curve': 'sm2p256v1',
                    'key_size': 256,
                    'usage': ['数字签名', '密钥协商', '会话密钥加密']
                }
            },
            'hash_algorithms': {
                'SM3': {
                    'name': 'SM3密码杂凑算法',
                    'standard': 'GB/T 32905-2016',
                    'digest_size': 256,
                    'usage': ['完整性校验', '密钥派生', '数字签名']
                }
            },
            'key_management': {
                'session_keys': {
                    'generation': 'per_request',
                    'algorithm': 'SM4',
                    'lifetime': 'single_use',
                    'security': 'forward_secure'
                },
                'long_term_keys': {
                    'algorithm': 'SM2',
                    'storage': 'memory_only',
                    'usage': 'session_key_protection'
                },
                'database_keys': {
                    'algorithm': 'SM4',
                    'derivation': 'SM3_based',
                    'isolation': 'complete_separation'
                }
            },
            'compliance': {
                'level': '商用密码安全等级',
                'certification': '国家密码管理局认证',
                'standards_compliance': True
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(algorithm_info)
        
    except Exception as e:
        logger.error(f"Failed to get algorithm info: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/tee_soft/public_key', methods=['GET'])
def get_public_key():
    """获取TEE公钥信息（改进版）"""
    try:
        tee_processor = get_tee_processor()
        
        # 尝试获取新版本的TEE公钥信息
        try:
            public_key_info = tee_processor.get_tee_public_key_info()
            return jsonify(public_key_info)
        except AttributeError:
            # 向后兼容：使用旧版本接口
            logger.warning("Using legacy public key interface")
            legacy_info = tee_processor.get_public_key_info()
            return jsonify({
                'tee_public_key': legacy_info.get('public_key', ''),
                'algorithm': 'SM2',
                'version': '1.0',
                'usage': 'legacy_compatibility',
                'note': 'Legacy public key format'
            })
        
    except Exception as e:
        logger.error(f"Failed to get TEE public key: {e}")
        raise TEEProcessorError(f"Failed to get TEE public key: {e}")


@app.route('/admin/cleanup', methods=['POST'])
def admin_cleanup():
    """管理员清理接口"""
    try:
        # 执行内存清理
        cleanup_result = cleanup_memory()
        
        # 执行数据库清理（可选）
        days = request.json.get('days', 90) if request.is_json else 90
        tee_processor = get_tee_processor()
        db_cleanup_result = tee_processor.cleanup_old_data(days)
        
        return jsonify({
            'success': True,
            'cleanup_results': {
                'memory': cleanup_result,
                'database': db_cleanup_result
            },
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        raise TEEProcessorError(f"Cleanup operation failed: {e}")


@app.route('/admin/stats', methods=['GET'])
def get_admin_stats():
    """获取管理员统计信息"""
    try:
        tee_processor = get_tee_processor()
        status = tee_processor.get_status()
        
        # 获取内存详细信息
        memory_status = get_memory_status()
        
        # 计算更多统计信息
        uptime = status.get('uptime', 0)
        total_requests = status.get('total_requests', 0)
        requests_per_hour = total_requests / max(uptime / 3600, 1)
        
        admin_stats = {
            'system': {
                'uptime_hours': uptime / 3600,
                'total_requests': total_requests,
                'requests_per_hour': requests_per_hour,
                'success_rate': status.get('success_rate', 0.0),
                'error_rate': 1.0 - status.get('success_rate', 0.0)
            },
            'memory': memory_status,
            'tee_processor': status
        }
        
        return jsonify({
            'success': True,
            'stats': admin_stats,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Failed to get admin stats: {e}")
        raise TEEProcessorError(f"Failed to get admin statistics: {e}")


# CORS预检请求处理
@app.route('/<path:path>', methods=['OPTIONS'])
def handle_options(path):
    """处理CORS预检请求"""
    return '', 204


if __name__ == '__main__':
    # 初始化应用
    if not initialize_application():
        logger.error("Failed to initialize application")
        exit(1)
    
    # 获取配置
    try:
        all_configs = get_all_configs()
        db_config = all_configs.get('database', {})
        
        # 启动应用
        host = os.getenv('FLASK_HOST', '0.0.0.0')
        port = int(os.getenv('FLASK_PORT', 5000))
        debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
        
        logger.info(f"Starting TEE Software server on {host}:{port}")
        logger.info(f"Debug mode: {debug}")
        
        app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=True
        )
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        exit(1)