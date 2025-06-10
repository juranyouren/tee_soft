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
        tee_processor = initialize_tee_processor()
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


@app.route('/tee_soft/public_key', methods=['GET'])
def get_public_key():
    """获取公钥信息"""
    try:
        tee_processor = get_tee_processor()
        public_key_info = tee_processor.get_public_key_info()
        
        return jsonify({
            'success': True,
            'public_key': public_key_info,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Failed to get public key: {e}")
        raise TEEProcessorError(f"Failed to get public key information: {e}")


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