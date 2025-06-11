#!/usr/bin/env python3
"""
TEE软件监控Dashboard
提供实时监控界面，展示TEE软件运行状态、通讯过程和加密信息
"""
import os
import json
import time
import threading
import logging
from datetime import datetime, timedelta
from collections import deque, defaultdict
from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
import psutil
import requests

# 导入TEE模块
from config import initialize_config, get_all_configs
from core.tee_processor import get_tee_processor
from utils.memory_monitor import get_memory_status

# 创建Flask应用
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = 'tee_dashboard_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 全局数据存储
class DashboardData:
    def __init__(self):
        self.communication_logs = deque(maxlen=1000)  # 通讯日志
        self.system_metrics = deque(maxlen=100)       # 系统指标
        self.encryption_events = deque(maxlen=500)    # 加密事件
        self.active_sessions = {}                     # 活跃会话
        self.performance_stats = defaultdict(list)   # 性能统计
        self.tee_server_url = "http://localhost:5000" # TEE服务器地址
        
dashboard_data = DashboardData()

def collect_system_metrics():
    """收集系统指标"""
    while True:
        try:
            # 获取系统资源使用情况
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('.')
            
            # 获取TEE软件状态
            tee_status = {}
            try:
                tee_processor = get_tee_processor()
                tee_status = tee_processor.get_status()
            except:
                tee_status = {'error': 'TEE processor not available'}
            
            # 获取内存监控状态
            memory_status = get_memory_status()
            
            metric = {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_used_mb': memory.used / 1024 / 1024,
                'memory_total_mb': memory.total / 1024 / 1024,
                'disk_percent': disk.percent,
                'disk_used_gb': disk.used / 1024 / 1024 / 1024,
                'disk_total_gb': disk.total / 1024 / 1024 / 1024,
                'tee_status': tee_status,
                'tee_memory': memory_status
            }
            
            dashboard_data.system_metrics.append(metric)
            
            # 实时推送到前端
            socketio.emit('system_update', metric, namespace='/dashboard')
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
        
        time.sleep(5)  # 每5秒收集一次

def log_communication(comm_type, direction, data, metadata=None):
    """记录通讯日志"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'type': comm_type,
        'direction': direction,  # 'inbound' or 'outbound'
        'data': data,
        'metadata': metadata or {},
        'size': len(str(data)) if data else 0
    }
    
    dashboard_data.communication_logs.append(log_entry)
    socketio.emit('communication_update', log_entry, namespace='/dashboard')

def log_encryption_event(event_type, details):
    """记录加密事件"""
    event = {
        'timestamp': datetime.now().isoformat(),
        'type': event_type,
        'details': details
    }
    
    dashboard_data.encryption_events.append(event)
    socketio.emit('encryption_update', event, namespace='/dashboard')

# 启动后台线程
def start_background_tasks():
    """启动后台任务"""
    metrics_thread = threading.Thread(target=collect_system_metrics, daemon=True)
    metrics_thread.start()

@app.route('/')
def dashboard():
    """Dashboard主页"""
    return render_template('dashboard.html')

@app.route('/api/overview')
def get_overview():
    """获取总览数据"""
    try:
        # 最新系统指标
        latest_metrics = dashboard_data.system_metrics[-1] if dashboard_data.system_metrics else {}
        
        # 通讯统计
        recent_comms = list(dashboard_data.communication_logs)[-50:]  # 最近50条
        comm_stats = {
            'total': len(dashboard_data.communication_logs),
            'inbound': len([c for c in recent_comms if c['direction'] == 'inbound']),
            'outbound': len([c for c in recent_comms if c['direction'] == 'outbound']),
            'last_hour': len([c for c in recent_comms if 
                datetime.fromisoformat(c['timestamp']) > datetime.now() - timedelta(hours=1)])
        }
        
        # 加密统计
        recent_encryptions = list(dashboard_data.encryption_events)[-50:]
        encryption_stats = {
            'total': len(dashboard_data.encryption_events),
            'last_hour': len([e for e in recent_encryptions if 
                datetime.fromisoformat(e['timestamp']) > datetime.now() - timedelta(hours=1)])
        }
        
        return jsonify({
            'system_metrics': latest_metrics,
            'communication_stats': comm_stats,
            'encryption_stats': encryption_stats,
            'active_sessions': len(dashboard_data.active_sessions)
        })
        
    except Exception as e:
        logger.error(f"Error getting overview: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/communications')
def get_communications():
    """获取通讯日志"""
    limit = request.args.get('limit', 100, type=int)
    comm_logs = list(dashboard_data.communication_logs)[-limit:]
    return jsonify(comm_logs)

@app.route('/api/encryption_events')
def get_encryption_events():
    """获取加密事件"""
    limit = request.args.get('limit', 100, type=int)
    events = list(dashboard_data.encryption_events)[-limit:]
    return jsonify(events)

@app.route('/api/system_metrics')
def get_system_metrics():
    """获取系统指标历史"""
    hours = request.args.get('hours', 1, type=int)
    cutoff_time = datetime.now() - timedelta(hours=hours)
    
    metrics = [m for m in dashboard_data.system_metrics 
               if datetime.fromisoformat(m['timestamp']) > cutoff_time]
    return jsonify(metrics)

@app.route('/api/simulate_request', methods=['POST'])
def simulate_request():
    """模拟客户端请求（用于测试）"""
    try:
        request_data = request.get_json()
        
        # 记录发送请求
        log_communication('tee_request', 'outbound', request_data, 
                         {'client_ip': request.remote_addr})
        
        # 发送到TEE服务器
        response = requests.post(
            f"{dashboard_data.tee_server_url}/tee_soft/process",
            json=request_data,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        # 记录响应
        response_data = response.json()
        log_communication('tee_response', 'inbound', response_data,
                         {'status_code': response.status_code})
        
        # 记录加密事件
        if 'result' in response_data and 'encryption_info' in response_data['result']:
            log_encryption_event('request_processed', response_data['result']['encryption_info'])
        
        return jsonify({
            'success': True,
            'response': response_data,
            'status_code': response.status_code
        })
        
    except Exception as e:
        logger.error(f"Error simulating request: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/tee_status')
def get_tee_status():
    """获取TEE服务器状态"""
    try:
        response = requests.get(f"{dashboard_data.tee_server_url}/status", timeout=5)
        return jsonify(response.json())
    except Exception as e:
        return jsonify({'error': str(e), 'available': False}), 503

@app.route('/api/test_encryption')
def test_encryption():
    """测试加密功能"""
    try:
        # 模拟加密测试
        test_data = {
            'user_id': 'test_user_dashboard',
            'features': {
                'ip': '192.168.1.100',
                'user_agent': 'Dashboard Test Client',
                'rtt': 42.5
            }
        }
        
        # 记录加密开始
        log_encryption_event('encryption_test_start', test_data)
        
        # 发送测试请求
        response = requests.post(
            f"{dashboard_data.tee_server_url}/tee_soft/process",
            json=test_data,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            log_encryption_event('encryption_test_success', {
                'original_size': len(str(test_data)),
                'response_size': len(str(result))
            })
            return jsonify({'success': True, 'result': result})
        else:
            log_encryption_event('encryption_test_failed', {'status_code': response.status_code})
            return jsonify({'success': False, 'error': response.text}), response.status_code
            
    except Exception as e:
        log_encryption_event('encryption_test_error', {'error': str(e)})
        return jsonify({'success': False, 'error': str(e)}), 500

# WebSocket事件处理
@socketio.on('connect', namespace='/dashboard')
def handle_connect():
    """处理WebSocket连接"""
    logger.info(f"Dashboard client connected: {request.sid}")
    
    # 发送初始数据
    emit('initial_data', {
        'system_metrics': list(dashboard_data.system_metrics)[-10:],
        'communications': list(dashboard_data.communication_logs)[-20:],
        'encryption_events': list(dashboard_data.encryption_events)[-20:]
    })

@socketio.on('disconnect', namespace='/dashboard')
def handle_disconnect():
    """处理WebSocket断开"""
    logger.info(f"Dashboard client disconnected: {request.sid}")

@socketio.on('request_test', namespace='/dashboard')
def handle_test_request(data):
    """处理测试请求"""
    try:
        # 模拟客户端请求
        test_request = {
            'user_id': data.get('user_id', 'test_user'),
            'features': data.get('features', {
                'ip': '192.168.1.100',
                'user_agent': 'Test Client',
                'rtt': 50.0
            })
        }
        
        log_communication('test_request', 'outbound', test_request)
        
        # 这里可以添加实际的TEE处理逻辑
        emit('test_response', {
            'success': True,
            'message': 'Test request processed',
            'data': test_request
        })
        
    except Exception as e:
        emit('test_response', {
            'success': False,
            'error': str(e)
        })

if __name__ == '__main__':
    # 初始化配置
    try:
        initialize_config()
        logger.info("Dashboard configuration initialized")
    except Exception as e:
        logger.warning(f"Could not initialize TEE config: {e}")
    
    # 启动后台任务
    start_background_tasks()
    
    # 添加一些测试数据
    log_communication('startup', 'inbound', {'message': 'Dashboard started'})
    log_encryption_event('system_start', {'dashboard_version': '1.0.0'})
    
    logger.info("Starting TEE Dashboard on http://localhost:5001")
    socketio.run(app, host='0.0.0.0', port=5001, debug=True) 