"""
Dashboard主应用
整合系统监控和API测试功能
"""
import os
import sys
import logging
import json
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
import threading
import requests
import psutil

# 添加项目根目录到路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.config import DashboardConfig
from dashboard.monitors import SystemMonitor
from dashboard.api_tester import APITester

# 配置日志
def setup_logging():
    """设置日志配置"""
    log_dir = os.path.dirname(DashboardConfig.LOGGING['file'])
    os.makedirs(log_dir, exist_ok=True)
    
    logging.basicConfig(
        level=getattr(logging, DashboardConfig.LOGGING['level']),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(DashboardConfig.LOGGING['file']),
            logging.StreamHandler()
        ]
    )

setup_logging()
logger = logging.getLogger(__name__)

# 创建Flask应用
app = Flask(__name__, 
           static_folder='static', 
           template_folder='templates')
app.config['SECRET_KEY'] = DashboardConfig.SECRET_KEY

# 创建SocketIO
socketio = SocketIO(app, **DashboardConfig.SOCKETIO)

# 全局组件
system_monitor: SystemMonitor = None
api_tester: APITester = None


def initialize_components():
    """初始化监控组件"""
    global system_monitor, api_tester
    
    try:
        # 初始化系统监控器
        system_monitor = SystemMonitor(DashboardConfig.SYSTEM_MONITOR)
        system_monitor.start_monitoring()
        logger.info("System monitor initialized and started")
        
        # 初始化API测试器
        api_test_config = DashboardConfig.API_TEST.copy()
        api_test_config['tee_server_url'] = DashboardConfig.TEE_SERVER_URL
        api_tester = APITester(api_test_config)
        
        # 设置测试进度回调
        def test_progress_callback(session_data):
            """测试进度回调函数"""
            socketio.emit('test_progress_update', session_data, namespace='/dashboard')
        
        api_tester.add_progress_callback(test_progress_callback)
        api_tester.start_testing()
        logger.info("API tester initialized and started")
        
        # 启动数据推送线程
        start_data_push_thread()
        
        return True
    except Exception as e:
        logger.error(f"Failed to initialize components: {e}")
        return False


def start_data_push_thread():
    """启动数据推送线程"""
    def push_data():
        while True:
            try:
                # 推送系统监控数据
                if system_monitor:
                    latest_metrics = system_monitor.get_latest_metrics()
                    if latest_metrics:
                        socketio.emit('system_update', latest_metrics, namespace='/dashboard')
                
                # 推送API测试结果
                if api_tester:
                    performance_summary = api_tester.get_performance_summary()
                    socketio.emit('api_test_update', performance_summary, namespace='/dashboard')
                
            except Exception as e:
                logger.error(f"Error pushing data: {e}")
            
            time.sleep(DashboardConfig.PERFORMANCE['chart_update_interval'])
    
    push_thread = threading.Thread(target=push_data, daemon=True)
    push_thread.start()
    logger.info("Data push thread started")


# Web路由
@app.route('/')
def dashboard():
    """Dashboard主页"""
    return render_template('dashboard.html', config={
        'tee_server_url': DashboardConfig.TEE_SERVER_URL,
        'update_interval': DashboardConfig.PERFORMANCE['chart_update_interval'],
        'system_thresholds': {
            'cpu': DashboardConfig.SYSTEM_MONITOR['cpu_alert_threshold'],
            'memory': DashboardConfig.SYSTEM_MONITOR['memory_alert_threshold'],
            'memory_limit_mb': DashboardConfig.SYSTEM_MONITOR['memory_limit_mb']
        }
    })


@app.route('/api/overview')
def get_overview():
    """获取总览数据"""
    try:
        overview_data = {
            'timestamp': datetime.now().isoformat(),
            'tee_server_url': DashboardConfig.TEE_SERVER_URL,
            'dashboard_status': 'running'
        }
        
        # 系统监控概览
        if system_monitor:
            system_summary = system_monitor.get_summary()
            overview_data['system'] = system_summary
        
        # API测试概览
        if api_tester:
            api_summary = api_tester.get_performance_summary()
            overview_data['api_tests'] = api_summary
        
        return jsonify(overview_data)
        
    except Exception as e:
        logger.error(f"Error getting overview: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/system/metrics')
def get_system_metrics():
    """获取系统指标"""
    try:
        hours = request.args.get('hours', 1, type=int)
        
        if not system_monitor:
            return jsonify({'error': 'System monitor not available'}), 503
        
        if hours == 0:  # 获取最新数据
            metrics = system_monitor.get_latest_metrics()
        else:  # 获取历史数据
            metrics = system_monitor.get_historical_metrics(hours)
        
        return jsonify(metrics)
        
    except Exception as e:
        logger.error(f"Error getting system metrics: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/system/alerts')
def get_system_alerts():
    """获取系统告警"""
    try:
        limit = request.args.get('limit', 50, type=int)
        
        if not system_monitor:
            return jsonify({'error': 'System monitor not available'}), 503
        
        alerts = system_monitor.get_alerts(limit)
        return jsonify(alerts)
        
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/system/alerts', methods=['DELETE'])
def clear_system_alerts():
    """清除系统告警"""
    try:
        if not system_monitor:
            return jsonify({'error': 'System monitor not available'}), 503
        
        system_monitor.clear_alerts()
        return jsonify({'success': True, 'message': 'Alerts cleared'})
        
    except Exception as e:
        logger.error(f"Error clearing alerts: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/tests/results')
def get_test_results():
    """获取API测试结果"""
    try:
        limit = request.args.get('limit', 50, type=int)
        
        if not api_tester:
            return jsonify({'error': 'API tester not available'}), 503
        
        results = api_tester.get_test_results(limit)
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error getting test results: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/tests/sessions')
def get_test_sessions():
    """获取测试会话列表"""
    try:
        limit = request.args.get('limit', 20, type=int)
        
        if not api_tester:
            return jsonify({'error': 'API tester not available'}), 503
        
        sessions = list(api_tester.test_sessions)[-limit:]
        return jsonify([session.to_dict() for session in sessions])
        
    except Exception as e:
        logger.error(f"Error getting test sessions: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/tests/sessions/<session_id>')
def get_test_session_detail(session_id):
    """获取特定测试会话的详细信息"""
    try:
        if not api_tester:
            return jsonify({'error': 'API tester not available'}), 503
        
        # 查找指定的测试会话
        session = None
        for test_session in api_tester.test_sessions:
            if test_session.id == session_id:
                session = test_session
                break
        
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        return jsonify(session.to_dict())
        
    except Exception as e:
        logger.error(f"Error getting session detail: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/tests/current_session')
def get_current_test_session():
    """获取当前运行的测试会话"""
    try:
        if not api_tester:
            return jsonify({'error': 'API tester not available'}), 503
        
        if not api_tester.current_session:
            return jsonify({'message': 'No active session'}), 200
        
        return jsonify(api_tester.current_session.to_dict())
        
    except Exception as e:
        logger.error(f"Error getting current session: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/tests/statistics')
def get_test_statistics():
    """获取API测试统计"""
    try:
        if not api_tester:
            return jsonify({'error': 'API tester not available'}), 503
        
        stats = api_tester.get_endpoint_statistics()
        performance = api_tester.get_performance_summary()
        
        return jsonify({
            'endpoint_stats': stats,
            'performance_summary': performance,
            'total_sessions': len(api_tester.test_sessions),
            'active_session': api_tester.current_session.to_dict() if api_tester.current_session else None
        })
        
    except Exception as e:
        logger.error(f"Error getting test statistics: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/tests/run', methods=['POST'])
def run_manual_test():
    """运行手动测试"""
    try:
        if not api_tester:
            return jsonify({'error': 'API tester not available'}), 503
        
        data = request.get_json()
        endpoint_url = data.get('endpoint_url', '/health')
        method = data.get('method', 'GET')
        test_data = data.get('data')
        
        result = api_tester.run_manual_test(endpoint_url, method, test_data)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error running manual test: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/tests/run_suite', methods=['POST'])
def run_test_suite():
    """手动运行完整测试套件"""
    try:
        if not api_tester:
            return jsonify({'error': 'API tester not available'}), 503
        
        # 在后台运行测试套件
        def run_suite():
            api_tester._run_detailed_test_suite()
        
        suite_thread = threading.Thread(target=run_suite, daemon=True)
        suite_thread.start()
        
        return jsonify({'message': 'Test suite started', 'status': 'running'})
        
    except Exception as e:
        logger.error(f"Error starting test suite: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/tests/clear', methods=['POST'])
def clear_test_history():
    """清除测试历史"""
    try:
        if not api_tester:
            return jsonify({'error': 'API tester not available'}), 503
        
        api_tester.clear_test_history()
        return jsonify({'success': True, 'message': 'Test history cleared'})
        
    except Exception as e:
        logger.error(f"Error clearing test history: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/config')
def get_config():
    """获取配置信息"""
    return jsonify({
        'tee_server_url': DashboardConfig.TEE_SERVER_URL,
        'system_monitor': {
            'enabled': DashboardConfig.SYSTEM_MONITOR['enabled'],
            'interval': DashboardConfig.SYSTEM_MONITOR['interval_seconds'],
            'thresholds': {
                'cpu': DashboardConfig.SYSTEM_MONITOR['cpu_alert_threshold'],
                'memory': DashboardConfig.SYSTEM_MONITOR['memory_alert_threshold'],
                'memory_limit_mb': DashboardConfig.SYSTEM_MONITOR['memory_limit_mb']
            }
        },
        'api_test': {
            'enabled': DashboardConfig.API_TEST['enabled'],
            'interval': DashboardConfig.API_TEST['test_interval_seconds'],
            'endpoints_count': len(DashboardConfig.API_TEST['endpoints'])
        }
    })


@app.route('/api/tee_memory_status', methods=['GET'])
def get_tee_memory_status():
    """获取TEE软件内存状态"""
    try:
        # 尝试从TEE软件获取内存状态
        tee_server_url = os.getenv('TEE_SERVER_URL', 'http://127.0.0.1:5000')
        
        try:
            # 请求TEE软件的内存状态
            response = requests.get(f"{tee_server_url}/admin/memory_status", timeout=5)
            if response.status_code == 200:
                tee_memory_data = response.json()
                return jsonify({
                    'success': True,
                    'source': 'tee_software',
                    'data': tee_memory_data,
                    'timestamp': datetime.utcnow().isoformat()
                })
        except requests.RequestException as e:
            logger.warning(f"Failed to get TEE memory status: {e}")
        
        # 如果无法从TEE软件获取，使用TEE进程监控
        system_monitor = get_system_monitor()
        tee_processes = system_monitor._find_tee_processes()
        
        if not tee_processes:
            return jsonify({
                'success': False,
                'error': 'TEE software processes not found',
                'message': 'TEE软件进程未运行',
                'timestamp': datetime.utcnow().isoformat()
            })
        
        # 计算TEE进程的总内存使用
        total_memory_mb = 0
        total_cpu_percent = 0
        process_count = len(tee_processes)
        
        for proc in tee_processes:
            try:
                memory_info = proc.memory_info()
                total_memory_mb += memory_info.rss / (1024 * 1024)
                total_cpu_percent += proc.cpu_percent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # 构造与TEE软件API兼容的响应格式
        memory_status = {
            'low_memory_mode': 'enabled',
            'memory_limit_mb': 128,  # 设定的限制
            'current_usage': {
                'used_mb': total_memory_mb,
                'usage_percent': (total_memory_mb / 128) * 100,
                'status': 'normal' if total_memory_mb < 96 else 'warning' if total_memory_mb < 115 else 'critical'
            },
            'tee_processes': {
                'count': process_count,
                'total_cpu_percent': total_cpu_percent,
                'total_memory_mb': total_memory_mb
            },
            'recommendations': []
        }
        
        # 添加建议
        usage_percent = memory_status['current_usage']['usage_percent']
        if usage_percent > 90:
            memory_status['recommendations'].append('Critical: Memory usage too high')
        elif usage_percent > 75:
            memory_status['recommendations'].append('Warning: Monitor memory usage')
        else:
            memory_status['recommendations'].append('Good: Memory usage is optimal')
        
        return jsonify({
            'success': True,
            'source': 'dashboard_monitor',
            'data': memory_status,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Failed to get TEE memory status: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500


@app.route('/api/tee_memory_analysis', methods=['GET'])
def get_tee_memory_analysis():
    """获取详细的TEE内存分析"""
    try:
        if not system_monitor:
            return jsonify({'error': 'System monitor not available'}), 503
        
        analysis = system_monitor.get_tee_memory_analysis()
        return jsonify(analysis)
        
    except Exception as e:
        logger.error(f"Error getting TEE memory analysis: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/tee_memory_optimization', methods=['POST'])
def trigger_tee_memory_optimization():
    """手动触发TEE内存优化"""
    try:
        if not system_monitor:
            return jsonify({'error': 'System monitor not available'}), 503
        
        # 获取当前内存状态
        latest_metrics = system_monitor.get_latest_metrics()
        if not latest_metrics or 'system' not in latest_metrics:
            return jsonify({'error': 'No TEE metrics available'}), 503
        
        current_memory = latest_metrics['system']['total_memory_mb']
        memory_limit = system_monitor.memory_limit_mb
        
        # 记录优化前状态
        optimization_record = {
            'timestamp': datetime.now().isoformat(),
            'trigger': 'manual_request',
            'memory_before_mb': current_memory,
            'memory_limit_mb': memory_limit,
            'utilization_before': (current_memory / memory_limit * 100),
            'actions': []
        }
        
        # 执行优化
        success = system_monitor._trigger_tee_memory_cleanup(latest_metrics['system'])
        
        # 等待一段时间获取优化后状态
        import time
        time.sleep(2)
        
        # 获取优化后状态
        updated_metrics = system_monitor.get_latest_metrics()
        memory_after = updated_metrics['system']['total_memory_mb'] if updated_metrics and 'system' in updated_metrics else current_memory
        
        optimization_record.update({
            'success': success,
            'memory_after_mb': memory_after,
            'utilization_after': (memory_after / memory_limit * 100),
            'memory_saved_mb': current_memory - memory_after,
            'improvement_percent': ((current_memory - memory_after) / current_memory * 100) if current_memory > 0 else 0
        })
        
        return jsonify({
            'success': True,
            'optimization_result': optimization_record,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error triggering TEE memory optimization: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/tee_memory_optimization_log', methods=['GET'])
def get_tee_memory_optimization_log():
    """获取TEE内存优化日志"""
    try:
        if not system_monitor:
            return jsonify({'error': 'System monitor not available'}), 503
        
        limit = request.args.get('limit', 50, type=int)
        optimization_log = system_monitor.get_memory_optimization_log()
        
        return jsonify({
            'success': True,
            'optimization_log': optimization_log[-limit:],
            'total_optimizations': len(optimization_log),
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting optimization log: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/tee_memory_recommendations', methods=['GET'])
def get_tee_memory_recommendations():
    """获取TEE内存优化建议"""
    try:
        if not system_monitor:
            return jsonify({'error': 'System monitor not available'}), 503
        
        analysis = system_monitor.get_tee_memory_analysis()
        
        if 'error' in analysis:
            return jsonify(analysis), 500
        
        return jsonify({
            'success': True,
            'current_status': {
                'memory_usage_mb': analysis['current_usage_mb'],
                'utilization_percent': analysis['utilization_percent'],
                'trend': analysis['trend']
            },
            'optimization_opportunities': analysis['optimization_opportunities'],
            'recommendations': analysis['recommendations'],
            'peak_periods': analysis['peak_usage_periods'],
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting memory recommendations: {e}")
        return jsonify({'error': str(e)}), 500


# WebSocket事件处理
@socketio.on('connect', namespace='/dashboard')
def handle_connect():
    """客户端连接事件"""
    logger.info(f"Client connected: {request.sid}")
    
    # 发送初始数据
    try:
        if system_monitor:
            latest_metrics = system_monitor.get_latest_metrics()
            emit('system_update', latest_metrics)
        
        if api_tester:
            performance_summary = api_tester.get_performance_summary()
            emit('api_test_update', performance_summary)
            
    except Exception as e:
        logger.error(f"Error sending initial data: {e}")


@socketio.on('disconnect', namespace='/dashboard')
def handle_disconnect():
    """客户端断开连接事件"""
    logger.info(f"Client disconnected: {request.sid}")


@socketio.on('request_refresh', namespace='/dashboard')
def handle_refresh_request(data):
    """处理刷新请求"""
    try:
        data_type = data.get('type', 'all')
        
        if data_type in ['all', 'system'] and system_monitor:
            latest_metrics = system_monitor.get_latest_metrics()
            emit('system_update', latest_metrics)
        
        if data_type in ['all', 'api'] and api_tester:
            performance_summary = api_tester.get_performance_summary()
            emit('api_test_update', performance_summary)
            
    except Exception as e:
        logger.error(f"Error handling refresh request: {e}")


# 错误处理
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


def cleanup_components():
    """清理组件"""
    global system_monitor, api_tester
    
    try:
        if system_monitor:
            system_monitor.stop_monitoring()
        
        if api_tester:
            api_tester.stop_testing()
            
        logger.info("Components cleaned up")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")


def main():
    """主函数"""
    try:
        logger.info("Starting TEE Dashboard")
        
        # 初始化组件
        if not initialize_components():
            logger.error("Failed to initialize components")
            return 1
        
        # 启动应用
        logger.info(f"Starting dashboard on {DashboardConfig.HOST}:{DashboardConfig.PORT}")
        
        socketio.run(
            app,
            host=DashboardConfig.HOST,
            port=DashboardConfig.PORT,
            debug=DashboardConfig.DEBUG,
            allow_unsafe_werkzeug=True
        )
        
    except KeyboardInterrupt:
        logger.info("Dashboard stopped by user")
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return 1
    finally:
        cleanup_components()
    
    return 0


if __name__ == '__main__':
    exit(main()) 