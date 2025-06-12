"""
TEE软件进程监控模块
专门监控TEE软件进程的CPU、内存、网络等资源占用
"""
import psutil
import time
import threading
import logging
from datetime import datetime, timedelta
from collections import deque, defaultdict
from typing import Dict, List, Optional, Any
import json
import socket
import os
import platform

logger = logging.getLogger(__name__)


class TEEProcessMonitor:
    """TEE软件进程监控器"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.enabled = config.get('enabled', True)
        self.interval = config.get('interval_seconds', 5)
        self.history_size = config.get('history_size', 1000)  # 恢复详细历史数据
        
        # 阈值配置
        self.cpu_threshold = config.get('cpu_alert_threshold', 80.0)
        self.memory_threshold = config.get('memory_alert_threshold', 85.0)
        self.memory_limit_mb = config.get('memory_limit_mb', 128)  # TEE软件内存限制
        
        # 数据存储 - 恢复详细存储
        self.process_metrics = deque(maxlen=self.history_size)
        self.network_metrics = deque(maxlen=self.history_size)
        self.alerts = deque(maxlen=200)  # 更多告警记录
        
        # TEE内存优化相关
        self.tee_memory_tracker = deque(maxlen=500)  # TEE内存历史跟踪
        self.memory_optimization_log = deque(maxlen=100)  # 内存优化日志
        self.memory_pressure_threshold = 0.8  # 内存压力阈值
        self.optimization_cooldown = {}  # 优化操作冷却
        
        # 监控状态
        self.is_running = False
        self.monitor_thread = None
        self.tee_process = None
        self.tee_children = []
        self.last_network_stats = {}
        
        # 告警冷却
        self.alert_cooldown = {}
        self.cooldown_seconds = 300  # 5分钟冷却
        
        # 平台信息
        self.is_windows = platform.system() == 'Windows'
        
        # TEE软件进程标识
        self.tee_process_names = ['python', 'main.py', 'tee_soft']
        self.tee_script_indicators = ['main.py', 'tee_soft', 'dashboard']
        
        # 内存清理计数器 - 针对TEE软件
        self.tee_cleanup_counter = 0
        self.tee_cleanup_interval = 60  # 每60个循环检查TEE内存
        
        logger.info("TEEProcessMonitor initialized")
    
    def start_monitoring(self):
        """启动监控"""
        if self.enabled and not self.is_running:
            self.is_running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            logger.info("TEE process monitoring started")
    
    def stop_monitoring(self):
        """停止监控"""
        self.is_running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("TEE process monitoring stopped")
    
    def _find_tee_processes(self) -> List[psutil.Process]:
        """查找TEE软件相关进程"""
        tee_processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cwd']):
                try:
                    proc_info = proc.info
                    cmdline = proc_info.get('cmdline', [])
                    cwd = proc_info.get('cwd', '')
                    name = proc_info.get('name', '')
                    
                    # 检查是否为TEE软件相关进程
                    is_tee_process = False
                    
                    # 1. 检查命令行参数
                    if cmdline:
                        cmdline_str = ' '.join(cmdline).lower()
                        if any(keyword in cmdline_str for keyword in [
                            'main.py', 'tee_soft', 'tee_software'
                        ]):
                            is_tee_process = True
                    
                    # 2. 检查工作目录
                    if cwd and 'tee_software' in cwd.lower():
                        is_tee_process = True
                    
                    # 3. 排除dashboard进程
                    if cmdline:
                        cmdline_str = ' '.join(cmdline).lower()
                        if 'dashboard' in cmdline_str:
                            is_tee_process = False
                    
                    # 4. 特别检查主TEE进程 (python main.py)
                    if cmdline and len(cmdline) >= 2:
                        if ('python' in cmdline[0].lower() and 
                            'main.py' in cmdline[1] and 
                            'dashboard' not in ' '.join(cmdline).lower()):
                            is_tee_process = True
                    
                    if is_tee_process:
                        tee_processes.append(proc)
                        logger.debug(f"Found TEE process: PID={proc.pid}, CMD={' '.join(cmdline)}")
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            logger.error(f"Error finding TEE processes: {e}")
        
        logger.info(f"Found {len(tee_processes)} TEE software processes")
        return tee_processes
    
    def _monitor_loop(self):
        """监控主循环"""
        while self.is_running:
            try:
                # 定期检查和优化TEE软件内存
                self.tee_cleanup_counter += 1
                if self.tee_cleanup_counter >= self.tee_cleanup_interval:
                    self._optimize_tee_memory()
                    self.tee_cleanup_counter = 0
                
                # 查找TEE进程
                tee_processes = self._find_tee_processes()
                
                if not tee_processes:
                    logger.warning("No TEE processes found")
                    # 创建空的监控数据
                    empty_metrics = self._create_empty_metrics()
                    self.process_metrics.append(empty_metrics)
                else:
                    # 收集TEE进程指标
                    process_metrics = self._collect_tee_process_metrics(tee_processes)
                    if process_metrics:
                        self.process_metrics.append(process_metrics)
                        
                        # 跟踪TEE内存使用
                        self._track_tee_memory_usage(process_metrics)
                        
                        # 收集网络指标
                        network_metrics = self._collect_tee_network_metrics(tee_processes)
                        if network_metrics:
                            self.network_metrics.append(network_metrics)
                        
                        # 检查告警
                        self._check_alerts(process_metrics)
                        
                        # 检查内存压力并执行优化
                        self._check_memory_pressure(process_metrics)
                
            except Exception as e:
                logger.error(f"Error in TEE monitoring loop: {e}")
            
            time.sleep(self.interval)
    
    def _create_empty_metrics(self) -> Dict[str, Any]:
        """创建空的监控指标"""
        return {
            'timestamp': datetime.now().isoformat(),
            'tee_processes': [],
            'total_processes': 0,
            'total_cpu_percent': 0.0,
            'total_memory_mb': 0.0,
            'total_memory_percent': 0.0,
            'main_process': None,
            'process_status': 'not_found',
            'uptime': 0,
            'threads_count': 0,
            'open_files': 0,
            'connections': 0
        }
    
    def _collect_tee_process_metrics(self, tee_processes: List[psutil.Process]) -> Optional[Dict[str, Any]]:
        """收集TEE进程指标"""
        try:
            process_data = []
            total_cpu = 0.0
            total_memory_mb = 0.0
            total_memory_percent = 0.0
            total_threads = 0
            total_open_files = 0
            total_connections = 0
            main_process = None
            oldest_create_time = float('inf')
            
            for proc in tee_processes:
                try:
                    # 获取进程信息
                    proc_info = {
                        'pid': proc.pid,
                        'name': proc.name(),
                        'cpu_percent': proc.cpu_percent(interval=0.1),
                        'memory_info': proc.memory_info(),
                        'memory_percent': proc.memory_percent(),
                        'status': proc.status(),
                        'create_time': proc.create_time(),
                        'num_threads': proc.num_threads(),
                        'cmdline': proc.cmdline()
                    }
                    
                    # 尝试获取额外信息
                    try:
                        proc_info['open_files'] = len(proc.open_files())
                    except:
                        proc_info['open_files'] = 0
                    
                    try:
                        proc_info['connections'] = len(proc.connections())
                    except:
                        proc_info['connections'] = 0
                    
                    try:
                        proc_info['cwd'] = proc.cwd()
                    except:
                        proc_info['cwd'] = 'N/A'
                    
                    # 计算运行时间
                    proc_info['uptime'] = time.time() - proc_info['create_time']
                    
                    # 累计统计
                    total_cpu += proc_info['cpu_percent']
                    total_memory_mb += proc_info['memory_info'].rss / (1024 * 1024)
                    total_memory_percent += proc_info['memory_percent']
                    total_threads += proc_info['num_threads']
                    total_open_files += proc_info['open_files']
                    total_connections += proc_info['connections']
                    
                    # 找到主进程（最早创建的）
                    if proc_info['create_time'] < oldest_create_time:
                        oldest_create_time = proc_info['create_time']
                        main_process = {
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cmdline': ' '.join(proc_info['cmdline']),
                            'uptime': proc_info['uptime'],
                            'uptime_formatted': self._format_uptime(proc_info['uptime'])
                        }
                    
                    process_data.append(proc_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'tee_processes': process_data,
                'total_processes': len(process_data),
                'total_cpu_percent': total_cpu,
                'total_memory_mb': total_memory_mb,
                'total_memory_percent': total_memory_percent,
                'main_process': main_process,
                'process_status': 'running' if process_data else 'not_found',
                'uptime': main_process['uptime'] if main_process else 0,
                'threads_count': total_threads,
                'open_files': total_open_files,
                'connections': total_connections,
                'system_info': {
                    'platform': platform.system(),
                    'python_version': platform.python_version(),
                    'machine': platform.machine()
                }
            }
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting TEE process metrics: {e}")
            return None
    
    def _collect_tee_network_metrics(self, tee_processes: List[psutil.Process]) -> Optional[Dict[str, Any]]:
        """收集TEE进程网络指标"""
        try:
            total_connections = 0
            connection_types = defaultdict(int)
            listening_ports = []
            
            for proc in tee_processes:
                try:
                    connections = proc.connections()
                    total_connections += len(connections)
                    
                    for conn in connections:
                        connection_types[conn.status] += 1
                        
                        # 记录监听端口
                        if conn.status == 'LISTEN' and conn.laddr:
                            listening_ports.append({
                                'pid': proc.pid,
                                'port': conn.laddr.port,
                                'address': conn.laddr.ip
                            })
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # 获取网络I/O统计（如果可用）
            network_io = {}
            try:
                # 尝试获取每个进程的网络I/O（在某些系统上可能不可用）
                for proc in tee_processes:
                    try:
                        if hasattr(proc, 'io_counters'):
                            io = proc.io_counters()
                            network_io[proc.pid] = {
                                'read_bytes': io.read_bytes,
                                'write_bytes': io.write_bytes,
                                'read_count': io.read_count,
                                'write_count': io.write_count
                            }
                    except:
                        continue
            except:
                pass
            
            return {
                'timestamp': datetime.now().isoformat(),
                'total_connections': total_connections,
                'connection_types': dict(connection_types),
                'listening_ports': listening_ports,
                'network_io': network_io
            }
            
        except Exception as e:
            logger.error(f"Error collecting TEE network metrics: {e}")
            return None
    
    def _check_alerts(self, metrics: Dict[str, Any]):
        """检查告警条件"""
        current_time = time.time()
        alerts = []
        
        # CPU告警
        cpu_percent = metrics['total_cpu_percent']
        if cpu_percent > self.cpu_threshold:
            alert_key = 'tee_cpu_high'
            if self._should_alert(alert_key, current_time):
                alerts.append({
                    'type': 'tee_cpu_high',
                    'level': 'WARNING' if cpu_percent < 90 else 'CRITICAL',
                    'message': f'TEE软件CPU使用率过高: {cpu_percent:.1f}%',
                    'value': cpu_percent,
                    'threshold': self.cpu_threshold,
                    'timestamp': datetime.now().isoformat(),
                    'process_count': metrics['total_processes']
                })
        
        # 内存告警
        memory_mb = metrics['total_memory_mb']
        if memory_mb > self.memory_limit_mb:
            alert_key = 'tee_memory_high'
            if self._should_alert(alert_key, current_time):
                alerts.append({
                    'type': 'tee_memory_high',
                    'level': 'WARNING' if memory_mb < self.memory_limit_mb * 1.5 else 'CRITICAL',
                    'message': f'TEE软件内存使用过高: {memory_mb:.1f}MB',
                    'value': memory_mb,
                    'threshold': self.memory_limit_mb,
                    'timestamp': datetime.now().isoformat(),
                    'process_count': metrics['total_processes']
                })
        
        # 进程数量告警
        if metrics['total_processes'] == 0:
            alert_key = 'tee_process_missing'
            if self._should_alert(alert_key, current_time):
                alerts.append({
                    'type': 'tee_process_missing',
                    'level': 'CRITICAL',
                    'message': 'TEE软件进程未找到或已停止',
                    'value': 0,
                    'threshold': 1,
                    'timestamp': datetime.now().isoformat()
                })
        
        # 添加告警到队列
        for alert in alerts:
            self.alerts.append(alert)
            logger.warning(f"TEE Alert: {alert['message']}")
    
    def _should_alert(self, alert_key: str, current_time: float) -> bool:
        """检查是否应该发送告警（考虑冷却时间）"""
        last_alert_time = self.alert_cooldown.get(alert_key, 0)
        if current_time - last_alert_time > self.cooldown_seconds:
            self.alert_cooldown[alert_key] = current_time
            return True
        return False
    
    def _format_uptime(self, uptime_seconds: float) -> str:
        """格式化运行时间"""
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        return f"{days}天 {hours}小时 {minutes}分钟"
    
    def _cleanup_memory(self):
        """清理内存，减少内存占用"""
        try:
            # 清理旧的进程列表缓存
            self.tee_children.clear()
            self.last_network_stats.clear()
            
            # 强制清理告警冷却记录
            current_time = time.time()
            expired_alerts = []
            for key, timestamp in self.alert_cooldown.items():
                if current_time - timestamp > self.cooldown_seconds * 2:  # 超过冷却时间的2倍就清理
                    expired_alerts.append(key)
            
            for key in expired_alerts:
                del self.alert_cooldown[key]
            
            # 手动触发垃圾回收
            import gc
            gc.collect()
            
            logger.debug(f"Memory cleanup completed. Cleared {len(expired_alerts)} expired alert records")
            
        except Exception as e:
            logger.error(f"Error during memory cleanup: {e}")
    
    def _track_tee_memory_usage(self, metrics: Dict[str, Any]):
        """跟踪TEE软件内存使用情况"""
        try:
            memory_info = {
                'timestamp': metrics['timestamp'],
                'total_memory_mb': metrics['total_memory_mb'],
                'total_memory_percent': metrics['total_memory_percent'],
                'process_count': metrics['total_processes'],
                'memory_per_process': metrics['total_memory_mb'] / max(metrics['total_processes'], 1)
            }
            
            self.tee_memory_tracker.append(memory_info)
            
        except Exception as e:
            logger.error(f"Error tracking TEE memory usage: {e}")
    
    def _check_memory_pressure(self, metrics: Dict[str, Any]):
        """检查TEE软件内存压力并触发优化"""
        try:
            current_usage_mb = metrics['total_memory_mb']
            usage_ratio = current_usage_mb / self.memory_limit_mb
            
            if usage_ratio > self.memory_pressure_threshold:
                optimization_key = 'memory_pressure'
                current_time = time.time()
                
                # 检查优化冷却时间
                if self._should_optimize(optimization_key, current_time):
                    logger.warning(f"TEE memory pressure detected: {current_usage_mb:.1f}MB ({usage_ratio:.1%})")
                    self._trigger_tee_memory_cleanup(metrics)
                    
        except Exception as e:
            logger.error(f"Error checking memory pressure: {e}")
    
    def _should_optimize(self, optimization_key: str, current_time: float) -> bool:
        """检查是否应该执行优化（考虑冷却时间）"""
        last_optimization_time = self.optimization_cooldown.get(optimization_key, 0)
        cooldown_duration = 300  # 5分钟冷却
        
        if current_time - last_optimization_time > cooldown_duration:
            self.optimization_cooldown[optimization_key] = current_time
            return True
        return False
    
    def _optimize_tee_memory(self):
        """优化TEE软件内存使用"""
        try:
            if not self.process_metrics:
                return
            
            latest_metrics = self.process_metrics[-1]
            current_usage_mb = latest_metrics.get('total_memory_mb', 0)
            
            if current_usage_mb > self.memory_limit_mb * 0.7:  # 超过70%限制时开始优化
                logger.info(f"Starting TEE memory optimization. Current usage: {current_usage_mb:.1f}MB")
                
                # 记录优化操作
                optimization_record = {
                    'timestamp': datetime.now().isoformat(),
                    'trigger': 'scheduled_optimization',
                    'memory_before_mb': current_usage_mb,
                    'actions': []
                }
                
                # 执行内存优化
                success = self._trigger_tee_memory_cleanup(latest_metrics)
                
                optimization_record['success'] = success
                optimization_record['memory_after_mb'] = self._get_current_tee_memory()
                
                self.memory_optimization_log.append(optimization_record)
                
        except Exception as e:
            logger.error(f"Error during TEE memory optimization: {e}")
    
    def _trigger_tee_memory_cleanup(self, metrics: Dict[str, Any]) -> bool:
        """触发TEE软件内存清理"""
        try:
            import requests
            tee_server_url = os.getenv('TEE_SERVER_URL', 'http://127.0.0.1:5000')
            
            # 尝试调用TEE软件的内存清理API
            try:
                response = requests.post(f"{tee_server_url}/admin/memory_cleanup", 
                                       timeout=10,
                                       json={'force': True, 'reason': 'dashboard_optimization'})
                
                if response.status_code == 200:
                    logger.info("Successfully triggered TEE memory cleanup via API")
                    return True
                else:
                    logger.warning(f"TEE memory cleanup API returned status {response.status_code}")
                    
            except requests.RequestException as e:
                logger.warning(f"Failed to call TEE memory cleanup API: {e}")
            
            # 如果API调用失败，记录建议
            logger.info("Logged memory optimization recommendation for TEE software")
            return False
            
        except Exception as e:
            logger.error(f"Error triggering TEE memory cleanup: {e}")
            return False
    
    def _get_current_tee_memory(self) -> float:
        """获取当前TEE软件内存使用量"""
        try:
            if self.process_metrics:
                return self.process_metrics[-1].get('total_memory_mb', 0)
            return 0
        except:
            return 0
    
    def get_latest_metrics(self) -> Dict[str, Any]:
        """获取最新的TEE进程指标"""
        if not self.process_metrics:
            return self._create_empty_metrics()
        
        latest = {
            'system': self.process_metrics[-1],
            'processes': self.process_metrics[-1],  # 为了兼容性
            'network': self.network_metrics[-1] if self.network_metrics else {}
        }
        
        return latest
    
    def get_historical_metrics(self, hours: int = 1) -> Dict[str, List]:
        """获取历史指标数据"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        def filter_by_time(metrics_list):
            return [
                m for m in metrics_list
                if datetime.fromisoformat(m['timestamp']) > cutoff_time
            ]
        
        return {
            'system': filter_by_time(list(self.process_metrics)),
            'processes': filter_by_time(list(self.process_metrics)),
            'network': filter_by_time(list(self.network_metrics))
        }
    
    def get_alerts(self, limit: int = 50) -> List[Dict]:
        """获取告警信息"""
        return list(self.alerts)[-limit:]
    
    def clear_alerts(self):
        """清除告警"""
        self.alerts.clear()
        logger.info("TEE alerts cleared")
    
    def get_summary(self) -> Dict[str, Any]:
        """获取TEE软件监控摘要"""
        if not self.process_metrics:
            return {'error': 'No TEE process metrics available'}
        
        latest = self.process_metrics[-1]
        
        # 判断健康状态
        status = 'healthy'
        if latest['total_processes'] == 0:
            status = 'critical'
        elif (latest['total_cpu_percent'] > self.cpu_threshold or 
              latest['total_memory_mb'] > self.memory_limit_mb):
            status = 'warning'
        
        # 计算内存趋势
        memory_trend = self._calculate_memory_trend()
        
        return {
            'status': status,
            'process_count': latest['total_processes'],
            'uptime': latest['main_process']['uptime_formatted'] if latest['main_process'] else 'N/A',
            'cpu_usage': f"{latest['total_cpu_percent']:.1f}%",
            'memory_usage': f"{latest['total_memory_mb']:.1f}MB",
            'memory_percent': f"{latest['total_memory_percent']:.1f}%",
            'memory_limit': f"{self.memory_limit_mb}MB",
            'memory_utilization': f"{(latest['total_memory_mb'] / self.memory_limit_mb * 100):.1f}%",
            'memory_trend': memory_trend,
            'threads_count': latest['threads_count'],
            'connections': latest['connections'],
            'active_alerts': len([a for a in self.alerts if a['level'] in ['WARNING', 'CRITICAL']]),
            'optimization_count': len(self.memory_optimization_log),
            'last_optimization': self.memory_optimization_log[-1]['timestamp'] if self.memory_optimization_log else 'None',
            'last_update': latest['timestamp']
        }
    
    def get_tee_memory_analysis(self) -> Dict[str, Any]:
        """获取详细的TEE内存分析"""
        try:
            if not self.tee_memory_tracker:
                return {'error': 'No TEE memory tracking data available'}
            
            recent_data = list(self.tee_memory_tracker)[-100:]  # 最近100条记录
            
            # 计算统计信息
            memory_values = [item['total_memory_mb'] for item in recent_data]
            
            analysis = {
                'current_usage_mb': memory_values[-1] if memory_values else 0,
                'memory_limit_mb': self.memory_limit_mb,
                'utilization_percent': (memory_values[-1] / self.memory_limit_mb * 100) if memory_values else 0,
                'statistics': {
                    'avg_memory_mb': sum(memory_values) / len(memory_values) if memory_values else 0,
                    'max_memory_mb': max(memory_values) if memory_values else 0,
                    'min_memory_mb': min(memory_values) if memory_values else 0,
                    'memory_variance': self._calculate_variance(memory_values),
                },
                'trend': self._calculate_memory_trend(),
                'peak_usage_periods': self._identify_peak_periods(recent_data),
                'optimization_opportunities': self._identify_optimization_opportunities(recent_data),
                'recommendations': self._generate_memory_recommendations(recent_data),
                'last_analysis_time': datetime.now().isoformat()
            }
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error generating TEE memory analysis: {e}")
            return {'error': str(e)}
    
    def get_memory_optimization_log(self) -> List[Dict]:
        """获取内存优化日志"""
        return list(self.memory_optimization_log)
    
    def _calculate_memory_trend(self) -> str:
        """计算内存趋势"""
        try:
            if len(self.tee_memory_tracker) < 10:
                return 'insufficient_data'
            
            recent_data = list(self.tee_memory_tracker)[-20:]
            memory_values = [item['total_memory_mb'] for item in recent_data]
            
            # 计算简单的线性趋势
            n = len(memory_values)
            x_avg = (n - 1) / 2
            y_avg = sum(memory_values) / n
            
            numerator = sum((i - x_avg) * (memory_values[i] - y_avg) for i in range(n))
            denominator = sum((i - x_avg) ** 2 for i in range(n))
            
            if denominator == 0:
                return 'stable'
            
            slope = numerator / denominator
            
            if slope > 1:
                return 'increasing'
            elif slope < -1:
                return 'decreasing'
            else:
                return 'stable'
                
        except Exception as e:
            logger.error(f"Error calculating memory trend: {e}")
            return 'unknown'
    
    def _calculate_variance(self, values: List[float]) -> float:
        """计算方差"""
        if not values:
            return 0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance
    
    def _identify_peak_periods(self, data: List[Dict]) -> List[Dict]:
        """识别内存使用高峰期"""
        try:
            if len(data) < 10:
                return []
            
            memory_values = [item['total_memory_mb'] for item in data]
            threshold = self.memory_limit_mb * 0.8  # 80%阈值
            
            peaks = []
            in_peak = False
            peak_start = None
            
            for i, item in enumerate(data):
                if item['total_memory_mb'] > threshold:
                    if not in_peak:
                        in_peak = True
                        peak_start = i
                else:
                    if in_peak:
                        peaks.append({
                            'start_time': data[peak_start]['timestamp'],
                            'end_time': data[i-1]['timestamp'],
                            'max_memory_mb': max(memory_values[peak_start:i]),
                            'duration_minutes': (i - peak_start) * (self.interval / 60)
                        })
                        in_peak = False
            
            return peaks[-5:]  # 返回最近5个高峰期
            
        except Exception as e:
            logger.error(f"Error identifying peak periods: {e}")
            return []
    
    def _identify_optimization_opportunities(self, data: List[Dict]) -> List[str]:
        """识别优化机会"""
        opportunities = []
        
        try:
            if not data:
                return opportunities
            
            current_memory = data[-1]['total_memory_mb']
            memory_limit = self.memory_limit_mb
            
            # 内存使用率检查
            usage_ratio = current_memory / memory_limit
            if usage_ratio > 0.9:
                opportunities.append("Critical: Memory usage >90%, immediate cleanup needed")
            elif usage_ratio > 0.8:
                opportunities.append("Warning: Memory usage >80%, consider cleanup")
            
            # 进程数量检查
            if data[-1]['process_count'] > 3:
                opportunities.append("Multiple TEE processes detected, consider consolidation")
            
            # 内存增长趋势检查
            trend = self._calculate_memory_trend()
            if trend == 'increasing':
                opportunities.append("Memory usage trending upward, monitor for leaks")
            
            # 内存方差检查
            memory_values = [item['total_memory_mb'] for item in data[-20:]]
            variance = self._calculate_variance(memory_values)
            if variance > 100:  # 高方差表示不稳定
                opportunities.append("High memory usage variance, investigate stability")
            
        except Exception as e:
            logger.error(f"Error identifying optimization opportunities: {e}")
        
        return opportunities
    
    def _generate_memory_recommendations(self, data: List[Dict]) -> List[str]:
        """生成内存优化建议"""
        recommendations = []
        
        try:
            if not data:
                return recommendations
            
            current_memory = data[-1]['total_memory_mb']
            memory_limit = self.memory_limit_mb
            usage_ratio = current_memory / memory_limit
            
            # 基于使用率的建议
            if usage_ratio > 0.95:
                recommendations.extend([
                    "Immediately trigger memory cleanup via /admin/memory_cleanup API",
                    "Consider restarting TEE software if cleanup is insufficient",
                    "Review recent operations for memory leaks"
                ])
            elif usage_ratio > 0.8:
                recommendations.extend([
                    "Schedule regular memory cleanup operations",
                    "Monitor for memory leaks in TEE operations",
                    "Consider optimizing batch processing sizes"
                ])
            elif usage_ratio < 0.5:
                recommendations.append("Memory usage is optimal, no action needed")
            
            # 基于趋势的建议
            trend = self._calculate_memory_trend()
            if trend == 'increasing':
                recommendations.append("Set up automated memory monitoring alerts")
            
            # 基于进程数的建议
            if data[-1]['process_count'] > 1:
                recommendations.append("Multiple TEE processes may indicate inefficient resource usage")
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
        
        return recommendations
    
    def get_process_details(self) -> Dict[str, Any]:
        """获取TEE进程详细信息"""
        if not self.process_metrics:
            return {'error': 'No TEE process data available'}
        
        latest = self.process_metrics[-1]
        
        return {
            'main_process': latest['main_process'],
            'all_processes': latest['tee_processes'],
            'summary': {
                'total_processes': latest['total_processes'],
                'total_cpu_percent': latest['total_cpu_percent'],
                'total_memory_mb': latest['total_memory_mb'],
                'total_threads': latest['threads_count'],
                'total_open_files': latest['open_files'],
                'total_connections': latest['connections']
            },
            'system_info': latest.get('system_info', {}),
            'timestamp': latest['timestamp']
        }


# 为了向后兼容，保留SystemMonitor类名
SystemMonitor = TEEProcessMonitor 