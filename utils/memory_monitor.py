"""
内存监控模块
用于监控TEE环境的内存使用情况，实现内存限制和安全清理
"""
import os
import gc
import psutil
import threading
import time
import logging
from typing import Dict, Any, Optional, Callable, List
from collections import deque


class MemoryMonitorError(Exception):
    """内存监控异常"""
    pass


class MemoryMonitor:
    """内存监控器"""
    
    def __init__(self, config: Dict):
        """
        初始化内存监控器
        
        Args:
            config: 安全配置
        """
        self.config = config
        self.tee_config = config.get('tee', {})
        self.monitor_config = self.tee_config.get('memory_monitor', {})
        self.logger = logging.getLogger(__name__)
        
        # 内存限制配置
        self.memory_limit = self.tee_config.get('memory_limit', 134217728)  # 128MB默认
        self.secure_memory = self.tee_config.get('secure_memory', True)
        self.memory_encryption = self.tee_config.get('memory_encryption', True)
        
        # 监控配置
        self.monitor_interval = self.monitor_config.get('interval', 5)  # 5秒
        self.alert_threshold = self.monitor_config.get('alert_threshold', 0.8)  # 80%
        self.cleanup_threshold = self.monitor_config.get('cleanup_threshold', 0.9)  # 90%
        
        # 监控状态
        self.monitoring = False
        self.monitor_thread = None
        self.memory_history = deque(maxlen=100)  # 保留最近100次记录
        self.alert_callbacks = []
        self.cleanup_callbacks = []
        
        # 获取进程信息
        self.process = psutil.Process()
        self.start_time = time.time()
        
        self.logger.info("Memory monitor initialized successfully")
    
    def start_monitoring(self):
        """启动内存监控"""
        if self.monitoring:
            self.logger.warning("Memory monitoring already started")
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.info("Memory monitoring started")
    
    def stop_monitoring(self):
        """停止内存监控"""
        if not self.monitoring:
            return
        
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info("Memory monitoring stopped")
    
    def _monitoring_loop(self):
        """监控循环"""
        while self.monitoring:
            try:
                memory_status = self.check_memory_usage()
                self.memory_history.append({
                    'timestamp': time.time(),
                    'status': memory_status
                })
                
                # 检查是否需要报警
                usage_percent = memory_status['memory_usage_percent']
                
                if usage_percent >= self.cleanup_threshold:
                    self.logger.warning(f"Memory usage critical: {usage_percent:.1f}%")
                    self._trigger_emergency_cleanup()
                elif usage_percent >= self.alert_threshold:
                    self.logger.warning(f"Memory usage high: {usage_percent:.1f}%")
                    self._trigger_alert(memory_status)
                
                time.sleep(self.monitor_interval)
                
            except Exception as e:
                self.logger.error(f"Memory monitoring error: {e}")
                time.sleep(self.monitor_interval)
    
    def check_memory_usage(self) -> Dict[str, Any]:
        """检查内存使用情况"""
        try:
            # 获取进程内存信息
            memory_info = self.process.memory_info()
            memory_percent = self.process.memory_percent()
            
            # 获取系统内存信息
            system_memory = psutil.virtual_memory()
            
            # 计算相对于限制的使用率
            if self.memory_limit > 0:
                limit_usage_percent = (memory_info.rss / self.memory_limit) * 100
                status = self._get_status_from_usage(limit_usage_percent)
            else:
                limit_usage_percent = memory_percent
                status = self._get_status_from_usage(memory_percent)
            
            return {
                'status': status,
                'memory_used_mb': memory_info.rss / 1024 / 1024,
                'memory_limit_mb': self.memory_limit / 1024 / 1024 if self.memory_limit > 0 else 0,
                'memory_usage_percent': limit_usage_percent,
                'system_memory_percent': memory_percent,
                'system_memory_available_mb': system_memory.available / 1024 / 1024,
                'memory_info': {
                    'rss': memory_info.rss,
                    'vms': memory_info.vms,
                    'peak_rss': getattr(memory_info, 'peak_wset', memory_info.rss),
                    'num_page_faults': getattr(memory_info, 'num_page_faults', 0)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Failed to check memory usage: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'memory_used_mb': 0,
                'memory_limit_mb': 0,
                'memory_usage_percent': 0
            }
    
    def _get_status_from_usage(self, usage_percent: float) -> str:
        """根据使用率获取状态"""
        if usage_percent >= self.cleanup_threshold * 100:
            return 'critical'
        elif usage_percent >= self.alert_threshold * 100:
            return 'warning'
        elif usage_percent >= 50:
            return 'normal'
        else:
            return 'low'
    
    def cleanup_memory(self) -> Dict[str, Any]:
        """执行内存清理"""
        cleanup_start = time.time()
        
        try:
            # 记录清理前的内存状态
            before_cleanup = self.check_memory_usage()
            
            # 执行各种清理操作
            gc_collected = gc.collect()  # 强制垃圾回收
            
            # 触发清理回调
            for callback in self.cleanup_callbacks:
                try:
                    callback()
                except Exception as e:
                    self.logger.warning(f"Cleanup callback failed: {e}")
            
            # 再次强制垃圾回收
            gc_collected += gc.collect()
            
            # 记录清理后的内存状态
            after_cleanup = self.check_memory_usage()
            
            cleanup_duration = time.time() - cleanup_start
            
            memory_freed = before_cleanup['memory_used_mb'] - after_cleanup['memory_used_mb']
            
            result = {
                'success': True,
                'duration_seconds': cleanup_duration,
                'gc_collected_objects': gc_collected,
                'memory_before_mb': before_cleanup['memory_used_mb'],
                'memory_after_mb': after_cleanup['memory_used_mb'],
                'memory_freed_mb': memory_freed,
                'cleanup_timestamp': time.time()
            }
            
            self.logger.info(f"Memory cleanup completed: freed {memory_freed:.2f}MB in {cleanup_duration:.3f}s")
            return result
            
        except Exception as e:
            self.logger.error(f"Memory cleanup failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'duration_seconds': time.time() - cleanup_start,
                'cleanup_timestamp': time.time()
            }
    
    def _trigger_emergency_cleanup(self):
        """触发紧急清理"""
        self.logger.warning("Triggering emergency memory cleanup")
        
        try:
            # 执行紧急清理
            cleanup_result = self.cleanup_memory()
            
            # 如果清理后仍然超过阈值，记录错误
            current_status = self.check_memory_usage()
            if current_status['memory_usage_percent'] >= self.cleanup_threshold * 100:
                self.logger.error("Emergency cleanup failed to reduce memory usage below threshold")
                
        except Exception as e:
            self.logger.error(f"Emergency cleanup failed: {e}")
    
    def _trigger_alert(self, memory_status: Dict[str, Any]):
        """触发内存报警"""
        for callback in self.alert_callbacks:
            try:
                callback(memory_status)
            except Exception as e:
                self.logger.warning(f"Alert callback failed: {e}")
    
    def register_alert_callback(self, callback: Callable):
        """注册报警回调"""
        self.alert_callbacks.append(callback)
    
    def register_cleanup_callback(self, callback: Callable):
        """注册清理回调"""
        self.cleanup_callbacks.append(callback)
    
    def get_memory_report(self) -> Dict[str, Any]:
        """获取内存详细报告"""
        current_status = self.check_memory_usage()
        
        # 计算统计信息
        if self.memory_history:
            history_usage = [h['status']['memory_usage_percent'] for h in self.memory_history 
                           if 'memory_usage_percent' in h['status']]
            
            if history_usage:
                avg_usage = sum(history_usage) / len(history_usage)
                max_usage = max(history_usage)
                min_usage = min(history_usage)
            else:
                avg_usage = max_usage = min_usage = 0
        else:
            avg_usage = max_usage = min_usage = 0
        
        # 获取垃圾回收统计
        gc_stats = {
            'collections': gc.get_count(),
            'thresholds': gc.get_threshold(),
            'stats': gc.get_stats() if hasattr(gc, 'get_stats') else []
        }
        
        uptime = time.time() - self.start_time
        
        return {
            'current_status': current_status,
            'limits': {
                'memory_limit_mb': self.memory_limit / 1024 / 1024 if self.memory_limit > 0 else 'unlimited',
                'alert_threshold': self.alert_threshold,
                'cleanup_threshold': self.cleanup_threshold
            },
            'statistics': {
                'uptime_hours': uptime / 3600,
                'monitoring_enabled': self.monitoring,
                'history_records': len(self.memory_history),
                'average_usage_percent': avg_usage,
                'max_usage_percent': max_usage,
                'min_usage_percent': min_usage
            },
            'garbage_collection': gc_stats,
            'configuration': {
                'secure_memory': self.secure_memory,
                'memory_encryption': self.memory_encryption,
                'monitor_interval': self.monitor_interval
            },
            'report_timestamp': time.time()
        }
    
    def enforce_memory_limit(self) -> bool:
        """强制执行内存限制"""
        if self.memory_limit <= 0:
            return True  # 无限制
        
        current_status = self.check_memory_usage()
        usage_percent = current_status['memory_usage_percent']
        
        if usage_percent >= 100:  # 超过限制
            self.logger.error("Memory limit exceeded, triggering emergency cleanup")
            self._trigger_emergency_cleanup()
            
            # 重新检查
            new_status = self.check_memory_usage()
            if new_status['memory_usage_percent'] >= 100:
                self.logger.critical("Failed to enforce memory limit after cleanup")
                return False
        
        return True
    
    def get_memory_history(self, minutes: int = 10) -> List[Dict]:
        """获取内存使用历史"""
        cutoff_time = time.time() - (minutes * 60)
        
        return [
            record for record in self.memory_history
            if record['timestamp'] >= cutoff_time
        ]
    
    def secure_zero_memory(self, data: Any):
        """安全清零内存数据"""
        if not self.secure_memory:
            return
        
        try:
            if isinstance(data, bytes):
                # 对于bytes类型，尝试清零
                for i in range(len(data)):
                    data = data[:i] + b'\x00' + data[i+1:]
            elif isinstance(data, bytearray):
                # 对于bytearray类型，直接清零
                for i in range(len(data)):
                    data[i] = 0
            elif hasattr(data, '__dict__'):
                # 对于对象，递归清理属性
                for attr_name in list(data.__dict__.keys()):
                    delattr(data, attr_name)
            
        except Exception as e:
            self.logger.warning(f"Secure memory zero failed: {e}")
    
    def get_process_info(self) -> Dict[str, Any]:
        """获取进程信息"""
        try:
            with self.process.oneshot():
                cpu_percent = self.process.cpu_percent()
                memory_info = self.process.memory_info()
                num_threads = self.process.num_threads()
                num_fds = self.process.num_fds() if hasattr(self.process, 'num_fds') else 0
                
            return {
                'pid': self.process.pid,
                'name': self.process.name(),
                'status': self.process.status(),
                'cpu_percent': cpu_percent,
                'memory_mb': memory_info.rss / 1024 / 1024,
                'num_threads': num_threads,
                'num_file_descriptors': num_fds,
                'create_time': self.process.create_time()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get process info: {e}")
            return {'error': str(e)}


# 全局内存监控器实例
_memory_monitor: Optional[MemoryMonitor] = None


def initialize_memory_monitor(config: Dict) -> MemoryMonitor:
    """
    初始化内存监控器
    
    Args:
        config: 安全配置
        
    Returns:
        内存监控器实例
    """
    global _memory_monitor
    _memory_monitor = MemoryMonitor(config)
    
    # 自动启动监控
    _memory_monitor.start_monitoring()
    
    return _memory_monitor


def get_memory_monitor() -> MemoryMonitor:
    """获取内存监控器实例"""
    if _memory_monitor is None:
        raise MemoryMonitorError("Memory monitor not initialized. Call initialize_memory_monitor() first.")
    return _memory_monitor


def get_memory_status() -> Dict[str, Any]:
    """获取内存状态（便捷函数）"""
    try:
        monitor = get_memory_monitor()
        return monitor.check_memory_usage()
    except MemoryMonitorError:
        # 如果监控器未初始化，返回基本信息
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            
            return {
                'status': 'unknown',
                'memory_used_mb': memory_info.rss / 1024 / 1024,
                'memory_limit_mb': 0,
                'memory_usage_percent': process.memory_percent(),
                'monitoring_enabled': False
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'memory_used_mb': 0,
                'monitoring_enabled': False
            }


def cleanup_memory() -> Dict[str, Any]:
    """执行内存清理（便捷函数）"""
    try:
        monitor = get_memory_monitor()
        return monitor.cleanup_memory()
    except MemoryMonitorError:
        # 如果监控器未初始化，执行基本清理
        try:
            gc_collected = gc.collect()
            return {
                'success': True,
                'gc_collected_objects': gc_collected,
                'monitoring_enabled': False,
                'cleanup_timestamp': time.time()
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'monitoring_enabled': False,
                'cleanup_timestamp': time.time()
            }


def enforce_memory_limit() -> bool:
    """强制执行内存限制（便捷函数）"""
    try:
        monitor = get_memory_monitor()
        return monitor.enforce_memory_limit()
    except MemoryMonitorError:
        return True  # 如果监控器未初始化，假设无限制


# 注册清理函数
def register_cleanup_function(func: Callable):
    """注册清理函数"""
    try:
        monitor = get_memory_monitor()
        monitor.register_cleanup_callback(func)
    except MemoryMonitorError:
        pass  # 忽略，监控器未初始化


# 注册报警函数
def register_alert_function(func: Callable):
    """注册报警函数"""
    try:
        monitor = get_memory_monitor()
        monitor.register_alert_callback(func)
    except MemoryMonitorError:
        pass  # 忽略，监控器未初始化 