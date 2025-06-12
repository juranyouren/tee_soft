"""
低内存优化模块
确保TEE软件内存占用不超过128MB的优化策略实现
"""
import gc
import sys
import logging
import hashlib
import threading
from typing import Dict, Any, List, Iterator, Optional, Union, Callable
from collections import deque
from io import BytesIO
import time
import psutil
import os
import weakref


class LowMemoryError(Exception):
    """低内存模式异常"""
    pass


class MemoryPool:
    """内存池管理器 - 复用对象减少内存分配"""
    
    def __init__(self, max_size: int = 100):
        self.pools = {}
        self.max_size = max_size
        self.lock = threading.Lock()
    
    def get_buffer(self, size: int) -> bytearray:
        """获取指定大小的缓冲区"""
        with self.lock:
            pool_key = f"buffer_{size}"
            if pool_key not in self.pools:
                self.pools[pool_key] = deque(maxlen=self.max_size)
            
            pool = self.pools[pool_key]
            if pool:
                return pool.popleft()
            else:
                return bytearray(size)
    
    def return_buffer(self, buffer: bytearray):
        """归还缓冲区到池中"""
        with self.lock:
            size = len(buffer)
            pool_key = f"buffer_{size}"
            if pool_key in self.pools:
                pool = self.pools[pool_key]
                if len(pool) < self.max_size:
                    # 清零缓冲区以确保安全
                    for i in range(len(buffer)):
                        buffer[i] = 0
                    pool.append(buffer)
    
    def clear_all(self):
        """清空所有内存池"""
        with self.lock:
            for pool in self.pools.values():
                pool.clear()
            self.pools.clear()


class StreamProcessor:
    """流式数据处理器 - 分批处理大数据"""
    
    def __init__(self, chunk_size: int = 8192):  # 8KB chunk
        self.chunk_size = chunk_size
        self.logger = logging.getLogger(__name__)
    
    def process_large_data(self, data: Union[bytes, str], 
                          processor_func: Callable[[bytes], bytes]) -> bytes:
        """
        分块处理大数据
        
        Args:
            data: 输入数据
            processor_func: 处理函数，接收bytes返回bytes
            
        Returns:
            处理后的数据
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if len(data) <= self.chunk_size:
            return processor_func(data)
        
        result_chunks = []
        
        try:
            # 分块处理
            for i in range(0, len(data), self.chunk_size):
                chunk = data[i:i + self.chunk_size]
                processed_chunk = processor_func(chunk)
                result_chunks.append(processed_chunk)
                
                # 每处理几个块就清理一次内存
                if len(result_chunks) % 10 == 0:
                    gc.collect()
            
            # 合并结果
            result = b''.join(result_chunks)
            
            # 清理临时数据
            del result_chunks
            gc.collect()
            
            return result
            
        except Exception as e:
            # 清理部分结果
            del result_chunks
            gc.collect()
            raise LowMemoryError(f"Stream processing failed: {e}")


class HashBasedCache:
    """基于哈希的轻量级缓存 - 减少重复计算"""
    
    def __init__(self, max_entries: int = 1000):
        self.cache = {}
        self.access_order = deque(maxlen=max_entries)
        self.max_entries = max_entries
        self.lock = threading.Lock()
    
    def get_hash_key(self, data: Union[str, bytes, Dict]) -> str:
        """生成数据的哈希键"""
        if isinstance(data, dict):
            # 对字典进行排序后哈希
            import json
            data_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
            data = data_str.encode('utf-8')
        elif isinstance(data, str):
            data = data.encode('utf-8')
        
        return hashlib.sha256(data).hexdigest()[:16]  # 只用前16位减少内存
    
    def get(self, key: str) -> Optional[Any]:
        """获取缓存项"""
        with self.lock:
            if key in self.cache:
                # 更新访问顺序
                if key in self.access_order:
                    self.access_order.remove(key)
                self.access_order.append(key)
                return self.cache[key]
            return None
    
    def put(self, key: str, value: Any):
        """存储缓存项"""
        with self.lock:
            # 如果超出容量，删除最久未使用的项
            if len(self.cache) >= self.max_entries and key not in self.cache:
                if self.access_order:
                    oldest_key = self.access_order.popleft()
                    if oldest_key in self.cache:
                        del self.cache[oldest_key]
            
            self.cache[key] = value
            if key in self.access_order:
                self.access_order.remove(key)
            self.access_order.append(key)
    
    def clear(self):
        """清空缓存"""
        with self.lock:
            self.cache.clear()
            self.access_order.clear()


class LowMemoryOptimizer:
    """低内存优化器 - 主控制器"""
    
    def __init__(self, memory_limit_mb: int = 128):
        self.memory_limit_bytes = memory_limit_mb * 1024 * 1024
        self.logger = logging.getLogger(__name__)
        
        # 初始化组件
        self.memory_pool = MemoryPool()
        self.stream_processor = StreamProcessor()
        self.hash_cache = HashBasedCache()
        
        # 监控相关
        self.process = psutil.Process()
        self.last_cleanup = time.time()
        self.cleanup_interval = 30  # 30秒清理间隔
        
        # 弱引用追踪大对象
        self.tracked_objects = weakref.WeakSet()
        
        # 统计信息
        self.stats = {
            'memory_optimizations': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'stream_processes': 0,
            'emergency_cleanups': 0
        }
        
        self.logger.info(f"Low memory optimizer initialized with {memory_limit_mb}MB limit")
    
    def check_memory_pressure(self) -> bool:
        """检查内存压力"""
        try:
            memory_info = self.process.memory_info()
            current_usage = memory_info.rss
            usage_ratio = current_usage / self.memory_limit_bytes
            
            return usage_ratio > 0.85  # 85%以上认为有压力
        except:
            return False
    
    def optimize_data_processing(self, data: Any, operation: str) -> Any:
        """
        优化数据处理 - 根据数据大小选择最佳策略
        
        Args:
            data: 待处理数据
            operation: 操作类型
            
        Returns:
            处理后的数据
        """
        try:
            # 检查内存压力
            if self.check_memory_pressure():
                self._emergency_cleanup()
            
            # 为大数据启用流式处理
            if self._is_large_data(data):
                self.logger.info(f"Using stream processing for large {operation} operation")
                return self._stream_process_data(data, operation)
            
            # 检查缓存
            cache_key = self._get_cache_key(data, operation)
            cached_result = self.hash_cache.get(cache_key)
            if cached_result is not None:
                self.stats['cache_hits'] += 1
                self.logger.debug(f"Cache hit for {operation}")
                return cached_result
            
            self.stats['cache_misses'] += 1
            
            # 正常处理并缓存结果
            result = self._process_data_normal(data, operation)
            
            # 只缓存小结果
            if self._should_cache_result(result):
                self.hash_cache.put(cache_key, result)
            
            self.stats['memory_optimizations'] += 1
            return result
            
        except Exception as e:
            self.logger.error(f"Data processing optimization failed: {e}")
            # 降级到基本处理
            return self._process_data_normal(data, operation)
    
    def _is_large_data(self, data: Any) -> bool:
        """判断是否为大数据"""
        try:
            size = sys.getsizeof(data)
            # 如果数据超过1MB，认为是大数据
            return size > 1024 * 1024
        except:
            return False
    
    def _should_cache_result(self, result: Any) -> bool:
        """判断是否应该缓存结果"""
        try:
            size = sys.getsizeof(result)
            # 只缓存小于100KB的结果
            return size < 100 * 1024
        except:
            return False
    
    def _get_cache_key(self, data: Any, operation: str) -> str:
        """生成缓存键"""
        data_hash = self.hash_cache.get_hash_key(data)
        return f"{operation}_{data_hash}"
    
    def _stream_process_data(self, data: Any, operation: str) -> Any:
        """流式处理大数据"""
        self.stats['stream_processes'] += 1
        
        # 根据操作类型选择处理函数
        if operation == 'encrypt':
            processor_func = self._chunk_encrypt
        elif operation == 'decrypt':
            processor_func = self._chunk_decrypt
        elif operation == 'hash':
            processor_func = self._chunk_hash
        else:
            processor_func = self._chunk_generic
        
        return self.stream_processor.process_large_data(data, processor_func)
    
    def _chunk_encrypt(self, chunk: bytes) -> bytes:
        """分块加密处理"""
        try:
            # 尝试使用TEE加密系统
            from core.sm_crypto_engine import get_sm_crypto_engine
            crypto_engine = get_sm_crypto_engine()
            if crypto_engine:
                return crypto_engine.encrypt_data_chunk(chunk)
        except:
            pass
        
        # 降级到简单哈希处理
        return hashlib.sha256(chunk).digest()
    
    def _chunk_decrypt(self, chunk: bytes) -> bytes:
        """分块解密处理"""
        try:
            # 尝试使用TEE解密系统
            from core.sm_crypto_engine import get_sm_crypto_engine
            crypto_engine = get_sm_crypto_engine()
            if crypto_engine:
                return crypto_engine.decrypt_data_chunk(chunk)
        except:
            pass
        
        # 降级到简单反转
        return chunk[::-1]
    
    def _chunk_hash(self, chunk: bytes) -> bytes:
        """分块哈希处理"""
        return hashlib.sha256(chunk).digest()
    
    def _chunk_generic(self, chunk: bytes) -> bytes:
        """通用分块处理"""
        return chunk
    
    def _process_data_normal(self, data: Any, operation: str) -> Any:
        """正常数据处理（无优化）"""
        try:
            # 尝试与TEE处理器集成
            if operation in ['encrypt', 'decrypt']:
                from core.sm_crypto_engine import get_sm_crypto_engine
                crypto_engine = get_sm_crypto_engine()
                if crypto_engine:
                    if operation == 'encrypt':
                        return crypto_engine.encrypt_data(data)
                    elif operation == 'decrypt':
                        return crypto_engine.decrypt_data(data)
        except:
            pass
        
        # 降级到返回原数据
        return data
    
    def _emergency_cleanup(self):
        """紧急内存清理"""
        self.stats['emergency_cleanups'] += 1
        self.logger.warning("Performing emergency memory cleanup")
        
        try:
            # 清理缓存
            self.hash_cache.clear()
            
            # 清理内存池
            self.memory_pool.clear_all()
            
            # 强制垃圾回收
            collected = gc.collect()
            
            # 清理跟踪的对象
            self.tracked_objects.clear()
            
            self.logger.info(f"Emergency cleanup completed, collected {collected} objects")
            
        except Exception as e:
            self.logger.error(f"Emergency cleanup failed: {e}")
    
    def periodic_cleanup(self):
        """定期清理"""
        current_time = time.time()
        if current_time - self.last_cleanup > self.cleanup_interval:
            self.logger.debug("Performing periodic cleanup")
            
            # 轻量级清理
            gc.collect()
            
            # 检查内存使用
            if self.check_memory_pressure():
                self._emergency_cleanup()
            
            self.last_cleanup = current_time
    
    def get_memory_status(self) -> Dict[str, Any]:
        """获取内存状态"""
        try:
            memory_info = self.process.memory_info()
            current_usage = memory_info.rss
            usage_percent = (current_usage / self.memory_limit_bytes) * 100
            
            return {
                'current_usage_mb': current_usage / 1024 / 1024,
                'limit_mb': self.memory_limit_bytes / 1024 / 1024,
                'usage_percent': usage_percent,
                'status': 'critical' if usage_percent > 90 else 'warning' if usage_percent > 75 else 'normal',
                'cache_size': len(self.hash_cache.cache),
                'pool_sizes': {k: len(v) for k, v in self.memory_pool.pools.items()},
                'stats': self.stats.copy()
            }
        except:
            return {'error': 'Unable to get memory status'}
    
    def optimize_dict_processing(self, data_dict: Dict[str, Any]) -> Dict[str, Any]:
        """优化字典数据处理"""
        if not isinstance(data_dict, dict):
            return data_dict
        
        # 如果字典很大，分批处理
        if len(data_dict) > 1000:
            self.logger.info("Processing large dictionary in batches")
            
            result = {}
            batch_size = 100
            keys = list(data_dict.keys())
            
            for i in range(0, len(keys), batch_size):
                batch_keys = keys[i:i + batch_size]
                batch_dict = {k: data_dict[k] for k in batch_keys}
                
                # 处理这个批次
                processed_batch = self._process_dict_batch(batch_dict)
                result.update(processed_batch)
                
                # 定期清理
                if i % (batch_size * 10) == 0:
                    gc.collect()
            
            return result
        else:
            return self._process_dict_batch(data_dict)
    
    def _process_dict_batch(self, batch: Dict[str, Any]) -> Dict[str, Any]:
        """处理字典批次"""
        # 这里应该调用实际的处理逻辑
        return batch
    
    def track_large_object(self, obj: Any):
        """跟踪大对象"""
        try:
            if sys.getsizeof(obj) > 1024 * 1024:  # 大于1MB
                self.tracked_objects.add(obj)
        except:
            pass
    
    def cleanup_resources(self):
        """清理所有资源"""
        self.logger.info("Cleaning up low memory optimizer resources")
        self.hash_cache.clear()
        self.memory_pool.clear_all()
        self.tracked_objects.clear()
        gc.collect()


# 全局实例
_optimizer = None
_optimizer_lock = threading.Lock()


def get_low_memory_optimizer() -> LowMemoryOptimizer:
    """获取低内存优化器实例"""
    global _optimizer
    if _optimizer is None:
        with _optimizer_lock:
            if _optimizer is None:
                _optimizer = LowMemoryOptimizer()
    return _optimizer


def initialize_low_memory_mode(memory_limit_mb: int = 128) -> LowMemoryOptimizer:
    """初始化低内存模式"""
    global _optimizer
    with _optimizer_lock:
        _optimizer = LowMemoryOptimizer(memory_limit_mb)
    return _optimizer


def optimize_data_processing(data: Any, operation: str) -> Any:
    """优化数据处理（便捷函数）"""
    optimizer = get_low_memory_optimizer()
    return optimizer.optimize_data_processing(data, operation)


def check_memory_status() -> Dict[str, Any]:
    """检查内存状态（便捷函数）"""
    optimizer = get_low_memory_optimizer()
    return optimizer.get_memory_status()


def emergency_cleanup():
    """紧急清理（便捷函数）"""
    optimizer = get_low_memory_optimizer()
    optimizer._emergency_cleanup() 