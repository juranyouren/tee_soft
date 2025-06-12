"""
API功能测试模块
测试TEE软件的各种API接口功能
"""
import requests
import time
import json
import threading
import logging
from datetime import datetime, timedelta
from collections import deque, defaultdict
from typing import Dict, List, Optional, Any, Tuple, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import random
import uuid

logger = logging.getLogger(__name__)


class TestStep:
    """测试步骤类"""
    def __init__(self, name: str, description: str):
        self.id = str(uuid.uuid4())
        self.name = name
        self.description = description
        self.status = 'pending'  # pending, running, success, failed
        self.start_time = None
        self.end_time = None
        self.duration = 0
        self.result = None
        self.error = None
        
    def start(self):
        self.status = 'running'
        self.start_time = time.time()
        
    def complete(self, success: bool, result: Any = None, error: str = None):
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time if self.start_time else 0
        self.status = 'success' if success else 'failed'
        self.result = result
        self.error = error
        
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'status': self.status,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': self.duration,
            'result': self.result,
            'error': self.error
        }


class TestSession:
    """测试会话类"""
    def __init__(self, name: str, description: str):
        self.id = str(uuid.uuid4())
        self.name = name
        self.description = description
        self.start_time = time.time()
        self.end_time = None
        self.status = 'running'
        self.steps = []
        self.progress = 0
        
    def add_step(self, step: TestStep):
        self.steps.append(step)
        
    def update_progress(self):
        completed_steps = len([s for s in self.steps if s.status in ['success', 'failed']])
        self.progress = (completed_steps / len(self.steps) * 100) if self.steps else 0
        
    def complete(self):
        self.end_time = time.time()
        self.status = 'completed'
        self.progress = 100
        
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'status': self.status,
            'progress': self.progress,
            'total_steps': len(self.steps),
            'completed_steps': len([s for s in self.steps if s.status in ['success', 'failed']]),
            'successful_steps': len([s for s in self.steps if s.status == 'success']),
            'failed_steps': len([s for s in self.steps if s.status == 'failed']),
            'steps': [step.to_dict() for step in self.steps]
        }


class APITester:
    """API功能测试器"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.enabled = config.get('enabled', True)
        self.base_url = config.get('tee_server_url', 'http://localhost:5000')
        self.timeout = config.get('timeout_seconds', 15)
        self.retry_attempts = config.get('retry_attempts', 3)
        self.test_interval = config.get('test_interval_seconds', 30)
        
        # 测试端点配置
        self.endpoints = config.get('endpoints', self._get_default_endpoints())
        self.test_data = config.get('test_data', self._get_default_test_data())
        
        # 测试结果存储
        self.test_sessions = deque(maxlen=100)  # 存储测试会话
        self.current_session = None
        self.test_results = deque(maxlen=500)
        self.endpoint_stats = defaultdict(lambda: {
            'total_tests': 0,
            'success_count': 0,
            'failure_count': 0,
            'avg_response_time': 0.0,
            'last_success': None,
            'last_failure': None,
            'success_rate': 0.0
        })
        
        # 测试状态
        self.is_running = False
        self.test_thread = None
        self.session = requests.Session()
        
        # 性能统计
        self.performance_stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'avg_response_time': 0.0,
            'min_response_time': float('inf'),
            'max_response_time': 0.0
        }
        
        # 进度回调
        self.progress_callbacks = []
        
        logger.info("APITester initialized")
    
    def _get_default_endpoints(self) -> List[Dict]:
        """获取默认测试端点"""
        return [
            {'url': '/health', 'method': 'GET', 'name': '健康检查'},
            {'url': '/api/status', 'method': 'GET', 'name': '状态查询'},
            {'url': '/tee_soft/encrypt', 'method': 'POST', 'name': 'TEE加密'},
            {'url': '/tee_soft/decrypt', 'method': 'POST', 'name': 'TEE解密'},
            {'url': '/tee_soft/process', 'method': 'POST', 'name': 'TEE处理'},
        ]
    
    def _get_default_test_data(self) -> Dict:
        """获取默认测试数据"""
        return {
            'encrypt': {
                'data': 'Hello TEE Software',
                'algorithm': 'AES-256-GCM'
            },
            'decrypt': {
                'encrypted_data': '',
                'algorithm': 'AES-256-GCM'
            },
            'process': {
                'operation': 'encrypt',
                'data': 'Test data for processing',
                'params': {
                    'algorithm': 'AES-256-GCM',
                    'key_size': 256
                }
            }
        }
    
    def add_progress_callback(self, callback: Callable):
        """添加进度回调函数"""
        self.progress_callbacks.append(callback)
    
    def _notify_progress(self, session: TestSession):
        """通知进度更新"""
        for callback in self.progress_callbacks:
            try:
                callback(session.to_dict())
            except Exception as e:
                logger.error(f"Error in progress callback: {e}")
    
    def start_testing(self):
        """启动API测试"""
        if self.enabled and not self.is_running:
            self.is_running = True
            self.test_thread = threading.Thread(target=self._test_loop, daemon=True)
            self.test_thread.start()
            logger.info("API testing started")
    
    def stop_testing(self):
        """停止API测试"""
        self.is_running = False
        if self.test_thread:
            self.test_thread.join(timeout=5)
        logger.info("API testing stopped")
    
    def _test_loop(self):
        """测试主循环"""
        while self.is_running:
            try:
                # 执行一轮完整测试
                self._run_detailed_test_suite()
            except Exception as e:
                logger.error(f"Error in test loop: {e}")
            
            time.sleep(self.test_interval)
    
    def _run_detailed_test_suite(self):
        """运行详细的测试套件"""
        # 创建新的测试会话
        session = TestSession(
            name=f"API测试套件 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            description="完整的TEE API功能测试"
        )
        
        self.current_session = session
        self.test_sessions.append(session)
        
        try:
            # 1. 连接性测试
            self._add_and_run_step(session, "连接性测试", "测试服务器连接状态", 
                                 self._test_connectivity)
            
            # 2. 基础端点测试
            self._add_and_run_step(session, "基础端点测试", "测试基础API端点", 
                                 self._test_basic_endpoints_detailed)
            
            # 3. TEE功能测试
            self._add_and_run_step(session, "TEE功能测试", "测试TEE核心功能", 
                                 self._test_tee_functionality_detailed)
            
            # 4. 性能测试
            self._add_and_run_step(session, "性能测试", "测试API性能表现", 
                                 self._test_performance_detailed)
            
            # 5. 错误处理测试
            self._add_and_run_step(session, "错误处理测试", "测试异常情况处理", 
                                 self._test_error_handling_detailed)
            
            # 6. 安全性测试
            self._add_and_run_step(session, "安全性测试", "测试API安全性", 
                                 self._test_security)
            
        finally:
            session.complete()
            self._notify_progress(session)
            logger.info(f"Test session {session.id} completed")
    
    def _add_and_run_step(self, session: TestSession, name: str, description: str, 
                         test_func: Callable) -> TestStep:
        """添加并运行测试步骤"""
        step = TestStep(name, description)
        session.add_step(step)
        
        step.start()
        self._notify_progress(session)
        
        try:
            result = test_func()
            step.complete(True, result)
        except Exception as e:
            step.complete(False, error=str(e))
            logger.error(f"Step {name} failed: {e}")
        
        session.update_progress()
        self._notify_progress(session)
        
        return step
    
    def _test_connectivity(self) -> Dict:
        """测试连接性"""
        result = {
            'server_reachable': False,
            'response_time': None,
            'server_info': None
        }
        
        try:
            start_time = time.time()
            response = self.session.get(f"{self.base_url}/health", timeout=self.timeout)
            response_time = time.time() - start_time
            
            result['server_reachable'] = True
            result['response_time'] = response_time
            
            if response.status_code == 200:
                try:
                    result['server_info'] = response.json()
                except:
                    result['server_info'] = {'status': 'ok'}
            
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def _test_basic_endpoints_detailed(self) -> Dict:
        """详细测试基础端点"""
        results = []
        
        for endpoint_config in self.endpoints:
            url = endpoint_config['url']
            method = endpoint_config['method']
            name = endpoint_config['name']
            
            result = self._test_endpoint_detailed(url, method, name)
            results.append(result)
        
        return {
            'total_endpoints': len(results),
            'successful_endpoints': len([r for r in results if r['success']]),
            'failed_endpoints': len([r for r in results if not r['success']]),
            'results': results
        }
    
    def _test_endpoint_detailed(self, url: str, method: str, name: str, 
                              data: Dict = None) -> Dict:
        """详细测试单个端点"""
        full_url = f"{self.base_url}{url}"
        start_time = time.time()
        
        test_result = {
            'endpoint': url,
            'method': method,
            'name': name,
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'response_time': 0.0,
            'status_code': None,
            'error_message': None,
            'response_size': 0,
            'response_headers': {},
            'response_data': None,
            'request_data': data
        }
        
        for attempt in range(self.retry_attempts):
            try:
                # 记录请求开始
                request_start = time.time()
                
                # 发送请求
                if method.upper() == 'GET':
                    response = self.session.get(full_url, timeout=self.timeout)
                elif method.upper() == 'POST':
                    response = self.session.post(full_url, json=data, timeout=self.timeout)
                else:
                    response = self.session.request(method, full_url, json=data, timeout=self.timeout)
                
                # 记录响应信息
                response_time = time.time() - request_start
                test_result.update({
                    'success': 200 <= response.status_code < 400,
                    'response_time': response_time,
                    'status_code': response.status_code,
                    'response_size': len(response.content),
                    'response_headers': dict(response.headers),
                    'attempt': attempt + 1
                })
                
                # 验证响应内容
                if response.headers.get('content-type', '').startswith('application/json'):
                    try:
                        response_data = response.json()
                        test_result['response_data'] = response_data
                        test_result['response_valid'] = True
                    except json.JSONDecodeError:
                        test_result['response_valid'] = False
                        test_result['error_message'] = 'Invalid JSON response'
                
                # 如果成功就跳出重试循环
                if test_result['success']:
                    break
                    
            except requests.exceptions.Timeout:
                test_result['error_message'] = f'Request timeout (attempt {attempt + 1})'
            except requests.exceptions.ConnectionError:
                test_result['error_message'] = f'Connection error (attempt {attempt + 1})'
            except Exception as e:
                test_result['error_message'] = f'{str(e)} (attempt {attempt + 1})'
        
        test_result['total_response_time'] = time.time() - start_time
        
        # 更新端点统计
        self._update_endpoint_stats(url, test_result)
        
        return test_result
    
    def _test_tee_functionality_detailed(self) -> Dict:
        """详细测试TEE功能"""
        results = []
        
        # 测试TEE处理端点
        tee_test_data = self.test_data.copy()
        tee_test_data['user_id'] = f"test_{int(time.time())}"
        
        tee_result = self._test_endpoint_detailed('/tee_soft/process', 'POST', 'TEE处理', tee_test_data)
        results.append(tee_result)
        
        # 测试加密功能
        if tee_result['success'] and 'response_data' in tee_result:
            encryption_test = self._validate_encryption_response(tee_result['response_data'])
            results.append({
                'endpoint': '/tee_soft/process',
                'method': 'POST',
                'name': '加密功能验证',
                'timestamp': datetime.now().isoformat(),
                'success': encryption_test['valid'],
                'response_time': 0.0,
                'details': encryption_test
            })
        
        # 测试批量处理
        batch_results = self._test_batch_processing_detailed()
        results.extend(batch_results)
        
        return {
            'total_tests': len(results),
            'successful_tests': len([r for r in results if r['success']]),
            'failed_tests': len([r for r in results if not r['success']]),
            'results': results
        }
    
    def _test_performance_detailed(self) -> Dict:
        """详细性能测试"""
        results = []
        
        # 并发测试
        concurrent_result = self._test_concurrent_requests_detailed()
        results.append(concurrent_result)
        
        # 负载测试
        load_result = self._test_load_performance_detailed()
        results.append(load_result)
        
        return {
            'total_tests': len(results),
            'successful_tests': len([r for r in results if r['success']]),
            'failed_tests': len([r for r in results if not r['success']]),
            'results': results
        }
    
    def _test_error_handling_detailed(self) -> Dict:
        """详细测试错误处理"""
        results = []
        
        # 测试无效请求
        invalid_data_result = self._test_endpoint_detailed('/tee_soft/process', 'POST', '无效数据测试', {'invalid': 'data'})
        results.append(invalid_data_result)
        
        # 测试空请求
        empty_data_result = self._test_endpoint_detailed('/tee_soft/process', 'POST', '空数据测试', {})
        results.append(empty_data_result)
        
        # 测试不存在的端点
        not_found_result = self._test_endpoint_detailed('/non_existent_endpoint', 'GET', '404测试')
        results.append(not_found_result)
        
        return {
            'total_tests': len(results),
            'successful_tests': len([r for r in results if r['success']]),
            'failed_tests': len([r for r in results if not r['success']]),
            'results': results
        }
    
    def _test_security(self) -> Dict:
        """测试安全性"""
        results = []
        
        # 测试加密功能
        encryption_result = self._test_endpoint_detailed('/tee_soft/encrypt', 'POST', '加密功能测试', self.test_data['encrypt'])
        results.append(encryption_result)
        
        # 测试解密功能
        decryption_result = self._test_endpoint_detailed('/tee_soft/decrypt', 'POST', '解密功能测试', self.test_data['decrypt'])
        results.append(decryption_result)
        
        return {
            'total_tests': len(results),
            'successful_tests': len([r for r in results if r['success']]),
            'failed_tests': len([r for r in results if not r['success']]),
            'results': results
        }
    
    def _test_batch_processing_detailed(self) -> List[Dict]:
        """详细测试批量处理"""
        results = []
        
        # 生成多个测试用户
        batch_size = 3
        batch_start_time = time.time()
        
        for i in range(batch_size):
            test_data = self.test_data.copy()
            test_data['user_id'] = f"batch_test_{i}_{int(time.time())}"
            
            result = self._test_endpoint_detailed('/tee_soft/process', 'POST', f'批量测试{i+1}', test_data)
            results.append(result)
        
        # 添加批量汇总结果
        successful = len([r for r in results if r['success']])
        batch_summary = {
            'endpoint': '/tee_soft/process',
            'method': 'POST',
            'name': f'批量处理汇总({batch_size}个)',
            'timestamp': datetime.now().isoformat(),
            'success': successful > 0,
            'response_time': time.time() - batch_start_time,
            'batch_size': batch_size,
            'successful_requests': successful,
            'failed_requests': batch_size - successful,
            'success_rate': successful / batch_size
        }
        results.append(batch_summary)
        
        return results
    
    def _test_concurrent_requests_detailed(self) -> Dict:
        """详细测试并发请求"""
        start_time = time.time()
        concurrent_count = 5
        
        test_result = {
            'endpoint': '/tee_soft/process',
            'method': 'POST',
            'name': f'并发测试({concurrent_count}个请求)',
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'response_time': 0.0,
            'concurrent_count': concurrent_count,
            'successful_requests': 0,
            'failed_requests': 0
        }
        
        try:
            with ThreadPoolExecutor(max_workers=concurrent_count) as executor:
                # 提交并发请求
                futures = []
                for i in range(concurrent_count):
                    test_data = self.test_data.copy()
                    test_data['user_id'] = f"concurrent_test_{i}_{int(time.time())}"
                    
                    future = executor.submit(self._single_request_detailed, '/tee_soft/process', 'POST', test_data)
                    futures.append(future)
                
                # 收集结果
                successful = 0
                failed = 0
                
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result['success']:
                            successful += 1
                        else:
                            failed += 1
                    except Exception:
                        failed += 1
                
                test_result.update({
                    'success': successful > 0,
                    'successful_requests': successful,
                    'failed_requests': failed,
                    'success_rate': successful / concurrent_count if concurrent_count > 0 else 0
                })
                
        except Exception as e:
            test_result['error_message'] = str(e)
        
        test_result['response_time'] = time.time() - start_time
        return test_result
    
    def _test_load_performance_detailed(self) -> Dict:
        """详细负载性能测试"""
        start_time = time.time()
        request_count = 10
        
        test_result = {
            'endpoint': '/tee_soft/process',
            'method': 'POST',
            'name': f'负载测试({request_count}个请求)',
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'response_time': 0.0,
            'request_count': request_count,
            'avg_response_time': 0.0,
            'min_response_time': float('inf'),
            'max_response_time': 0.0
        }
        
        try:
            response_times = []
            successful = 0
            
            for i in range(request_count):
                test_data = self.test_data.copy()
                test_data['user_id'] = f"load_test_{i}_{int(time.time())}"
                
                result = self._single_request_detailed('/tee_soft/process', 'POST', test_data)
                response_times.append(result['response_time'])
                
                if result['success']:
                    successful += 1
            
            if response_times:
                test_result.update({
                    'success': successful > 0,
                    'successful_requests': successful,
                    'avg_response_time': sum(response_times) / len(response_times),
                    'min_response_time': min(response_times),
                    'max_response_time': max(response_times),
                    'requests_per_second': request_count / (time.time() - start_time)
                })
            
        except Exception as e:
            test_result['error_message'] = str(e)
        
        test_result['response_time'] = time.time() - start_time
        return test_result
    
    def _single_request_detailed(self, url: str, method: str, data: Dict = None) -> Dict:
        """发送单个详细请求"""
        full_url = f"{self.base_url}{url}"
        start_time = time.time()
        
        try:
            if method.upper() == 'POST':
                response = self.session.post(full_url, json=data, timeout=self.timeout)
            else:
                response = self.session.get(full_url, timeout=self.timeout)
            
            return {
                'success': 200 <= response.status_code < 400,
                'response_time': time.time() - start_time,
                'status_code': response.status_code
            }
        except Exception as e:
            return {
                'success': False,
                'response_time': time.time() - start_time,
                'error': str(e)
            }
    
    def _validate_encryption_response(self, response_data: Dict) -> Dict:
        """验证加密响应"""
        validation = {
            'valid': False,
            'has_result': False,
            'has_encryption_info': False,
            'has_risk_score': False,
            'encryption_algorithm': None,
            'details': {}
        }
        
        try:
            # 检查基本结构
            if 'result' in response_data:
                validation['has_result'] = True
                result = response_data['result']
                
                if 'encryption_info' in result:
                    validation['has_encryption_info'] = True
                    encryption_info = result['encryption_info']
                    
                    if 'algorithm' in encryption_info:
                        validation['encryption_algorithm'] = encryption_info['algorithm']
                
                if 'risk_score' in result:
                    validation['has_risk_score'] = True
                    validation['risk_score'] = result['risk_score']
            
            # 综合判断
            validation['valid'] = (
                validation['has_result'] and 
                validation['has_encryption_info'] and 
                validation['has_risk_score']
            )
            
        except Exception as e:
            validation['error'] = str(e)
        
        return validation
    
    def _update_endpoint_stats(self, endpoint: str, result: Dict):
        """更新端点统计信息"""
        stats = self.endpoint_stats[endpoint]
        
        stats['total_tests'] += 1
        
        if result['success']:
            stats['success_count'] += 1
            stats['last_success'] = result['timestamp']
        else:
            stats['failure_count'] += 1
            stats['last_failure'] = result['timestamp']
        
        # 更新成功率
        stats['success_rate'] = stats['success_count'] / stats['total_tests']
        
        # 更新平均响应时间
        if result['response_time'] > 0:
            current_avg = stats['avg_response_time']
            stats['avg_response_time'] = (
                (current_avg * (stats['total_tests'] - 1) + result['response_time']) / 
                stats['total_tests']
            )
    
    def _update_statistics(self, results: List[Dict]):
        """更新总体统计信息"""
        self.performance_stats['total_requests'] += len(results)
        
        for result in results:
            if result['success']:
                self.performance_stats['successful_requests'] += 1
            else:
                self.performance_stats['failed_requests'] += 1
            
            # 更新响应时间统计
            response_time = result.get('response_time', 0)
            if response_time > 0:
                self.performance_stats['min_response_time'] = min(
                    self.performance_stats['min_response_time'], response_time
                )
                self.performance_stats['max_response_time'] = max(
                    self.performance_stats['max_response_time'], response_time
                )
                
                # 更新平均响应时间
                total_requests = self.performance_stats['total_requests']
                current_avg = self.performance_stats['avg_response_time']
                self.performance_stats['avg_response_time'] = (
                    (current_avg * (total_requests - 1) + response_time) / total_requests
                )
    
    def get_test_results(self, limit: int = 50) -> List[Dict]:
        """获取测试结果"""
        return list(self.test_results)[-limit:]
    
    def get_endpoint_statistics(self) -> Dict[str, Any]:
        """获取端点统计信息"""
        return dict(self.endpoint_stats)
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """获取性能摘要"""
        stats = self.performance_stats.copy()
        
        if stats['min_response_time'] == float('inf'):
            stats['min_response_time'] = 0.0
        
        # 计算成功率
        total = stats['total_requests']
        if total > 0:
            stats['success_rate'] = stats['successful_requests'] / total
            stats['failure_rate'] = stats['failed_requests'] / total
        else:
            stats['success_rate'] = 0.0
            stats['failure_rate'] = 0.0
        
        return stats
    
    def run_manual_test(self, endpoint_url: str, method: str = 'GET', data: Dict = None) -> Dict:
        """手动运行单次测试"""
        return self._test_endpoint_detailed(endpoint_url, method, f'手动测试-{endpoint_url}', data)
    
    def clear_test_history(self):
        """清除测试历史"""
        self.test_results.clear()
        self.endpoint_stats.clear()
        self.performance_stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'avg_response_time': 0.0,
            'min_response_time': float('inf'),
            'max_response_time': 0.0
        }
        logger.info("Test history cleared") 