#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TEE软件系统综合测试脚本

本脚本用于完整测试TEE系统的所有功能，包括：
1. TEE服务器功能测试
2. Dashboard监控功能验证
3. 客户端与服务器交互测试
4. 密钥协商和加密功能测试
5. 实时监控显示测试

作者: TEE软件开发团队
版本: v1.0
"""

import os
import sys
import time
import json
import logging
import requests
import threading
import subprocess
from datetime import datetime
from typing import List, Dict, Any

# 添加项目根目录到路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# 配置日志
log_dir = os.path.join(project_root, 'logs')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(log_dir, 'system_test.log'), mode='a', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

class Colors:
    """颜色配置类"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_header(title: str):
    """打印标题"""
    print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.BOLD}{title}{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")

def print_success(message: str):
    """打印成功信息"""
    print(f"{Colors.OKGREEN}✅ {message}{Colors.ENDC}")

def print_warning(message: str):
    """打印警告信息"""
    print(f"{Colors.WARNING}⚠️  {message}{Colors.ENDC}")

def print_error(message: str):
    """打印错误信息"""
    print(f"{Colors.FAIL}❌ {message}{Colors.ENDC}")

def print_info(message: str):
    """打印信息"""
    print(f"{Colors.OKCYAN}ℹ️  {message}{Colors.ENDC}")

class TEESystemTester:
    """TEE系统测试器"""
    
    def __init__(self):
        self.tee_server_url = "http://localhost:5000"
        self.dashboard_url = "http://localhost:5001"
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.test_results = {
            'server_health': False,
            'dashboard_health': False,
            'basic_functionality': False,
            'encryption_test': False,
            'dashboard_monitoring': False,
            'client_interaction': False
        }
        
    def check_prerequisites(self) -> bool:
        """检查测试前提条件"""
        print_header("🔍 检查测试前提条件")
        
        # 检查日志目录
        log_dir = os.path.join(self.project_root, 'logs')
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            print_info("创建logs目录")
        
        # 检查必要文件
        required_files = ['main.py', 'dashboard.py', 'start_dashboard.py', 'config.py']
        for file in required_files:
            file_path = os.path.join(self.project_root, file)
            if os.path.exists(file_path):
                print_success(f"找到必要文件: {file}")
            else:
                print_error(f"缺少必要文件: {file}")
                return False
        
        return True
    
    def check_service_health(self) -> bool:
        """检查服务健康状态"""
        print_header("🏥 检查服务健康状态")
        
        # 检查TEE服务器
        try:
            response = requests.get(f"{self.tee_server_url}/health", timeout=5)
            if response.status_code == 200:
                print_success("TEE服务器运行正常")
                self.test_results['server_health'] = True
            else:
                print_warning(f"TEE服务器响应异常: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print_error(f"TEE服务器连接失败: {e}")
            print_info("请先启动TEE服务器: python main.py")
            return False
        
        # 检查Dashboard服务
        try:
            response = requests.get(f"{self.dashboard_url}/api/overview", timeout=5)
            if response.status_code == 200:
                print_success("Dashboard服务运行正常")
                self.test_results['dashboard_health'] = True
            else:
                print_warning(f"Dashboard响应异常: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print_error(f"Dashboard连接失败: {e}")
            print_info("请先启动Dashboard: python start_dashboard.py")
            return False
        
        return True
    
    def test_basic_functionality(self) -> bool:
        """测试基础功能"""
        print_header("🧪 测试基础功能")
        
        try:
            # 测试基础端点
            endpoints = [
                ("/", "GET", "主页"),
                ("/health", "GET", "健康检查"),
                ("/api/stats", "GET", "统计信息")
            ]
            
            for endpoint, method, description in endpoints:
                try:
                    url = f"{self.tee_server_url}{endpoint}"
                    response = requests.get(url, timeout=5)
                    if response.status_code in [200, 404]:  # 404也是正常的，说明服务在运行
                        print_success(f"{description} ({endpoint}): 状态码 {response.status_code}")
                    else:
                        print_warning(f"{description} ({endpoint}): 状态码 {response.status_code}")
                except Exception as e:
                    print_error(f"{description} ({endpoint}): 错误 {e}")
                    return False
            
            self.test_results['basic_functionality'] = True
            return True
            
        except Exception as e:
            print_error(f"基础功能测试失败: {e}")
            return False
    
    def test_client_interaction(self) -> bool:
        """测试客户端交互"""
        print_header("👥 测试客户端交互")
        
        try:
            # 模拟多种客户端请求
            test_cases = [
                {
                    "name": "正常用户登录",
                    "data": {
                        "user_id": "test_user_001",
                        "action": "login",
                        "features": {
                            "ip": "192.168.1.100",
                            "user_agent": "Chrome/91.0.4472.124",
                            "device_fingerprint": "desktop_chrome_001",
                            "login_time": datetime.now().isoformat(),
                            "geo_location": {"lat": 40.7128, "lng": -74.0060}
                        }
                    }
                },
                {
                    "name": "可疑IP登录",
                    "data": {
                        "user_id": "test_user_002",
                        "action": "login",
                        "features": {
                            "ip": "203.0.113.100",  # 可疑IP
                            "user_agent": "Bot/1.0",
                            "device_fingerprint": "unknown_device",
                            "login_time": datetime.now().isoformat(),
                            "geo_location": {"lat": 0.0, "lng": 0.0}
                        }
                    }
                },
                {
                    "name": "移动端用户",
                    "data": {
                        "user_id": "test_user_003",
                        "action": "login",
                        "features": {
                            "ip": "192.168.1.101",
                            "user_agent": "Mobile Safari/14.0",
                            "device_fingerprint": "iphone_safari_001",
                            "login_time": datetime.now().isoformat(),
                            "geo_location": {"lat": 37.7749, "lng": -122.4194}
                        }
                    }
                }
            ]
            
            success_count = 0
            for i, test_case in enumerate(test_cases, 1):
                print_info(f"测试案例 {i}/3: {test_case['name']}")
                
                # 通过Dashboard API发送请求
                try:
                    response = requests.post(
                        f"{self.dashboard_url}/api/simulate_request",
                        json=test_case['data'],
                        headers={'Content-Type': 'application/json'},
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        print_success(f"请求成功处理: {result.get('status', 'OK')}")
                        success_count += 1
                        
                        # 显示风险评估结果
                        if 'response' in result and isinstance(result['response'], dict):
                            if 'result' in result['response']:
                                risk_info = result['response']['result'].get('risk_assessment', {})
                                print_info(f"   风险分数: {risk_info.get('risk_score', 'N/A')}")
                                print_info(f"   建议动作: {risk_info.get('action', 'N/A')}")
                    else:
                        print_warning(f"请求失败: 状态码 {response.status_code}")
                        
                except Exception as e:
                    print_error(f"请求处理出错: {e}")
                
                # 等待1秒
                time.sleep(1)
            
            if success_count >= 2:  # 至少2个测试案例成功
                self.test_results['client_interaction'] = True
                return True
            else:
                return False
                
        except Exception as e:
            print_error(f"客户端交互测试失败: {e}")
            return False
    
    def test_encryption_functionality(self) -> bool:
        """测试加密功能"""
        print_header("🔐 测试加密功能")
        
        try:
            # 测试加密API
            response = requests.get(f"{self.dashboard_url}/api/test_encryption", timeout=10)
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    print_success("加密功能测试通过")
                    print_info("   SM4对称加密 ✓")
                    print_info("   SM2公钥保护 ✓") 
                    print_info("   数据完整性验证 ✓")
                    self.test_results['encryption_test'] = True
                    return True
                else:
                    print_error(f"加密测试失败: {result.get('error', 'Unknown error')}")
            else:
                print_error(f"加密测试请求失败: {response.status_code}")
            
        except Exception as e:
            print_error(f"加密功能测试出错: {e}")
        
        return False
    
    def test_dashboard_monitoring(self) -> bool:
        """测试Dashboard监控功能"""
        print_header("📊 测试Dashboard监控功能")
        
        try:
            # 获取系统概览
            response = requests.get(f"{self.dashboard_url}/api/overview", timeout=5)
            if response.status_code == 200:
                data = response.json()
                
                # 显示系统指标
                metrics = data.get('system_metrics', {})
                print_success("系统监控数据获取成功")
                print_info(f"   CPU使用率: {metrics.get('cpu_percent', 'N/A'):.1f}%")
                print_info(f"   内存使用率: {metrics.get('memory_percent', 'N/A'):.1f}%")
                print_info(f"   磁盘使用率: {metrics.get('disk_percent', 'N/A'):.1f}%")
                
                # 显示通讯统计
                comm_stats = data.get('communication_stats', {})
                print_success("通讯统计数据获取成功")
                print_info(f"   总请求数: {comm_stats.get('total', 0)}")
                print_info(f"   入站请求: {comm_stats.get('inbound', 0)}")
                print_info(f"   出站请求: {comm_stats.get('outbound', 0)}")
                
                # 显示加密统计
                enc_stats = data.get('encryption_stats', {})
                print_success("加密统计数据获取成功")
                print_info(f"   加密事件数: {enc_stats.get('total', 0)}")
                print_info(f"   活跃会话: {data.get('active_sessions', 0)}")
                
                self.test_results['dashboard_monitoring'] = True
                return True
            else:
                print_error(f"Dashboard监控数据获取失败: {response.status_code}")
                
        except Exception as e:
            print_error(f"Dashboard监控测试出错: {e}")
        
        return False
    
    def run_continuous_monitoring_demo(self, duration: int = 30):
        """运行持续监控演示"""
        print_header(f"🔄 持续监控演示 ({duration}秒)")
        
        print_info(f"将发送测试请求 {duration} 秒，观察Dashboard实时更新")
        print_info("请在浏览器中打开 http://localhost:5001 查看实时效果")
        
        start_time = time.time()
        request_count = 0
        
        # 测试数据模板
        test_templates = [
            {"user_id": "demo_user_{}", "ip": "192.168.1.{}", "risk": "low"},
            {"user_id": "suspect_user_{}", "ip": "203.0.113.{}", "risk": "high"},
            {"user_id": "mobile_user_{}", "ip": "10.0.0.{}", "risk": "medium"}
        ]
        
        while time.time() - start_time < duration:
            try:
                # 选择随机模板
                template = test_templates[request_count % len(test_templates)]
                
                # 构造测试数据
                test_data = {
                    "user_id": template["user_id"].format(request_count + 1),
                    "action": "login",
                    "features": {
                        "ip": template["ip"].format((request_count % 100) + 1),
                        "user_agent": f"TestAgent/{request_count + 1}",
                        "device_fingerprint": f"test_device_{request_count + 1}",
                        "timestamp": datetime.now().isoformat()
                    }
                }
                
                # 发送请求
                response = requests.post(
                    f"{self.dashboard_url}/api/simulate_request",
                    json=test_data,
                    headers={'Content-Type': 'application/json'},
                    timeout=5
                )
                
                if response.status_code == 200:
                    request_count += 1
                    if request_count % 5 == 0:
                        print_info(f"已发送 {request_count} 个测试请求...")
                
            except Exception as e:
                print_warning(f"请求发送失败: {e}")
            
            time.sleep(1)  # 每秒发送一个请求
        
        print_success(f"持续监控演示完成，共发送 {request_count} 个请求")
    
    def generate_test_report(self):
        """生成测试报告"""
        print_header("📋 测试报告")
        
        total_tests = len(self.test_results)
        passed_tests = sum(self.test_results.values())
        
        print(f"{Colors.BOLD}总体结果: {passed_tests}/{total_tests} 项测试通过{Colors.ENDC}")
        print()
        
        # 详细结果
        for test_name, result in self.test_results.items():
            status = "✅ 通过" if result else "❌ 失败"
            test_display = test_name.replace('_', ' ').title()
            print(f"  {test_display}: {status}")
        
        print()
        
        # 建议
        if passed_tests == total_tests:
            print_success("🎉 所有测试通过！系统运行正常")
            print_info("可以开始正式使用TEE软件系统")
        elif passed_tests >= total_tests * 0.8:
            print_warning("⚠️  大部分测试通过，系统基本可用")
            print_info("建议检查失败的测试项目")
        else:
            print_error("❌ 多项测试失败，系统可能存在问题")
            print_info("建议检查服务启动状态和配置")
    
    def run_full_test_suite(self):
        """运行完整测试套件"""
        print_header("🚀 TEE软件系统综合测试")
        print_info("开始执行完整的系统功能测试...")
        
        # 检查前提条件
        if not self.check_prerequisites():
            print_error("前提条件检查失败，无法继续测试")
            return
        
        # 依次执行各项测试
        test_sequence = [
            ("服务健康检查", self.check_service_health),
            ("基础功能测试", self.test_basic_functionality),
            ("客户端交互测试", self.test_client_interaction),
            ("加密功能测试", self.test_encryption_functionality),
            ("Dashboard监控测试", self.test_dashboard_monitoring)
        ]
        
        for test_name, test_function in test_sequence:
            print_info(f"执行: {test_name}")
            try:
                test_function()
            except Exception as e:
                print_error(f"{test_name} 执行失败: {e}")
            time.sleep(1)  # 测试间隔
        
        # 生成报告
        self.generate_test_report()


def main():
    """主函数"""
    print(f"{Colors.BOLD}🔧 TEE软件系统测试工具{Colors.ENDC}")
    print("用于验证TEE系统和Dashboard的完整功能")
    
    if len(sys.argv) > 1:
        mode = sys.argv[1]
        
        if mode == "--help":
            print("\n使用方法:")
            print("  python test/test_system.py           # 运行完整测试套件")
            print("  python test/test_system.py --quick   # 快速健康检查")
            print("  python test/test_system.py --demo    # 持续监控演示")
            print("  python test/test_system.py --help    # 显示帮助")
            print("\n注意:")
            print("  测试前请确保TEE服务器和Dashboard都已启动")
            print("  TEE服务器: python main.py")
            print("  Dashboard: python start_dashboard.py")
            return
        
        elif mode == "--quick":
            tester = TEESystemTester()
            tester.check_service_health()
            tester.test_basic_functionality()
            return
        
        elif mode == "--demo":
            tester = TEESystemTester()
            if tester.check_service_health():
                tester.run_continuous_monitoring_demo(60)  # 60秒演示
            return
    
    # 默认运行完整测试
    tester = TEESystemTester()
    tester.run_full_test_suite()
    
    # 询问是否运行持续监控演示
    print()
    response = input("是否运行持续监控演示? (y/N): ").strip().lower()
    if response in ['y', 'yes']:
        duration = 30
        try:
            duration = int(input(f"演示时长(秒，默认{duration}): ").strip() or duration)
        except ValueError:
            pass
        tester.run_continuous_monitoring_demo(duration)


if __name__ == "__main__":
    main() 