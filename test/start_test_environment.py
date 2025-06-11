#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TEE软件测试环境一键启动脚本

本脚本用于快速启动TEE系统的完整测试环境：
1. 启动TEE服务器
2. 启动Dashboard监控系统
3. 打开浏览器Dashboard界面
4. 运行系统测试或持续监控演示

作者: TEE软件开发团队
版本: v1.0
"""

import os
import sys
import time
import subprocess
import threading
import webbrowser
import requests
from typing import Optional

# 添加项目根目录到路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_header(title: str):
    print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.BOLD}{title}{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")

def print_success(message: str):
    print(f"{Colors.OKGREEN}✅ {message}{Colors.ENDC}")

def print_warning(message: str):
    print(f"{Colors.WARNING}⚠️  {message}{Colors.ENDC}")

def print_error(message: str):
    print(f"{Colors.FAIL}❌ {message}{Colors.ENDC}")

def print_info(message: str):
    print(f"{Colors.OKCYAN}ℹ️  {message}{Colors.ENDC}")

class TEEEnvironmentManager:
    """TEE测试环境管理器"""
    
    def __init__(self):
        self.tee_server_process: Optional[subprocess.Popen] = None
        self.dashboard_process: Optional[subprocess.Popen] = None
        self.tee_server_url = "http://localhost:5000"
        self.dashboard_url = "http://localhost:5001"
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
    def check_port_available(self, port: int) -> bool:
        """检查端口是否可用"""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('localhost', port))
                return True
            except OSError:
                return False
    
    def wait_for_service(self, url: str, service_name: str, max_wait: int = 30) -> bool:
        """等待服务启动"""
        print_info(f"等待{service_name}启动...")
        
        for i in range(max_wait):
            try:
                response = requests.get(url, timeout=2)
                if response.status_code in [200, 404]:  # 404也表示服务在运行
                    print_success(f"{service_name}启动成功")
                    return True
            except requests.exceptions.RequestException:
                pass
            
            print(f"  等待中... ({i+1}/{max_wait})", end='\r')
            time.sleep(1)
        
        print_error(f"{service_name}启动失败或超时")
        return False
    
    def start_tee_server(self) -> bool:
        """启动TEE服务器"""
        print_info("启动TEE服务器...")
        
        # 检查端口
        if not self.check_port_available(5000):
            print_warning("端口5000已被占用，尝试连接现有服务...")
            if self.wait_for_service(f"{self.tee_server_url}/health", "TEE服务器", 5):
                return True
            else:
                print_error("无法连接到现有TEE服务器")
                return False
        
        try:
            # 启动TEE服务器
            self.tee_server_process = subprocess.Popen(
                [sys.executable, "main.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.project_root
            )
            
            # 等待服务启动
            return self.wait_for_service(f"{self.tee_server_url}/health", "TEE服务器")
            
        except Exception as e:
            print_error(f"TEE服务器启动失败: {e}")
            return False
    
    def start_dashboard(self) -> bool:
        """启动Dashboard"""
        print_info("启动Dashboard监控系统...")
        
        # 检查端口
        if not self.check_port_available(5001):
            print_warning("端口5001已被占用，尝试连接现有服务...")
            if self.wait_for_service(f"{self.dashboard_url}/api/overview", "Dashboard", 5):
                return True
            else:
                print_error("无法连接到现有Dashboard")
                return False
        
        try:
            # 启动Dashboard
            self.dashboard_process = subprocess.Popen(
                [sys.executable, "start_dashboard.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.project_root
            )
            
            # 等待服务启动
            return self.wait_for_service(f"{self.dashboard_url}/api/overview", "Dashboard")
            
        except Exception as e:
            print_error(f"Dashboard启动失败: {e}")
            return False
    
    def open_dashboard_browser(self):
        """打开Dashboard浏览器界面"""
        print_info("打开Dashboard浏览器界面...")
        try:
            webbrowser.open(self.dashboard_url)
            print_success("Dashboard界面已在浏览器中打开")
        except Exception as e:
            print_warning(f"无法自动打开浏览器: {e}")
            print_info(f"请手动打开: {self.dashboard_url}")
    
    def run_system_test(self):
        """运行系统测试"""
        print_info("运行系统功能测试...")
        try:
            test_script_path = os.path.join(os.path.dirname(__file__), "test_system.py")
            subprocess.run([sys.executable, test_script_path], check=True, cwd=self.project_root)
        except subprocess.CalledProcessError as e:
            print_error(f"系统测试失败: {e}")
        except FileNotFoundError:
            print_error("找不到test_system.py文件")
    
    def run_monitoring_demo(self, duration: int = 60):
        """运行监控演示"""
        print_info(f"运行{duration}秒监控演示...")
        try:
            test_script_path = os.path.join(os.path.dirname(__file__), "test_system.py")
            subprocess.run([sys.executable, test_script_path, "--demo"], check=True, cwd=self.project_root)
        except subprocess.CalledProcessError as e:
            print_error(f"监控演示失败: {e}")
        except FileNotFoundError:
            print_error("找不到test_system.py文件")
    
    def cleanup(self):
        """清理进程"""
        print_info("正在清理进程...")
        
        if self.tee_server_process:
            print_info("停止TEE服务器...")
            self.tee_server_process.terminate()
            self.tee_server_process.wait(timeout=5)
            
        if self.dashboard_process:
            print_info("停止Dashboard...")
            self.dashboard_process.terminate()
            self.dashboard_process.wait(timeout=5)
        
        print_success("环境清理完成")
    
    def start_complete_environment(self) -> bool:
        """启动完整测试环境"""
        print_header("🚀 启动TEE软件测试环境")
        
        # 1. 启动TEE服务器
        if not self.start_tee_server():
            return False
        
        # 2. 启动Dashboard
        if not self.start_dashboard():
            self.cleanup()
            return False
        
        # 3. 打开浏览器
        self.open_dashboard_browser()
        
        print_success("✨ 测试环境启动完成！")
        print()
        print_info("服务地址:")
        print(f"  📊 Dashboard: {self.dashboard_url}")
        print(f"  🖥️  TEE服务器: {self.tee_server_url}")
        print()
        
        return True


def show_menu():
    """显示主菜单"""
    print_header("🔧 TEE软件测试环境管理")
    print("请选择操作:")
    print("1. 🚀 启动完整测试环境")
    print("2. 🧪 启动环境 + 运行系统测试")
    print("3. 📊 启动环境 + 运行监控演示")
    print("4. ⚡ 仅运行快速健康检查")
    print("5. 📋 查看使用说明")
    print("0. 🚪 退出")
    print()


def show_instructions():
    """显示使用说明"""
    print_header("📋 使用说明")
    print()
    print("🎯 测试环境包含:")
    print("  • TEE服务器 (localhost:5000) - 核心加密和风险评估服务")
    print("  • Dashboard (localhost:5001) - 实时监控和可视化界面")
    print("  • 自动化测试工具 - 验证系统功能")
    print()
    print("🔧 手动启动命令:")
    print("  python main.py                     # 启动TEE服务器")
    print("  python start_dashboard.py          # 启动Dashboard")
    print("  python test/test_system.py         # 运行系统测试")
    print()
    print("📊 Dashboard功能:")
    print("  • 实时系统资源监控")
    print("  • 通讯流量可视化")
    print("  • 加密操作统计")
    print("  • 风险评估结果展示")
    print()
    print("🧪 测试功能:")
    print("  • 服务健康检查")
    print("  • 加密功能验证")
    print("  • 客户端交互模拟")
    print("  • 持续监控演示")
    print()


def main():
    """主函数"""
    print(f"{Colors.BOLD}🔐 TEE软件测试环境管理器{Colors.ENDC}")
    print("一键启动和测试TEE系统的完整功能")
    
    env_manager = TEEEnvironmentManager()
    
    try:
        while True:
            show_menu()
            
            try:
                choice = input("请输入选择 (0-5): ").strip()
            except KeyboardInterrupt:
                print("\n")
                break
            
            if choice == "0":
                break
            elif choice == "1":
                # 启动完整环境
                if env_manager.start_complete_environment():
                    print_info("按任意键继续...")
                    input()
            
            elif choice == "2":
                # 启动环境 + 系统测试
                if env_manager.start_complete_environment():
                    time.sleep(2)
                    env_manager.run_system_test()
            
            elif choice == "3":
                # 启动环境 + 监控演示
                if env_manager.start_complete_environment():
                    time.sleep(2)
                    duration = 60
                    try:
                        duration_input = input(f"演示时长(秒，默认{duration}): ").strip()
                        if duration_input:
                            duration = int(duration_input)
                    except ValueError:
                        pass
                    env_manager.run_monitoring_demo(duration)
            
            elif choice == "4":
                # 快速健康检查
                try:
                    test_script_path = os.path.join(os.path.dirname(__file__), "test_system.py")
                    subprocess.run([sys.executable, test_script_path, "--quick"], check=True, cwd=env_manager.project_root)
                except (subprocess.CalledProcessError, FileNotFoundError) as e:
                    print_error(f"快速检查失败: {e}")
            
            elif choice == "5":
                # 显示说明
                show_instructions()
                input("\n按任意键返回主菜单...")
            
            else:
                print_warning("无效选择，请重新输入")
                time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n")
    
    finally:
        # 清理资源
        env_manager.cleanup()
        print_success("👋 感谢使用TEE软件测试工具！")


if __name__ == "__main__":
    main() 