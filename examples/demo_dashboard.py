#!/usr/bin/env python3
"""
TEE Dashboard 演示脚本
展示Dashboard的监控功能和使用方法
"""
import os
import sys
import time
import logging
import threading
import requests
import json
from datetime import datetime

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def demo_info():
    """显示演示信息"""
    print("\n" + "="*60)
    print("🚀 TEE软件监控Dashboard演示")
    print("="*60)
    print("\n📋 演示内容:")
    print("1. 系统资源监控 - 实时CPU、内存、磁盘使用率")
    print("2. 通讯抽象展示 - 客户端与TEE服务器交互")
    print("3. 加密过程可视化 - 明文→密文→保护密钥")
    print("4. 性能监控 - 请求处理时间和成功率")
    print("\n🔧 需要准备:")
    print("✅ TEE服务器运行在 http://localhost:5000")
    print("✅ Dashboard运行在 http://localhost:5001") 
    print("✅ 浏览器打开Dashboard界面")
    print("\n⏰ 演示时长: 约5分钟")
    print("="*60)

def check_services():
    """检查服务状态"""
    logger.info("🔍 检查服务状态...")
    
    # 检查TEE服务器
    try:
        response = requests.get("http://localhost:5000/health", timeout=5)
        if response.status_code == 200:
            logger.info("✅ TEE服务器运行正常")
        else:
            logger.warning(f"⚠️ TEE服务器响应异常: {response.status_code}")
    except requests.exceptions.RequestException:
        logger.error("❌ TEE服务器未启动，请先运行: python main.py")
        return False
    
    # 检查Dashboard
    try:
        response = requests.get("http://localhost:5001/api/overview", timeout=5)
        if response.status_code == 200:
            logger.info("✅ Dashboard服务运行正常")
        else:
            logger.warning(f"⚠️ Dashboard响应异常: {response.status_code}")
    except requests.exceptions.RequestException:
        logger.error("❌ Dashboard未启动，请先运行: python start_dashboard.py")
        return False
    
    return True

def send_test_requests():
    """发送测试请求演示通讯抽象"""
    logger.info("\n📡 开始通讯抽象演示...")
    
    # 测试数据集
    test_cases = [
        {
            "name": "用户登录请求",
            "data": {
                "user_id": "demo_user_001",
                "features": {
                    "ip": "192.168.1.100",
                    "user_agent": "Chrome/91.0.4472.124",
                    "rtt": 35.2,
                    "geo_location": "40.7128,-74.0060"
                }
            }
        },
        {
            "name": "高风险IP请求",
            "data": {
                "user_id": "demo_user_002", 
                "features": {
                    "ip": "203.0.113.100",  # 可疑IP
                    "user_agent": "Bot/1.0",
                    "rtt": 150.5,
                    "geo_location": "0.0,0.0"
                }
            }
        },
        {
            "name": "移动端请求",
            "data": {
                "user_id": "demo_user_003",
                "features": {
                    "ip": "192.168.1.101",
                    "user_agent": "Mobile Safari/14.0",
                    "rtt": 25.8,
                    "geo_location": "37.7749,-122.4194"
                }
            }
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        logger.info(f"📤 发送测试请求 {i}/3: {test_case['name']}")
        
        try:
            # 通过Dashboard API发送请求
            response = requests.post(
                "http://localhost:5001/api/simulate_request",
                json=test_case['data'],
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"✅ 请求成功 - 状态码: {result.get('status_code', 'N/A')}")
                
                # 显示部分响应数据
                if 'response' in result and 'result' in result['response']:
                    risk_score = result['response']['result'].get('risk_assessment', {}).get('risk_score', 'N/A')
                    action = result['response']['result'].get('risk_assessment', {}).get('action', 'N/A')
                    logger.info(f"   风险分数: {risk_score}, 建议动作: {action}")
            else:
                logger.warning(f"⚠️ 请求失败 - 状态码: {response.status_code}")
                
        except Exception as e:
            logger.error(f"❌ 请求出错: {e}")
        
        # 等待2秒再发送下一个请求
        if i < len(test_cases):
            time.sleep(2)

def demo_encryption_process():
    """演示加密过程"""
    logger.info("\n🔐 开始加密过程演示...")
    
    # 触发加密测试
    try:
        response = requests.get("http://localhost:5001/api/test_encryption", timeout=10)
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                logger.info("✅ 加密测试成功")
                logger.info("   明文 → SM4加密 → SM2保护 完整流程验证通过")
            else:
                logger.warning(f"⚠️ 加密测试失败: {result.get('error')}")
        else:
            logger.warning(f"⚠️ 加密测试请求失败: {response.status_code}")
    except Exception as e:
        logger.error(f"❌ 加密测试出错: {e}")

def monitor_system_resources():
    """监控系统资源"""
    logger.info("\n📊 系统资源监控演示...")
    
    try:
        response = requests.get("http://localhost:5001/api/overview", timeout=5)
        if response.status_code == 200:
            data = response.json()
            metrics = data.get('system_metrics', {})
            
            logger.info("💻 当前系统状态:")
            logger.info(f"   CPU使用率: {metrics.get('cpu_percent', 'N/A'):.1f}%")
            logger.info(f"   内存使用率: {metrics.get('memory_percent', 'N/A'):.1f}%")
            logger.info(f"   内存使用量: {metrics.get('memory_used_mb', 'N/A'):.1f} MB")
            logger.info(f"   磁盘使用率: {metrics.get('disk_percent', 'N/A'):.1f}%")
            
            # 通讯统计
            comm_stats = data.get('communication_stats', {})
            logger.info("\n📡 通讯统计:")
            logger.info(f"   总请求数: {comm_stats.get('total', 0)}")
            logger.info(f"   入站请求: {comm_stats.get('inbound', 0)}")
            logger.info(f"   出站请求: {comm_stats.get('outbound', 0)}")
            logger.info(f"   近1小时: {comm_stats.get('last_hour', 0)}")
            
            # 加密统计
            enc_stats = data.get('encryption_stats', {})
            logger.info("\n🔐 加密统计:")
            logger.info(f"   加密事件数: {enc_stats.get('total', 0)}")
            logger.info(f"   近1小时: {enc_stats.get('last_hour', 0)}")
            logger.info(f"   活跃会话: {data.get('active_sessions', 0)}")
            
        else:
            logger.warning(f"⚠️ 获取概览数据失败: {response.status_code}")
    except Exception as e:
        logger.error(f"❌ 系统监控出错: {e}")

def continuous_monitoring():
    """持续监控演示"""
    logger.info("\n🔄 开始持续监控演示 (30秒)...")
    
    start_time = time.time()
    request_count = 0
    
    while time.time() - start_time < 30:  # 运行30秒
        # 发送随机测试请求
        test_data = {
            "user_id": f"monitor_user_{request_count:03d}",
            "features": {
                "ip": f"192.168.1.{100 + (request_count % 50)}",
                "user_agent": f"Monitor Client {request_count}",
                "rtt": 20 + (request_count % 50),
                "geo_location": f"{40 + (request_count % 10)}.{-74 + (request_count % 10)}"
            }
        }
        
        try:
            requests.post(
                "http://localhost:5001/api/simulate_request",
                json=test_data,
                timeout=5
            )
            request_count += 1
            
            if request_count % 5 == 0:
                logger.info(f"📊 已发送 {request_count} 个监控请求")
                
        except Exception as e:
            logger.warning(f"监控请求失败: {e}")
        
        time.sleep(3)  # 每3秒发送一个请求
    
    logger.info(f"✅ 持续监控完成，总共发送 {request_count} 个请求")

def main():
    """主演示函数"""
    demo_info()
    
    input("\n🎯 按Enter键开始演示...")
    
    # 检查服务状态
    if not check_services():
        print("\n❌ 服务检查失败，请确保TEE服务器和Dashboard都在运行")
        print("启动命令:")
        print("  TEE服务器: python main.py")
        print("  Dashboard: python start_dashboard.py")
        sys.exit(1)
    
    logger.info("\n🚀 开始Dashboard演示...")
    
    # 1. 系统资源监控
    monitor_system_resources()
    time.sleep(2)
    
    # 2. 发送测试请求演示通讯抽象
    send_test_requests()
    time.sleep(2)
    
    # 3. 加密过程演示
    demo_encryption_process()
    time.sleep(2)
    
    # 4. 持续监控演示
    if input("\n🔄 是否进行持续监控演示？(y/N): ").lower() == 'y':
        continuous_monitoring()
    
    # 最终状态检查
    logger.info("\n📋 演示结束 - 最终状态:")
    monitor_system_resources()
    
    print("\n" + "="*60)
    print("✅ Dashboard演示完成！")
    print("\n💡 下一步操作:")
    print("1. 在浏览器中查看 http://localhost:5001")
    print("2. 观察实时数据更新")
    print("3. 尝试使用测试控制面板")
    print("4. 查看加密过程可视化")
    print("5. 监控系统资源图表")
    print("="*60)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\n👋 演示被用户中断")
    except Exception as e:
        logger.error(f"\n❌ 演示出错: {e}")
        sys.exit(1) 