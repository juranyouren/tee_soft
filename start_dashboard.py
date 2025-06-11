#!/usr/bin/env python3
"""
TEE Dashboard 启动脚本
快速启动TEE软件监控Dashboard
"""
import os
import sys
import subprocess
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_dependencies():
    """检查依赖是否安装"""
    try:
        import flask_socketio
        import psutil
        import requests
        logger.info("✅ 所有依赖已安装")
        return True
    except ImportError as e:
        logger.error(f"❌ 缺少依赖: {e}")
        logger.info("请运行: pip install flask-socketio psutil requests")
        return False

def setup_environment():
    """设置环境变量"""
    env_vars = {
        'TEE_MASTER_KEY': "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd",
        'DB_PASSWORD': "demo_password",
        'DB_MASTER_KEY': "1234567890abcdef1234567890abcdef"
    }
    
    for key, default_value in env_vars.items():
        if not os.getenv(key):
            os.environ[key] = default_value
            logger.info(f"✅ 设置环境变量 {key}")

def start_dashboard():
    """启动Dashboard"""
    try:
        logger.info("🚀 启动TEE软件监控Dashboard...")
        logger.info("📊 Dashboard将在 http://localhost:5001 启动")
        logger.info("🔧 TEE服务器应在 http://localhost:5000 运行")
        logger.info("=" * 50)
        
        # 导入并启动dashboard
        from dashboard import app, socketio
        socketio.run(app, host='0.0.0.0', port=5001, debug=False)
        
    except Exception as e:
        logger.error(f"❌ Dashboard启动失败: {e}")
        return False

def main():
    """主函数"""
    logger.info("🔧 TEE软件监控Dashboard启动器")
    logger.info("=" * 50)
    
    # 检查依赖
    if not check_dependencies():
        sys.exit(1)
    
    # 设置环境
    setup_environment()
    
    # 显示说明
    print("\n📋 使用说明:")
    print("1. 确保TEE服务器在端口5000运行: python main.py")
    print("2. Dashboard将在端口5001启动")
    print("3. 在浏览器中访问 http://localhost:5001")
    print("4. 使用Dashboard监控TEE软件状态")
    print("5. 按 Ctrl+C 停止Dashboard")
    print("=" * 50)
    
    try:
        start_dashboard()
    except KeyboardInterrupt:
        logger.info("\n👋 Dashboard已停止")
    except Exception as e:
        logger.error(f"❌ 启动失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 