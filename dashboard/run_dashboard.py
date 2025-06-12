#!/usr/bin/env python3
"""
Dashboard启动脚本
"""
import sys
import os

# 添加项目根目录到路径
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)

from dashboard.main import main

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 TEE软件监控仪表板启动中...")
    print("=" * 60)
    print("📊 功能特性:")
    print("  • 实时系统资源监控 (CPU、内存、磁盘、网络)")
    print("  • TEE API功能性测试")
    print("  • 系统告警和通知")
    print("  • 性能图表和统计")
    print("  • WebSocket实时数据推送")
    print("=" * 60)
    print("🔗 访问地址: http://127.0.0.1:8080")
    print("⚡ 使用 Ctrl+C 停止服务")
    print("=" * 60)
    
    exit_code = main()
    sys.exit(exit_code) 