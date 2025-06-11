// TEE Dashboard JavaScript
class TEEDashboard {
    constructor() {
        this.socket = null;
        this.systemChart = null;
        this.chartData = {
            cpu: [],
            memory: [],
            disk: [],
            timestamps: []
        };
        this.maxDataPoints = 20;
        this.activeSessions = new Set();
        
        this.initializeSocket();
        this.initializeChart();
        this.updateCurrentTime();
        this.startPeriodicUpdates();
        
        console.log('TEE Dashboard initialized');
    }
    
    initializeSocket() {
        try {
            this.socket = io('/dashboard');
            
            this.socket.on('connect', () => {
                console.log('Connected to dashboard server');
                this.updateConnectionStatus(true);
            });
            
            this.socket.on('disconnect', () => {
                console.log('Disconnected from dashboard server');
                this.updateConnectionStatus(false);
            });
            
            this.socket.on('initial_data', (data) => {
                console.log('Received initial data:', data);
                this.handleInitialData(data);
            });
            
            this.socket.on('system_update', (data) => {
                this.handleSystemUpdate(data);
            });
            
            this.socket.on('communication_update', (data) => {
                this.handleCommunicationUpdate(data);
            });
            
            this.socket.on('encryption_update', (data) => {
                this.handleEncryptionUpdate(data);
            });
            
        } catch (error) {
            console.error('Socket initialization failed:', error);
            this.updateConnectionStatus(false);
        }
    }
    
    updateConnectionStatus(connected) {
        const statusElement = document.getElementById('connectionStatus');
        if (connected) {
            statusElement.className = 'status-indicator connected';
            statusElement.innerHTML = '<i class="fas fa-circle"></i><span>已连接</span>';
        } else {
            statusElement.className = 'status-indicator disconnected';
            statusElement.innerHTML = '<i class="fas fa-circle"></i><span>连接断开</span>';
        }
    }
    
    initializeChart() {
        const ctx = document.getElementById('systemChart').getContext('2d');
        
        this.systemChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'CPU使用率 (%)',
                        data: [],
                        borderColor: '#e74c3c',
                        backgroundColor: 'rgba(231, 76, 60, 0.1)',
                        tension: 0.3,
                        hidden: false
                    },
                    {
                        label: '内存使用率 (%)',
                        data: [],
                        borderColor: '#3498db',
                        backgroundColor: 'rgba(52, 152, 219, 0.1)',
                        tension: 0.3,
                        hidden: false
                    },
                    {
                        label: '磁盘使用率 (%)',
                        data: [],
                        borderColor: '#f39c12',
                        backgroundColor: 'rgba(243, 156, 18, 0.1)',
                        tension: 0.3,
                        hidden: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    title: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        ticks: {
                            callback: function(value) {
                                return value + '%';
                            }
                        }
                    },
                    x: {
                        display: true,
                        ticks: {
                            maxTicksLimit: 8
                        }
                    }
                },
                elements: {
                    point: {
                        radius: 3
                    }
                }
            }
        });
    }
    
    handleInitialData(data) {
        // 处理系统指标
        if (data.system_metrics && data.system_metrics.length > 0) {
            data.system_metrics.forEach(metric => {
                this.addDataPoint(metric);
            });
        }
        
        // 处理通讯日志
        if (data.communications) {
            data.communications.forEach(comm => {
                this.addCommunicationLog(comm);
            });
        }
        
        // 处理加密事件
        if (data.encryption_events) {
            data.encryption_events.forEach(event => {
                this.addEncryptionLog(event);
            });
        }
        
        this.updateOverviewCards();
    }
    
    handleSystemUpdate(data) {
        console.log('System update:', data);
        this.addDataPoint(data);
        this.updateSystemMetrics(data);
    }
    
    handleCommunicationUpdate(data) {
        console.log('Communication update:', data);
        this.addCommunicationLog(data);
        this.updateCommunicationStats();
    }
    
    handleEncryptionUpdate(data) {
        console.log('Encryption update:', data);
        this.addEncryptionLog(data);
        this.updateEncryptionStats();
    }
    
    addDataPoint(data) {
        const time = new Date(data.timestamp).toLocaleTimeString();
        
        // 添加新数据点
        this.chartData.timestamps.push(time);
        this.chartData.cpu.push(data.cpu_percent || 0);
        this.chartData.memory.push(data.memory_percent || 0);
        this.chartData.disk.push(data.disk_percent || 0);
        
        // 限制数据点数量
        if (this.chartData.timestamps.length > this.maxDataPoints) {
            this.chartData.timestamps.shift();
            this.chartData.cpu.shift();
            this.chartData.memory.shift();
            this.chartData.disk.shift();
        }
        
        // 更新图表
        this.systemChart.data.labels = this.chartData.timestamps;
        this.systemChart.data.datasets[0].data = this.chartData.cpu;
        this.systemChart.data.datasets[1].data = this.chartData.memory;
        this.systemChart.data.datasets[2].data = this.chartData.disk;
        this.systemChart.update('none');
    }
    
    updateSystemMetrics(data) {
        document.getElementById('cpuUsage').textContent = (data.cpu_percent || 0).toFixed(1) + '%';
        document.getElementById('memoryUsage').textContent = (data.memory_percent || 0).toFixed(1) + '%';
        document.getElementById('diskUsage').textContent = (data.disk_percent || 0).toFixed(1) + '%';
        
        // 更新TEE状态
        if (data.tee_status) {
            const statusElement = document.getElementById('teeStatus');
            if (data.tee_status.error) {
                statusElement.textContent = '不可用';
                statusElement.className = 'metric-value status unhealthy';
            } else {
                statusElement.textContent = '正常';
                statusElement.className = 'metric-value status healthy';
                
                // 更新成功率
                const successRate = data.tee_status.success_rate || 0;
                document.getElementById('successRate').textContent = (successRate * 100).toFixed(1) + '%';
            }
        }
    }
    
    addCommunicationLog(data) {
        const logsContainer = document.getElementById('communicationLogs');
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${data.direction}`;
        
        const timestamp = new Date(data.timestamp).toLocaleString();
        const dataPreview = this.truncateData(JSON.stringify(data.data, null, 2), 200);
        
        logEntry.innerHTML = `
            <span class="timestamp">[${timestamp}] ${data.type} (${data.direction}) - ${data.size} bytes</span>
            <div class="data">${dataPreview}</div>
        `;
        
        logsContainer.insertBefore(logEntry, logsContainer.firstChild);
        
        // 限制日志条目数量
        while (logsContainer.children.length > 50) {
            logsContainer.removeChild(logsContainer.lastChild);
        }
    }
    
    addEncryptionLog(data) {
        const logsContainer = document.getElementById('encryptionLogs');
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        
        const timestamp = new Date(data.timestamp).toLocaleString();
        const detailsStr = JSON.stringify(data.details, null, 2);
        
        logEntry.innerHTML = `
            <span class="timestamp">[${timestamp}] ${data.type}</span>
            <div class="data">${this.truncateData(detailsStr, 300)}</div>
        `;
        
        logsContainer.insertBefore(logEntry, logsContainer.firstChild);
        
        // 限制日志条目数量
        while (logsContainer.children.length > 50) {
            logsContainer.removeChild(logsContainer.lastChild);
        }
    }
    
    truncateData(data, maxLength) {
        if (data.length <= maxLength) return data;
        return data.substring(0, maxLength) + '...';
    }
    
    updateCurrentTime() {
        const timeElement = document.getElementById('currentTime');
        setInterval(() => {
            timeElement.textContent = new Date().toLocaleString();
        }, 1000);
    }
    
    startPeriodicUpdates() {
        // 定期获取概览数据
        setInterval(() => {
            this.fetchOverviewData();
        }, 10000); // 每10秒更新一次
        
        // 立即获取一次
        this.fetchOverviewData();
    }
    
    async fetchOverviewData() {
        try {
            const response = await fetch('/api/overview');
            const data = await response.json();
            this.updateOverviewCards(data);
        } catch (error) {
            console.error('Failed to fetch overview data:', error);
        }
    }
    
    updateOverviewCards(data = {}) {
        const stats = data.communication_stats || {};
        const encStats = data.encryption_stats || {};
        
        document.getElementById('totalRequests').textContent = stats.total || 0;
        document.getElementById('inboundRequests').textContent = stats.inbound || 0;
        document.getElementById('outboundRequests').textContent = stats.outbound || 0;
        document.getElementById('encryptionEvents').textContent = encStats.total || 0;
        document.getElementById('recentEncryptions').textContent = encStats.last_hour || 0;
        document.getElementById('activeSessions').textContent = data.active_sessions || 0;
    }
    
    updateCommunicationStats() {
        // 通过API更新通讯统计
        this.fetchOverviewData();
    }
    
    updateEncryptionStats() {
        // 通过API更新加密统计
        this.fetchOverviewData();
    }
}

// 全局函数
window.toggleChart = function(type) {
    const dashboard = window.teeDashboard;
    if (!dashboard || !dashboard.systemChart) return;
    
    const datasets = dashboard.systemChart.data.datasets;
    let datasetIndex = -1;
    
    switch (type) {
        case 'cpu': datasetIndex = 0; break;
        case 'memory': datasetIndex = 1; break;
        case 'disk': datasetIndex = 2; break;
    }
    
    if (datasetIndex >= 0) {
        const dataset = datasets[datasetIndex];
        dataset.hidden = !dataset.hidden;
        dashboard.systemChart.update();
        
        // 更新按钮状态
        const buttons = document.querySelectorAll('.chart-controls .btn-small');
        buttons[datasetIndex].classList.toggle('active', !dataset.hidden);
    }
};

window.clearCommunicationLogs = function() {
    const logsContainer = document.getElementById('communicationLogs');
    logsContainer.innerHTML = '<div class="log-entry"><span class="timestamp">通讯日志已清空</span></div>';
};

window.clearEncryptionLogs = function() {
    const logsContainer = document.getElementById('encryptionLogs');
    logsContainer.innerHTML = '<div class="log-entry"><span class="timestamp">加密日志已清空</span></div>';
};

window.testCommunication = function() {
    const testData = {
        user_id: 'test_communication_user',
        features: {
            ip: '192.168.1.100',
            user_agent: 'Test Communication Client',
            rtt: 35.0
        }
    };
    
    window.teeDashboard.socket.emit('request_test', testData);
};

window.testEncryption = async function() {
    try {
        const response = await fetch('/api/test_encryption');
        const result = await response.json();
        
        if (result.success) {
            console.log('Encryption test successful:', result);
        } else {
            console.error('Encryption test failed:', result);
        }
    } catch (error) {
        console.error('Encryption test error:', error);
    }
};

window.showEncryptionDemo = async function() {
    const steps = ['step1', 'step2', 'step3'];
    const plaintextElement = document.getElementById('plaintextData');
    const ciphertextElement = document.getElementById('ciphertextData');
    const protectedKeyElement = document.getElementById('protectedKey');
    
    // 重置所有步骤
    steps.forEach(stepId => {
        document.getElementById(stepId).classList.remove('active');
    });
    
    // 演示数据
    const testData = {
        user_id: 'demo_user',
        features: {
            ip: '192.168.1.100',
            user_agent: 'Demo Client',
            rtt: 42.5,
            geo_location: '40.7128,-74.0060'
        }
    };
    
    // 步骤1：显示明文
    document.getElementById('step1').classList.add('active');
    plaintextElement.textContent = JSON.stringify(testData, null, 2);
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // 步骤2：显示密文
    document.getElementById('step2').classList.add('active');
    const mockCiphertext = 'SM4加密后的数据:\n' + btoa(JSON.stringify(testData)).replace(/(.{50})/g, '$1\n');
    ciphertextElement.textContent = mockCiphertext;
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // 步骤3：显示受保护的密钥
    document.getElementById('step3').classList.add('active');
    const mockProtectedKey = 'SM2保护的会话密钥:\n04' + 
        Array.from({length: 32}, () => Math.floor(Math.random() * 16).toString(16)).join('').toUpperCase();
    protectedKeyElement.textContent = mockProtectedKey;
    
    // 5秒后重置
    setTimeout(() => {
        steps.forEach(stepId => {
            document.getElementById(stepId).classList.remove('active');
        });
        plaintextElement.textContent = '等待演示...';
        ciphertextElement.textContent = '等待演示...';
        protectedKeyElement.textContent = '等待演示...';
    }, 5000);
};

window.sendTestRequest = async function() {
    const userIdInput = document.getElementById('testUserId');
    const featuresInput = document.getElementById('testFeatures');
    const resultsContainer = document.getElementById('testResults');
    
    try {
        const features = JSON.parse(featuresInput.value);
        const requestData = {
            user_id: userIdInput.value,
            features: features
        };
        
        resultsContainer.innerHTML = '<div class="loading"></div> 发送请求中...';
        
        const response = await fetch('/api/simulate_request', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
        });
        
        const result = await response.json();
        
        if (result.success) {
            resultsContainer.innerHTML = `
                <div style="color: green; margin-bottom: 1rem;">✅ 测试请求成功</div>
                <div><strong>状态码:</strong> ${result.status_code}</div>
                <div><strong>响应时间:</strong> ${new Date().toLocaleString()}</div>
                <div><strong>响应数据:</strong></div>
                <pre>${JSON.stringify(result.response, null, 2)}</pre>
            `;
        } else {
            resultsContainer.innerHTML = `
                <div style="color: red;">❌ 测试请求失败</div>
                <div>错误: ${result.error}</div>
            `;
        }
    } catch (error) {
        resultsContainer.innerHTML = `
            <div style="color: red;">❌ 测试请求出错</div>
            <div>错误: ${error.message}</div>
        `;
    }
};

window.clearTestResults = function() {
    document.getElementById('testResults').innerHTML = '';
};

// 初始化Dashboard
document.addEventListener('DOMContentLoaded', function() {
    window.teeDashboard = new TEEDashboard();
}); 