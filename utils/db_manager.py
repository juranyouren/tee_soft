"""
数据库管理模块
用于处理加密数据的存储和读取
"""
import os
import json
import hashlib
import pymysql
import logging
from typing import Dict, List, Optional, Any, Tuple
from contextlib import contextmanager
from pymysql.cursors import DictCursor


class DatabaseError(Exception):
    """数据库操作异常"""
    pass


class DatabaseManager:
    """数据库管理器"""
    
    def __init__(self, config: Dict):
        """
        初始化数据库管理器
        
        Args:
            config: 数据库配置
        """
        self.config = config
        self.db_config = config['mysql']
        self.pool_config = config.get('pool', {})
        self.connection_pool = []
        self.max_connections = self.pool_config.get('max_connections', 10)
        self.logger = logging.getLogger(__name__)
        
        # 从环境变量获取密码
        password_env = self.db_config.get('password_env', 'DB_PASSWORD')
        self.db_config['password'] = os.getenv(password_env, '')
        
        if not self.db_config['password']:
            raise DatabaseError(f"Database password not found in environment variable: {password_env}")
        
        # 初始化连接池
        self._initialize_pool()
    
    def _initialize_pool(self):
        """初始化连接池"""
        try:
            # 测试连接
            test_conn = self._create_connection()
            test_conn.close()
            self.logger.info("Database connection test successful")
            
        except Exception as e:
            raise DatabaseError(f"Failed to connect to database: {e}")
    
    def _create_connection(self):
        """创建数据库连接"""
        return pymysql.connect(
            host=self.db_config['host'],
            port=self.db_config['port'],
            database=self.db_config['database'],
            user=self.db_config['user'],
            password=self.db_config['password'],
            charset=self.db_config.get('charset', 'utf8mb4'),
            cursorclass=DictCursor,
            autocommit=False
        )
    
    @contextmanager
    def get_connection(self):
        """获取数据库连接（上下文管理器）"""
        connection = None
        try:
            connection = self._create_connection()
            yield connection
        except Exception as e:
            if connection:
                connection.rollback()
            raise DatabaseError(f"Database operation failed: {e}")
        finally:
            if connection:
                connection.close()
    
    def store_risk_log(self, user_id: str, encrypted_features: Dict, 
                      risk_score: float, action: str, 
                      metadata: Optional[Dict] = None) -> int:
        """
        存储风险评估日志
        
        Args:
            user_id: 用户ID
            encrypted_features: 加密后的特征数据
            risk_score: 风险分数
            action: 处理动作
            metadata: 元数据
            
        Returns:
            插入记录的ID
        """
        try:
            # 计算特征哈希用于去重和索引
            feature_hash = self._calculate_feature_hash(encrypted_features)
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # 插入风险日志
                sql = """
                INSERT INTO risk_logs 
                (user_id, features, risk_score, action, feature_hash, created_at) 
                VALUES (%s, %s, %s, %s, %s, NOW())
                """
                
                cursor.execute(sql, [
                    user_id,
                    json.dumps(encrypted_features),
                    risk_score,
                    action,
                    feature_hash
                ])
                
                record_id = cursor.lastrowid
                conn.commit()
                
                self.logger.info(f"Risk log stored for user {user_id}, record ID: {record_id}")
                return record_id
                
        except Exception as e:
            raise DatabaseError(f"Failed to store risk log: {e}")
    
    def get_user_history(self, user_id: str, limit: int = 100) -> List[Dict]:
        """
        获取用户历史记录
        
        Args:
            user_id: 用户ID
            limit: 记录数量限制
            
        Returns:
            用户历史记录列表
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                sql = """
                SELECT id, features, risk_score, action, created_at, feature_hash
                FROM risk_logs 
                WHERE user_id = %s 
                ORDER BY created_at DESC 
                LIMIT %s
                """
                
                cursor.execute(sql, [user_id, limit])
                records = cursor.fetchall()
                
                # 解析JSON特征数据
                for record in records:
                    if record['features']:
                        record['features'] = json.loads(record['features'])
                
                return records
                
        except Exception as e:
            raise DatabaseError(f"Failed to get user history: {e}")
    
    def get_feature_statistics(self, feature_name: str, days: int = 30) -> Dict:
        """
        获取特征统计信息
        
        Args:
            feature_name: 特征名称
            days: 统计天数
            
        Returns:
            特征统计信息
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # 获取特征值频次统计
                sql = """
                SELECT 
                    JSON_EXTRACT(features, %s) as feature_value,
                    COUNT(*) as count,
                    AVG(risk_score) as avg_risk_score
                FROM risk_logs 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
                    AND JSON_EXTRACT(features, %s) IS NOT NULL
                GROUP BY JSON_EXTRACT(features, %s)
                ORDER BY count DESC
                LIMIT 100
                """
                
                feature_path = f'$.{feature_name}'
                cursor.execute(sql, [feature_path, days, feature_path, feature_path])
                results = cursor.fetchall()
                
                # 计算总统计
                total_sql = """
                SELECT 
                    COUNT(*) as total_records,
                    COUNT(DISTINCT JSON_EXTRACT(features, %s)) as unique_values,
                    AVG(risk_score) as overall_avg_risk
                FROM risk_logs 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
                    AND JSON_EXTRACT(features, %s) IS NOT NULL
                """
                
                cursor.execute(total_sql, [feature_path, days, feature_path])
                totals = cursor.fetchone()
                
                return {
                    'feature_name': feature_name,
                    'statistics_period_days': days,
                    'total_records': totals['total_records'],
                    'unique_values': totals['unique_values'],
                    'overall_avg_risk': float(totals['overall_avg_risk'] or 0),
                    'value_frequencies': results
                }
                
        except Exception as e:
            raise DatabaseError(f"Failed to get feature statistics: {e}")
    
    def update_feature_history(self, feature_name: str, feature_value_hash: str):
        """
        更新特征历史记录
        
        Args:
            feature_name: 特征名称
            feature_value_hash: 特征值哈希
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # 使用 ON DUPLICATE KEY UPDATE 语法
                sql = """
                INSERT INTO feature_history (feature_name, feature_value_hash, occurrence_count) 
                VALUES (%s, %s, 1)
                ON DUPLICATE KEY UPDATE 
                    occurrence_count = occurrence_count + 1,
                    last_seen = CURRENT_TIMESTAMP
                """
                
                cursor.execute(sql, [feature_name, feature_value_hash])
                conn.commit()
                
        except Exception as e:
            raise DatabaseError(f"Failed to update feature history: {e}")
    
    def get_global_statistics(self) -> Dict:
        """
        获取全局统计信息
        
        Returns:
            全局统计信息
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # 基本统计
                basic_stats_sql = """
                SELECT 
                    COUNT(*) as total_records,
                    COUNT(DISTINCT user_id) as unique_users,
                    AVG(risk_score) as avg_risk_score,
                    MAX(created_at) as last_record_time,
                    MIN(created_at) as first_record_time
                FROM risk_logs
                """
                
                cursor.execute(basic_stats_sql)
                basic_stats = cursor.fetchone()
                
                # 风险分数分布
                risk_distribution_sql = """
                SELECT 
                    CASE 
                        WHEN risk_score < 0.3 THEN 'low'
                        WHEN risk_score < 0.7 THEN 'medium'
                        ELSE 'high'
                    END as risk_level,
                    COUNT(*) as count
                FROM risk_logs
                GROUP BY risk_level
                """
                
                cursor.execute(risk_distribution_sql)
                risk_distribution = cursor.fetchall()
                
                # 动作统计
                action_stats_sql = """
                SELECT action, COUNT(*) as count
                FROM risk_logs
                GROUP BY action
                """
                
                cursor.execute(action_stats_sql)
                action_stats = cursor.fetchall()
                
                return {
                    'basic_statistics': basic_stats,
                    'risk_distribution': risk_distribution,
                    'action_statistics': action_stats,
                    'generated_at': 'NOW()'
                }
                
        except Exception as e:
            raise DatabaseError(f"Failed to get global statistics: {e}")
    
    def cleanup_old_records(self, days: int = 90) -> int:
        """
        清理旧记录
        
        Args:
            days: 保留天数
            
        Returns:
            删除的记录数
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                sql = """
                DELETE FROM risk_logs 
                WHERE created_at < DATE_SUB(NOW(), INTERVAL %s DAY)
                """
                
                cursor.execute(sql, [days])
                deleted_count = cursor.rowcount
                conn.commit()
                
                self.logger.info(f"Cleaned up {deleted_count} old records older than {days} days")
                return deleted_count
                
        except Exception as e:
            raise DatabaseError(f"Failed to cleanup old records: {e}")
    
    def _calculate_feature_hash(self, features: Dict) -> str:
        """
        计算特征数据的哈希值
        
        Args:
            features: 特征数据
            
        Returns:
            SHA-256哈希值
        """
        # 对特征数据进行排序以确保一致的哈希
        sorted_features = json.dumps(features, sort_keys=True)
        return hashlib.sha256(sorted_features.encode()).hexdigest()
    
    def create_tables_if_not_exist(self):
        """创建数据表（如果不存在）"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # 创建 risk_logs 表
                risk_logs_sql = """
                CREATE TABLE IF NOT EXISTS risk_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL,
                    features JSON NOT NULL,
                    risk_score FLOAT,
                    action VARCHAR(50),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    feature_hash VARCHAR(64),
                    INDEX idx_user (user_id),
                    INDEX idx_created (created_at),
                    INDEX idx_feature_hash (feature_hash)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                """
                
                cursor.execute(risk_logs_sql)
                
                # 创建 feature_history 表
                feature_history_sql = """
                CREATE TABLE IF NOT EXISTS feature_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    feature_name VARCHAR(100) NOT NULL,
                    feature_value_hash VARCHAR(64) NOT NULL,
                    occurrence_count INT DEFAULT 1,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY unique_feature (feature_name, feature_value_hash),
                    INDEX idx_last_seen (last_seen)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                """
                
                cursor.execute(feature_history_sql)
                conn.commit()
                
                self.logger.info("Database tables created successfully")
                
        except Exception as e:
            raise DatabaseError(f"Failed to create tables: {e}")


# 全局数据库管理器实例
db_manager = None


def initialize_database(config: Dict) -> DatabaseManager:
    """
    初始化数据库管理器
    
    Args:
        config: 数据库配置
        
    Returns:
        数据库管理器实例
    """
    global db_manager
    db_manager = DatabaseManager(config['database'])
    
    # 创建表结构
    db_manager.create_tables_if_not_exist()
    
    return db_manager


def get_db_manager() -> DatabaseManager:
    """获取数据库管理器实例"""
    if db_manager is None:
        raise DatabaseError("Database manager not initialized")
    return db_manager 