"""
RBA风险评估引擎
基于贝叶斯模型计算用户行为风险分数
"""
import logging
import math
import time
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict


class RBACalculationError(Exception):
    """RBA计算异常"""
    pass


class RBAEngine:
    """RBA风险评估引擎"""
    
    def __init__(self, config: Dict):
        """
        初始化RBA引擎
        
        Args:
            config: 特征配置
        """
        self.config = config
        self.risk_config = config.get('risk_calculation', {})
        self.malicious_indicators = config.get('malicious_indicators', {})
        self.feature_weights = self._extract_feature_weights(config.get('features', {}))
        self.logger = logging.getLogger(__name__)
        
        # 贝叶斯参数
        self.bayesian_params = self.risk_config.get('bayesian_params', {})
        self.smoothing_factor = self.bayesian_params.get('smoothing_factor', 0.01)
        self.prior_malicious = self.bayesian_params.get('prior_malicious', 0.1)
        self.prior_benign = self.bayesian_params.get('prior_benign', 0.9)
        
        # 风险阈值
        self.thresholds = self.risk_config.get('thresholds', {})
        self.reject_threshold = self.thresholds.get('reject', 0.7)
        self.challenge_threshold = self.thresholds.get('challenge', 0.4)
        
        self.logger.info("RBA engine initialized successfully")
    
    def _extract_feature_weights(self, features_config: Dict) -> Dict[str, float]:
        """从配置中提取特征权重"""
        weights = {}
        for feature_name, feature_config in features_config.items():
            if isinstance(feature_config, dict):
                weights[feature_name] = feature_config.get('weight', 0.1)
        return weights
    
    def calculate_risk_score(self, user_id: str, features: Dict[str, Any], 
                           feature_weights: Dict[str, float], 
                           global_stats: Dict[str, Any],
                           user_history: List[Dict]) -> Dict[str, Any]:
        """
        计算用户风险分数
        
        Args:
            user_id: 用户ID
            features: 用户特征
            feature_weights: 特征权重
            global_stats: 全局统计信息
            user_history: 用户历史记录
            
        Returns:
            风险评估结果
        """
        try:
            # 计算各个维度的风险分数
            feature_risks = self._calculate_feature_risks(features, global_stats)
            behavioral_risk = self._calculate_behavioral_risk(user_id, features, user_history)
            anomaly_risk = self._calculate_anomaly_risk(features, user_history)
            threat_intel_risk = self._calculate_threat_intelligence_risk(features)
            
            # 加权合并风险分数
            combined_risk = self._combine_risk_scores(
                feature_risks, behavioral_risk, anomaly_risk, 
                threat_intel_risk, feature_weights
            )
            
            # 应用贝叶斯调整
            final_risk = self._apply_bayesian_adjustment(combined_risk, user_history)
            
            # 确定处理动作
            action = self._determine_action(final_risk)
            
            result = {
                'user_id': user_id,
                'risk_score': final_risk,
                'action': action,
                'risk_breakdown': {
                    'feature_risks': feature_risks,
                    'behavioral_risk': behavioral_risk,
                    'anomaly_risk': anomaly_risk,
                    'threat_intel_risk': threat_intel_risk,
                    'combined_risk': combined_risk
                },
                'calculation_timestamp': time.time()
            }
            
            self.logger.info(f"Risk calculated for user {user_id}: {final_risk:.3f} -> {action}")
            return result
            
        except Exception as e:
            self.logger.error(f"Risk calculation failed for user {user_id}: {e}")
            raise RBACalculationError(f"Risk calculation failed: {e}")
    
    def _calculate_feature_risks(self, features: Dict[str, Any], 
                               global_stats: Dict[str, Any]) -> Dict[str, float]:
        """计算特征风险分数"""
        feature_risks = {}
        
        for feature_name, feature_value in features.items():
            try:
                risk_score = self._calculate_single_feature_risk(
                    feature_name, feature_value, global_stats
                )
                feature_risks[feature_name] = risk_score
            except Exception as e:
                self.logger.warning(f"Failed to calculate risk for feature {feature_name}: {e}")
                feature_risks[feature_name] = 0.5  # 默认中等风险
        
        return feature_risks
    
    def _calculate_single_feature_risk(self, feature_name: str, feature_value: Any, 
                                     global_stats: Dict[str, Any]) -> float:
        """计算单个特征的风险分数"""
        if feature_name == 'ip':
            return self._calculate_ip_risk(feature_value)
        elif feature_name == 'user_agent':
            return self._calculate_user_agent_risk(feature_value)
        elif feature_name == 'rtt':
            return self._calculate_rtt_risk(feature_value)
        elif feature_name == 'geo_location':
            return self._calculate_geo_risk(feature_value)
        elif feature_name == 'device_fingerprint':
            return self._calculate_device_risk(feature_value)
        else:
            return self._calculate_generic_risk(feature_value, global_stats)
    
    def _calculate_ip_risk(self, ip_data: Any) -> float:
        """计算IP地址风险"""
        if isinstance(ip_data, dict):
            risk = 0.0
            
            # 私有IP风险较低
            if ip_data.get('is_private', False):
                risk += 0.1
            else:
                risk += 0.3
            
            # 回环地址风险低
            if ip_data.get('is_loopback', False):
                risk += 0.05
            
            # 组播地址风险中等
            if ip_data.get('is_multicast', False):
                risk += 0.4
            
            return min(risk, 1.0)
        else:
            # 简单IP字符串，基于模式判断
            ip_str = str(ip_data)
            if ip_str.startswith('127.') or ip_str.startswith('192.168.'):
                return 0.1
            elif ip_str.startswith('10.') or ip_str.startswith('172.'):
                return 0.2
            else:
                return 0.4
    
    def _calculate_user_agent_risk(self, ua_data: Any) -> float:
        """计算User-Agent风险"""
        if isinstance(ua_data, dict):
            risk = 0.0
            
            # 检查浏览器类型
            browser = ua_data.get('browser')
            if browser in ['Chrome', 'Firefox', 'Safari', 'Edge']:
                risk += 0.1
            elif browser:
                risk += 0.3
            else:
                risk += 0.5  # 未知浏览器
            
            # 检查是否为移动设备
            if ua_data.get('is_mobile', False):
                risk += 0.1
            
            # 检查User-Agent长度
            length = ua_data.get('length', 0)
            if length < 50 or length > 500:
                risk += 0.2
            
            return min(risk, 1.0)
        else:
            # 简单字符串分析
            ua_str = str(ua_data).lower()
            suspicious_patterns = self.malicious_indicators.get('suspicious_uas', [])
            
            for pattern in suspicious_patterns:
                if pattern.lower() in ua_str:
                    return 0.8
            
            return 0.2
    
    def _calculate_rtt_risk(self, rtt_data: Any) -> float:
        """计算RTT风险"""
        if isinstance(rtt_data, dict):
            rtt_value = rtt_data.get('value', 0)
            category = rtt_data.get('category', 'unknown')
            
            risk_mapping = {
                'excellent': 0.1,
                'good': 0.2,
                'fair': 0.3,
                'poor': 0.5,
                'very_poor': 0.7
            }
            
            return risk_mapping.get(category, 0.4)
        else:
            # 数值型RTT
            try:
                rtt_value = float(rtt_data)
                high_risk_rtt = self.malicious_indicators.get('high_risk_rtt', 1000)
                
                if rtt_value > high_risk_rtt:
                    return 0.8
                elif rtt_value > high_risk_rtt * 0.5:
                    return 0.5
                else:
                    return 0.2
            except (TypeError, ValueError):
                return 0.5
    
    def _calculate_geo_risk(self, geo_data: Any) -> float:
        """计算地理位置风险"""
        if isinstance(geo_data, dict):
            region = geo_data.get('region', 'Unknown')
            high_risk_countries = self.malicious_indicators.get('countries', [])
            
            if region in high_risk_countries:
                return 0.8
            elif region == 'Unknown':
                return 0.6
            else:
                return 0.2
        else:
            return 0.3
    
    def _calculate_device_risk(self, device_data: Any) -> float:
        """计算设备指纹风险"""
        if isinstance(device_data, dict):
            risk = 0.0
            
            # 检查屏幕分辨率
            if 'screen_area' in device_data:
                area = device_data['screen_area']
                if area < 300000 or area > 10000000:  # 异常分辨率
                    risk += 0.3
            
            # 检查长宽比
            if 'aspect_ratio' in device_data:
                ratio = device_data['aspect_ratio']
                if ratio < 0.5 or ratio > 3.0:  # 异常比例
                    risk += 0.2
            
            return min(risk, 1.0)
        else:
            return 0.3
    
    def _calculate_generic_risk(self, feature_value: Any, global_stats: Dict[str, Any]) -> float:
        """计算通用特征风险"""
        # 基于特征值的通用风险评估
        if feature_value is None:
            return 0.5
        
        # 检查特征值是否为空或异常
        if isinstance(feature_value, str) and len(feature_value.strip()) == 0:
            return 0.6
        
        return 0.3  # 默认低风险
    
    def _calculate_behavioral_risk(self, user_id: str, current_features: Dict[str, Any], 
                                 user_history: List[Dict]) -> float:
        """计算行为风险分数"""
        if not user_history:
            return 0.4  # 新用户中等风险
        
        try:
            # 分析特征变化模式
            feature_consistency = self._analyze_feature_consistency(current_features, user_history)
            temporal_pattern = self._analyze_temporal_pattern(user_history)
            frequency_pattern = self._analyze_frequency_pattern(user_history)
            
            # 合并行为风险
            behavioral_risk = (
                (1.0 - feature_consistency) * 0.5 +
                temporal_pattern * 0.3 +
                frequency_pattern * 0.2
            )
            
            return min(max(behavioral_risk, 0.0), 1.0)
            
        except Exception as e:
            self.logger.warning(f"Behavioral risk calculation failed: {e}")
            return 0.5
    
    def _analyze_feature_consistency(self, current_features: Dict[str, Any], 
                                   user_history: List[Dict]) -> float:
        """分析特征一致性"""
        if not user_history:
            return 0.5
        
        consistency_scores = []
        
        for feature_name, current_value in current_features.items():
            historical_values = []
            
            for record in user_history[-10:]:  # 最近10条记录
                if 'features' in record and feature_name in record['features']:
                    historical_values.append(record['features'][feature_name])
            
            if historical_values:
                consistency = self._calculate_feature_consistency(current_value, historical_values)
                consistency_scores.append(consistency)
        
        return sum(consistency_scores) / len(consistency_scores) if consistency_scores else 0.5
    
    def _calculate_feature_consistency(self, current_value: Any, historical_values: List[Any]) -> float:
        """计算单个特征的一致性"""
        if not historical_values:
            return 0.5
        
        # 简单的一致性检查
        matches = 0
        for hist_val in historical_values:
            if self._values_similar(current_value, hist_val):
                matches += 1
        
        return matches / len(historical_values)
    
    def _values_similar(self, val1: Any, val2: Any) -> bool:
        """判断两个值是否相似"""
        if val1 == val2:
            return True
        
        # 对于字典类型（如处理后的特征）
        if isinstance(val1, dict) and isinstance(val2, dict):
            # 比较关键字段
            key_fields = ['address', 'browser', 'os', 'region', 'value']
            for field in key_fields:
                if field in val1 and field in val2:
                    return val1[field] == val2[field]
        
        # 对于数值类型
        try:
            num1, num2 = float(val1), float(val2)
            return abs(num1 - num2) / max(abs(num1), abs(num2), 1) < 0.1
        except (TypeError, ValueError):
            pass
        
        return False
    
    def _analyze_temporal_pattern(self, user_history: List[Dict]) -> float:
        """分析时间模式风险"""
        if len(user_history) < 2:
            return 0.3
        
        try:
            # 计算访问间隔
            intervals = []
            for i in range(1, min(len(user_history), 10)):
                prev_time = user_history[i-1].get('created_at')
                curr_time = user_history[i].get('created_at')
                
                if prev_time and curr_time:
                    # 这里需要根据实际的时间格式来处理
                    interval = abs(time.time() - time.time())  # 简化处理
                    intervals.append(interval)
            
            if not intervals:
                return 0.3
            
            # 分析间隔的规律性
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            
            # 高方差表示不规律访问
            if variance > avg_interval * 2:
                return 0.6
            else:
                return 0.2
                
        except Exception:
            return 0.3
    
    def _analyze_frequency_pattern(self, user_history: List[Dict]) -> float:
        """分析访问频率风险"""
        if not user_history:
            return 0.3
        
        # 简单的频率分析
        recent_count = len([r for r in user_history if r.get('created_at')])
        
        if recent_count > 100:  # 频繁访问
            return 0.7
        elif recent_count > 50:
            return 0.4
        else:
            return 0.2
    
    def _calculate_anomaly_risk(self, features: Dict[str, Any], 
                              user_history: List[Dict]) -> float:
        """计算异常检测风险"""
        if not user_history:
            return 0.3
        
        try:
            anomaly_scores = []
            
            # 检测各种异常
            ip_anomaly = self._detect_ip_anomaly(features, user_history)
            ua_anomaly = self._detect_user_agent_anomaly(features, user_history)
            geo_anomaly = self._detect_geo_anomaly(features, user_history)
            
            anomaly_scores.extend([ip_anomaly, ua_anomaly, geo_anomaly])
            
            return sum(anomaly_scores) / len(anomaly_scores) if anomaly_scores else 0.3
            
        except Exception as e:
            self.logger.warning(f"Anomaly detection failed: {e}")
            return 0.5
    
    def _detect_ip_anomaly(self, features: Dict[str, Any], user_history: List[Dict]) -> float:
        """检测IP异常"""
        current_ip = features.get('ip')
        if not current_ip:
            return 0.5
        
        # 提取历史IP
        historical_ips = set()
        for record in user_history[-20:]:
            if 'features' in record and 'ip' in record['features']:
                ip_data = record['features']['ip']
                if isinstance(ip_data, dict):
                    historical_ips.add(ip_data.get('address'))
                else:
                    historical_ips.add(str(ip_data))
        
        # 检查当前IP是否在历史记录中
        current_ip_str = current_ip.get('address') if isinstance(current_ip, dict) else str(current_ip)
        
        if current_ip_str in historical_ips:
            return 0.1  # 已知IP，低风险
        else:
            return 0.7  # 新IP，高风险
    
    def _detect_user_agent_anomaly(self, features: Dict[str, Any], user_history: List[Dict]) -> float:
        """检测User-Agent异常"""
        current_ua = features.get('user_agent')
        if not current_ua:
            return 0.5
        
        # 提取历史User-Agent
        historical_browsers = set()
        for record in user_history[-10:]:
            if 'features' in record and 'user_agent' in record['features']:
                ua_data = record['features']['user_agent']
                if isinstance(ua_data, dict):
                    browser = ua_data.get('browser')
                    if browser:
                        historical_browsers.add(browser)
        
        # 检查浏览器一致性
        current_browser = current_ua.get('browser') if isinstance(current_ua, dict) else None
        
        if not historical_browsers:
            return 0.3  # 无历史记录
        elif current_browser in historical_browsers:
            return 0.1  # 已知浏览器
        else:
            return 0.6  # 新浏览器
    
    def _detect_geo_anomaly(self, features: Dict[str, Any], user_history: List[Dict]) -> float:
        """检测地理位置异常"""
        current_geo = features.get('geo_location')
        if not current_geo:
            return 0.3
        
        # 提取历史地理位置
        historical_regions = set()
        for record in user_history[-5:]:
            if 'features' in record and 'geo_location' in record['features']:
                geo_data = record['features']['geo_location']
                if isinstance(geo_data, dict):
                    region = geo_data.get('region')
                    if region:
                        historical_regions.add(region)
        
        # 检查地理位置一致性
        current_region = current_geo.get('region') if isinstance(current_geo, dict) else None
        
        if not historical_regions:
            return 0.3  # 无历史记录
        elif current_region in historical_regions:
            return 0.1  # 已知区域
        else:
            return 0.8  # 新区域，高风险
    
    def _calculate_threat_intelligence_risk(self, features: Dict[str, Any]) -> float:
        """计算威胁情报风险"""
        threat_risk = 0.0
        
        # 检查恶意指标
        ip_data = features.get('ip')
        if ip_data:
            ip_str = ip_data.get('address') if isinstance(ip_data, dict) else str(ip_data)
            # 这里可以集成外部威胁情报
            # 暂时使用简单的黑名单检查
            if self._is_suspicious_ip(ip_str):
                threat_risk += 0.8
        
        # 检查User-Agent
        ua_data = features.get('user_agent')
        if ua_data:
            if self._is_suspicious_user_agent(ua_data):
                threat_risk += 0.6
        
        return min(threat_risk, 1.0)
    
    def _is_suspicious_ip(self, ip_str: str) -> bool:
        """检查IP是否可疑"""
        # 简单的可疑IP检查
        suspicious_patterns = ['127.0.0.1', '0.0.0.0']
        return any(pattern in ip_str for pattern in suspicious_patterns)
    
    def _is_suspicious_user_agent(self, ua_data: Any) -> bool:
        """检查User-Agent是否可疑"""
        if isinstance(ua_data, dict):
            original = ua_data.get('original', '').lower()
        else:
            original = str(ua_data).lower()
        
        suspicious_patterns = self.malicious_indicators.get('suspicious_uas', [])
        return any(pattern.lower() in original for pattern in suspicious_patterns)
    
    def _combine_risk_scores(self, feature_risks: Dict[str, float], 
                           behavioral_risk: float, anomaly_risk: float,
                           threat_intel_risk: float, 
                           feature_weights: Dict[str, float]) -> float:
        """合并各维度风险分数"""
        # 计算加权特征风险
        weighted_feature_risk = 0.0
        total_weight = 0.0
        
        for feature_name, risk_score in feature_risks.items():
            weight = feature_weights.get(feature_name, 0.1)
            weighted_feature_risk += risk_score * weight
            total_weight += weight
        
        if total_weight > 0:
            weighted_feature_risk /= total_weight
        
        # 合并所有风险维度
        combined_risk = (
            weighted_feature_risk * 0.4 +
            behavioral_risk * 0.3 +
            anomaly_risk * 0.2 +
            threat_intel_risk * 0.1
        )
        
        return min(max(combined_risk, 0.0), 1.0)
    
    def _apply_bayesian_adjustment(self, combined_risk: float, user_history: List[Dict]) -> float:
        """应用贝叶斯调整"""
        if not user_history:
            return combined_risk
        
        try:
            # 计算历史风险分布
            historical_risks = [record.get('risk_score', 0.5) for record in user_history[-10:]]
            avg_historical_risk = sum(historical_risks) / len(historical_risks)
            
            # 贝叶斯更新
            likelihood_malicious = combined_risk
            likelihood_benign = 1.0 - combined_risk
            
            # 使用历史风险作为先验调整
            if avg_historical_risk < 0.3:
                # 历史低风险用户
                prior_adjustment = 0.8
            elif avg_historical_risk > 0.7:
                # 历史高风险用户
                prior_adjustment = 1.2
            else:
                prior_adjustment = 1.0
            
            # 贝叶斯公式简化版本
            posterior_malicious = (
                likelihood_malicious * self.prior_malicious * prior_adjustment
            )
            posterior_benign = (
                likelihood_benign * self.prior_benign
            )
            
            # 归一化
            total_posterior = posterior_malicious + posterior_benign
            if total_posterior > 0:
                final_risk = posterior_malicious / total_posterior
            else:
                final_risk = combined_risk
            
            # 应用平滑因子
            final_risk = (
                final_risk * (1 - self.smoothing_factor) + 
                combined_risk * self.smoothing_factor
            )
            
            return min(max(final_risk, 0.0), 1.0)
            
        except Exception as e:
            self.logger.warning(f"Bayesian adjustment failed: {e}")
            return combined_risk
    
    def _determine_action(self, risk_score: float) -> str:
        """根据风险分数确定处理动作"""
        if risk_score >= self.reject_threshold:
            return "REJECT"
        elif risk_score >= self.challenge_threshold:
            return "CHALLENGE"
        else:
            return "ALLOW"
    
    def get_feature_weights(self) -> Dict[str, float]:
        """获取特征权重"""
        return self.feature_weights.copy()
    
    def update_thresholds(self, new_thresholds: Dict[str, float]):
        """更新风险阈值"""
        if 'reject' in new_thresholds:
            self.reject_threshold = new_thresholds['reject']
        if 'challenge' in new_thresholds:
            self.challenge_threshold = new_thresholds['challenge']
        
        self.logger.info(f"Updated thresholds: reject={self.reject_threshold}, challenge={self.challenge_threshold}")

    def assess_risk(self, features: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        评估风险（向后兼容方法）
        
        Args:
            features: 特征数据
            context: 上下文信息
            
        Returns:
            风险评估结果
        """
        if context is None:
            context = {}
        
        # 提取用户ID和其他参数
        user_id = context.get('user_id', 'unknown')
        
        # 使用默认权重
        feature_weights = self.get_feature_weights()
        
        # 创建默认的全局统计信息
        global_stats = {'basic_statistics': {'total_records': 1000}}
        
        # 创建空的用户历史记录
        user_history = []
        
        try:
            # 调用完整的风险计算方法
            result = self.calculate_risk_score(
                user_id, features, feature_weights, global_stats, user_history
            )
            
            # 转换为简化的结果格式
            simplified_result = {
                'user_id': user_id,
                'risk_score': result['risk_score'],
                'risk_level': self._get_risk_level(result['risk_score']),
                'action': result['action'],
                'assessment_timestamp': result['calculation_timestamp'],
                'context': context
            }
            
            return simplified_result
            
        except Exception as e:
            self.logger.error(f"Risk assessment failed: {e}")
            return {
                'user_id': user_id,
                'risk_score': 0.5,
                'risk_level': 'MEDIUM',
                'action': 'CHALLENGE',
                'error': str(e),
                'assessment_timestamp': time.time(),
                'context': context
            }
    
    def _get_risk_level(self, risk_score: float) -> str:
        """根据风险分数获取风险等级"""
        if risk_score >= self.reject_threshold:
            return 'HIGH'
        elif risk_score >= self.challenge_threshold:
            return 'MEDIUM'
        else:
            return 'LOW'


# 全局RBA引擎实例
_rba_engine: Optional[RBAEngine] = None


def initialize_rba_engine(config: Dict) -> RBAEngine:
    """
    初始化RBA引擎
    
    Args:
        config: 特征配置
        
    Returns:
        RBA引擎实例
    """
    global _rba_engine
    _rba_engine = RBAEngine(config)
    return _rba_engine


def get_rba_engine() -> RBAEngine:
    """获取RBA引擎实例"""
    if _rba_engine is None:
        raise RBACalculationError("RBA engine not initialized. Call initialize_rba_engine() first.")
    return _rba_engine 