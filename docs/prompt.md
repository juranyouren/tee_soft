## 要求

- 编写一个程序名为tee_soft
- tee_soft接收到一个查询（该查询是哈希值）时，进行以下流程。

- tee_soft与外部加密数据库连接，读取加密数据后在程序里解密。
- tee_soft根据解密出来的频次计算rba分数，并返回rba分数。



## 总览

我们将安全飞地视为一个名为 `tee_soft` 的黑盒子，详细拆解其输入、输出、内部处理、存储的密钥以及使用的加密算法。

### `tee_soft` 黑盒子详解

1.  根据数据库结构和提供的RBA分数计算代码，我将设计一个专门处理`(ip, user_agent, rtt)`三元组的弱化安全飞地黑盒子`weak_tee`。以下是完整方案：
    
    ### 黑盒子 `weak_tee` 设计
    
    #### 1. **输入 (Input)**
    - **固定格式的三元组**：`(ip_address, user_agent, rtt)`
      - `ip_address`：IPv4/IPv6地址（如 "192.168.1.1"）
      - `user_agent`：浏览器代理字符串（如 "Mozilla/5.0..."）
      - `rtt`：往返时间（单位毫秒，如 12.3）
    
    **但是是经过哈希后的**
    
    #### 2. **输出 (Output)**
    - **风险分数**：浮点数（如 0.75）
    - **存储确认**：布尔值（true 表示成功存储）
    
    #### 3. **内部处理流程 (Processing Flow)**
    ```mermaid
    graph TD
        A[输入三元组] --> B[数据解析验证]
        B --> C[查询历史频次]
        C --> D[计算风险分数]
        D --> E[加密存储记录]
        E --> F[输出结果]
        
        subgraph tee_soft
            B --> B1[验证IP格式]
            B --> B2[提取UA特征]
            B --> B3[验证RTT范围]
            
            C --> C1[查询IP频次]
            C --> C2[查询UA频次]
            C --> C3[查询RTT分布]
            
            D --> D1[计算特征概率]
            D --> D2[应用贝叶斯公式]
            D --> D3[恶意IP检查]
            
            E --> E1[加密特征数据]
            E --> E2[更新频率缓存]
            E --> E3[写入审计日志]
        end
        
        C1 --> DB[risk_logs表]
        C2 --> DB
        C3 --> DB
    ```
    
    #### 4. **核心处理逻辑**
    
    1. **数据解析与特征提取**：
       ```python
       def parse_input(ip, ua, rtt):
           # 验证并标准化输入
           ip = validate_ip(ip)
           browser, version, os = parse_user_agent(ua)  # 提取UA特征
           rtt = float(rtt)  # 确保数值类型
           return {
               'ip': ip,
               'ua': ua,
               'browser': browser,
               'version': version,
               'os': os,
               'rtt': rtt
           }
       ```
    
    2. **历史频次查询**：
       ```python
       def query_frequencies(features):
           # 查询相同IP的出现次数
           ip_freq = query_db("""
               SELECT COUNT(*) 
               FROM risk_logs 
               WHERE ip_address = %s
           """, [features['ip']])
           
           # 查询相似UA的出现次数
           ua_freq = query_db("""
               SELECT COUNT(*) 
               FROM risk_logs 
               WHERE user_agent LIKE %s
           """, [f"%{features['browser']}%"])
           
           # 查询RTT分布
           rtt_freq = query_db("""
               SELECT COUNT(*) 
               FROM risk_logs 
               WHERE rtt BETWEEN %s AND %s
           """, [features['rtt'] - 0.5, features['rtt'] + 0.5])
           
           return ip_freq, ua_freq, rtt_freq
       ```
    
    3. **风险分数计算**（基于贝叶斯概率模型）：
       ```python
       def calculate_risk(user_id, features, freqs):
           total_records = get_total_records()  # 获取总记录数
           
           # 特征概率计算
           p_ip = freqs[0] / total_records
           p_ua = freqs[1] / total_records
           p_rtt = freqs[2] / total_records
           
           # 用户特定概率
           user_records = get_user_records(user_id)
           p_user = user_records / total_records if user_records > 0 else 0.01
           
           # 恶意IP检查
           malicious_factor = 1.0
           if is_malicious_ip(features['ip']):
               malicious_factor = 10.0  # 恶意IP风险倍增
           
           # 应用贝叶斯公式
           risk_score = (p_ip * p_ua * p_rtt) / p_user * malicious_factor
           return min(risk_score, 1.0)  # 上限1.0
       ```
    
    4. **数据存储**：
       ```python
       def store_record(user_id, features, risk_score):
           # 加密敏感特征
           encrypted_features = {
               'ip': aes_encrypt(features['ip'], storage_key),
               'ua': aes_encrypt(features['ua'], storage_key),
               'geo': get_geo_data(features['ip'])
           }
           
           # 数据库插入
           execute_db("""
               INSERT INTO risk_logs 
               (user_id, ip_address, user_agent, risk_score, features) 
               VALUES (%s, %s, %s, %s, %s)
           """, [user_id, features['ip'], features['ua'], risk_score, 
                json.dumps(encrypted_features)])
           
           # 更新内部缓存
           update_frequency_cache(features, risk_score)
           return True
       ```
    
    #### 5. **内部数据存储**
    
    1. **频率缓存**（内存加速）：
       ```python
       {
           'ips': {
               '192.168.1.1': 1500,
               '10.0.0.1': 1200,
               ...
           },
           'uas': {
               'Chrome': 9500,
               'Firefox': 3200,
               ...
           },
           'rtt_ranges': {
               '10.0-10.5': 2300,
               '12.0-12.5': 1850,
               ...
           },
           'user_history': {
               'user1': 45,
               'user2': 32,
               ...
           }
       }
       ```
    
    2. **恶意IP列表**（初始化加载）：
       ```python
       [
           '192.168.34.0/24',
           '10.100.0.0/16',
           ...
       ]
       ```
    
    #### 6. **密钥管理**
    - **存储加密密钥**：`storage_key` (AES-256-GCM)
      - 飞地初始化时生成，使用硬件熵源
      - 永不导出飞地
    - **查询签名密钥**：`query_signing_key` (Ed25519)
      - 用于签名数据库查询，防止SQL注入
    
    #### 7. **加密算法**
    - **数据加密**：AES-256-GCM
    - **数字签名**：Ed25519
    - **密钥派生**：HKDF-SHA256
    - **内存加密**：XTS-AES-128（由TEE硬件支持）
    
    ### 接口设计
    
    ```python
    class WeakTEE:
        def __init__(self, db_config, malicious_ip_path=None):
            self.db = connect_db(db_config)
            self.storage_key = self.generate_storage_key()
            self.load_malicious_ips(malicious_ip_path)
            self.init_frequency_cache()
        
        def process_request(self, user_id: str, ip: str, ua: str, rtt: float) -> (float, bool):
            """主处理接口"""
            try:
                # 1. 解析输入
                features = self.parse_features(ip, ua, rtt)
                
                # 2. 查询历史频次
                freqs = self.query_frequencies(features)
                
                # 3. 计算风险分数
                risk_score = self.calculate_risk(user_id, features, freqs)
                
                # 4. 存储记录
                storage_success = self.store_record(user_id, features, risk_score)
                
                return risk_score, storage_success
            except Exception as e:
                log_error(e)
                return 1.0, False  # 异常时返回最高风险
        
        # 其他辅助方法...
    ```
    
    ### 安全特性
    
    1. **敏感数据全加密**：
       - IP/UA在存储前使用AES-GCM加密
       - 内存中的敏感数据使用TEE内存加密
    
    2. **查询完整性保护**：
       - 所有SQL查询使用Ed25519签名
       - 数据库只执行签名验证通过的查询
    
    3. **最小化数据暴露**：
       - 原始数据只在飞地内存中解密
       - 外部只能获取风险分数，无法访问原始特征
    
    4. **安全密钥管理**：
       - 密钥在飞地内生成且永不导出
       - 密钥定期轮换（如每24小时）
    
    ### 示例执行
    
    **输入**：`("192.168.1.1", "Mozilla/5.0...", 12.3)`
    
    1. 特征提取：
       ```json
       {
         "ip": "192.168.1.1",
         "ua": "Mozilla/5.0...",
         "browser": "Mozilla",
         "version": "5.0",
         "os": "Windows",
         "rtt": 12.3
       }
       ```
    
    2. 频次查询结果：
       - IP频次：1500
       - UA频次：9500
       - RTT频次：2300
       - 总记录：10000
    
    3. 风险计算：
       ```
       p_ip = 1500/10000 = 0.15
       p_ua = 9500/10000 = 0.95
       p_rtt = 2300/10000 = 0.23
       p_user = 45/10000 = 0.0045 (假设user有45条记录)
       
       risk_score = (0.15 * 0.95 * 0.23) / 0.0045 * 1.0 = 7.28 → 上限1.0
       ```
    
    4. 存储记录：
       ```json
       {
         "user_id": "test_user",
         "ip_address": "AES_ENC(...)",
         "user_agent": "AES_ENC(...)",
         "risk_score": 1.0,
         "features": {
            "encrypted_ip": "GCM_CIPHERTEXT",
            "encrypted_ua": "GCM_CIPHERTEXT",
            "geo": {"city": "New York", "country": "USA"}
         }
       }
       ```
    
    5. 输出：`(1.0, true)`
    
    这个弱化版的`tee_soft`专注于处理固定格式的三元组输入，通过优化的频次查询和概率模型计算风险分数，同时确保所有敏感数据在飞地内加密处理，符合数据库结构和RBA计算的核心逻辑。

---

### 总结 `tee_soft` 黑盒子

*   **输入：** 加密数据 (`Ciphertext_in`)， 加密的列密钥 (`EncCEK`)， 操作指令 (`Op`)， (可选)加密参数 (`EncParams`)， (可选)新加密值 (`NewEncValue`)， (初始化时)证明证据 (`Evidence`)。
*   **输出：** 不含明文的操作结果 (`Result` - e.g., 行ID列表， 布尔值， 状态)， (可选)重新加密的列密钥 (`NewEncCEK`)， (可选)加密的中间结果 (`EncIntermediate`)， 操作后的新加密数据 (写回数据库)。
*   **内部核心动作：**
    1.  (用 CMK *外部*解密后得到的 `EncCEK`) 在 `tee_soft` 内解密为 **明文 CEK**。
    2.  用 **明文 CEK** 解密输入数据/参数得到 **明文数据**。
    3.  在 **明文数据** 上执行安全计算 (`Op`)。
    4.  生成 **不含明文的输出结果** 或 **用 CEK 重新加密的结果数据**。
    5.  **彻底清除**内存中的所有明文密钥和数据。
*   **村里（内存中）的密钥：** 仅**短暂存在**的 **明文 CEK** 和可能的**内部临时会话密钥**。**永不存储** CMK。
*   **主要算法：**
    *   **数据加密/解密：** AES-256 (CBC for Deterministic, GCM/CBC for Randomized).
    *   **密钥包装/解包：** RSA-OAEP (for Asymmetric CMK), AES-256-CBC (for Symmetric CMK).
    *   **完整性与签名：** HMAC-SHA-256, ECDSA, SHA-256.

`tee_soft` 的核心价值在于它创造了一个短暂而安全的“绿洲”，让敏感的明文密钥和数据可以短暂地、受保护地存在并用于计算，而计算的结果以一种不泄露明文的方式输出，最终确保数据库服务器引擎在处理过程中也完全无法接触到敏感信息的明文。

## 数据库

```sql
-- MySQL dump 10.13  Distrib 9.2.0, for Win64 (x86_64)
--
-- Host: localhost    Database: risk_assessment
-- ------------------------------------------------------
-- Server version	9.2.0

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `risk_logs`
--

DROP TABLE IF EXISTS `risk_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `risk_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` varchar(36) COLLATE utf8mb4_unicode_ci NOT NULL,
  `ip_address` varchar(45) COLLATE utf8mb4_unicode_ci NOT NULL,
  `geo_data` json DEFAULT NULL,
  `risk_score` float DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `features` json DEFAULT NULL,
  `user_agent` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `action` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `rtt` decimal(10,3) DEFAULT NULL COMMENT '寰€杩旀椂闂达紝鍗曚綅姣',
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_created` (`created_at`)
) ENGINE=InnoDB AUTO_INCREMENT=149 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `risk_logs`
--

LOCK TABLES `risk_logs` WRITE;
/*!40000 ALTER TABLE `risk_logs` DISABLE KEYS */;
INSERT INTO `risk_logs` VALUES (1,'test_user','192.168.1.1','{\"city\": \"New York\", \"country\": \"USA\"}',0.3,'2025-03-02 12:28:23',NULL,NULL,NULL,NULL),(2,'test_user','192.168.1.2','{\"city\": \"Los Angeles\", \"country\": \"USA\"}',0.5,'2025-03-02 12:28:23',NULL,NULL,NULL,NULL),(3,'test_user','192.168.1.3','{\"city\": \"Chicago\", \"country\": \"USA\"}',0.7,'2025-03-02 12:28:23',NULL,NULL,NULL,NULL),(4,'admin','10.0.0.1','{\"city\": \"Washington\", \"country\": \"USA\"}',0.2,'2025-03-02 12:28:23',NULL,NULL,NULL,NULL),(5,'admin','10.0.0.2','{\"city\": \"Houston\", \"country\": \"USA\"}',0.4,'2025-03-02 12:28:23',NULL,NULL,NULL,NULL),(6,'admin','10.0.0.3','{\"city\": \"Phoenix\", \"country\": \"USA\"}',0.6,'2025-03-02 12:28:23',NULL,NULL,NULL,NULL),(7,'1740483425007','::1','{}',0.175,'2025-03-05 11:42:13',NULL,'Unknown','ALLOW',NULL),(8,'1740483425007','::1','{}',0.175,'2025-03-05 12:00:36',NULL,'Unknown','ALLOW',NULL),(9,'1740483425007','::1','{}',0.175,'2025-03-05 12:09:26',NULL,'Unknown','ALLOW',NULL),(10,'1740483425007','::1','{}',0.175,'2025-03-05 12:31:49',NULL,'Unknown','ALLOW',NULL),(11,'1740483425007','::1','{}',0.175,'2025-03-05 12:32:22',NULL,'Unknown','ALLOW',NULL),(12,'1740483425007','::ffff:127.0.0.1','{}',0.175,'2025-03-07 12:01:06',NULL,'Unknown','ALLOW',NULL),(13,'1740483425007','::ffff:127.0.0.1','{}',0.175,'2025-03-07 12:02:07',NULL,'Unknown','ALLOW',NULL),(14,'1740483425007','::ffff:127.0.0.1','{}',0.175,'2025-03-07 12:02:32',NULL,'Unknown','ALLOW',NULL),(15,'1740483425007','::ffff:127.0.0.1','{}',0.175,'2025-03-07 12:02:55',NULL,'Unknown','ALLOW',NULL),(16,'1740483425007','::ffff:127.0.0.1','{}',0.175,'2025-03-10 13:40:14',NULL,'Unknown','ALLOW',NULL),(17,'1740483425007','::ffff:127.0.0.1','{}',0.175,'2025-03-10 13:58:31',NULL,'Unknown','ALLOW',NULL),(18,'1741615061630','::ffff:127.0.0.1','{}',0.0875,'2025-03-10 14:00:22',NULL,'Unknown','ALLOW',NULL),(19,'1741615061630','::ffff:127.0.0.1','{}',0.0875,'2025-03-10 14:01:25',NULL,'Unknown','ALLOW',NULL),(20,'1740483425007','::ffff:127.0.0.1','{}',0.0875,'2025-03-10 14:01:56',NULL,'Unknown','ALLOW',NULL),(21,'1740483425007','::ffff:127.0.0.1','{}',0.175,'2025-03-10 14:02:34',NULL,'Unknown','ALLOW',NULL),(22,'1740483425007','::ffff:127.0.0.1','{}',0.175,'2025-03-10 14:02:52',NULL,'Unknown','ALLOW',NULL),(23,'1740483425007','::ffff:127.0.0.1','{}',0.175,'2025-03-10 14:03:14',NULL,'Unknown','ALLOW',NULL),(24,'1740483425007','::ffff:127.0.0.1','{}',0.175,'2025-03-15 12:52:55',NULL,'Unknown','ALLOW',NULL),(25,'1740483425007','::ffff:127.0.0.1','{\"cc\": \"XX\", \"ip\": \"::ffff:127.0.0.1\", \"asn\": \"Unknown\"}',0.175,'2025-03-15 12:52:56',NULL,'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0',NULL,NULL),;
/*!40000 ALTER TABLE `risk_logs` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-05-25 14:06:40

```

## 计算风险分数

这里给出js的实现，具体实现语言结合情况进行转化，要留出独立接口，方便后续改进

```
async calculate(userId, features) {
        let geoData = null;
        let score = 1.0;
        const { globalHistory, userHistory } = await this._getHistories(userId);

        // 新增：记录当前登录特征，用于后续更新用户历史
        const currentFeatures = {};

        // 新增调试日志头
        console.debug(`[风险计算] 用户 ${userId} 开始风险评估`, {
            globalLoginCount: globalHistory.loginCount,
            userLoginCount: userHistory.loginCount
        });

        // 遍历所有主特征
        for (const mainFeature of Object.keys(config.coefficients)) {
            const featureValue = this._parseFeature(mainFeature, features);

            // 新增：记录当前特征值
            currentFeatures[mainFeature] = featureValue;

            console.debug(`[特征处理] 主特征 ${mainFeature} 解析结果:`, JSON.stringify(featureValue));

            // ===================== 攻击者概率 p_A_given_xk =====================
            let pA = 1.0;
            // 新增：针对rtt特征的特殊处理
            if (mainFeature === 'rtt') {
                // rtt没有子特征，直接使用主特征值
                const rttValue = featureValue;
                pA = rttValue > 1000 ? 0.8 : 0.1; // 根据延迟时间判断风险

                // 新增调试日志
                console.debug(`[RTT特征]`, {
                    rawValue: featureValue,
                    parsedValue: rttValue,
                    pA: pA.toFixed(4)
                });
            }
            else {
                for (const [subFeature, weight] of Object.entries(config.coefficients[mainFeature])) {
                    const subValue = this._parseSubFeature(subFeature, featureValue);

                    // 子特征攻击概率判断
                    let subRisk;
                    switch (subFeature) {
                        case 'asn':
                            subRisk = subValue === 'Local' ? 0.01 :
                                this.maliciousNetworks.includes(subValue) ? 0.9 : 0.1;
                            break;
                        case 'cc':
                            subRisk = subValue === 'LOCAL' ? 0.01 :
                                config.maliciousCountries.includes(subValue) ? 0.8 : 0.2;
                            break;
                        case 'bv':
                            const minVersion = config.minBrowserVersion[featureValue.ua] || 70;
                            subRisk = parseInt(subValue) < minVersion ? 0.7 : 0.1;
                            break;
                        default:
                            subRisk = 0.5;
                    }
                    pA *= subRisk; // 各子特征攻击概率相乘

                    // 新增子特征日志
                    console.debug(`[攻击者概率] 特征 ${mainFeature}.${subFeature}`, {
                        subValue: subValue.toString(),
                        subRisk: subRisk.toFixed(2),
                        currentPA: pA.toFixed(4)
                    });
                }
            }

            // ===================== 全局概率 p_xk =====================
            let pXk = 1.0;
            if (mainFeature === 'rtt') {
                // rtt直接使用主特征统计
                const globalCount = globalHistory.features[mainFeature]?.[featureValue] || 0;
                const globalTotal = globalHistory.total[mainFeature] || 1;
                pXk = this._smooth(globalCount, globalTotal);
                // 新增调试日志
                console.debug(`[RTT全局统计]`, {
                    rawValue: featureValue,
                    count: globalCount,
                    total: globalTotal,
                    pXk: pXk.toFixed(4)

                });
            } else {
                for (const [subFeature, weight] of Object.entries(config.coefficients[mainFeature])) {
                    const subValue = this._parseSubFeature(subFeature, featureValue);
                    const globalCount = globalHistory.features[subFeature]?.[subValue] || 0;
                    const globalTotal = globalHistory.total[subFeature] || 1;
                    const pHistory = this._smooth(globalCount, globalTotal);
                    pXk *= pHistory; // 各子特征全局概率相乘

                    // 新增全局概率日志
                    console.debug(`[全局概率] 特征 ${mainFeature}.${subFeature}`, {
                        subValue: subValue.toString(),
                        globalCount,
                        globalTotal,
                        pHistory: pHistory.toFixed(4),
                        currentPXk: pXk.toFixed(4)
                    });
                }
            }

            // ===================== 用户本地概率 p_xk_given_u_L =====================
            let pXkL = 1.0;
            if (mainFeature === 'rtt') {
                // rtt直接使用用户历史统计
                const userCount = userHistory.features[mainFeature]?.[featureValue] || 0;
                const userTotal = userHistory.total[mainFeature] || 0;
                pXkL = this._smooth(userCount, userTotal);
                // 新增用户统计日志
                console.debug(`[RTT用户统计]`, {
                    rawValue: featureValue,
                    count: userCount,
                    total: userTotal,
                    pXkL: pXkL.toFixed(4)
                });
            } else {
                for (const [subFeature, weight] of Object.entries(config.coefficients[mainFeature])) {
                    const subValue = this._parseSubFeature(subFeature, featureValue);

                    // 使用新的用户概率计算方法
                    const userProb = this._calculateUserProbability(subFeature, subValue, userHistory);

                    // 安全检查
                    if (userProb > 1.0) {
                        console.warn(`[警告] 用户概率异常: ${userProb.toFixed(4)}，已修正为1.0`);
                        userProb = 1.0;
                    }

                    pXkL *= userProb; // 各子特征用户概率相乘

                    // 新增用户概率日志
                    console.debug(`[用户概率] 特征 ${mainFeature}.${subFeature}`, {
                        subValue: subValue.toString(),
                        userCount: userHistory.features[subFeature]?.[subValue] || 0,
                        userTotal: userHistory.total[subFeature] || 0,
                        userProb: userProb.toFixed(4),
                        currentPXkL: pXkL.toFixed(4)
                    });
                }
            }

            // ===================== 特征贡献值 =====================
            const beforeScore = score;
            // 在特征贡献值计算中添加保护措施
            score *= (pA * pXk) / Math.max(pXkL, 0.01);  // 确保分母至少为0.01

            // 在特征贡献值计算中添加最小值保护
            if (score < 0.0001) {
                console.warn(`[警告] 风险分数过小: ${score.toExponential(4)}，已调整为最小值`);
                score = 0.0001;  // 防止数值下溢
            }

            console.debug(`[特征贡献] ${mainFeature}`, {
                pA: pA.toFixed(4),
                pXk: pXk.toFixed(4),
                pXkL: pXkL.toFixed(4),
                contribution: (score / beforeScore).toFixed(4),
                newScore: score.toFixed(4)
            });
        }

        // ===================== 全局用户比例调整 p_u_given_A / p_u_given_L =====================
        const totalUsers = Object.keys(this.history.users).length || 1;
        const pUGivenA = 1 / totalUsers; // 攻击者中该用户的概率
        const pUGivenL = userHistory.loginCount / globalHistory.loginCount || 0.01; // 正常用户中该用户的活跃度

        // 新增比例调整日志
        console.debug(`[比例调整] 用户 ${userId}`, {
            totalUsers,
            pUGivenA: pUGivenA.toExponential(2),
            pUGivenL: pUGivenL.toExponential(2),
            ratio: (pUGivenA / pUGivenL).toExponential(2)
        });

        // 计算最终分数
        let finalScore = Number(score * (pUGivenA / Math.max(pUGivenL, 0.001)));
        if (isNaN(finalScore)) {
            console.error('风险评估异常: 最终分数为 NaN', { score, pUGivenA, pUGivenL });
            finalScore = 1.0; // 默认安全值
        }
        finalScore = Math.min(finalScore, 1.0);
        // ===================== 阈值判断 =====================
        const rejectThreshold = config.risk.rejectThreshold || 0.7;
        const requestThreshold = config.risk.requestThreshold || 0.4;
        let action = 'ALLOW';

        if (finalScore > rejectThreshold) {
            action = 'REJECT';
            console.error(`[风险拒绝] 用户 ${userId} 分数: ${finalScore.toFixed(2)}`);
        } else if (finalScore > requestThreshold) {
            action = 'CHALLENGE';
            console.warn(`[需要验证] 用户 ${userId} 分数: ${finalScore.toFixed(2)}`);
        }

        // // ===================== 保存完整日志 =====================
        // await query(
        //     `INSERT INTO risk_logs 
        //     (user_id, ip_address, user_agent, geo_data, risk_score, action) 
        //     VALUES (?, ?, ?, ?, ?, ?)`,
        //     [
        //         userId,
        //         features.ip || '0.0.0.0', // 处理 ip 缺失
        //         features.userAgent || 'Unknown',
        //         JSON.stringify(geoData || {}), // 处理 geoData 未定义
        //         finalScore,
        //         action
        //     ]
        // );

        // 新增：更新用户历史记录
        await this._updateUserHistory(userId, currentFeatures, userHistory);

        return {
            score: finalScore,
            action: action
        };
    }
```

## 特别注意

- 在运行过程中记录内存的使用状况，可以有两个个档次（128MB，无限制）