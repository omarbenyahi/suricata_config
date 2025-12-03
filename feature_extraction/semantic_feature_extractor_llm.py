import json
import time
import re
from datetime import datetime
import requests
from openai import OpenAI

class LLMSemanticExtractor:
    """
    LESFE (LLM-based Semantic Extractor)
    INPUT: Suricata JSON
    AI MODEL: DeepSeek LLM
    OUTPUT: Semantic Feature Vector (contextual representation)
    """
    
    def __init__(self, eve_json_path, output_json='semantic_features.json', 
                 deepseek_api_key=None, use_llm=True):
        self.eve_json_path = eve_json_path
        self.output_json = output_json
        self.file_position = 0
        self.use_llm = use_llm
        
        # تكوين DeepSeek API
        if use_llm and deepseek_api_key:
            self.client = OpenAI(
                api_key=deepseek_api_key,
                base_url="https://api.deepseek.com"
            )
            print("[+] DeepSeek LLM initialized successfully")
        else:
            self.client = None
            if use_llm:
                print("[!] Warning: No API key provided, using rule-based extraction")
        
        # تهيئة ملف الإخراج
        self.init_output_file()
    
    def init_output_file(self):
        """تهيئة ملف JSON الإخراج"""
        with open(self.output_json, 'w') as f:
            json.dump([], f)
    
    def analyze_with_llm(self, signature, category, src_ip, dest_ip, proto, app_proto):
        """
        تحليل Alert باستخدام DeepSeek LLM
        """
        if not self.client:
            return None
        
        prompt = f"""Analyze this network security alert and extract semantic features:

Alert Details:
- Signature: {signature}
- Category: {category}
- Source IP: {src_ip}
- Destination IP: {dest_ip}
- Protocol: {proto}
- App Protocol: {app_proto}

Please analyze and provide:
1. Threat Type (malware, exploit, scan, dos, botnet, phishing, data_exfiltration, suspicious, or benign)
2. Severity Level (critical, high, medium, low)
3. Attack Intent (reconnaissance, exploitation, persistence, lateral_movement, exfiltration, impact, or unknown)
4. Target Asset Type (web_server, database, workstation, network_device, iot, cloud, or unknown)
5. Confidence Score (0.0 to 1.0)
6. Brief contextual description (max 100 words)

Return ONLY a valid JSON object with these fields:
{
  "threat_type": "...",
  "severity_level": "...",
  "attack_intent": "...",
  "target_asset": "...",
  "confidence_score": 0.0,
  "description": "..."
}"""

        try:
            response = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing network alerts. Respond only with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500
            )
            
            llm_output = response.choices[0].message.content
            
            # استخراج JSON من الإجابة
            json_match = re.search(r'\{.*\}', llm_output, re.DOTALL)
            if json_match:
                llm_features = json.loads(json_match.group())
                return llm_features
            
            return None
            
        except Exception as e:
            print(f"[!] LLM Error: {e}")
            return None
    
    def extract_rule_based_features(self, event):
        """
        استخراج ميزات دلالية بدون LLM (fallback)
        """
        signature = event.get('alert', {}).get('signature', '')
        category = event.get('alert', {}).get('category', '')
        
        features = {
            # Textual Features
            'signature_text': signature,
            'category_text': category,
            'signature_length': len(signature),
            'signature_word_count': len(signature.split()),
            
            # Threat Classification
            'threat_malware': 1 if re.search(r'(malware|trojan|virus|worm|ransomware)', signature, re.I) else 0,
            'threat_exploit': 1 if re.search(r'(exploit|overflow|injection|xss|sqli)', signature, re.I) else 0,
            'threat_scan': 1 if re.search(r'(scan|probe|reconnaissance)', signature, re.I) else 0,
            'threat_dos': 1 if re.search(r'(dos|ddos|flood)', signature, re.I) else 0,
            'threat_botnet': 1 if re.search(r'(botnet|c2|command)', signature, re.I) else 0,
            'threat_suspicious': 1 if re.search(r'(suspicious|anomal|unusual)', signature, re.I) else 0,
        }
        
        return features
    
    def extract_semantic_features(self, event):
        """
        استخراج الميزات الدلالية الكاملة
        """
        if event.get('event_type') != 'alert':
            return None
        
        signature = event.get('alert', {}).get('signature', '')
        category = event.get('alert', {}).get('category', '')
        src_ip = event.get('src_ip', '')
        dest_ip = event.get('dest_ip', '')
        proto = event.get('proto', '')
        app_proto = event.get('app_proto', '')
        
        # الميزات الأساسية
        features = {
            'alert_id': event.get('flow_id', 0),
            'timestamp': datetime.fromisoformat(
                event.get('timestamp', '').replace('Z', '+00:00')
            ).timestamp() if event.get('timestamp') else 0,
            
            # Context Information
            'signature_text': signature,
            'category_text': category,
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'proto': proto,
            'app_proto': app_proto,
            'src_port': event.get('src_port', 0),
            'dest_port': event.get('dest_port', 0),
        }
        
        # استخراج ميزات باستخدام LLM
        if self.use_llm and self.client:
            print(f"  ├─ Analyzing with DeepSeek LLM...")
            llm_features = self.analyze_with_llm(signature, category, src_ip, dest_ip, proto, app_proto)
            
            if llm_features:
                features['llm_threat_type'] = llm_features.get('threat_type', 'unknown')
                features['llm_severity'] = llm_features.get('severity_level', 'unknown')
                features['llm_attack_intent'] = llm_features.get('attack_intent', 'unknown')
                features['llm_target_asset'] = llm_features.get('target_asset', 'unknown')
                features['llm_confidence'] = llm_features.get('confidence_score', 0.0)
                features['llm_description'] = llm_features.get('description', '')
                print(f"  ├─ LLM Analysis: {llm_features['threat_type']} ({llm_features['confidence_score']})")
            else:
                print(f"  ├─ LLM failed, using rule-based fallback")
        
        # استخراج ميزات إضافية (rule-based)
        rule_features = self.extract_rule_based_features(event)
        features.update(rule_features)
        
        # HTTP Context
        if event.get('http'):
            features['http_hostname'] = event.get('http', {}).get('hostname', '')
            features['http_url'] = event.get('http', {}).get('url', '')
            features['http_method'] = event.get('http', {}).get('http_method', '')
            features['http_user_agent'] = event.get('http', {}).get('http_user_agent', '')
        
        # DNS Context
        if event.get('dns'):
            features['dns_query'] = event.get('dns', {}).get('rrname', '')
            features['dns_type'] = event.get('dns', {}).get('rrtype', '')
        
        # TLS Context
        if event.get('tls'):
            features['tls_sni'] = event.get('tls', {}).get('sni', '')
            features['tls_subject'] = event.get('tls', {}).get('subject', '')
        
        # Flow Direction
        features['flow_direction'] = event.get('direction', '')
        
        return features
    
    def update_output_file(self, new_features):
        """تحديث ملف JSON"""
        with open(self.output_json, 'r') as f:
            try:
                features_list = json.load(f)
            except json.JSONDecodeError:
                features_list = []
        
        features_list.append(new_features)
        
        with open(self.output_json, 'w') as f:
            json.dump(features_list, f, indent=2)
    
    def monitor_eve_json(self):
        """مراقبة eve.json في الوقت الفعلي"""
        print(f"\n{'='*70}")
        print(f"  LESFE - LLM-based Semantic Feature Extractor")
        print(f"{'='*70}")
        print(f"[+] Input: {self.eve_json_path}")
        print(f"[+] Output: {self.output_json}")
        print(f"[+] AI Model: DeepSeek LLM")
        print(f"[+] Status: Monitoring in real-time...")
        print(f"[+] Press Ctrl+C to stop\n")
        
        alert_count = 0
        
        with open(self.eve_json_path, 'r') as f:
            f.seek(0, 2)
            self.file_position = f.tell()
            
            while True:
                line = f.readline()
                
                if not line:
                    self.file_position = f.tell()
                    time.sleep(0.1)
                    continue
                
                try:
                    event = json.loads(line.strip())
                    features = self.extract_semantic_features(event)
                    
                    if features:
                        self.update_output_file(features)
                        alert_count += 1
                        
                        print(f"\n[Alert #{alert_count}] Semantic Features Extracted")
                        print(f"  ├─ Alert ID: {features['alert_id']}")
                        print(f"  ├─ Signature: {features['signature_text'][:60]}...")
                        
                        if 'llm_threat_type' in features:
                            print(f"  ├─ LLM Threat Type: {features['llm_threat_type']}")
                            print(f"  ├─ LLM Severity: {features['llm_severity']}")
                            print(f"  ├─ LLM Confidence: {features['llm_confidence']}")
                        
                        print(f"  └─ Saved to {self.output_json}\n")
                    
                    self.file_position = f.tell()
                    
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"[!] Error: {e}")
                    continue
    
    def run(self):
        """تشغيل المستخرج"""
        try:
            self.monitor_eve_json()
        except KeyboardInterrupt:
            print(f"\n[+] Semantic Feature Extractor stopped")
            print(f"[+] Features saved to: {self.output_json}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 semantic_feature_extractor_llm.py <eve.json_path> [deepseek_api_key]")
        print("\nExample:")
        print("  python3 semantic_feature_extractor_llm.py /var/log/suricata/eve.json sk-xxxxx")
        print("\nOr set API key as environment variable:")
        print("  export DEEPSEEK_API_KEY='sk-xxxxx'")
        print("  python3 semantic_feature_extractor_llm.py /var/log/suricata/eve.json")
        sys.exit(1)
    
    eve_json_path = sys.argv[1]
    
    # الحصول على API key
    import os
    deepseek_api_key = None
    
    if len(sys.argv) > 2:
        deepseek_api_key = sys.argv[2]
    elif os.getenv('DEEPSEEK_API_KEY'):
        deepseek_api_key = os.getenv('DEEPSEEK_API_KEY')
    else:
        print("[!] No DeepSeek API key provided. Using rule-based extraction only.")
        use_llm_input = input("Continue without LLM? (y/n): ")
        if use_llm_input.lower() != 'y':
            sys.exit(1)
    
    extractor = LLMSemanticExtractor(
        eve_json_path, 
        output_json='semantic_features.json',
        deepseek_api_key=deepseek_api_key,
        use_llm=bool(deepseek_api_key)
    )
    
    extractor.run()
