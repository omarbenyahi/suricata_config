import json
import time
from datetime import datetime
import os

class StatisticalFeatureExtractor:
    """
    Statistical Feature Extractor
    INPUT: Suricata JSON (eve.json)
    PROCESS: Statistical analysis
    OUTPUT: Statistical Feature Vector (numeric metrics)
    """
    
    def __init__(self, eve_json_path, output_json='statistical_features.json'):
        self.eve_json_path = eve_json_path
        self.output_json = output_json
        self.file_position = 0
        self.features_list = []
        
        # إنشاء ملف JSON فارغ في البداية
        self.init_output_file()
    
    def init_output_file(self):
        """
        تهيئة ملف JSON الإخراج
        """
        with open(self.output_json, 'w') as f:
            json.dump([], f)
    
    def extract_statistical_features(self, event):
        """
        استخراج الميزات الإحصائية الرقمية
        """
        if event.get('event_type') != 'alert':
            return None
        
        # Statistical Features Vector
        features = {
            # Alert Metadata
            'alert_id': event.get('flow_id', 0),
            'timestamp': datetime.fromisoformat(
                event.get('timestamp', '').replace('Z', '+00:00')
            ).timestamp() if event.get('timestamp') else 0,
            
            # Alert Characteristics
            'signature_id': event.get('alert', {}).get('signature_id', 0),
            'severity': event.get('alert', {}).get('severity', 0),
            'gid': event.get('alert', {}).get('gid', 0),
            'rev': event.get('alert', {}).get('rev', 0),
            
            # Protocol Features
            'proto_tcp': 1 if event.get('proto') == 'TCP' else 0,
            'proto_udp': 1 if event.get('proto') == 'UDP' else 0,
            'proto_icmp': 1 if event.get('proto') == 'ICMP' else 0,
            'proto_other': 1 if event.get('proto') not in ['TCP', 'UDP', 'ICMP'] else 0,
            
            # Port Features
            'src_port': event.get('src_port', 0),
            'dest_port': event.get('dest_port', 0),
            'port_well_known': 1 if event.get('dest_port', 0) <= 1023 else 0,
            'port_registered': 1 if 1024 <= event.get('dest_port', 0) <= 49151 else 0,
            'port_dynamic': 1 if event.get('dest_port', 0) >= 49152 else 0,
            
            # Flow Statistics
            'pkts_toserver': event.get('flow', {}).get('pkts_toserver', 0),
            'pkts_toclient': event.get('flow', {}).get('pkts_toclient', 0),
            'bytes_toserver': event.get('flow', {}).get('bytes_toserver', 0),
            'bytes_toclient': event.get('flow', {}).get('bytes_toclient', 0),
            
            # Derived Statistics
            'total_packets': event.get('flow', {}).get('pkts_toserver', 0) + 
                           event.get('flow', {}).get('pkts_toclient', 0),
            'total_bytes': event.get('flow', {}).get('bytes_toserver', 0) + 
                         event.get('flow', {}).get('bytes_toclient', 0),
            'avg_packet_size': 0,
            'packet_ratio': 0,
            'byte_ratio': 0,
            
            # Action Features
            'action_allowed': 1 if event.get('alert', {}).get('action') == 'allowed' else 0,
            'action_blocked': 1 if event.get('alert', {}).get('action') == 'blocked' else 0,
            
            # Application Protocol
            'app_proto_http': 1 if event.get('app_proto') == 'http' else 0,
            'app_proto_dns': 1 if event.get('app_proto') == 'dns' else 0,
            'app_proto_tls': 1 if event.get('app_proto') == 'tls' else 0,
            'app_proto_ssh': 1 if event.get('app_proto') == 'ssh' else 0,
            'app_proto_other': 1 if event.get('app_proto') not in ['http', 'dns', 'tls', 'ssh'] else 0,
        }
        
        # حساب الإحصائيات المشتقة
        if features['total_packets'] > 0:
            features['avg_packet_size'] = features['total_bytes'] / features['total_packets']
        
        if features['pkts_toclient'] > 0:
            features['packet_ratio'] = features['pkts_toserver'] / features['pkts_toclient']
        
        if features['bytes_toclient'] > 0:
            features['byte_ratio'] = features['bytes_toserver'] / features['bytes_toclient']
        
        return features
    
    def update_output_file(self, new_features):
        """
        تحديث ملف JSON بالميزات الجديدة
        """
        # قراءة الملف الحالي
        with open(self.output_json, 'r') as f:
            try:
                features_list = json.load(f)
            except json.JSONDecodeError:
                features_list = []
        
        # إضافة الميزات الجديدة
        features_list.append(new_features)
        
        # كتابة الملف المحدث
        with open(self.output_json, 'w') as f:
            json.dump(features_list, f, indent=2)
    
    def monitor_eve_json(self):
        """
        مراقبة eve.json في الوقت الفعلي
        """
        print(f"[Statistical Feature Extractor]")
        print(f"[+] Input: {self.eve_json_path}")
        print(f"[+] Output: {self.output_json}")
        print(f"[+] Status: Monitoring in real-time...")
        print(f"[+] Press Ctrl+C to stop\n")
        
        alert_count = 0
        
        with open(self.eve_json_path, 'r') as f:
            # بدء من نهاية الملف (الأحداث الجديدة فقط)
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
                    features = self.extract_statistical_features(event)
                    
                    if features:
                        # تحديث ملف JSON
                        self.update_output_file(features)
                        
                        alert_count += 1
                        
                        print(f"[Alert #{alert_count}] Statistical Features Extracted")
                        print(f"  ├─ Alert ID: {features['alert_id']}")
                        print(f"  ├─ Severity: {features['severity']}")
                        print(f"  ├─ Total Packets: {features['total_packets']}")
                        print(f"  ├─ Total Bytes: {features['total_bytes']}")
                        print(f"  ├─ Avg Packet Size: {features['avg_packet_size']:.2f}")
                        print(f"  └─ Saved to {self.output_json}\n")
                    
                    self.file_position = f.tell()
                    
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"[!] Error: {e}")
                    continue
    
    def run(self):
        """
        تشغيل المستخرج
        """
        try:
            self.monitor_eve_json()
        except KeyboardInterrupt:
            print(f"\n[+] Statistical Feature Extractor stopped")
            print(f"[+] Features saved to: {self.output_json}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 statistical_feature_extractor.py <eve.json_path> [output_json]")
        print("Example: python3 statistical_feature_extractor.py /var/log/suricata/eve.json")
        sys.exit(1)
    
    eve_json_path = sys.argv[1]
    output_json = sys.argv[2] if len(sys.argv) > 2 else 'statistical_features.json'
    
    extractor = StatisticalFeatureExtractor(eve_json_path, output_json)
    extractor.run()
