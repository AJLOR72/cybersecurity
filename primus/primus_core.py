
#!/usr/bin/env python3
"""
PRIMUS - Self-Modifying Autonomous Cybersecurity Defense System
"""

import os
import sys
import json
import time
import threading
import logging
import hashlib
import sqlite3
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from collections import deque
import socket
import struct

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('primus.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("PRIMUS")

# ============================================================================
# ENUMS AND CONSTANTS
# ============================================================================

class ThreatSeverity(Enum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

class ThreatCategory(Enum):
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    C2_BEACON = "c2_beacon"
    DATA_EXFIL = "data_exfiltration"
    MALWARE = "malware"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DDOS = "ddos"
    SUSPICIOUS = "suspicious"

class ResponseAction(Enum):
    LOG_ONLY = "log_only"
    INCREASE_LOGGING = "increase_logging"
    RATE_LIMIT = "rate_limit"
    BLOCK_IP = "block_ip"
    QUARANTINE = "quarantine"
    ISOLATE_HOST = "isolate_host"
    ESCALATE_HUMAN = "escalate_human"

# ============================================================================
# DATABASE MANAGER
# ============================================================================

class DatabaseManager:
    """SQLite database for persistent storage"""
    
    def __init__(self, db_path: str = "primus.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    source_ip TEXT,
                    dest_ip TEXT,
                    dest_port INTEGER,
                    threat_type TEXT,
                    threat_score REAL,
                    severity INTEGER,
                    action TEXT,
                    details TEXT
                )
            ''')
            
            # Blocked IPs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip TEXT PRIMARY KEY,
                    reason TEXT,
                    blocked_at REAL,
                    expires_at REAL
                )
            ''')
            
            # Learning memory (for self-modification)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS learning_memory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern TEXT,
                    confidence REAL,
                    occurrences INTEGER,
                    last_seen REAL
                )
            ''')
            
            conn.commit()
            logger.info("Database initialized at %s", self.db_path)
    
    def log_event(self, event: Dict):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO events (timestamp, source_ip, dest_ip, dest_port, 
                                   threat_type, threat_score, severity, action, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.get('timestamp', time.time()),
                event.get('source_ip', ''),
                event.get('dest_ip', ''),
                event.get('dest_port', 0),
                event.get('threat_type', ''),
                event.get('threat_score', 0),
                event.get('severity', 0),
                event.get('action', ''),
                event.get('details', '')
            ))
            conn.commit()
    
    def block_ip(self, ip: str, reason: str, duration_hours: int = 24):
        expires = time.time() + (duration_hours * 3600)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, expires_at)
                VALUES (?, ?, ?, ?)
            ''', (ip, reason, time.time(), expires))
            conn.commit()
        logger.warning("IP %s blocked for %d hours: %s", ip, duration_hours, reason)
    
    def unblock_ip(self, ip: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
            conn.commit()
    
    def get_blocked_ips(self) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM blocked_ips WHERE expires_at > ?', (time.time(),))
            return [{'ip': row[0], 'reason': row[1], 'expires_at': row[3]} for row in cursor.fetchall()]
    
    def learn_pattern(self, pattern: str, confidence: float):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO learning_memory (pattern, confidence, occurrences, last_seen)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(id) DO UPDATE SET
                    confidence = (confidence + excluded.confidence) / 2,
                    occurrences = occurrences + 1,
                    last_seen = excluded.last_seen
            ''', (pattern, confidence, time.time()))
            conn.commit()


# ============================================================================
# THREAT DETECTOR
# ============================================================================

class ThreatDetector:
    """Detects various types of cyber threats"""
    
    # Known malicious ports
    MALICIOUS_PORTS = {
        4444: "Cobalt Strike", 5555: "Android Debug Bridge",
        1337: "Metasploit", 31337: "Back Orifice",
        6667: "IRC Botnet", 8080: "Proxy", 22: "SSH Brute Force",
        3389: "RDP Attack", 445: "SMB Exploit"
    }
    
    # Suspicious outbound ports (C2)
    C2_PORTS = {4444, 5555, 1337, 31337, 6667, 9999}
    
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.ip_history: Dict[str, deque] = {}
        self.learning_enabled = True
        self.confidence_threshold = 0.6
    
    def detect(self, src_ip: str, dst_ip: str, dst_port: int, 
               bytes_sent: int, duration_ms: float, 
               process_name: str = "", log_line: str = "") -> Optional[Dict]:
        """
        Analyze a network event for threats
        Returns threat dict or None if benign
        """
        threats = []
        
        # 1. C2 Beacon Detection
        if dst_port in self.C2_PORTS:
            threats.append({
                'category': ThreatCategory.C2_BEACON,
                'score': 0.92,
                'severity': ThreatSeverity.CRITICAL,
                'reason': f'Connection to known C2 port {dst_port}'
            })
        
        # 2. Port Scan Detection
        if src_ip not in self.ip_history:
            self.ip_history[src_ip] = deque(maxlen=100)
        
        recent_ports = self.ip_history[src_ip]
        if dst_port not in recent_ports:
            recent_ports.append(dst_port)
        
        if len(set(recent_ports)) > 20 and duration_ms < 50:
            threats.append({
                'category': ThreatCategory.PORT_SCAN,
                'score': 0.75,
                'severity': ThreatSeverity.MEDIUM,
                'reason': f'Port scan detected: {len(set(recent_ports))} ports in short period'
            })
        
        # 3. Brute Force Detection
        if dst_port == 22 and 'failed' in log_line.lower():
            threats.append({
                'category': ThreatCategory.BRUTE_FORCE,
                'score': 0.85,
                'severity': ThreatSeverity.HIGH,
                'reason': f'SSH brute force attempt: {log_line[:100]}'
            })
        
        # 4. Data Exfiltration Detection
        if bytes_sent > 100000 and dst_port == 53:
            threats.append({
                'category': ThreatCategory.DATA_EXFIL,
                'score': 0.88,
                'severity': ThreatSeverity.CRITICAL,
                'reason': f'Potential DNS exfiltration: {bytes_sent} bytes sent'
            })
        
        # 5. Malware Detection
        if '.exe' in process_name.lower() and 'temp' in process_name.lower():
            threats.append({
                'category': ThreatCategory.MALWARE,
                'score': 0.80,
                'severity': ThreatSeverity.HIGH,
                'reason': f'Suspicious process: {process_name}'
            })
        
        # Return highest severity threat
        if threats:
            best = max(threats, key=lambda x: x['score'])
            best['source_ip'] = src_ip
            best['dest_ip'] = dst_ip
            best['dest_port'] = dst_port
            return best
        
        return None
    
    def update_learning(self, threat: Dict, was_correct: bool):
        """Self-modification: learn from feedback"""
        if not self.learning_enabled:
            return
        
        pattern = f"{threat['category'].value}_{threat['dest_port']}"
        confidence = threat['score'] * (1.1 if was_correct else 0.5)
        
        self.db.learn_pattern(pattern, confidence)
        logger.info("Learning updated for pattern: %s (confidence: %.2f)", pattern, confidence)


# ============================================================================
# RESPONSE ENGINE
# ============================================================================

class ResponseEngine:
    """Executes response actions based on threat severity"""
    
    def __init__(self, db: DatabaseManager, dry_run: bool = True):
        self.db = db
        self.dry_run = dry_run
        self.blocked_ips: Dict[str, float] = {}
        self.action_history: List[Dict] = []
        self.webhook_url = None
        
    def set_webhook(self, url: str):
        self.webhook_url = url
    
    def execute(self, threat: Dict) -> Dict:
        """Execute appropriate response for detected threat"""
        severity = threat['severity']
        src_ip = threat['source_ip']
        action = self._determine_action(severity)
        
        result = {
            'action': action.value,
            'timestamp': time.time(),
            'target': src_ip,
            'threat': threat['category'].value,
            'severity': severity.value,
            'dry_run': self.dry_run
        }
        
        # Execute based on action type
        if action == ResponseAction.BLOCK_IP:
            if not self.dry_run:
                self.db.block_ip(src_ip, threat['reason'], 24)
                self.blocked_ips[src_ip] = time.time() + 86400
                self._send_webhook(f"🚨 PRIMUS Blocked {src_ip}: {threat['reason']}")
            result['message'] = f"Blocked IP {src_ip}"
            
        elif action == ResponseAction.INCREASE_LOGGING:
            result['message'] = f"Increased logging for {src_ip}"
            
        elif action == ResponseAction.ESCALATE_HUMAN:
            self._send_webhook(f"⚠️ PRIMUS Alert: {threat['category'].value} from {src_ip}")
            result['message'] = f"Escalated to human: {threat['reason']}"
            
        else:  # LOG_ONLY
            result['message'] = f"Logged threat from {src_ip}"
        
        # Log to database
        self.db.log_event({
            'timestamp': time.time(),
            'source_ip': src_ip,
            'threat_type': threat['category'].value,
            'threat_score': threat['score'],
            'severity': severity.value,
            'action': action.value,
            'details': threat['reason']
        })
        
        self.action_history.append(result)
        return result
    
    def _determine_action(self, severity: ThreatSeverity) -> ResponseAction:
        """Determine action based on severity level"""
        mapping = {
            ThreatSeverity.INFO: ResponseAction.LOG_ONLY,
            ThreatSeverity.LOW: ResponseAction.LOG_ONLY,
            ThreatSeverity.MEDIUM: ResponseAction.INCREASE_LOGGING,
            ThreatSeverity.HIGH: ResponseAction.BLOCK_IP,
            ThreatSeverity.CRITICAL: ResponseAction.ESCALATE_HUMAN
        }
        return mapping.get(severity, ResponseAction.LOG_ONLY)
    
    def _send_webhook(self, message: str):
        """Send alert to configured webhook (Slack, Teams, etc.)"""
        if self.webhook_url:
            try:
                import requests
                requests.post(self.webhook_url, json={'text': message}, timeout=2)
            except Exception as e:
                logger.warning("Webhook failed: %s", e)
    
    def get_stats(self) -> Dict:
        return {
            'total_actions': len(self.action_history),
            'blocked_ips': len(self.blocked_ips),
            'dry_run': self.dry_run,
            'recent_actions': self.action_history[-10:]
        }


# ============================================================================
# PRIMUS CORE ENGINE
# ============================================================================

class PRIMUSCore:
    """Main PRIMUS engine - integrates all components"""
    
    def __init__(self, config_path: str = "primus_config.json"):
        self.config = self._load_config(config_path)
        self.db = DatabaseManager()
        self.detector = ThreatDetector(self.db)
        self.response = ResponseEngine(self.db, dry_run=self.config.get('dry_run', True))
        self.running = False
        self.stats = {
            'events_processed': 0,
            'threats_detected': 0,
            'start_time': time.time()
        }
        
        # Setup webhook if configured
        if self.config.get('webhook_url'):
            self.response.set_webhook(self.config['webhook_url'])
        
        logger.info("PRIMUS Core initialized")
    
    def _load_config(self, path: str) -> Dict:
        default_config = {
            'dry_run': True,
            'auto_block': True,
            'learning_enabled': True,
            'webhook_url': None,
            'ip_whitelist': ['127.0.0.1', '192.168.1.1'],
            'port_whitelist': [80, 443, 53]
        }
        
        if os.path.exists(path):
            with open(path, 'r') as f:
                config = json.load(f)
                default_config.update(config)
        else:
            with open(path, 'w') as f:
                json.dump(default_config, f, indent=2)
        
        return default_config
    
    def analyze_event(self, source_ip: str, dest_ip: str, dest_port: int,
                      bytes_sent: int = 0, duration_ms: float = 0,
                      process_name: str = "", log_line: str = "") -> Dict:
        """
        Analyze a single network event
        Returns analysis result with threat info and action taken
        """
        self.stats['events_processed'] += 1
        
        # Whitelist check
        if source_ip in self.config.get('ip_whitelist', []):
            return {'status': 'ignored', 'reason': 'IP whitelisted'}
        
        if dest_port in self.config.get('port_whitelist', []):
            return {'status': 'ignored', 'reason': 'Port whitelisted'}
        
        # Detect threat
        threat = self.detector.detect(
            source_ip, dest_ip, dest_port,
            bytes_sent, duration_ms, process_name, log_line
        )
        
        if threat:
            self.stats['threats_detected'] += 1
            logger.warning("THREAT DETECTED: %s from %s (score: %.2f)", 
                          threat['category'].value, source_ip, threat['score'])
            
            # Execute response
            result = self.response.execute(threat)
            
            # Update learning (for self-modification)
            self.detector.update_learning(threat, was_correct=True)
            
            return {
                'status': 'threat_detected',
                'threat': threat['category'].value,
                'score': threat['score'],
                'severity': threat['severity'].value,
                'action': result['action'],
                'message': result['message']
            }
        
        return {'status': 'clean', 'threat': None}
    
    def get_status(self) -> Dict:
        uptime = time.time() - self.stats['start_time']
        return {
            'running': self.running,
            'uptime_seconds': uptime,
            'events_processed': self.stats['events_processed'],
            'threats_detected': self.stats['threats_detected'],
            'threat_rate': self.stats['threats_detected'] / max(1, self.stats['events_processed']),
            'blocked_ips': len(self.response.blocked_ips),
            'dry_run': self.response.dry_run,
            'learning_enabled': self.detector.learning_enabled,
            'config': self.config
        }
    
    def halt(self):
        """Emergency stop"""
        self.running = False
        logger.warning("PRIMUS HALTED - Emergency stop activated")
    
    def resume(self):
        """Resume operations"""
        self.running = True
        logger.info("PRIMUS RESUMED")
    
    def set_dry_run(self, enabled: bool):
        self.response.dry_run = enabled
        self.config['dry_run'] = enabled
        logger.info("Dry-run mode: %s", enabled)
    
    def unblock_ip(self, ip: str):
        self.db.unblock_ip(ip)
        self.response.blocked_ips.pop(ip, None)
        logger.info("IP %s unblocked", ip)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    print("="*60)
    print("🛡️  PRIMUS - Self-Modifying Cybersecurity System")
    print("="*60)
    
    primus = PRIMUSCore()
    print(f"\n✅ PRIMUS initialized")
    print(f"   Dry-run mode: {primus.config['dry_run']}")
    print(f"   Learning: {primus.config['learning_enabled']}")
    
    # Test with sample events
    print("\n🧪 Testing with sample attacks...")
    
    test_attacks = [
        ("45.33.22.11", "192.168.1.100", 4444, 500, 30000, "", ""),  # C2 Beacon
        ("203.0.113.45", "192.168.1.100", 22, 150, 300, "sshd", "Failed password for root"),  # Brute Force
        ("192.168.1.100", "8.8.8.8", 53, 250000, 1500, "", ""),  # Data Exfil
    ]
    
    for src, dst, port, bytes_sent, duration, proc, log in test_attacks:
        result = primus.analyze_event(src, dst, port, bytes_sent, duration, proc, log)
        print(f"   {src}:{port} → {result['status']}")
        if result['status'] == 'threat_detected':
            print(f"      Threat: {result.get('threat')} (severity: {result.get('severity')})")
            print(f"      Action: {result.get('action')}")
    
    print("\n✅ PRIMUS is ready for deployment!")