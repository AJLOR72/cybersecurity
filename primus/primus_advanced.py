#!/usr/bin/env python3
"""
PRIMUS-ADVANCED - Self-Learning Autonomous Cybersecurity System
With COGNET-style plasticity and memory
"""

import os
import sys
import json
import time
import sqlite3
import threading
import logging
import hashlib
import random
import numpy as np
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from collections import deque
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import JSONResponse

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger("PRIMUS-ADVANCED")

# Initialize FastAPI app
app = FastAPI(title="PRIMUS-ADVANCED", description="Self-Learning Cybersecurity System")

# ============================================================================
# CONSTANTS & ENUMS
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
    ZERO_DAY = "zero_day"

class ResponseAction(Enum):
    LOG_ONLY = "log_only"
    INCREASE_LOGGING = "increase_logging"
    RATE_LIMIT = "rate_limit"
    BLOCK_IP = "block_ip"
    QUARANTINE = "quarantine"
    ISOLATE_HOST = "isolate_host"
    ESCALATE_HUMAN = "escalate_human"

# ============================================================================
# NEURAL MEMORY (HEBBIAN LEARNING)
# ============================================================================

class NeuralMemory:
    """
    Hebbian learning memory - strengthens connections between correlated threats
    Implements: "Neurons that fire together, wire together"
    """
    
    def __init__(self):
        self.synapses = {}  # (pattern1, pattern2) -> weight
        self.pattern_history = deque(maxlen=1000)
        self.learning_rate = 0.1
        self.decay_rate = 0.01
        
    def learn(self, pattern: str, context: Dict):
        """Learn a pattern with its context"""
        # Create pattern signature
        pattern_key = self._create_pattern_key(pattern, context)
        self.pattern_history.append((pattern_key, time.time()))
        
        # Hebbian update: strengthen connections between co-occurring patterns
        for other_pattern, other_time in list(self.pattern_history)[-10:]:
            if other_pattern != pattern_key and time.time() - other_time < 60:
                synapse_key = tuple(sorted([pattern_key, other_pattern]))
                current = self.synapses.get(synapse_key, 0.5)
                # Hebbian rule: Δw = η * (x_i * x_j)
                self.synapses[synapse_key] = min(1.0, current + self.learning_rate * (1 - current))
        
        # Decay old synapses
        to_remove = []
        for key, weight in self.synapses.items():
            new_weight = weight - self.decay_rate
            if new_weight <= 0:
                to_remove.append(key)
            else:
                self.synapses[key] = new_weight
        
        for key in to_remove:
            del self.synapses[key]
    
    def predict(self, pattern: str, context: Dict) -> List[Tuple[str, float]]:
        """Predict related threats based on learned patterns"""
        pattern_key = self._create_pattern_key(pattern, context)
        predictions = []
        
        for (p1, p2), weight in self.synapses.items():
            if p1 == pattern_key:
                predictions.append((p2, weight))
            elif p2 == pattern_key:
                predictions.append((p1, weight))
        
        return sorted(predictions, key=lambda x: -x[1])[:5]
    
    def _create_pattern_key(self, pattern: str, context: Dict) -> str:
        """Create unique pattern signature"""
        # Extract key features for pattern matching
        features = [
            pattern,
            context.get('source_ip', '').split('.')[0],  # /8 subnet
            str(context.get('dest_port', 0)),
            context.get('threat_type', '')
        ]
        return "|".join(features)


# ============================================================================
# ANOMALY DETECTOR (ZERO-DAY LEARNING)
# ============================================================================

class AnomalyDetector:
    """
    Learns normal behavior baselines and detects anomalies (zero-day threats)
    """
    
    def __init__(self):
        self.baselines = {}  # ip -> {features: mean, std}
        self.window_size = 100
        self.anomaly_threshold = 2.5  # standard deviations
        
    def update_baseline(self, ip: str, features: Dict):
        """Update normal behavior baseline for an IP"""
        if ip not in self.baselines:
            self.baselines[ip] = {
                'ports': deque(maxlen=self.window_size),
                'bytes_per_sec': deque(maxlen=self.window_size),
                'connection_count': deque(maxlen=self.window_size),
                'time_of_day': deque(maxlen=self.window_size)
            }
        
        baseline = self.baselines[ip]
        baseline['ports'].append(features.get('dest_port', 0))
        baseline['bytes_per_sec'].append(features.get('bytes_sent', 0))
        baseline['connection_count'].append(features.get('connection_count', 1))
        baseline['time_of_day'].append(datetime.now().hour)
    
    def detect_anomaly(self, ip: str, features: Dict) -> Tuple[bool, float]:
        """Detect if current activity is anomalous"""
        if ip not in self.baselines:
            return False, 0.0
        
        baseline = self.baselines[ip]
        anomaly_score = 0.0
        
        # Check port anomaly (new ports)
        current_port = features.get('dest_port', 0)
        if len(baseline['ports']) > 10:
            unique_ports = set(baseline['ports'])
            if current_port not in unique_ports:
                anomaly_score += 0.3
        
        # Check byte rate anomaly
        if len(baseline['bytes_per_sec']) > 10:
            mean_bytes = np.mean(baseline['bytes_per_sec'])
            std_bytes = np.std(baseline['bytes_per_sec']) + 0.01
            current_bytes = features.get('bytes_sent', 0)
            z_score = abs(current_bytes - mean_bytes) / std_bytes
            if z_score > self.anomaly_threshold:
                anomaly_score += min(0.5, (z_score - self.anomaly_threshold) / 10)
        
        # Check connection frequency anomaly
        if len(baseline['connection_count']) > 10:
            mean_conn = np.mean(baseline['connection_count'])
            std_conn = np.std(baseline['connection_count']) + 0.01
            current_conn = features.get('connection_count', 1)
            z_score = abs(current_conn - mean_conn) / std_conn
            if z_score > self.anomaly_threshold:
                anomaly_score += min(0.4, (z_score - self.anomaly_threshold) / 10)
        
        is_anomaly = anomaly_score > 0.5
        return is_anomaly, min(1.0, anomaly_score)


# ============================================================================
# REINFORCEMENT LEARNING AGENT
# ============================================================================

class RLAgent:
    """
    Reinforcement learning agent that learns optimal responses from feedback
    Q-learning with experience replay
    """
    
    def __init__(self, learning_rate=0.1, discount_factor=0.95, epsilon=0.1):
        self.q_table = {}  # (state, action) -> value
        self.lr = learning_rate
        self.gamma = discount_factor
        self.epsilon = epsilon
        self.experience_replay = deque(maxlen=10000)
        
    def get_state_key(self, threat_type: str, severity: int, confidence: float) -> str:
        """Convert threat to state key"""
        confidence_level = int(confidence * 10) / 10  # round to 0.1
        return f"{threat_type}|{severity}|{confidence_level}"
    
    def get_action(self, state_key: str, available_actions: List[str]) -> str:
        """Epsilon-greedy action selection"""
        if random.random() < self.epsilon:
            return random.choice(available_actions)
        
        # Get Q-values for all actions in this state
        q_values = {}
        for action in available_actions:
            q_values[action] = self.q_table.get((state_key, action), 0.0)
        
        if not q_values:
            return available_actions[0]
        
        return max(q_values, key=q_values.get)
    
    def learn_from_feedback(self, state_key: str, action: str, reward: float, next_state: str):
        """Q-learning update"""
        # Current Q-value
        old_q = self.q_table.get((state_key, action), 0.0)
        
        # Best future Q-value
        future_actions = self.get_available_actions(state_key)
        future_q = max([self.q_table.get((next_state, a), 0.0) for a in future_actions], default=0.0)
        
        # Q-learning update
        new_q = old_q + self.lr * (reward + self.gamma * future_q - old_q)
        self.q_table[(state_key, action)] = new_q
        
        # Store experience
        self.experience_replay.append((state_key, action, reward, next_state))
    
    def get_available_actions(self, state_key: str) -> List[str]:
        """Get available actions for a state"""
        # Based on severity
        parts = state_key.split('|')
        severity = int(parts[1]) if len(parts) > 1 else 3
        
        if severity >= 5:
            return ['escalate_human', 'isolate_host']
        elif severity >= 4:
            return ['block_ip', 'quarantine']
        elif severity >= 3:
            return ['block_ip', 'increase_logging']
        else:
            return ['log_only', 'increase_logging']
    
    def get_reward(self, action: str, was_correct: bool, severity: int) -> float:
        """Calculate reward based on action outcome"""
        if was_correct:
            # Positive reward for correct action
            base_reward = 1.0
            # Bonus for taking appropriate severity action
            if severity >= 4 and action in ['block_ip', 'escalate_human']:
                base_reward += 0.5
            return base_reward
        else:
            # Negative reward for incorrect action
            return -0.5


# ============================================================================
# CROSS-IP CORRELATION ENGINE
# ============================================================================

class CorrelationEngine:
    """
    Links attacks from different IPs into coordinated campaigns
    Detects distributed attacks (DDoS, coordinated scanning)
    """
    
    def __init__(self, time_window=300):  # 5 minutes
        self.time_window = time_window
        self.attack_events = deque(maxlen=10000)
        self.campaigns = {}
        
    def add_event(self, event: Dict):
        """Add an attack event for correlation"""
        self.attack_events.append({
            'timestamp': time.time(),
            'source_ip': event.get('source_ip'),
            'target_ip': event.get('dest_ip'),
            'threat_type': event.get('threat_type'),
            'severity': event.get('severity')
        })
        self._detect_campaigns()
    
    def _detect_campaigns(self):
        """Detect coordinated attack campaigns"""
        now = time.time()
        campaign_id = f"campaign_{int(now)}"
        
        # Group events by target and time window
        for event in self.attack_events:
            if now - event['timestamp'] > self.time_window:
                continue
            
            target = event['target_ip']
            if target not in self.campaigns:
                self.campaigns[target] = []
            
            # Check if this event is part of an existing campaign
            is_new = True
            for campaign in self.campaigns[target]:
                if now - campaign['last_seen'] < self.time_window:
                    campaign['events'].append(event)
                    campaign['last_seen'] = now
                    campaign['unique_sources'] = len(set(e['source_ip'] for e in campaign['events']))
                    is_new = False
                    break
            
            if is_new:
                self.campaigns[target].append({
                    'id': campaign_id,
                    'events': [event],
                    'start_time': now,
                    'last_seen': now,
                    'unique_sources': 1
                })
        
        # Clean old campaigns
        for target in list(self.campaigns.keys()):
            self.campaigns[target] = [c for c in self.campaigns[target] 
                                      if now - c['last_seen'] < self.time_window]
            if not self.campaigns[target]:
                del self.campaigns[target]
    
    def get_campaign_risk(self, target_ip: str) -> float:
        """Calculate risk score for a target based on coordinated attacks"""
        if target_ip not in self.campaigns:
            return 0.0
        
        risk = 0.0
        for campaign in self.campaigns[target_ip]:
            # More sources = higher risk (DDoS indication)
            source_bonus = min(1.0, campaign['unique_sources'] / 10)
            # More events = higher risk
            event_bonus = min(1.0, len(campaign['events']) / 50)
            risk = max(risk, (source_bonus + event_bonus) / 2)
        
        return risk


# ============================================================================
# ENHANCED PRIMUS CORE
# ============================================================================

class PRIMUSAdvanced:
    """Advanced self-learning cybersecurity system"""
    
    def __init__(self, config_path: str = "primus_config.json"):
        self.config = self._load_config(config_path)
        
        # Advanced components
        self.memory = NeuralMemory()
        self.anomaly_detector = AnomalyDetector()
        self.rl_agent = RLAgent()
        self.correlation_engine = CorrelationEngine()
        
        # Database
        self.db_path = "primus_advanced.db"
        self._init_database()
        
        # State
        self.running = True
        self.dry_run = self.config.get('dry_run', True)
        self.stats = {
            'events_processed': 0,
            'threats_detected': 0,
            'zero_day_detected': 0,
            'start_time': time.time(),
            'learning_iterations': 0
        }
        
        # IP tracking for correlation
        self.ip_connections = {}
        
        logger.info("PRIMUS-ADVANCED initialized with self-learning capabilities")
    
    def _load_config(self, path: str) -> Dict:
        default_config = {
            'dry_run': True,
            'auto_block': True,
            'learning_enabled': True,
            'anomaly_detection': True,
            'correlation_enabled': True,
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
    
    def _init_database(self):
        """Initialize advanced database schema"""
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
                    confidence REAL,
                    zero_day BOOLEAN,
                    details TEXT
                )
            ''')
            
            # Learned patterns table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS learned_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern TEXT,
                    confidence REAL,
                    occurrences INTEGER,
                    last_seen REAL,
                    successful BOOLEAN
                )
            ''')
            
            # RL experiences table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rl_experiences (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    state TEXT,
                    action TEXT,
                    reward REAL,
                    timestamp REAL
                )
            ''')
            
            # Baseline table for anomaly detection
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS baselines (
                    ip TEXT,
                    feature TEXT,
                    mean REAL,
                    std REAL,
                    samples INTEGER,
                    updated_at REAL,
                    PRIMARY KEY (ip, feature)
                )
            ''')
            
            conn.commit()
            logger.info("Advanced database initialized")
    
    def analyze_event(self, source_ip: str, dest_ip: str, dest_port: int,
                      bytes_sent: int = 0, duration_ms: float = 0,
                      process_name: str = "", log_line: str = "",
                      protocol: str = "tcp") -> Dict:
        """
        Analyze event with advanced threat detection
        """
        self.stats['events_processed'] += 1
        
        # Whitelist check
        if source_ip in self.config.get('ip_whitelist', []):
            return {'status': 'ignored', 'reason': 'IP whitelisted'}
        
        if dest_port in self.config.get('port_whitelist', []):
            return {'status': 'ignored', 'reason': 'Port whitelisted'}
        
        # Track connection frequency
        conn_key = (source_ip, dest_ip)
        self.ip_connections[conn_key] = self.ip_connections.get(conn_key, 0) + 1
        connection_count = self.ip_connections.get(conn_key, 1)
        
        # Build feature vector for anomaly detection
        features = {
            'dest_port': dest_port,
            'bytes_sent': bytes_sent,
            'duration_ms': duration_ms,
            'connection_count': connection_count,
            'protocol': protocol
        }
        
        # Update baseline for this IP
        self.anomaly_detector.update_baseline(source_ip, features)
        
        # Detect anomalies (zero-day potential)
        is_anomaly, anomaly_score = self.anomaly_detector.detect_anomaly(source_ip, features)
        
        # Threat detection logic
        threat = None
        confidence = 0.0
        
        # 1. C2 Beacon Detection
        if dest_port in [4444, 5555, 1337, 31337, 6667, 9999]:
            threat = ThreatCategory.C2_BEACON
            confidence = 0.92
            severity = ThreatSeverity.CRITICAL
        
        # 2. Brute Force Detection
        elif dest_port == 22 and 'failed' in log_line.lower():
            threat = ThreatCategory.BRUTE_FORCE
            confidence = 0.85
            severity = ThreatSeverity.HIGH
        
        # 3. Data Exfiltration
        elif bytes_sent > 100000 and dest_port == 53:
            threat = ThreatCategory.DATA_EXFIL
            confidence = 0.88
            severity = ThreatSeverity.CRITICAL
        
        # 4. Port Scan Detection
        elif self._is_port_scan(source_ip, dest_port, duration_ms):
            threat = ThreatCategory.PORT_SCAN
            confidence = 0.75
            severity = ThreatSeverity.MEDIUM
        
        # 5. Malware Detection
        elif '.exe' in process_name.lower() and 'temp' in process_name.lower():
            threat = ThreatCategory.MALWARE
            confidence = 0.80
            severity = ThreatSeverity.HIGH
        
        # 6. Lateral Movement
        elif source_ip.startswith('192.168.') and dest_port == 445:
            threat = ThreatCategory.LATERAL_MOVEMENT
            confidence = 0.70
            severity = ThreatSeverity.HIGH
        
        # 7. Zero-day anomaly
        elif is_anomaly and self.config.get('anomaly_detection', True):
            threat = ThreatCategory.ZERO_DAY
            confidence = anomaly_score
            severity = ThreatSeverity.HIGH
            self.stats['zero_day_detected'] += 1
            logger.warning(f"ZERO-DAY ANOMALY detected from {source_ip} (score: {anomaly_score:.2f})")
        
        # If threat detected, process it
        if threat:
            self.stats['threats_detected'] += 1
            
            # Hebbian learning: remember this pattern
            context = {
                'source_ip': source_ip,
                'dest_port': dest_port,
                'threat_type': threat.value
            }
            self.memory.learn(threat.value, context)
            
            # Predict related threats
            predictions = self.memory.predict(threat.value, context)
            if predictions:
                logger.info(f"Related threat prediction: {predictions[:3]}")
            
            # Get RL action
            state_key = self.rl_agent.get_state_key(threat.value, severity.value, confidence)
            available_actions = self.rl_agent.get_available_actions(state_key)
            action = self.rl_agent.get_action(state_key, available_actions)
            
            # Execute response
            result = self._execute_response(threat, severity, source_ip, action, confidence)
            
            # Store event
            self._store_event(source_ip, dest_ip, dest_port, threat.value, 
                             confidence, severity.value, action, is_anomaly, result)
            
            # Update correlation engine
            if self.config.get('correlation_enabled', True):
                self.correlation_engine.add_event({
                    'source_ip': source_ip,
                    'dest_ip': dest_ip,
                    'threat_type': threat.value,
                    'severity': severity.value
                })
                
                # Check coordinated attack risk
                campaign_risk = self.correlation_engine.get_campaign_risk(dest_ip)
                if campaign_risk > 0.7:
                    logger.warning(f"COORDINATED ATTACK on {dest_ip} - risk: {campaign_risk:.2f}")
                    # Escalate risk
                    if campaign_risk > 0.8:
                        self._execute_response(threat, ThreatSeverity.CRITICAL, source_ip,
                                              'escalate_human', confidence)
            
            return {
                'status': 'threat_detected',
                'threat': threat.value,
                'score': confidence,
                'severity': severity.value,
                'action': action,
                'message': result.get('message', ''),
                'zero_day': is_anomaly,
                'predictions': [p[0] for p in predictions[:3]]
            }
        
        return {'status': 'clean', 'threat': None}
    
    def _is_port_scan(self, ip: str, dest_port: int, duration_ms: float) -> bool:
        """Detect port scanning behavior"""
        if ip not in self._port_scan_tracker:
            self._port_scan_tracker[ip] = {'ports': set(), 'timestamps': deque(maxlen=50)}
        
        tracker = self._port_scan_tracker[ip]
        tracker['ports'].add(dest_port)
        tracker['timestamps'].append(time.time())
        
        # Check if more than 20 ports in last 10 seconds
        recent_timestamps = [t for t in tracker['timestamps'] if time.time() - t < 10]
        if len(tracker['ports']) > 20 or (len(recent_timestamps) > 30 and duration_ms < 50):
            return True
        
        return False
    
    _port_scan_tracker = {}
    
    def _execute_response(self, threat: ThreatCategory, severity: ThreatSeverity,
                          target_ip: str, action: str, confidence: float) -> Dict:
        """Execute response action"""
        result = {
            'action': action,
            'target': target_ip,
            'timestamp': time.time(),
            'dry_run': self.dry_run
        }
        
        if not self.running:
            result['message'] = "System halted"
            return result
        
        if action == 'block_ip' and not self.dry_run:
            # Block IP (simulate - in production, call firewall API)
            result['message'] = f"Blocked IP {target_ip} for {threat.value}"
            logger.warning(f"BLOCKED IP: {target_ip} - {threat.value}")
        
        elif action == 'quarantine' and not self.dry_run:
            result['message'] = f"Quarantined {target_ip}"
            logger.warning(f"QUARANTINED: {target_ip}")
        
        elif action == 'escalate_human' and not self.dry_run:
            result['message'] = f"Escalated {threat.value} to human review"
            logger.warning(f"ESCALATED: {threat.value} from {target_ip}")
        
        elif action == 'increase_logging' and not self.dry_run:
            result['message'] = f"Increased logging for {target_ip}"
        
        else:
            result['message'] = f"[DRY-RUN] Would {action} {target_ip}"
        
        return result
    
    def _store_event(self, source_ip: str, dest_ip: str, dest_port: int,
                     threat_type: str, confidence: float, severity: int,
                     action: str, is_zero_day: bool, result: Dict):
        """Store event in database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO events (timestamp, source_ip, dest_ip, dest_port,
                                   threat_type, threat_score, severity, action,
                                   confidence, zero_day, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                time.time(), source_ip, dest_ip, dest_port,
                threat_type, confidence, severity, action,
                confidence, is_zero_day, result.get('message', '')
            ))
            conn.commit()
    
    def learn_from_feedback(self, event_id: int, was_correct: bool):
        """Reinforcement learning from human feedback"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT threat_type, severity, action FROM events WHERE id = ?', (event_id,))
            row = cursor.fetchone()
            
            if row:
                threat_type, severity, action = row
                state_key = self.rl_agent.get_state_key(threat_type, severity, 0.8)
                reward = self.rl_agent.get_reward(action, was_correct, severity)
                self.rl_agent.learn_from_feedback(state_key, action, reward, state_key)
                
                # Store learned pattern
                cursor.execute('''
                    INSERT INTO learned_patterns (pattern, confidence, occurrences, last_seen, successful)
                    VALUES (?, ?, 1, ?, ?)
                    ON CONFLICT DO UPDATE SET 
                        confidence = (confidence + excluded.confidence) / 2,
                        occurrences = occurrences + 1,
                        last_seen = excluded.last_seen,
                        successful = excluded.successful
                ''', (threat_type, 0.8 if was_correct else 0.2, time.time(), was_correct))
                conn.commit()
                
                logger.info(f"Learned from feedback: {threat_type} was {'correct' if was_correct else 'incorrect'}")
    
    def get_status(self) -> Dict:
        """Get detailed status"""
        uptime = time.time() - self.stats['start_time']
        return {
            'running': self.running,
            'uptime_seconds': uptime,
            'events_processed': self.stats['events_processed'],
            'threats_detected': self.stats['threats_detected'],
            'zero_day_detected': self.stats['zero_day_detected'],
            'threat_rate': self.stats['threats_detected'] / max(1, self.stats['events_processed']),
            'dry_run': self.dry_run,
            'learning_enabled': self.config.get('learning_enabled', True),
            'memory_synapses': len(self.memory.synapses),
            'rl_experiences': len(self.rl_agent.experience_replay),
            'active_campaigns': len(self.correlation_engine.campaigns),
            'config': self.config
        }
    
    def set_dry_run(self, enabled: bool):
        self.dry_run = enabled
        logger.info(f"Dry-run mode: {enabled}")
    
    def halt(self):
        self.running = False
        logger.warning("PRIMUS-ADVANCED HALTED")
    
    def resume(self):
        self.running = True
        logger.info("PRIMUS-ADVANCED RESUMED")
@app.get("/threats")
async def get_threats(limit: int = 50):
    """Get recent threats from database"""
    import sqlite3
    try:
        conn = sqlite3.connect('primus_advanced.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT timestamp, source_ip, threat_type, threat_score, severity, action, zero_day
            FROM events 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        threats = []
        for row in cursor.fetchall():
            threats.append({
                'timestamp': row[0],
                'source_ip': row[1],
                'threat_type': row[2],
                'threat_score': row[3],
                'severity': row[4],
                'action': row[5],
                'zero_day': bool(row[6]) if row[6] else False
            })
        conn.close()
        return {"threats": threats, "count": len(threats)}
    except Exception as e:
        return {"threats": [], "count": 0, "error": str(e)}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    print("="*60)
    print("🧠 PRIMUS-ADVANCED - Self-Learning Cybersecurity System")
    print("="*60)
    
    primus = PRIMUSAdvanced()
    
    print(f"\n✅ System initialized")
    print(f"   Mode: {'DRY-RUN' if primus.dry_run else 'LIVE'}")
    print(f"   Learning: {primus.config.get('learning_enabled', True)}")
    print(f"   Anomaly Detection: {primus.config.get('anomaly_detection', True)}")
    
    # Test with sample attacks
    print("\n🧪 Testing threat detection...")
    
    test_attacks = [
        ("45.33.22.11", "192.168.1.100", 4444, 500, 30000, "", ""),  # C2 Beacon
        ("203.0.113.45", "192.168.1.100", 22, 150, 300, "sshd", "Failed password for root"),  # Brute Force
        ("192.168.1.100", "8.8.8.8", 9999, 250000, 1500, "", ""),  # Data Exfil (non-standard port)
    ]
    
    for src, dst, port, bytes_sent, duration, proc, log in test_attacks:
        result = primus.analyze_event(src, dst, port, bytes_sent, duration, proc, log)
        print(f"   {src}:{port} → {result['status']}")
        if result['status'] == 'threat_detected':
            print(f"      Threat: {result['threat']} (score: {result['score']})")
            print(f"      Action: {result['action']}")
            if result.get('zero_day'):
                print(f"      ⚠️ ZERO-DAY ANOMALY")
    
    print("\n✅ PRIMUS-ADVANCED ready for deployment")