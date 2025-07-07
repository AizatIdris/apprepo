from scapy.all import *
from collections import defaultdict
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import time
import psutil
import threading
from queue import Queue, Empty
import tkinter as tk
from tkinter import ttk
import joblib
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from colorama import init, Fore, Back, Style
import warnings
import json
import subprocess
from threading import Timer
import os
import sqlite3
from sklearn.base import BaseEstimator, ClassifierMixin
from database import NetworkDatabase

# Initialize colorama
init(autoreset=True)
warnings.filterwarnings('ignore')

alert_queue = Queue(maxsize=1000)  # Queue to hold alerts for real-time processing

class LSTMWrapper(BaseEstimator, ClassifierMixin):
    """Wrapper to make LSTM compatible with sklearn VotingClassifier"""
    def __init__(self, model):
        self.model = model
    
    def fit(self, X, y):
        X_reshaped = X.reshape((X.shape[0], 1, X.shape[1]))
        self.model.fit(X_reshaped, y, verbose=0)
        return self
    
    def predict(self, X):
        X_reshaped = X.reshape((X.shape[0], 1, X.shape[1]))
        return (self.model.predict(X_reshaped) > 0.5).astype(int).flatten()
    
    def predict_proba(self, X):
        X_reshaped = X.reshape((X.shape[0], 1, X.shape[1]))
        proba = self.model.predict(X_reshaped)
        return np.hstack([1 - proba, proba])

class NetworkMonitor:
    def _init_db(self):
        """Initialize database tables"""
        with sqlite3.connect('network_monitor.db') as conn:
            cursor = conn.cursor()
            
            # Create blocked_ips table if not exists
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                source_ip TEXT,
                dest_ip TEXT,
                reason TEXT,
                unblock_time DATETIME
            )
            ''')
            
            # Create suspicious_activity table if not exists
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS suspicious_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                source_ip TEXT,
                dest_ip TEXT,
                protocol TEXT,
                description TEXT,
                confidence REAL,
                features TEXT
            )
            ''')
            
            # Create packet_log table if not exists
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS packet_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                source_ip TEXT,
                dest_ip TEXT,
                protocol TEXT,
                length INTEGER,
                src_port INTEGER,
                dest_port INTEGER,
                flags TEXT
            )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocked_ips_source_ip ON blocked_ips(source_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_suspicious_activity_source_ip ON suspicious_activity(source_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_packet_log_timestamp ON packet_log(timestamp)')
            
            conn.commit()

    def __init__(self):
        # Attack detection thresholds
        self.scaler = None
        self.pattern_weight = {
            'sequential_ports': 0.15,
            'syn_packets': 0.10,
            'unique_ports': 0.12,
        }
        self.db = NetworkDatabase()
        self._init_db()
        
        self.thresholds = {
            'dos': {
                'packet_rate': 500,
                'syn_rate': 60,
                'small_packet_rate': 2000,
                'duration': 1
            },
            'port_scan': {
                'unique_ports': 20,
                'port_ratio': 2,
                'stealth_scan': {
                    'fin_threshold': 5,
                    'xmas_threshold': 5,
                    'null_threshold': 5,
                    'ack_threshold': 5
                },
                'aggressive_syn_threshold': 100,
                'service_detect_threshold': 10,
                'udp_scan_threshold': 20,
                'comprehensive_scan_threshold': 5
            },
            'mitm': {
                'arp_cache_poisoning': 3
            },
            'nmap': {
                'os_detection': 5,
                'idle_scan': 5
            }
        }
        
        # State tracking
        self.syn_tracker = {}
        self.dos_alert_state = {}
        self.port_scan_history = defaultdict(lambda: defaultdict(int))
        self.flows = defaultdict(lambda: {'packets': [], 'start_time': None})
        self.packet_queue = Queue()
        self.is_running = False
        self.model = None
        self.pipeline = None
        self.feature_names = None
        self.interface = None
        self.alert_count = defaultdict(int)
        self.arp_table = {}  # IP -> MAC mapping
        self.blocked_ips = set()
        self.scan_techniques = defaultdict(int)
        self.devices = {}  # Track discovered devices
        self.local_network = None
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'suspicious_flows': 0,
            'alerts': defaultdict(int),
            'suspicious_activities': 0,
            'attack_types': defaultdict(int),
            'scan_types': defaultdict(int)
        }
        
        self.class_names = {0: 'Normal', 1: 'Attack'}
        self.attack_threshold = 0.38
        
        # AI thresholds
        self.ai_thresholds = {
            'normal': 0.25,
            'attack': 0.40,
            'suspicious': 0.85
        }
        
        self.min_packets_for_analysis = 5
        self.interface_ip = None

    def load_model(self, model_path):
        """Load the complete model bundle"""
        try:
            print(f"{Fore.YELLOW}Loading AI model...{Style.RESET_ALL}")
            bundle = joblib.load(model_path)
            self.model = bundle['models']['full_ensemble'] 
            self.scaler = bundle['scaler']
            self.feature_names = bundle['feature_names']
            print(f"{Fore.GREEN}Model loaded successfully!{Style.RESET_ALL}")
            print(f"Features expected ({len(self.feature_names)}):")
            print(self.feature_names)
            self.test_model(attack_threshold=self.attack_threshold)
        except Exception as e:
            print(f"{Fore.RED}Error loading model: {e}{Style.RESET_ALL}")

    def is_whitelisted_traffic(self, src_ip):
        """Check if traffic should be whitelisted"""
        whitelist_ips = [
            '192.168.0.1',  # Router
            '8.8.8.8',      # Google DNS
            '1.1.1.1',      # Cloudflare DNS
            '192.168.0.117',
        ]
        
        if src_ip.endswith('.255') or src_ip.startswith(('224.', '239.')):
            return True
        
        return src_ip in whitelist_ips

    def get_readable_interfaces(self):
        """Get network interfaces with MAC addresses"""
        return {
            iface: f"{iface} ({next((addr.address for addr in addrs if addr.family == psutil.AF_LINK), '')})"
            for iface, addrs in psutil.net_if_addrs().items()
        }

    def scan_network(self, subnet=None):
        """Discover all devices on the local network using ARP"""
        if not subnet:
            if self.interface_ip:
                subnet = ".".join(self.interface_ip.split(".")[:3]) + ".0/24"
            else:
                print(f"{Fore.RED}Cannot determine subnet for scanning{Style.RESET_ALL}")
                return []

        print(f"{Fore.CYAN}Scanning network {subnet}...{Style.RESET_ALL}")
        
        # Create ARP request packet
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        try:
            # Send packet and get responses
            result = srp(packet, timeout=3, verbose=0)[0]
            
            self.devices = {}
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc
                self.devices[ip] = {
                    'mac': mac,
                    'type': self.guess_device_type(ip, mac),
                    'last_seen': time.time()
                }
                self.arp_table[ip] = mac  # Update ARP table

            print(f"{Fore.GREEN}Discovered {len(self.devices)} devices:{Style.RESET_ALL}")
            for ip, data in self.devices.items():
                print(f"  {ip} ({data['mac']}) - {data['type']}")

            return self.devices

        except Exception as e:
            print(f"{Fore.RED}Network scan failed: {e}{Style.RESET_ALL}")
            return []

    def guess_device_type(self, ip, mac):
        """Guess device type based on IP and MAC"""
        if ip.endswith('.1'):
            return "Router/Gateway"

        # Normalize MAC OUI
        oui = mac.upper().replace('-', ':')[:8]

        # Known OUIs for different device types
        iot_ouis = ['00:1A:22', '00:0D:83', '00:12:1C', '00:1E:42']
        apple_ouis = ['F8:FF:C2', '68:5B:35', 'A4:5E:60', '3C:15:C2', '88:E9:FE']
        android_ouis = [
            'FC:C2:DE',  # Samsung
            '00:08:22',  # HTC
            'AC:37:43',  # Huawei
            '38:F9:D3',  # Xiaomi
            '64:BC:0C',  # OnePlus
            '5C:AD:CF',  # Oppo
            '7C:01:91',  # Vivo
            '0C:F3:EE',  # LG
        ]

        if any(oui.startswith(x) for x in iot_ouis):
            return "IoT Device"
        elif any(oui.startswith(x) for x in apple_ouis):
            return "Apple Device"
        elif any(oui.startswith(x) for x in android_ouis):
            return "Android Device"
        else:
            return "Unknown Device"


    def test_model(self, attack_threshold=0.4):
        """Test the model with sample data"""
        test_features = np.array([
            [1000, 80, 1.0, 6, 2000, 12345, 3000, 3000, 0.33, 10, 
             5, 2.5, 2.5, 50, 8.0, 6, 300, 0, 0.5, 12345-80],
            [5, 1, 0.001, 6, 5, 9999, 10000, 1, 0.99, 5000,
             2000, 15.0, 0.01, 0.1, 0.1, 6, 1, 1.0, 9999-1, 0]
        ], dtype=np.float32)
        
        try:
            print("\nModel Test Results (Attack Threshold = {:.2f}):".format(attack_threshold))
            features_scaled = self.scaler.transform(test_features)
            probas = self.model.predict_proba(features_scaled)
            
            predictions = (probas[:, 1] > attack_threshold).astype(int)
            
            for i, (pred, proba) in enumerate(zip(predictions, probas)):
                print(f"Sample {i+1}: Pred={pred}, Prob={proba}, Class={self.class_names[pred]}")
                
        except Exception as e:
            print(f"\nError during testing: {str(e)}")

    def start_capture(self, interface):
        """Start packet capture on specified interface"""
        self.interface = interface
        self.is_running = True
        self.interface_ip = self.get_interface_ip(interface)
        
        # Scan network first
        self.scan_network()

        # Start processing thread
        processor = threading.Thread(target=self.process_packets)
        processor.daemon = True
        processor.start()
        
        # Start stats display thread
        stats_thread = threading.Thread(target=self.display_periodic_stats)
        stats_thread.daemon = True
        stats_thread.start()
        
        print(f"\n{Fore.CYAN}Starting capture on {interface}...{Style.RESET_ALL}")
        print("=" * 90)
        print(f"{'Timestamp':<20} {'Source':<25} {'Destination':<25} {'Protocol':<10} {'Length':<8} {'Alert':<15}")
        print("=" * 90)

        # Start sniffing in promiscuous mode
        sniff(iface=interface, prn=self.packet_callback, store=False, promisc=True)

    def get_interface_ip(self, interface):
        """Get the IP address of our interface"""
        addrs = psutil.net_if_addrs().get(interface, [])
        for addr in addrs:
            if addr.family == 2:  # AF_INET
                return addr.address
        return None

    def log_packet(self, packet):
        """Log packet to database"""
        try:
            if IP in packet:
                ip = packet[IP]
                pkt_data = {
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': ip.src,
                    'dest_ip': ip.dst,
                    'protocol': 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'Other',
                    'length': len(packet),
                    'src_port': packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else None,
                    'dest_port': packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None,
                    'flags': str(packet[TCP].flags) if TCP in packet else None
                }
                
                with sqlite3.connect('network_monitor.db') as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                    INSERT INTO packet_log 
                    (timestamp, source_ip, dest_ip, protocol, length, src_port, dest_port, flags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        pkt_data['timestamp'],
                        pkt_data['source_ip'],
                        pkt_data['dest_ip'],
                        pkt_data['protocol'],
                        pkt_data['length'],
                        pkt_data['src_port'],
                        pkt_data['dest_port'],
                        pkt_data['flags']
                    ))
                    conn.commit()
        except Exception as e:
            print(f"{Fore.RED}Error logging packet: {e}{Style.RESET_ALL}")

    def log_suspicious_activity(self, source_ip, dest_ip, protocol, description, confidence, features=None):
        """Log suspicious activity to separate table"""
        try:
            features_json = json.dumps(features) if features is not None else None
            
            with sqlite3.connect('network_monitor.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                INSERT INTO suspicious_activity 
                (timestamp, source_ip, dest_ip, protocol, description, confidence, features)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.now().isoformat(),
                    source_ip,
                    dest_ip,
                    protocol,
                    description,
                    confidence,
                    features_json
                ))
                conn.commit()
        except Exception as e:
            print(f"{Fore.RED}Error logging suspicious activity: {e}{Style.RESET_ALL}")

    def log_alert(self, alert_type, source_ip, dest_ip, description, severity='medium'):
        """Log alert to database"""
        if alert_type.lower() == 'Normal':
            return
        else:
            with sqlite3.connect('network_monitor.db') as conn:
                cursor= conn.cursor()
                cursor.execute('''
                INSERT INTO alerts 
                (timestamp, alert_type, source_ip, dest_ip, description, severity)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                alert_type,
                source_ip,
                dest_ip,
                description,
                severity
            ))
            conn.commit()

    def packet_callback(self, packet):
        """Process each captured packet"""
        if not self.is_running:
            return

        try:
            # Handle ARP packets separately
            if ARP in packet:
                self.detect_arp_spoofing(packet)
                return

            # Skip non-IP packets
            if not IP in packet:
                return

            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst

            # Skip broadcast/multicast
            if dst_ip.endswith('.255') or dst_ip.startswith(('224.', '239.')):
                return

            # Skip whitelisted IPs
            if self.is_whitelisted_traffic(src_ip):
                return
            
            # Log the packet
            self.log_packet(packet)
            
            # Update device tracking
            if src_ip not in self.devices:
                self.devices[src_ip] = {
                    'mac': packet[Ether].src if Ether in packet else 'Unknown',
                    'type': 'New Device',
                    'last_seen': time.time()
                }
                print(f"{Fore.YELLOW}New device detected: {src_ip}{Style.RESET_ALL}")

            # Process the packet
            protocol = 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'Other'
            flow_key = f"{src_ip}:{dst_ip}:{protocol}"

            # Initialize flow if new
            if flow_key not in self.flows:
                self.flows[flow_key] = {
                    'start_time': time.time(),
                    'packets': []
                }

            # Store packet data
            pkt_data = {
                'timestamp': time.time(),
                'length': len(packet),
                'protocol': protocol,
                'direction': 'in' if dst_ip == self.interface_ip else 'out'
            }

            # Add port info if available
            if TCP in packet:
                tcp = packet[TCP]
                pkt_data.update({
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'flags': tcp.flags,
                    'window': tcp.window
                })
                
                # Detect stealth scans
                if tcp.flags & 0x01:  # FIN scan
                    self.detect_stealth_scan(src_ip, dst_ip, 'FIN')
                elif tcp.flags & 0x02:  # SYN scan
                    self.detect_syn_activity(src_ip, dst_ip, tcp)
                elif tcp.flags & 0x29 == 0x29:  # XMAS scan
                    self.detect_stealth_scan(src_ip, dst_ip, 'XMAS')
                elif tcp.flags == 0:  # NULL scan
                    self.detect_stealth_scan(src_ip, dst_ip, 'NULL')

                self.detect_os_fingerprinting(src_ip, dst_ip, tcp)
                
            elif UDP in packet:
                udp = packet[UDP]
                pkt_data.update({
                    'src_port': udp.sport,
                    'dst_port': udp.dport
                })
                if dst_ip == self.interface_ip and udp.dport > 0:
                    self.detect_udp_scan(src_ip, dst_ip, udp.dport)

            self.flows[flow_key]['packets'].append(pkt_data)
            self.packet_queue.put(packet)
            self.stats['total_packets'] += 1

        except Exception as e:
            print(f"{Fore.RED}Packet processing error: {e}{Style.RESET_ALL}")

    def process_packets(self):
        """Process queued packets for attack detection"""
        while self.is_running:
            try:
                packet = self.packet_queue.get(timeout=1)
                if packet is None:
                    continue

                if IP in packet:
                    ip = packet[IP]
                    src_ip = ip.src
                    dst_ip = ip.dst
                    protocol = 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'Other'
                    flow_key = f"{src_ip}:{dst_ip}:{protocol}"

                    # Initialize flow tracking if needed
                    if flow_key not in self.flows:
                        self.flows[flow_key] = {
                            'start_time': time.time(),
                            'packets': []
                        }

                    # Analyze if we have enough packets or time has passed
                    flow = self.flows[flow_key]
                    if (len(flow['packets']) >= 10 or 
                        (time.time() - flow['start_time']) >= 1):
                        
                        try:
                            alert = self.analyze_flow(flow_key)
                            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            
                            if flow['packets']:
                                last_pkt = flow['packets'][-1]
                                self.print_packet_info(
                                    timestamp, src_ip, dst_ip, protocol, 
                                    last_pkt.get('length', 0), alert
                                )
                            
                            # Reset flow tracking
                            self.flows[flow_key] = {
                                'start_time': time.time(),
                                'packets': []
                            }
                        
                        except Exception as e:
                            print(f"{Fore.RED}Flow analysis error: {e}{Style.RESET_ALL}")

            except Empty:
                continue
            except Exception as e:
                print(f"{Fore.RED}Queue processing error: {e}{Style.RESET_ALL}")

    def detect_arp_spoofing(self, packet):
        """Detect ARP spoofing attacks"""
        if not ARP in packet:
            return

        arp = packet[ARP]
        if arp.op != 2:  # Only check ARP replies
            return

        ip = arp.psrc
        mac = arp.hwsrc
        
        if ip in self.arp_table:
            if self.arp_table[ip] != mac:
                self.alert_count['MITM'] += 1
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                if ip in self.dos_alert_state:
                    self.dos_alert_state[ip]['count'] += 1
                    if self.dos_alert_state[ip]['count'] > self.thresholds['mitm']['arp_cache_poisoning']:
                        alert_msg = f"MITM Attack: {ip} changed MAC {self.dos_alert_state[ip]['count']} times"
                        self.print_packet_info(
                            timestamp, ip, arp.pdst, 'ARP', 
                            len(packet), 
                            (alert_msg, Fore.RED)
                        )
                        self.mitigate_attack(ip, "ARP Spoofing")
                else:
                    self.dos_alert_state[ip] = {'count': 1, 'first_seen': time.time()}
                    self.print_packet_info(
                        timestamp, ip, arp.pdst, 'ARP', 
                        len(packet), 
                        (f"MITM Warning: {ip} changed from {self.arp_table[ip]} to {mac}", Fore.YELLOW)
                    )
        
        self.arp_table[ip] = mac

    def detect_stealth_scan(self, src_ip, dst_ip, scan_type):
        """Detect stealth scans (FIN, XMAS, NULL)"""
        if self.is_whitelisted_traffic(src_ip):
            return
        
        threshold = self.thresholds['port_scan']['stealth_scan'].get(f"{scan_type.lower()}_threshold", 5)
        
        if dst_ip == self.interface_ip or dst_ip.startswith('192.168.'):
            self.port_scan_history[src_ip][scan_type] += 1
            self.scan_techniques[src_ip] += 1
        
        if (self.port_scan_history[src_ip][scan_type] >= threshold and
            self.port_scan_history[src_ip]['target_count'] >= 3):
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.print_packet_info(
                timestamp, src_ip, dst_ip, "TCP", 0,
                (f"Stealth Scan: {scan_type} scan detected from {src_ip}", Fore.RED)
            )
            self.mitigate_attack(src_ip, f"{scan_type} Scan")
            self.port_scan_history[src_ip][scan_type] = 0
            self.stats['scan_types'][f"{scan_type}_scan"] += 1

    def detect_udp_scan(self, src_ip, dst_ip, port):
        """Detect UDP port scans"""
        self.port_scan_history[src_ip]['UDP'] += 1
        self.scan_techniques[src_ip] += 1
        
        if self.port_scan_history[src_ip]['UDP'] >= self.thresholds['port_scan']['udp_scan_threshold']:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.print_packet_info(
                timestamp, src_ip, dst_ip, "UDP", 0,
                (f"UDP Scan: Detected from {src_ip} to port {port}", Fore.RED)
            )
            self.mitigate_attack(src_ip, "UDP Scan")
            self.port_scan_history[src_ip]['UDP'] = 0
            self.stats['scan_types']['udp_scan'] += 1

    def detect_os_fingerprinting(self, src_ip, dst_ip, tcp_packet):
        """Detect OS fingerprinting attempts"""
        try:
            key = f"{src_ip}-{dst_ip}-os"
            if key not in self.port_scan_history:
                self.port_scan_history[key] = {
                    'ttl': set(),
                    'window': set(),
                    'count': 0,
                    'options': set()
                }
            
            record = self.port_scan_history[key]
            
            if IP in tcp_packet:
                ttl = tcp_packet[IP].ttl
                record['ttl'].add(ttl)
                
                if hasattr(tcp_packet, 'window'):
                    record['window'].add(tcp_packet.window)
                
                if hasattr(tcp_packet, 'options'):
                    options = tuple(sorted(opt[0] for opt in tcp_packet.options if opt))
                    record['options'].add(options)
                
                record['count'] += 1
                self.scan_techniques[src_ip] += 1
                
                if (len(record['ttl']) > 2 or 
                    len(record['window']) > 2 or
                    len(record['options']) > 2 or
                    record['count'] > self.thresholds['nmap']['os_detection']):
                    
                    if dst_ip == self.interface_ip or dst_ip.startswith('192.168.'):
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        variations = []
                        if len(record['ttl']) > 2:
                            variations.append(f"{len(record['ttl'])} TTLs")
                        if len(record['window']) > 2:
                            variations.append(f"{len(record['window'])} window sizes")
                        if len(record['options']) > 2:
                            variations.append(f"{len(record['options'])} TCP options")
                        
                        variation_text = ", ".join(variations)
                        self.print_packet_info(
                            timestamp, src_ip, dst_ip, "TCP", 0,
                            (f"OS Fingerprinting: Detected from {src_ip} ({variation_text})", Fore.RED)
                        )
                        self.mitigate_attack(src_ip, "OS Fingerprinting")
                        self.stats['scan_types']['os_fingerprinting'] += 1
                    
                    del self.port_scan_history[key]
        
        except Exception as e:
            print(f"{Fore.RED}OS Fingerprinting detection error: {e}{Style.RESET_ALL}")

    def detect_comprehensive_scan(self, src_ip):
        """Detect comprehensive scans using multiple techniques"""
        if self.scan_techniques.get(src_ip, 0) >= 3:
            technique_count = sum(1 for k, v in self.port_scan_history[src_ip].items() if v > 0)
            total_scan_packets = sum(self.port_scan_history[src_ip].values())
            
            if (technique_count >= 3 and 
                total_scan_packets >= 10 and 
                not self.is_whitelisted_traffic(src_ip)):
                
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.print_packet_info(
                    timestamp, src_ip, "Multiple", "TCP", 0,
                    (f"Comprehensive Scan: {technique_count} techniques detected from {src_ip}", Fore.RED)
                )
                self.mitigate_attack(src_ip, "Comprehensive Scan")
                self.stats['scan_types']['comprehensive_scan'] += 1
                self.scan_techniques[src_ip] = 0
                self.port_scan_history[src_ip] = defaultdict(int)

    def detect_syn_activity(self, src_ip, dst_ip, tcp_packet):
        """Detect SYN floods and scans"""
        now = time.time()
        if src_ip not in self.syn_tracker:
            self.syn_tracker[src_ip] = {
                'syn_count': 0,
                'unique_ports': set(),
                'start_time': now,
                'last_alert': 0,
                'last_port_scan_alert': 0
            }
        
        tracker = self.syn_tracker[src_ip]
        tracker['syn_count'] += 1
        tracker['unique_ports'].add(tcp_packet.dport)
        
        duration = now - tracker['start_time']
        if duration <= 0:
            duration = 1
        syn_rate = tracker['syn_count'] / max(duration, 1)
        unique_ports = len(tracker['unique_ports'])
        
        alert_cooldown = 2
        
        # SYN Flood Detection
        if (syn_rate > 40 and 
            unique_ports < 3 and 
            now - tracker['last_alert'] > alert_cooldown):
            
            self.print_packet_info(
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                src_ip, dst_ip, "TCP", 0,
                (f"DoS:SYN_Flood: {syn_rate:.1f} SYN/s to {unique_ports} ports", Fore.RED)
            )
            tracker['last_alert'] = now
            self.mitigate_attack(src_ip, "SYN Flood")
            self.stats['attack_types']['syn_flood'] += 1
            return "syn_flood"
        
        # SYN Scan Detection
        elif (unique_ports >= 10 and
            now - tracker['last_port_scan_alert'] > alert_cooldown):
            
            self.print_packet_info(
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                src_ip, dst_ip, "TCP", 0,
                (f"SYN Scan: {unique_ports} ports at {syn_rate:.1f} SYN/s", Fore.RED)
            )
            tracker['last_port_scan_alert'] = now
            self.mitigate_attack(src_ip, "SYN Scan")
            self.stats['attack_types']['syn_scan'] += 1
            return "syn_scan"
        
        # Reset counters if time window expired
        if duration > 1:
            self.syn_tracker[src_ip] = {
                'syn_count': 1,
                'unique_ports': {tcp_packet.dport},
                'start_time': now,
                'last_alert': tracker['last_alert'],
                'last_port_scan_alert': tracker['last_port_scan_alert']
            }

    def analyze_flow(self, flow_key):
        """Analyze network flow for attacks"""
        try:
            flow = self.flows[flow_key]
            packets = flow['packets']
            
            if not packets or len(packets) < self.min_packets_for_analysis:
                return ("Normal (Insufficient data)", Fore.GREEN)
            
            # Get AI prediction
            ai_result = self.ai_detection(flow_key)
            ai_prediction, ai_confidence = ai_result['prediction'], ai_result['confidence']
            # Get rule-based detection
            rule_result = self.detect_known_attacks(flow_key, ai_prediction, ai_confidence)

            # Decision matrix
            if rule_result['alerts']:
                best_alert = max(rule_result['alerts'], key=lambda x: x[1])
                alert_msg, confidence = best_alert
                color = Fore.RED 
                if ai_prediction == 1:
                    return (alert_msg, color)
            
            if ai_prediction == 1:
                if ai_confidence > 0.7:
                    return (f"Potential Attack (AI:{ai_confidence:.2f})", Fore.YELLOW)
                else:
                    if not self.is_whitelisted_traffic(flow_key.split(':')[0]):
                        return ("Suspicious Activity", Fore.YELLOW)
            
            return ("Normal", Fore.GREEN)
            
        except Exception as e:
            print(f"{Fore.RED}Flow analysis error: {e}{Style.RESET_ALL}")
            return ("Error", Fore.WHITE)

    def detect_known_attacks(self, flow_key, ai_prediction=None, ai_confidence=None):
        """Detect known attack patterns"""
        try:
            flow = self.flows[flow_key]
            packets = flow['packets']
            src_ip = flow_key.split(':')[0]
            dst_ip = flow_key.split(':')[1]
            duration = max(time.time() - flow['start_time'], 0.1)
            dst_ports = [p['dst_port'] for p in packets if 'dst_port' in p]
            unique_ports = len(set(dst_ports))

            results = {
                'alerts': [],
                'max_confidence': 0.0,
                'attack_types': set()
            }

            # Calculate basic metrics
            packet_rate = len(packets) / duration
            avg_packet_size = sum(p['length'] for p in packets) / len(packets) if packets else 0

            # 1. SYN Flood Detection
            syn_packets = [p for p in packets if p.get('flags', 0) & 0x02]
            syn_rate = len(syn_packets) / duration
            if syn_rate > 40 and unique_ports <= 3:
                confidence = min(1.0, syn_rate / 200)
                results['alerts'].append((f"DoS:SYN_Flood ({syn_rate:.1f} SYN/s)", confidence))
                results['attack_types'].add('syn_flood')

            # 2. General Flood Detection
            if packet_rate > 1000 and avg_packet_size < 100:
                confidence = min(1.0, packet_rate / 5000)
                results['alerts'].append((f"DoS:Flood ({packet_rate:.1f} pkt/s)", confidence))
                results['attack_types'].add('flood')

            # 3. Stealth Scan Detection
            null_scan = all(p.get('flags', 0) == 0 for p in packets)
            fin_scan = all(p.get('flags', 0) == 0x01 for p in packets)
            xmas_scan = all(p.get('flags', 0) & 0x29 == 0x29 for p in packets)
            ack_scan = all(p.get('flags', 0) == 0x10 for p in packets)

            if null_scan and unique_ports >= 5:
                confidence = min(1.0, unique_ports / 20)
                results['alerts'].append((f"Port_Scan:NULL ({unique_ports} ports)", confidence))
                results['attack_types'].add('null_scan')

            if fin_scan and unique_ports >= 5:
                confidence = min(1.0, unique_ports / 20)
                results['alerts'].append((f"Port_Scan:FIN ({unique_ports} ports)", confidence))
                results['attack_types'].add('fin_scan')

            if xmas_scan and unique_ports >= 5:
                confidence = min(1.0, unique_ports / 20)
                results['alerts'].append((f"Port_Scan:XMAS ({unique_ports} ports)", confidence))
                results['attack_types'].add('xmas_scan')

            if ack_scan and unique_ports >= 5:
                confidence = min(1.0, unique_ports / 20)
                results['alerts'].append((f"Port_Scan:ACK ({unique_ports} ports)", confidence))
                results['attack_types'].add('ack_scan')

            # Add AI info if available
            if ai_prediction is not None and ai_confidence is not None:
                results['ai_info'] = {
                    'prediction': ai_prediction,
                    'confidence': ai_confidence
                }

            # Determine max confidence
            if results['alerts']:
                results['max_confidence'] = max([alert[1] for alert in results['alerts']])

            # Queue alerts for real-time processing
            for alert_msg, confidence in results['alerts']:
                alert_dict = {
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "src": src_ip,
                    "dst": dst_ip,
                    "proto": packets[0]['protocol'] if packets else "Unknown",
                    "length": packets[0]['length'] if packets else 0,
                    "alert": alert_msg,
                    "confidence": confidence,
                    "ai_prediction": ai_prediction,
                    "ai_confidence": ai_confidence
                }
                try:
                    alert_queue.put(alert_dict, timeout=1)
                except Exception as e:
                    print(f"Error putting alert in queue: {e}")

            return results

        except Exception as e:
            print(f"{Fore.RED}Attack detection error: {e}{Style.RESET_ALL}")
            return {
                'alerts': [("Error", 0.0)],
                'max_confidence': 0.0,
                'attack_types': set(),
                'error': str(e)
            }

    def extract_flow_features(self, flow_key):
        """Extract features for AI analysis"""
        flow = self.flows[flow_key]
        packets = flow['packets']
        duration = max(time.time() - flow['start_time'], 0.1)
        
        src_bytes = sum(p['length'] for p in packets if p.get('direction') == 'in')
        dst_bytes = sum(p['length'] for p in packets if p.get('direction') == 'out')
        total_bytes = src_bytes + dst_bytes
        num_packets = len(packets)
        
        dst_ports = [p.get('dst_port', 0) for p in packets]
        src_ports = [p.get('src_port', 0) for p in packets]
        
        features = {
            'dst_bytes': dst_bytes,
            'dst_port': dst_ports[-1] if dst_ports else 0,
            'duration': duration,
            'protocol': 6 if flow_key.endswith('TCP') else 17 if flow_key.endswith('UDP') else 0,
            'src_bytes': src_bytes,
            'src_port': src_ports[0] if src_ports else 0,
            'bytes_per_second': total_bytes / duration,
            'total_bytes': total_bytes,
            'bytes_ratio': src_bytes / (dst_bytes + 1e-6),
            'packet_velocity': num_packets / duration,
            'dst_packet_velocity': len([p for p in packets if p.get('direction') == 'out']) / duration,
            'src_port_entropy': self.calculate_entropy(src_ports),
            'dst_port_entropy': self.calculate_entropy(dst_ports),
            'byte_std_dev': np.std([p['length'] for p in packets]) if len(packets) > 1 else 0,
            'total_bytes_log': np.log(total_bytes + 1),
            'protocol_encoded': 1 if flow_key.endswith('TCP') else 2 if flow_key.endswith('UDP') else 0,
            'protocol_byte_mean': total_bytes / num_packets if num_packets > 0 else 0,
            'state_encoded': 1 if len(set(dst_ports)) > 3 else 0,
            'src_dst_byte_ratio': src_bytes / (dst_bytes + 1e-6),
            'port_dif': abs((src_ports[0] if src_ports else 0) - (dst_ports[-1] if dst_ports else 0))
        }
        
        features_df = pd.DataFrame([features])[self.feature_names]
        return features_df.values.reshape(1, -1)

    def calculate_entropy(self, ports):
        """Calculate port entropy"""
        if not ports:
            return 0
        _, counts = np.unique(ports, return_counts=True)
        probs = counts / len(ports)
        return -np.sum(probs * np.log2(probs + 1e-10))

    def ai_detection(self, flow_key):
        """Get AI prediction for a flow"""
        try:
            features = self.extract_flow_features(flow_key)
            
            if len(features.shape) == 1:
                features = features.reshape(1, -1)
            elif len(features.shape) == 3:
                features = features.reshape(features.shape[0], -1)
                
            features_scaled = self.scaler.transform(features)
            proba = self.model.predict_proba(features_scaled)[0]
            attack_prob = proba[1]
            
            prediction = 1 if attack_prob >= self.ai_thresholds['attack'] else 0
            confidence = attack_prob if prediction == 1 else 1 - attack_prob
            
            return {
                'prediction': prediction,
                'confidence': confidence,
                'raw_probability': attack_prob
            }
        except Exception as e:
            print(f"{Fore.RED}AI detection error: {e}{Style.RESET_ALL}")
            return {
                'prediction': 0,
                'confidence': 0.0,
                'raw_probability': 0.0
            }

    def block_ip_at_firewall(self, src_ip):
        """Block IP using Windows Firewall"""
        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=Block_" + src_ip,
                "dir=in",
                "action=block",
                "remoteip=" + src_ip,
                "enable=yes"
            ], check=True)
            print(f"{Fore.YELLOW}Blocked IP {src_ip} using Windows Firewall.")
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}Failed to block IP {src_ip}: {e}")

    def mitigate_attack(self, src_ip, attack_type):
        """Take action against detected attacks"""
        if src_ip in self.blocked_ips:
            return
            
        print(f"{Back.RED}{Fore.WHITE}MITIGATING {attack_type} FROM {src_ip}{Style.RESET_ALL}")
        
        self.blocked_ips.add(src_ip)
        self.stats['attack_types'][attack_type] += 1

        with sqlite3.connect('network_monitor.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO blocked_ips 
            (timestamp, source_ip, reason, unblock_time)
            VALUES (?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                src_ip,
                attack_type,
                (datetime.now() + timedelta(minutes=10)).isoformat()
            ))
            conn.commit()
        
        # Schedule unblock after timeout
        Timer(30, self.unblock_ip, args=[src_ip]).start()
        self.block_ip_at_firewall(src_ip)

    def unblock_ip(self, ip):
        """Remove IP from blocked list"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            print(f"{Fore.GREEN}Unblocked {ip}{Style.RESET_ALL}")

    def display_periodic_stats(self):
        """Display statistics periodically"""
        while self.is_running:
            time.sleep(60)
            self.print_statistics()

    def print_statistics(self):
        """Print summary statistics"""
        print(f"\n{Back.WHITE}{Fore.BLACK}=== Network Statistics ===")
        print(f"Total Packets: {Fore.GREEN}{self.stats['total_packets']}")
        print(f"Devices Detected: {Fore.CYAN}{len(self.devices)}")
        print(f"{Fore.RED}Alerts Detected:")
        for alert, count in self.stats['alerts'].items():
            print(f"  {alert}: {Fore.YELLOW}{count}")
        print(f"{Fore.RED}Attack Types:")
        for attack, count in self.stats['attack_types'].items():
            print(f"  {attack}: {Fore.YELLOW}{count}")
        print(f"{Fore.BLUE}Blocked IPs: {Fore.YELLOW}{len(self.blocked_ips)}")
        print("="*40 + Style.RESET_ALL)

    def print_packet_info(self, timestamp, src, dst, proto, length, alert_info):
        """Display packet information with colored alerts"""
        if isinstance(alert_info, tuple):
            alert, color = alert_info
        else:
            alert, color = alert_info, Fore.GREEN

        if dst == "" or dst is None:
            dst = "Multiple"
        
        if ":" in alert:
            alert_type = alert.split(":")[0]
        else:
            alert_type = alert
        
        if proto == 'TCP' and 'FIN' in alert:
            display_length = "54 bytes (header)"
        else:
            display_length = f"{length} bytes"
        
        # Get device types if known
        src_type = self.devices.get(src, {}).get('type', 'Unknown')
        dst_type = self.devices.get(dst, {}).get('type', 'Unknown')
        
        print(f"{Fore.CYAN}{timestamp}{Style.RESET_ALL} | "
            f"{Fore.BLUE}{src} ({src_type}){Style.RESET_ALL} → "
            f"{Fore.MAGENTA}{dst} ({dst_type}){Style.RESET_ALL} | "
            f"{proto:<6} | {display_length:<15} | "
            f"{color}{alert}{Style.RESET_ALL}")    

        alert_dict = {
            'timestamp': time.time(),
            'type': alert_type,
            'source': src,
            'destination': dst,
            'protocol': proto,
            'confidence': 90 if color == Fore.RED else 70 if color == Fore.YELLOW else 30,
            'description': alert
        }

        try:
            alert_queue.put(alert_dict)
        except Exception as e:
            print(f"{Fore.RED}Error putting alert in queue: {e}{Style.RESET_ALL}") 

        if alert_info is not None and not alert.startswith("Normal"):
            alert_type = alert.split(':')[0] if ':' in alert else alert
            self.stats['alerts'][alert_type] += 1

            #severity = 'high' if color == Fore.RED else 'medium

            if color == Fore.YELLOW:
                self.log_suspicious_activity(
                    source_ip=src,
                    dest_ip=dst,
                    protocol=proto,
                    description=alert,
                    confidence=0.7,  
                    features=None
                )
                self.stats['suspicious_activities'] += 1

            else:
                self.log_alert(alert_type=alert_type,
                            source_ip=src,
                            dest_ip=dst, 
                            description=alert,
                            severity='high'if color == Fore.RED else 'medium')


        if src in self.scan_techniques and self.scan_techniques[src] > 3:
            self.detect_comprehensive_scan(src)

        if self.stats['total_packets'] % 100 == 0:
            self.print_statistics()

def main():
    monitor = NetworkMonitor()
    
    # Create GUI for interface selection
    root = tk.Tk()
    root.title("Network Intrusion Detection System")
    root.geometry("500x300")
    
    # Load model bundle
    model_path = r"C:\Users\aiman\Downloads\king\enhanced_nids_bundle.pkl"  # Update with your path
    monitor.load_model(model_path)
    
    # Interface selection
    tk.Label(root, text="Select Network Interface:", font=('Arial', 12)).pack(pady=10)
    
    interfaces = monitor.get_readable_interfaces()
    interface_var = tk.StringVar()
    interface_dropdown = ttk.Combobox(root, textvariable=interface_var, values=list(interfaces.values()))
    interface_dropdown.pack(pady=10)
    
    # Start button
    def start_monitoring():
        selected_interface = next(k for k, v in interfaces.items() if v == interface_var.get())
        if monitor.model is None:
            print(f"{Fore.RED}Error: Model failed to load! Cannot start monitoring.{Style.RESET_ALL}")
            return
        root.destroy()
        monitor.start_capture(selected_interface)
    
    tk.Button(root, text="Start Monitoring", command=start_monitoring, 
              bg='#4CAF50', fg='white', font=('Arial', 12)).pack(pady=20)
    
    root.mainloop()

if __name__ == "__main__":
    main()
