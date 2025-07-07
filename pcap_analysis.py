from scapy.all import *
import pandas as pd
import numpy as np
from collections import defaultdict
import joblib
import tkinter as tk
from tkinter import filedialog
from scapy.layers.inet import IP, TCP, UDP

def extract_packet_features(packet):
    """Extract features from a single packet"""
    features = defaultdict(int)
    
    # Basic IP features
    if IP in packet:
        features['src_ip'] = int(ip2long(packet[IP].src))
        features['dst_ip'] = int(ip2long(packet[IP].dst))
        features['protocol'] = packet[IP].proto
    
    # TCP/UDP features
    if TCP in packet:
        features['src_port'] = packet[TCP].sport
        features['dst_port'] = packet[TCP].dport
        features['tcp_flags'] = packet[TCP].flags
        features['window_size'] = packet[TCP].window
    elif UDP in packet:
        features['src_port'] = packet[UDP].sport
        features['dst_port'] = packet[UDP].dport
    
    # Packet size features
    features['packet_size'] = len(packet)
    if Raw in packet:
        features['payload_size'] = len(packet[Raw])
    
    return features

def analyze_pcap(pcap_path):
    """Analyze PCAP file and extract flow features"""
    print(f"Analyzing PCAP file: {pcap_path}")
    
    # Read PCAP
    packets = rdpcap(pcap_path)
    flows = defaultdict(lambda: defaultdict(list))
    
    # Process packets
    for packet in packets:
        if IP not in packet:
            continue
            
        # Extract basic features
        features = extract_packet_features(packet)
        
        # Create flow key
        if TCP in packet or UDP in packet:
            flow_key = (
                packet[IP].src,
                packet[IP].dst,
                features['src_port'],
                features['dst_port'],
                features['protocol']
            )
            
            # Add to flow
            flows[flow_key]['packets'].append(features)
            flows[flow_key]['timestamps'].append(packet.time)
    
    # Calculate flow features
    flow_features = []
    flow_ips = []
    for flow_key, flow_data in flows.items():
        packets = flow_data['packets']
        timestamps = flow_data['timestamps']

        timestamps = [float(ts) for ts in timestamps]
        ip_info = {
            'src_ip': flow_key[0],
            'dst_ip': flow_key[1],
        }
        flow_ips.append(ip_info)
        
        if not packets:
            continue
        
        # Basic flow metrics
        src_bytes = sum(p['packet_size'] for p in packets)
        dst_bytes = sum(p['payload_size'] for p in packets if 'payload_size' in p)
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
        flow_bytes = src_bytes + dst_bytes
        
        # Calculate base features
        base_features = {
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'duration': duration,
            'flow_bytes': flow_bytes,
            'protocol': packets[0]['protocol'],
            'src_port': packets[0]['src_port'],
            'dst_port': packets[0]['dst_port'],
            'service': 0,  # Default value as we can't determine service from raw packets
            'state': 0,    # Default value
            'bytes_per_second': flow_bytes / (duration + 1e-6),
            'total_bytes': flow_bytes,
            'bytes_ratio': src_bytes / (dst_bytes + 1e-6),
            'protocol_type': packets[0]['protocol'],
            'bytes_variance': np.var([src_bytes, dst_bytes]) 
        }

        base_features.update({
    'packet_rate': len(packets) / (duration + 1e-6),
    'avg_packet_interval': duration / (len(packets) + 1e-6),
    'unique_ports': len(set(p['dst_port'] for p in packets))
})
        
        # Add squared and log features
        feature_extensions = {
            'dst_bytes_squared': base_features['dst_bytes'] ** 2,
            'dst_bytes_log': np.log1p(abs(base_features['dst_bytes'])),
            'dst_port_squared': base_features['dst_port'] ** 2,
            'dst_port_log': np.log1p(abs(base_features['dst_port'])),
            'duration_squared': base_features['duration'] ** 2,
            'duration_log': np.log1p(abs(base_features['duration'])),
            'flow_bytes_squared': base_features['flow_bytes'] ** 2,
            'flow_bytes_log': np.log1p(abs(base_features['flow_bytes'])),
            'protocol_squared': base_features['protocol'] ** 2,
            'protocol_log': np.log1p(abs(base_features['protocol']))
        }
        
        # Combine all features
        flow_features.append({**base_features, **feature_extensions})
    
    df = pd.DataFrame(flow_features)
    ip_df = pd.DataFrame(flow_ips)
    
    # Ensure all required features are present and in correct order
    required_features = [
        'dst_bytes', 'dst_port', 'duration', 'flow_bytes', 'protocol',
        'service', 'src_bytes', 'src_port', 'state', 'bytes_per_second',
        'total_bytes', 'bytes_ratio','bytes_variance', 'protocol_type', 'dst_bytes_squared',
        'dst_bytes_log', 'dst_port_squared', 'dst_port_log', 'duration_squared',
        'duration_log', 'flow_bytes_squared', 'flow_bytes_log', 'protocol_squared',
        'protocol_log','packet_rate', 'avg_packet_interval', 'unique_ports'
    ]
    
    # Add any missing features with 0s
    for feature in required_features:
        if feature not in df.columns:
            df[feature] = 0
    
    # Return DataFrame with features in correct order
    return df[required_features], ip_df

def check_normal_traffic_characteristics(flow_data):
    """Enhanced normal traffic detection"""
    bytes_per_sec = flow_data['bytes_per_second']
    total_bytes = flow_data['total_bytes']
    duration = flow_data['duration']
    packet_rate = flow_data['packet_rate']
    bytes_ratio = flow_data['bytes_ratio']
    
    # Normal traffic characteristics
    is_normal_volume = bytes_per_sec < 50000 # Typical web browsing/normal usage
    is_normal_duration = duration < 3.0  # Most normal flows are short
    is_normal_packet_rate = packet_rate < 50  # Normal packet rate
    is_balanced_ratio = 0.1 < bytes_ratio < 5 # Reasonable request/response ratio

    
    return is_normal_volume and is_normal_duration and is_normal_packet_rate and is_balanced_ratio


def predict_flows(flows_df, model, scaler, pca, feature_names):
    """Make predictions with enhanced ML validation and traffic pattern analysis"""
    # Initial ML predictions
    X = flows_df[feature_names].values
    X_scaled = scaler.transform(X)
    predictions = model.predict(X_scaled)
    probabilities = model.predict_proba(X_scaled)

    def validate_attack_confidence(flow_data):
        """Validate if flow shows strong attack characteristics"""
        bytes_per_sec = flow_data['bytes_per_second']
        packet_rate = flow_data['packet_rate']
        unique_ports = flow_data['unique_ports']
        duration = flow_data['duration']
        
        # Strong attack indicators
        high_traffic = bytes_per_sec > 100000
        high_port_count = unique_ports > 3
        sustained_duration = duration > 1.0
        high_packet_rate = packet_rate > 100
        
        # Score the indicators
        score = sum([high_traffic, high_port_count, sustained_duration, high_packet_rate])
        return score >= 2  # Return True if at least 2 indicators are present
    
    def check_dos_characteristics(flow_data):
        """Enhanced DOS detection with multiple indicators"""
        bytes_per_sec = flow_data['bytes_per_second']
        total_bytes = flow_data['total_bytes']
        duration = flow_data['duration']
        packet_rate = flow_data['packet_rate']
        
        # Primary DOS indicators
        is_high_volume = bytes_per_sec > 800000
        is_sustained = duration > 0.5
        is_large_flow = total_bytes > 800000
        high_packet_rate = packet_rate > 1500
        
        # Secondary indicators
        has_consistent_traffic = flow_data['bytes_ratio'] > 0.8
        is_aggressive = packet_rate / (duration + 1e-6) > 1000
        
        # Combined scoring
        primary_score = sum([is_high_volume, is_sustained, is_large_flow, high_packet_rate])
        secondary_score = sum([has_consistent_traffic, is_aggressive])
        
        return primary_score >= 2 and secondary_score >= 1

    def check_portscan_characteristics(flow_data):
        """Enhanced port scan detection with stricter rules"""
        bytes_per_sec = flow_data['bytes_per_second']
        unique_ports = flow_data['unique_ports']
        duration = flow_data['duration']
        packet_rate = flow_data['packet_rate']
        
        # Primary portscan indicators with stricter thresholds
        is_low_volume = bytes_per_sec < 100000  # Increased threshold
        has_multiple_ports = unique_ports > 2    # Reduced ports threshold
        is_quick_scan = duration < 2.0           # Increased duration threshold
        is_probe_like = flow_data['bytes_ratio'] < 0.5  # Increased ratio threshold
        
        # Additional portscan indicators
        same_dest_different_ports = unique_ports > 2
        rapid_port_access = packet_rate > 20
        small_packets = flow_data['total_bytes'] / (flow_data['packet_rate'] + 1e-6) < 200
        
        # Scoring system for port scan detection
        score = 0
        if is_low_volume: score += 1
        if has_multiple_ports: score += 2  # Weighted more heavily
        if is_quick_scan: score += 1
        if is_probe_like: score += 1
        if same_dest_different_ports: score += 2
        if rapid_port_access: score += 1
        if small_packets: score += 1
        
        return score >= 4  # Reduced threshold for positive detection

    def check_mitm_characteristics(flow_data):
        """Enhanced MITM detection"""
        bytes_per_sec = flow_data['bytes_per_second']
        duration = flow_data['duration']
        bytes_ratio = flow_data['bytes_ratio']
        
        # MITM patterns
        is_moderate_volume = 50000 < bytes_per_sec < 500000
        is_sustained = duration > 2.0
        is_bidirectional = 0.3 < bytes_ratio < 3.0
        has_consistent_rate = flow_data['avg_packet_interval'] < 0.1
        
        return is_moderate_volume and is_sustained and is_bidirectional and has_consistent_rate

    def check_unknown_attack(flow_data, current_confidence):
        """Check for unknown attack patterns"""
        # Statistical anomalies
        is_anomalous_volume = flow_data['bytes_per_second'] > 1000000
        is_anomalous_duration = flow_data['duration'] > 10
        is_unusual_pattern = flow_data['bytes_ratio'] > 10 or flow_data['bytes_ratio'] < 0.1
        
        # Confidence check
        is_low_confidence = current_confidence < 0.6
        
        return (is_anomalous_volume or is_anomalous_duration or is_unusual_pattern) and is_low_confidence

    # Process predictions with enhanced logic
    adjusted_predictions = []
    adjusted_probabilities = []
    
    for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
        flow_data = flows_df.iloc[i]
        current_confidence = np.max(prob)
        new_prob = prob.copy()
        
        is_likely_attack = validate_attack_confidence(flow_data)
        # Check all attack characteristics
        if is_likely_attack:
            # Skip normal traffic check if strong attack indicators present
            is_normal = False
            is_dos = check_dos_characteristics(flow_data)
            is_portscan = check_portscan_characteristics(flow_data)
            is_mitm = check_mitm_characteristics(flow_data)
            is_unknown = check_unknown_attack(flow_data, current_confidence)
        else:
            # Only check normal characteristics if no strong attack indicators
            is_normal = check_normal_traffic_characteristics(flow_data)
            if not is_normal:
                is_dos = check_dos_characteristics(flow_data)
                is_portscan = check_portscan_characteristics(flow_data)
                is_mitm = check_mitm_characteristics(flow_data)
                is_unknown = check_unknown_attack(flow_data, current_confidence)
            else:
                is_dos = is_portscan = is_mitm = is_unknown = False
        
        # Decision logic with bias towards attack detection
        if is_likely_attack:
            if is_dos:
                adjusted_predictions.append(1)
                new_prob[1] = max(0.85, new_prob[1])
            elif is_portscan:
                adjusted_predictions.append(2)
                new_prob[2] = max(0.85, new_prob[2])
            elif is_mitm:
                adjusted_predictions.append(3)
                new_prob[3] = max(0.85, new_prob[3])
            else:
                adjusted_predictions.append(4)  # Unknown attack
                new_prob[4] = max(0.70, new_prob[4])
        elif is_normal and current_confidence > 0.9:  # Higher threshold for normal
            adjusted_predictions.append(0)
            new_prob[0] = max(0.90, new_prob[0])
        else:
            # Default to most likely attack type if unsure
            if current_confidence > 0.6:
                adjusted_predictions.append(pred)
            else:
                max_attack_prob = max(prob[1:])  # Check highest attack probability
                attack_type = np.argmax(prob[1:]) + 1
                adjusted_predictions.append(attack_type)
                new_prob[attack_type] = max(0.75, max_attack_prob)
        
        # Normalize probabilities
        new_prob /= new_prob.sum()
        adjusted_probabilities.append(new_prob)
    
    return np.array(adjusted_predictions), np.array(adjusted_probabilities)

def load_model(model_path):
    """Load the trained model and its components"""
    try:
        print(f"Loading model from: {model_path}")
        model_data = joblib.load(model_path)
        
        # Extract components
        model = model_data['model']
        scaler = model_data['scaler']
        pca = model_data['pca']
        label_mapping = model_data['label_mapping']
        feature_names = model_data['feature_names']
        
        print("Model loaded successfully")
        return model, scaler, pca, label_mapping, feature_names
        
    except Exception as e:
        print(f"Error loading model: {e}")
        return None
    
def generate_analysis_summary(flows_df, predictions, probabilities, label_mapping):
    """Generate a comprehensive analysis summary with ML debug information"""
    # Count packets by type
    attack_counts = defaultdict(int)
    ml_predictions = defaultdict(int)  # New counter for raw ML predictions
    suspicious_ips = defaultdict(int)
    total_flows = len(predictions)
    
    normal_flows = 0
    attack_flows = 0
    
    # Get initial ML predictions before adjustments
    raw_predictions = predictions.copy()  # Store raw predictions
    
    for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
        attack_type = label_mapping[pred]
        confidence = np.max(prob) * 100
        attack_counts[attack_type] += 1
        
        # Count raw ML predictions
        ml_predictions[label_mapping[raw_predictions[i]]] += 1
        
        if pred == 0:  # Normal traffic
            normal_flows += 1
        else:  # Attack traffic
            attack_flows += 1
            src_ip = flows_df.iloc[i].get('src_ip', 'Unknown')
            if src_ip != 'Unknown':
                suspicious_ips[src_ip] += 1
    
    # Enhanced summary output
    print("\n=== Analysis Summary ===")
    print("=" * 50)
    print(f"Total Flows Analyzed: {total_flows}")
    print(f"Normal Flows: {normal_flows} ({(normal_flows/total_flows*100):.2f}%)")
    print(f"Attack Flows: {attack_flows} ({(attack_flows/total_flows*100):.2f}%)")
    
    print("\nModel Prediction Distribution:")
    print("-" * 30)
    for label, count in sorted(ml_predictions.items()):
        print(f"ML predicted {label}: {count} flows ({(count/total_flows*100):.2f}%)")
    
    print("\nFinal Attack Type Distribution (After Logic Checks):")
    print("-" * 30)
    for attack_type, count in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{attack_type}: {count} flows ({(count/total_flows*100):.2f}%)")
    
    # Show prediction changes
    print("\nPrediction Adjustments:")
    print("-" * 30)
    changes = sum(1 for i in range(len(predictions)) if predictions[i] != raw_predictions[i])
    print(f"Logic rules adjusted {changes} predictions")
    print(f"Adjustment rate: {(changes/total_flows*100):.2f}%")
    
    if suspicious_ips:
        print("\nTop Suspicious IP Addresses:")
        print("-" * 30)
        for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"IP: {ip2int_to_str(ip)} - {count} suspicious flows")

def ip2int_to_str(ip_int):
    """Convert integer IP back to string format"""
    try:
        # Convert integer IP back to dotted decimal format
        octets = []
        for i in range(4):
            octets.insert(0, str(ip_int & 255))
            ip_int >>= 8
        return '.'.join(octets)
    except Exception:
        # Return original value if conversion fails
        return str(ip_int)

def main():
    # Setup GUI for file selection
    root = tk.Tk()
    root.withdraw()
    
    # Get PCAP file path
    pcap_path = filedialog.askopenfilename(
        title="Select PCAP file",
        filetypes=[("PCAP files", "*.pcap *.pcapng")]
    )
    
    if not pcap_path:
        print("No file selected")
        return
    
    # Get model path
    model_path = filedialog.askopenfilename(
        title="Select trained model file",
        filetypes=[("Model files", "*.pkl")]
    )
    
    if not model_path:
        print("No model file selected")
        return
    
    # Load model and components
    model_components = load_model(model_path)
    if model_components is None:
        return
        
    model, scaler, pca, label_mapping, feature_names = model_components
    
    # Analyze PCAP
    try:
        flows_df, ip_df = analyze_pcap(pcap_path)
        predictions, probabilities = predict_flows(flows_df, model, scaler, pca, feature_names)
        
        
        for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
            attack_type = label_mapping[pred]
            confidence = np.max(prob) * 100
            print(f"Flow {i+1}:")
            print(f"Source IP: {ip_df.iloc[i]['src_ip']}")
            print(f"Destination IP: {ip_df.iloc[i]['dst_ip']}")
            print(f"Predicted Attack Type: {attack_type}")
            print(f"Confidence: {confidence:.2f}%")
            print("-" * 30)

        generate_analysis_summary(flows_df, predictions, probabilities, label_mapping)

        
    except Exception as e:
        print(f"Error during analysis: {e}")

def ip2long(ip):
    """Convert IP address to integer"""
    parts = ip.split('.')
    return sum(int(part) << (24 - 8 * i) for i, part in enumerate(parts))

if __name__ == "__main__":
    main()
