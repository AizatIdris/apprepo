import streamlit as st
import pandas as pd
from scapy.all import sniff, get_if_list
from collections import defaultdict
import time
import threading
import psutil
from datetime import datetime
from pcap_analysis import analyze_pcap, load_model, predict_flows
#from monitoring_script import NetworkMonitor
from netnids import NetworkMonitor, alert_queue
import sqlite3
from datetime import timedelta
from collections import deque
import queue
from queue import Empty
from colorama import Fore, Style
#from monitoring_script import alert_queue


# Global variables to store packet data
packet_data = []
packet_counts = defaultdict(int)
protocol_counts = defaultdict(int)
source_ips = defaultdict(int)
destination_ips = defaultdict(int)
packet_sizes = []
timestamps = []
start_time = time.time()
stop_sniffing = False
lock = threading.Lock()

# Real-time NIDS monitor
monitor = NetworkMonitor()

def get_db_connection():
    return sqlite3.connect('network_monitor.db')

def get_recent_alerts(limit=5):
    """Get recent alerts from database"""
    conn = get_db_connection()
    query = """
    SELECT timestamp, alert_type, source_ip, dest_ip, description, severity 
    FROM alerts 
    ORDER BY timestamp DESC 
    LIMIT ?
    """
    alerts = pd.read_sql(query, conn, params=(limit,))
    conn.close()
    return alerts

def get_blocked_ips():
    """Get currently blocked IPs"""
    conn = get_db_connection()
    query = """
    SELECT timestamp, source_ip, reason 
    FROM blocked_ips 
    WHERE unblock_time > ?
    """
    now = datetime.now().isoformat()
    blocked = pd.read_sql(query, conn, params=(now,))
    conn.close()
    return blocked

def get_packet_stats():
    """Get packet statistics from database"""
    conn = get_db_connection()
    query = """
    SELECT 
        COUNT(*) as total_packets,
        COUNT(DISTINCT source_ip) as unique_src_ips,
        COUNT(DISTINCT dest_ip) as unique_dest_ips
    FROM packets
    """
    stats = pd.read_sql(query, conn)
    conn.close()
    return stats.iloc[0]

def display_alert_summary():
    """Show alert summary statistics"""
    conn = get_db_connection()
    
    # Alert count by type
    query1 = """
    SELECT alert_type, COUNT(*) as count 
    FROM alerts 
    GROUP BY alert_type
    ORDER BY count DESC
    """
    alert_types = pd.read_sql(query1, conn)
    
    # Alert count by severity
    query2 = """
    SELECT severity, COUNT(*) as count 
    FROM alerts 
    GROUP BY severity
    ORDER BY severity DESC
    """
    alert_severity = pd.read_sql(query2, conn)
    
    conn.close()
    
    # Display in columns
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Alert Types")
        st.bar_chart(alert_types.set_index('alert_type'))
    
    with col2:
        st.subheader("Alert Severity")
        st.bar_chart(alert_severity.set_index('severity'))

# In your frontend.py, modify the update_security_alerts function:

def update_security_alerts():
    """Update security alerts display"""
    alerts_container = st.empty()
    
    while True:
        try:
            # Get new alerts from the shared queue
            while not alert_queue.empty():
                try:
                    alert = alert_queue.get_nowait()
                    print(f"DEBUG (frontend): Got alert from queue: {alert}")  # Add this line
                    if 'alerts' not in st.session_state:
                        st.session_state.alerts = deque(maxlen=50)
                    
                    # Convert to expected format if needed
                    if isinstance(alert, tuple):
                        alert_msg, color = alert
                        alert = {
                            'timestamp': time.time(),
                            'type': alert_msg.split(':')[0] if ':' in alert_msg else alert_msg,
                            'source': 'Unknown',
                            'destination': 'Unknown',
                            'confidence': 90 if color == Fore.RED else 70 if color == Fore.YELLOW else 30,
                            'description': alert_msg
                        }
                    
                    st.session_state.alerts.appendleft(alert)
                except Empty:
                    break
            
            # Display alerts
            if hasattr(st.session_state, 'alerts') and st.session_state.alerts:
                with alerts_container.container():
                    for alert in st.session_state.alerts:
                        severity_color = {
                            'DOS': 'red',
                            'PORT_SCAN': 'orange',
                            'MITM': 'yellow',
                            'SYN_Flood': 'red',
                            'SYN Scan': 'orange',
                            'FIN': 'purple',
                            'XMAS': 'purple',
                            'ACK': 'purple',
                            'NULL': 'purple',
                            'UDP': 'green',
                        }.get(alert['type'], 'blue')
                        
                        st.markdown(f"""
                            <div style="
                                background-color: {severity_color}22;
                                border-left: 4px solid {severity_color};
                                padding: 10px;
                                margin: 5px 0;
                                border-radius: 4px;
                            ">
                                <strong>{datetime.fromtimestamp(alert['timestamp']).strftime('%H:%M:%S')}</strong> - 
                                {alert['type']}<br>
                                Source: {alert['source']} → Destination: {alert['destination']}<br>
                                <small>{alert['description']}</small>
                            </div>
                        """, unsafe_allow_html=True)
        
        except Exception as e:
            st.error(f"Error updating alerts: {e}")
        time.sleep(1)  # Update every second

def get_available_interfaces():
    """Get list of available network interfaces with their status"""
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    
    for interface_name in addrs:
        if interface_name in stats:
            is_up = "Up" if stats[interface_name].isup else "Down"
            interfaces.append(f"{interface_name} ({is_up})")
        else:
            interfaces.append(f"{interface_name} (Status Unknown)")
    
    # Also include scapy's interface list as fallback
    scapy_interfaces = get_if_list()
    for iface in scapy_interfaces:
        if iface not in interfaces:
            interfaces.append(iface)
    
    return sorted(list(set(interfaces)))

def clean_interface_name(interface):
    """Extract just the interface name from the displayed string"""
    return interface.split(' ')[0]

def process_packet(packet):
    global packet_data, packet_counts, protocol_counts, source_ips, destination_ips, packet_sizes, timestamps
    
    try:
        current_time = time.time() - start_time
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        with lock:
            timestamps.append(current_time)
        
        # Count packets per second
        time_key = int(current_time)
        with lock:
            packet_counts[time_key] += 1
        
        # Get packet info
        size = packet.len if hasattr(packet, 'len') else 0
        with lock:
            packet_sizes.append(size)
        
        src_ip = dst_ip = protocol = "N/A"
        if packet.haslayer('IP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            proto = packet['IP'].proto
            if proto == 6:
                protocol = 'TCP'
            elif proto == 17:
                protocol = 'UDP'
            elif proto == 1:
                protocol = 'ICMP'
            else:
                protocol = f'Other({proto})'
        else:
            protocol = 'Non-IP'
        
        # Store packet data with consistent structure
        packet_info = {
            'Timestamp': timestamp,
            'Source IP': src_ip,
            'Destination IP': dst_ip,
            'Protocol': protocol,
            'Size (bytes)': size
        }

        with lock:
            packet_data.append(packet_info)
        
        # Send packet to NIDS monitor for real-time detection
        monitor.packet_callback(packet) 
        # Update counts
        with lock:
            protocol_counts[protocol] += 1
            if src_ip != "N/A":
                source_ips[src_ip] += 1
            if dst_ip != "N/A":
                destination_ips[dst_ip] += 1

        alert = monitor.packet_callback(packet)
        if alert:
            alert_queue.put(alert)
            with lock:
                if alert not in st.session_state:
                    st.session_state.alerts = deque(maxlen=50)
                st.session_state.alerts.appendleft(alert)
    
    except Exception as e:
        print(f"Error processing packet: {str(e)}")

def start_sniffing(interface, count=0):
    try:
        sniff(iface=clean_interface_name(interface), prn=process_packet, store=False, count=count)
    except Exception as e:
        st.error(f"Error capturing on {interface}: {str(e)}")

def main():
    
    global stop_sniffing, packet_data
    
    # Initialize session state for persistent data and alert tracking
    if 'sniffing' not in st.session_state:
        st.session_state.sniffing = False
    if 'prev_alert_count' not in st.session_state:
        st.session_state.prev_alert_count = 0
    if 'last_refresh' not in st.session_state:
        st.session_state.last_refresh = time.time()
    
    # Mode selector in sidebar
    mode = st.sidebar.radio("Select Mode", ["Live Monitor", "Offline Analysis"])

    if mode == "Live Monitor":
        st.title("📊 AI-Powered Network Intrusion Detection System")
        st.write("Real-time network traffic monitoring with anomaly detection")
        
        # Get available interfaces
        interfaces = get_available_interfaces()
        
        if not interfaces:
            st.error("No network interfaces found!")
            return
        
        # Sidebar controls
        with st.sidebar:
            st.header("⚙️ Controls")
            selected_interface = st.selectbox(
                "Select Network Interface",
                interfaces,
                index=0
            )
            
            st.write(f"🔌 Selected: {clean_interface_name(selected_interface)}")
            
            sample_size = st.number_input("Sample Size (packets)", min_value=0, value=0, 
                                        help="0 for unlimited capture")
            update_interval = st.slider("Update Interval (seconds)", 1, 10, 2)
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🚀 Start Monitoring", type="primary", 
                           disabled=st.session_state.sniffing):
                    st.session_state.sniffing = True
                    stop_sniffing = False
                    monitor.is_running = True
                    
                    # Clear previous data
                    global packet_counts, protocol_counts, source_ips, destination_ips, packet_sizes, timestamps, start_time
                    with lock:
                        packet_counts = defaultdict(int)
                        protocol_counts = defaultdict(int)
                        source_ips = defaultdict(int)
                        destination_ips = defaultdict(int)
                        packet_sizes.clear()
                        timestamps.clear()
                        packet_data.clear()
                        start_time = time.time()
                    
                    # Start sniffing in background thread
                    threading.Thread(
                        target=start_sniffing,
                        args=(selected_interface, sample_size),
                        daemon=True
                    ).start()
                    st.toast(f"Started monitoring on {selected_interface}")
            
            with col2:
                if st.button("⏹️ Stop Monitoring", type="secondary", 
                           disabled=not st.session_state.sniffing):
                    st.session_state.sniffing = False
                    stop_sniffing = True
                    monitor.is_running = False
                    st.toast("Monitoring stopped")
        
        # Main dashboard layout
        tab1, tab2, tab3 = st.tabs(["Real-Time Dashboard", "Security Alerts", "Network Statistics"])
        dashboard_placeholder = st.empty()

        with tab1:
            dashboard_placeholder = st.empty()
        with tab2:
            alerts_placeholder = st.empty()
        with tab3:
            stats_placeholder = st.empty()
    
        while st.session_state.sniffing:
            # Update Real-Time Dashboard
            with dashboard_placeholder.container():
                st.subheader("🌐 Live Network Traffic")
                m1, m2, m3, m4 = st.columns(4)
                
                # Get current data with thread lock
                with lock:
                    packet_counts_local = dict(packet_counts)
                    protocol_counts_local = dict(protocol_counts)
                    source_ips_local = dict(source_ips)
                    destination_ips_local = dict(destination_ips)
                    packet_sizes_local = packet_sizes.copy()
                    packet_data_local = packet_data.copy()
                
                # Display metrics
                total_packets = len(packet_data_local)
                current_rate = sum(packet_counts_local.values()) if packet_counts_local  else 0
                unique_sources = len(source_ips_local)
                current_alerts = len(monitor.stats.get('alerts', []))
                
                m1.metric("Total Packets", total_packets)
                m2.metric("Current Rate", f"{current_rate} pkt/s")
                m3.metric("Unique Sources", unique_sources)
                m4.metric("Alerts", current_alerts)
                
                # Packet rate chart only in dashboard tab
                if packet_counts_local:
                    max_time = max(packet_counts_local.keys())
                    time_range = list(range(max(0, max_time - 60), max_time + 1))
                    packets_per_sec = [packet_counts_local.get(t, 0) for t in time_range]
                    
                    # Create DataFrame with formatted timestamps
                    base_time = datetime.now() - timedelta(seconds=len(time_range))
                    time_labels = [(base_time + timedelta(seconds=i)).strftime("%I:%M:%S %p") for i in range(len(time_range))]
                    
                    df_time = pd.DataFrame({
                        'Time': time_labels,
                        'Packets': packets_per_sec
                    }).set_index('Time')
                    
                    # Create the chart with custom styling
                    st.area_chart(df_time, height=300, use_container_width=True, 
                                color=(255, 0, 0))  # Blue color similar to screenshot
                    
                    # Add custom Y-axis labels
                    st.markdown("""
                    <style>
                    .stAreaChart {
                        background-color: transparent;
                    }
                    </style>
                    <div style="position: relative; top: -320px; left: 10px; pointer-events: none;">
                    </div>
                    """, unsafe_allow_html=True)
                
                # Protocol distribution
                if protocol_counts_local:
                    st.subheader("Protocol Distribution")
                    st.write("Counts of different protocols in the captured traffic")
                    df_protocol = pd.DataFrame({
                        'Protocol': list(protocol_counts_local.keys()),
                        'Count': list(protocol_counts_local.values())
                    }).sort_values('Count', ascending=False)
                    st.bar_chart(df_protocol.set_index('Protocol'), height=300)

            # Update Security Alerts tab (static content)
            with alerts_placeholder.container():
                alerts = get_recent_alerts(50)
                if not alerts.empty:
                    st.subheader("Recent Security Alerts")
                        # Create a scrollable container
                    alert_container = st.container()
                    with alert_container:
                        # Limit to 10 most recent alerts
                        recent_alerts = alerts.head(10)
                        
                        # Define color mapping for different alert types
                        alert_colors = {
                            'DOS': '#ff4444',  # Red
                            'SYN Flood': '#ff7675',  # Light red
                            'PORT_SCAN': '#ffb142',  # Orange
                            'SYN Scan' :"#f40ba3"  ,  # Pastel pink
                            'MITM Attack': '#fdcb6e',  # Yellow
                            'Stealth Scan': '#a55eea',  # Purple
                            'UDP': '#3498db',  # Blue
                            'Other': '#2ecc71'  # Green (default)
                        }
                        
                        # Create custom CSS for the scrollable container
                        st.markdown("""
                        <style>
                            .scrollable-container {
                                max-height: 500px;
                                overflow-y: auto;
                                padding-right: 10px;
                            }
                            .alert-box {
                                padding: 10px;
                                margin-bottom: 10px;
                                border-radius: 5px;
                                border-left: 5px solid;
                            }
                        </style>
                        """, unsafe_allow_html=True)
                        
                        # Create the scrollable div
                        st.markdown('<div class="scrollable-container">', unsafe_allow_html=True)
                        
                        for index, row in recent_alerts.iterrows():
                            # Get color based on alert type, default to green for unknown types
                            alert_type = row['alert_type'].lower()
                            matched_color = alert_colors['Other']  # Default color

                            for keyword, hex_color in alert_colors.items():
                                if keyword.lower() in alert_type:
                                    matched_color = hex_color
                                    break

                            
                            # Display each alert in a colored box
                            st.markdown(f"""
                                <div class="alert-box" style="border-left-color: {matched_color}; background-color: {matched_color}22;">
                                    <strong>{datetime.fromisoformat(row['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}</strong> -  
                                    <span style="color: {matched_color}; font-weight: bold;">{row['alert_type']}</span><br>
                                    Source: {row['source_ip']} → Destination: {row['dest_ip']}<br>
                                    <small>{row['description']}</small>
                                </div>
                            """, unsafe_allow_html=True)

                        
                        # Close the scrollable div
                        st.markdown('</div>', unsafe_allow_html=True)
                else:
                    st.info("No security alerts detected yet")
                if not alerts.empty:
                    #st.dataframe(
                        #alerts,
                       # height=500,
                      #  hide_index=True,
                     #   use_container_width=True
                   # )
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.subheader("Alert Types")
                        st.bar_chart(alerts['alert_type'].value_counts())
                    with col2:
                        st.subheader("Alert Severity")
                        st.bar_chart(alerts['severity'].value_counts())
                else:
                    st.info("No security alerts detected yet")
                
               

                
                st.subheader("⛔ Blocked IP Addresses")
                blocked_ips = get_blocked_ips()

                if not blocked_ips.empty:
                    st.dataframe(
                        blocked_ips,
                        column_config={
                            "timestamp": "Blocked At",
                            "source_ip": "IP Address",
                            "reason": "Reason"
                        },
                        use_container_width=True,
                        hide_index=True
                    )
                    
                    #button salah undo bro

                else:
                    st.info("No currently blocked IP addresses")

            # Update Network Statistics tab (static content)
            with stats_placeholder.container():
                st.subheader("📈 Network Statistics")
                col1, col2 = st.columns(2)
                
                with col1:
                    if source_ips_local:
                        st.write("Top Source IPs")
                        top_sources = pd.DataFrame({
                            'Source IP': list(source_ips_local.keys()),
                            'Count': list(source_ips_local.values())
                        }).sort_values('Count', ascending=False).head(10)
                        st.bar_chart(top_sources.set_index('Source IP'))
                
                with col2:
                    if destination_ips_local:
                        st.write("Top Destination IPs")
                        top_dests = pd.DataFrame({
                            'Destination IP': list(destination_ips_local.keys()),
                            'Count': list(destination_ips_local.values())
                        }).sort_values('Count', ascending=False).head(10)
                        st.bar_chart(top_dests.set_index('Destination IP'))
                with col1:
                    st.subheader("Database Statistics")
                    try:
                        stats = get_packet_stats()
                        st.write(f"Total packets in database: {stats['total_packets']}")
                        st.write(f"Unique source IPs: {stats['unique_src_ips']}")
                        st.write(f"Unique destination IPs: {stats['unique_dest_ips']}")
                    except Exception as e:
                        st.error(f"Could not load database stats: {e}")
                        

            # Control update frequency
            time.sleep(update_interval)
            if not st.session_state.sniffing:
                break

        # Auto-refresh logic - only rerun if sniffing is active
        if st.session_state.sniffing:
            now = time.time()
            if now - st.session_state.last_refresh > update_interval:
                st.session_state.last_refresh = now
                st.rerun()

    elif mode == "Offline Analysis":
        st.title("📂 Offline PCAP Analysis")
        tab1, tab2 = st.tabs(["PCAP Analysis", "Database Insight"])

        with tab1:
            uploaded_pcap = st.file_uploader("Upload PCAP file", type=["pcap","pcapng"])
            if uploaded_pcap:
                uploaded_model = st.file_uploader("Upload Trained Model (.pkl)", type=["pkl"])
                if uploaded_model:
                    with st.spinner("Analyzing PCAP and predicting attacks…"):
                        try:
                            model, scaler, pca, label_mapping, feature_names = load_model(uploaded_model)
                            flows_df, ip_df = analyze_pcap(uploaded_pcap)
                            preds, probs = predict_flows(flows_df, model, scaler, pca, feature_names)
                            results_df = flows_df.copy()
                            results_df["Prediction"] = [label_mapping[p] for p in preds]
                            results_df["Confidence"] = [max(prob)*100 for prob in probs]
                            st.subheader("PCAP Analysis Results")
                            st.dataframe(results_df)
                        except Exception as e:
                            st.error(f"Error during PCAP analysis: {e}")
        with tab2:
        
            st.subheader("Real time attack log")
            col1, col2 = st.columns(2)
            with col1:
                start_date = st.date_input("Start date", datetime.now() - timedelta(days=7))
            with col2:
                end_date = st.date_input("End date", datetime.now())
            
            # Add CSV download section right after the date inputs
            st.markdown("---")
            st.subheader("Export Data")
            export_col1, export_col2 = st.columns([3,1])
            
            with export_col1:
                data_type = st.radio(
                    "Select data to export:",
                    ("Alerts", "Blocked IPs", "Network Traffic"),
                    horizontal=True
                )
            
            with export_col2:
                st.write("")  # Spacer
                export_btn = st.button("📥 Generate CSV Export")
            
            if export_btn:
                with st.spinner(f"Preparing {data_type} data..."):
                    try:
                        conn = get_db_connection()
                        
                        if data_type == "Alerts":
                            query = """
                            SELECT * FROM alerts
                            WHERE timestamp BETWEEN ? AND ?
                            ORDER BY timestamp DESC
                            """
                            filename = f"alerts_{start_date}_to_{end_date}.csv"
                            
                        elif data_type == "Blocked IPs":
                            query = """
                            SELECT * FROM blocked_ips
                            WHERE timestamp BETWEEN ? AND ?
                            ORDER BY timestamp DESC
                            """
                            filename = f"blocked_ips_{start_date}_to_{end_date}.csv"
                            
                        else:  # Network Traffic
                            query = """
                            SELECT * FROM packets
                            WHERE timestamp BETWEEN ? AND ?
                            ORDER BY timestamp DESC
                            LIMIT 100000
                            """
                            filename = f"network_traffic_{start_date}_to_{end_date}.csv"
                        
                        df = pd.read_sql(
                            query,
                            conn,
                            params=(start_date.isoformat(), end_date.isoformat())
                        )
                        
                        if not df.empty:
                            csv = df.to_csv(index=False)
                            st.download_button(
                                label="⬇️ Download CSV",
                                data=csv,
                                file_name=filename,
                                mime="text/csv",
                                key=f"download_{data_type.replace(' ', '_').lower()}"
                            )
                        else:
                            st.warning(f"No {data_type} data found for selected period")
                        
                    except Exception as e:
                        st.error(f"Export failed: {str(e)}")
                    finally:
                        conn.close()
        
            if st.button("Analyze Database"):
                with st.spinner("Analyzing historical data..."):
                    try:
                        # Get alerts in date range
                        conn = get_db_connection()
                        query = """
                        SELECT * FROM alerts
                        WHERE timestamp BETWEEN ? AND ?
                        ORDER BY timestamp DESC
                        """
                        alerts = pd.read_sql(
                            query, 
                            conn,
                            params=(start_date.isoformat(), end_date.isoformat())
                        )
                        
                        # Display results
                        if not alerts.empty:
                            st.subheader("Alerts in Selected Period")
                            st.dataframe(alerts)
                            
                            # Show summary visualizations
                            display_alert_summary()
                            
                            # Top attackers
                            st.subheader("Top Attack Sources")
                            top_attackers = alerts['source_ip'].value_counts().head(10)
                            st.bar_chart(top_attackers)
                        else:
                            st.info("No alerts found in selected period")
                        
                        conn.close()
                    except Exception as e:
                        st.error(f"Error analyzing database: {e}")

if __name__ == "__main__":
    main()
