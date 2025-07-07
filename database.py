import sqlite3
from contextlib import contextmanager
from datetime import datetime
from sys import flags

class NetworkDatabase:
    def __init__(self, db_path='network_monitor.db',timeout=10):
        self.db_path = db_path
        self._init_db()
    
    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('PRAGMA journal_mode=WAL')

            # Create tables
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                source_ip TEXT,
                dest_ip TEXT,
                protocol TEXT,
                length INTEGER,
                src_port INTEGER,
                dest_port INTEGER,
                flags INTEGER
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                alert_type TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                description TEXT,
                severity TEXT,
                packet_count INTEGER DEFAULT 1
            )
            ''')
            
            # Add indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_source_ip ON packets(source_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_alert_type ON alerts(alert_type)')
            
            conn.commit()
    
    def log_packet(self, packet_data):
        """Log a packet to the database"""
        try:
            flags = int(packet_data.get('flags', 0)) if packet_data.get('flags') is not None else 0
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                INSERT INTO packets 
                (timestamp, source_ip, dest_ip, protocol, length, src_port, dest_port, flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.now().isoformat(),
                    packet_data.get('source_ip'),
                    packet_data.get('dest_ip'),
                    packet_data.get('protocol'),
                    packet_data.get('length'),
                    packet_data.get('src_port'),
                    packet_data.get('dest_port'),
                    flags
                ))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            print(f"Error logging packet: {e}")
    
    def log_alert(self, alert_type, source_ip, dest_ip, description, severity='medium'):
        """Log a security alert to the database"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
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

    def get_stats(self):
        """Get database statistics"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) as packet_count FROM packets')
            packet_count = cursor.fetchone()['packet_count']
            
            cursor.execute('SELECT COUNT(*) as alert_count FROM alerts')
            alert_count = cursor.fetchone()['alert_count']
            
            return {
                'packet_count': packet_count,
                'alert_count': alert_count,
                'db_path': self.db_path
            }
