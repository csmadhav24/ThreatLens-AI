# app/parsers/pcap_parser.py
"""
PCAP Parser Module - Network traffic analysis
Supported formats: PCAP, PCAPNG
Features: Protocol analysis, connection mapping, anomaly detection
"""

import pandas as pd
import tempfile
import os
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime
from collections import defaultdict, Counter
import ipaddress

# Import config
import sys
sys.path.append(str(Path(__file__).parent.parent))
from config import PCAP_CONFIG, FILE_LIMITS

# Try importing Scapy (primary PCAP parser)
try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR, Ether
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.layers.inet6 import IPv6
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Try importing dpkt as fallback
try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False


class PCAPParser:
    """
    PCAP/PCAPNG parser with network analysis capabilities
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.parse_stats = {}
        self.connections = []
        self.detected_anomalies = []
        
    def parse(self, file_bytes: bytes, file_name: str) -> Optional[pd.DataFrame]:
        """
        Main parsing method for PCAP files
        
        Args:
            file_bytes: Raw PCAP file bytes
            file_name: Original file name
            
        Returns:
            DataFrame with packet information
        """
        ext = Path(file_name).suffix.lower()
        
        if ext not in ['.pcap', '.pcapng']:
            if self.verbose:
                print(f"⚠️ Not a PCAP file: {ext}")
            return None
        
        if self.verbose:
            print(f"📡 Parsing PCAP: {file_name}")
        
        start_time = datetime.now()
        
        # Save to temporary file for Scapy
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                tmp.write(file_bytes)
                tmp_path = tmp.name
            
            # Parse using Scapy (preferred)
            if SCAPY_AVAILABLE:
                df = self._parse_with_scapy(tmp_path)
            elif DPKT_AVAILABLE:
                df = self._parse_with_dpkt(tmp_path)
            else:
                if self.verbose:
                    print("❌ No PCAP library available. Install scapy: pip install scapy")
                return None
            
            if df is not None and not df.empty:
                # Limit rows for performance
                if len(df) > FILE_LIMITS['max_pcap_packets']:
                    df = df.head(FILE_LIMITS['max_pcap_packets'])
                
                # Calculate hash
                file_hash = hashlib.md5(file_bytes).hexdigest()
                
                self.parse_stats = {
                    'file_name': file_name,
                    'file_size_mb': len(file_bytes) / (1024 * 1024),
                    'packets': len(df),
                    'parse_time_seconds': (datetime.now() - start_time).total_seconds(),
                    'file_hash': file_hash,
                    'anomalies_detected': len(self.detected_anomalies)
                }
                
                if self.verbose:
                    print(f"✅ Parsed {len(df)} packets, detected {len(self.detected_anomalies)} anomalies")
                
                return df
            else:
                return None
                
        except Exception as e:
            if self.verbose:
                print(f"❌ PCAP parse error: {str(e)}")
            return None
            
        finally:
            # Clean up temp file
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    def _parse_with_scapy(self, pcap_path: str) -> pd.DataFrame:
        """Parse PCAP using Scapy library"""
        try:
            packets = rdpcap(pcap_path)
            packet_data = []
            
            # Track for anomaly detection
            packet_times = []
            syn_packets = defaultdict(int)
            
            for idx, pkt in enumerate(packets):
                if idx >= FILE_LIMITS['max_pcap_packets']:
                    break
                
                packet_info = self._extract_packet_info(pkt)
                packet_data.append(packet_info)
                
                # Track for anomaly detection
                if packet_info.get('timestamp'):
                    packet_times.append(packet_info['timestamp'])
                
                # Track SYN packets for port scan detection
                if packet_info.get('tcp_flags') and 'S' in str(packet_info['tcp_flags']):
                    src_ip = packet_info.get('src_ip', '')
                    if src_ip:
                        syn_packets[src_ip] += 1
            
            df = pd.DataFrame(packet_data)
            
            # Run anomaly detection
            self._detect_anomalies(df, syn_packets, packet_times)
            
            return df
            
        except Exception as e:
            if self.verbose:
                print(f"Scapy parse error: {e}")
            return pd.DataFrame()
    
    def _extract_packet_info(self, pkt) -> Dict[str, Any]:
        """Extract all relevant information from a single packet"""
        packet_info = {
            'timestamp': float(pkt.time) if hasattr(pkt, 'time') else None,
            'length': len(pkt),
            'protocol': 'Unknown',
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'tcp_flags': None,
            'icmp_type': None,
            'dns_query': None,
            'http_method': None,
            'http_uri': None,
            'http_user_agent': None,
            'payload_preview': None,
            'suspicious_flags': []
        }
        
        # Convert timestamp to datetime
        if packet_info['timestamp']:
            packet_info['datetime'] = datetime.fromtimestamp(packet_info['timestamp'])
        
        # Ethernet layer
        if Ether in pkt:
            packet_info['src_mac'] = pkt[Ether].src
            packet_info['dst_mac'] = pkt[Ether].dst
        
        # IP Layer
        if IP in pkt:
            packet_info['src_ip'] = pkt[IP].src
            packet_info['dst_ip'] = pkt[IP].dst
            packet_info['ip_ttl'] = pkt[IP].ttl
            packet_info['ip_len'] = pkt[IP].len
            
        elif IPv6 in pkt:
            packet_info['src_ip'] = pkt[IPv6].src
            packet_info['dst_ip'] = pkt[IPv6].dst
            packet_info['ip_ttl'] = pkt[IPv6].hlim
        
        # TCP Layer
        if TCP in pkt:
            packet_info['protocol'] = 'TCP'
            packet_info['src_port'] = pkt[TCP].sport
            packet_info['dst_port'] = pkt[TCP].dport
            packet_info['tcp_flags'] = self._get_tcp_flags(pkt[TCP].flags)
            packet_info['tcp_seq'] = pkt[TCP].seq
            packet_info['tcp_ack'] = pkt[TCP].ack
            packet_info['tcp_window'] = pkt[TCP].window
            
            # Check for suspicious flags
            if 'S' in packet_info['tcp_flags'] and 'A' not in packet_info['tcp_flags']:
                packet_info['suspicious_flags'].append('syn_scan')
            if 'R' in packet_info['tcp_flags']:
                packet_info['suspicious_flags'].append('rst_packet')
        
        # UDP Layer
        elif UDP in pkt:
            packet_info['protocol'] = 'UDP'
            packet_info['src_port'] = pkt[UDP].sport
            packet_info['dst_port'] = pkt[UDP].dport
        
        # ICMP Layer
        elif ICMP in pkt:
            packet_info['protocol'] = 'ICMP'
            packet_info['icmp_type'] = pkt[ICMP].type
            packet_info['icmp_code'] = pkt[ICMP].code
            
            # Suspicious ICMP types
            if pkt[ICMP].type in [8, 13, 17]:  # Echo request, timestamp, address mask
                packet_info['suspicious_flags'].append('suspicious_icmp')
        
        # DNS Layer
        if DNS in pkt and pkt[DNS].qr == 0:  # Query
            packet_info['dns_query'] = pkt[DNS].qd.qname.decode('utf-8') if pkt[DNS].qd else None
            
            # Check for suspicious TLDs
            if packet_info['dns_query']:
                for tld in PCAP_CONFIG['dns_suspicious_tlds']:
                    if packet_info['dns_query'].endswith(tld):
                        packet_info['suspicious_flags'].append(f'dns_suspicious_tld_{tld}')
        
        # HTTP Layer
        if HTTP in pkt:
            if HTTPRequest in pkt:
                packet_info['http_method'] = pkt[HTTPRequest].Method.decode('utf-8') if pkt[HTTPRequest].Method else None
                packet_info['http_uri'] = pkt[HTTPRequest].Path.decode('utf-8') if pkt[HTTPRequest].Path else None
                packet_info['http_host'] = pkt[HTTPRequest].Host.decode('utf-8') if pkt[HTTPRequest].Host else None
                packet_info['http_user_agent'] = pkt[HTTPRequest].User_Agent.decode('utf-8') if pkt[HTTPRequest].User_Agent else None
                
                # Check for suspicious User-Agent
                if packet_info['http_user_agent']:
                    suspicious_agents = ['python', 'curl', 'wget', 'go-http', 'nikto', 'nmap']
                    for agent in suspicious_agents:
                        if agent.lower() in packet_info['http_user_agent'].lower():
                            packet_info['suspicious_flags'].append(f'suspicious_ua_{agent}')
        
        # Extract payload preview
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            packet_info['payload_preview'] = payload[:100].hex() if len(payload) > 0 else None
            
            # Check for encoded data in payload
            try:
                payload_str = payload.decode('utf-8', errors='ignore').lower()
                if 'base64' in payload_str or 'powershell' in payload_str:
                    packet_info['suspicious_flags'].append('encoded_payload')
                if 'eval(' in payload_str or 'exec(' in payload_str:
                    packet_info['suspicious_flags'].append('code_execution')
            except:
                pass
        
        # Check for suspicious ports
        if packet_info.get('dst_port') in PCAP_CONFIG['suspicious_ports']:
            packet_info['suspicious_flags'].append(f'suspicious_port_{packet_info["dst_port"]}')
        
        return packet_info
    
    def _get_tcp_flags(self, flags: int) -> str:
        """Convert TCP flags integer to readable string"""
        flag_map = {
            0x01: 'F',  # FIN
            0x02: 'S',  # SYN
            0x04: 'R',  # RST
            0x08: 'P',  # PSH
            0x10: 'A',  # ACK
            0x20: 'U',  # URG
            0x40: 'E',  # ECE
            0x80: 'C'   # CWR
        }
        
        result = []
        for bit, char in flag_map.items():
            if flags & bit:
                result.append(char)
        
        return ''.join(result) if result else 'None'
    
    def _parse_with_dpkt(self, pcap_path: str) -> pd.DataFrame:
        """Fallback parser using dpkt library"""
        if not DPKT_AVAILABLE:
            return pd.DataFrame()
        
        try:
            packet_data = []
            
            with open(pcap_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                for timestamp, buf in pcap:
                    if len(packet_data) >= FILE_LIMITS['max_pcap_packets']:
                        break
                    
                    packet_info = {
                        'timestamp': timestamp,
                        'datetime': datetime.fromtimestamp(timestamp),
                        'length': len(buf),
                        'protocol': 'Unknown',
                        'src_ip': None,
                        'dst_ip': None,
                        'src_port': None,
                        'dst_port': None
                    }
                    
                    # Parse Ethernet frame
                    eth = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        packet_info['src_ip'] = socket.inet_ntoa(ip.src)
                        packet_info['dst_ip'] = socket.inet_ntoa(ip.dst)
                        
                        # TCP
                        if isinstance(ip.data, dpkt.tcp.TCP):
                            tcp = ip.data
                            packet_info['protocol'] = 'TCP'
                            packet_info['src_port'] = tcp.sport
                            packet_info['dst_port'] = tcp.dport
                        
                        # UDP
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            udp = ip.data
                            packet_info['protocol'] = 'UDP'
                            packet_info['src_port'] = udp.sport
                            packet_info['dst_port'] = udp.dport
                        
                        # ICMP
                        elif isinstance(ip.data, dpkt.icmp.ICMP):
                            packet_info['protocol'] = 'ICMP'
                    
                    packet_data.append(packet_info)
            
            return pd.DataFrame(packet_data)
            
        except Exception as e:
            if self.verbose:
                print(f"dpkt parse error: {e}")
            return pd.DataFrame()
    
    def _detect_anomalies(self, df: pd.DataFrame, syn_packets: dict, packet_times: list):
        """Detect network anomalies from parsed packets"""
        
        # 1. Port Scan Detection
        if PCAP_CONFIG['detect_port_scans']:
            for src_ip, count in syn_packets.items():
                if count > PCAP_CONFIG['scan_threshold']:
                    self.detected_anomalies.append({
                        'type': 'port_scan',
                        'source_ip': src_ip,
                        'syn_packets': count,
                        'severity': 'HIGH',
                        'description': f"Potential port scan detected from {src_ip} with {count} SYN packets"
                    })
        
        # 2. DDoS Detection
        if PCAP_CONFIG['detect_ddos'] and len(packet_times) > 1:
            # Calculate packet rate
            time_span = packet_times[-1] - packet_times[0]
            if time_span > 0:
                packet_rate = len(packet_times) / time_span
                if packet_rate > PCAP_CONFIG['ddos_threshold']:
                    self.detected_anomalies.append({
                        'type': 'ddos',
                        'packet_rate': packet_rate,
                        'severity': 'CRITICAL',
                        'description': f"High packet rate detected: {packet_rate:.0f} packets/sec"
                    })
        
        # 3. Suspicious Protocol Usage
        if 'protocol' in df.columns:
            protocol_counts = df['protocol'].value_counts()
            
            # Too many ICMP packets
            icmp_count = protocol_counts.get('ICMP', 0)
            if icmp_count > len(df) * 0.3:  # More than 30% ICMP
                self.detected_anomalies.append({
                    'type': 'icmp_storm',
                    'icmp_packets': icmp_count,
                    'severity': 'MEDIUM',
                    'description': f"Unusual ICMP activity: {icmp_count} packets ({icmp_count/len(df)*100:.1f}% of total)"
                })
        
        # 4. Data Exfiltration Indicators
        if 'length' in df.columns:
            large_packets = df[df['length'] > 1400]  # Large packets
            if len(large_packets) > len(df) * 0.2:  # More than 20% large packets
                self.detected_anomalies.append({
                    'type': 'potential_exfiltration',
                    'large_packets': len(large_packets),
                    'severity': 'HIGH',
                    'description': "Many large packets detected - potential data exfiltration"
                })
        
        # 5. Suspicious DNS Queries
        if 'dns_query' in df.columns:
            dns_queries = df[df['dns_query'].notna()]
            suspicious_dns = dns_queries[dns_queries['dns_query'].str.contains('|'.join(PCAP_CONFIG['dns_suspicious_tlds']), 
                                                                              case=False, na=False)]
            if len(suspicious_dns) > 0:
                self.detected_anomalies.append({
                    'type': 'suspicious_dns',
                    'queries': len(suspicious_dns),
                    'severity': 'MEDIUM',
                    'description': f"DNS queries to suspicious TLDs detected: {suspicious_dns['dns_query'].tolist()[:5]}"
                })
    
    def get_connection_summary(self, df: pd.DataFrame) -> pd.DataFrame:
        """Build connection summary between IPs"""
        if df is None or df.empty:
            return pd.DataFrame()
        
        if 'src_ip' not in df.columns or 'dst_ip' not in df.columns:
            return pd.DataFrame()
        
        # Group by source-destination pairs
        connections = df.groupby(['src_ip', 'dst_ip']).size().reset_index(name='packet_count')
        connections = connections.sort_values('packet_count', ascending=False)
        
        return connections
    
    def get_protocol_summary(self, df: pd.DataFrame) -> Dict[str, int]:
        """Get protocol distribution"""
        if df is None or df.empty or 'protocol' not in df.columns:
            return {}
        
        return df['protocol'].value_counts().to_dict()
    
    def get_top_talkers(self, df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
        """Get top IPs by traffic volume"""
        if df is None or df.empty:
            return pd.DataFrame()
        
        src_counts = df['src_ip'].value_counts().head(n).reset_index()
        src_counts.columns = ['ip_address', 'packets_sent']
        
        dst_counts = df['dst_ip'].value_counts().head(n).reset_index()
        dst_counts.columns = ['ip_address', 'packets_received']
        
        return src_counts, dst_counts
    
    def get_anomalies(self) -> List[Dict]:
        """Get list of detected anomalies"""
        return self.detected_anomalies
    
    def get_stats(self) -> Dict[str, Any]:
        """Get parsing statistics"""
        return self.parse_stats


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def quick_parse_pcap(file_path: str) -> Optional[pd.DataFrame]:
    """Quick helper to parse PCAP from disk"""
    parser = PCAPParser(verbose=True)
    with open(file_path, 'rb') as f:
        file_bytes = f.read()
    return parser.parse(file_bytes, Path(file_path).name)


def analyze_pcap_summary(file_path: str) -> Dict[str, Any]:
    """Generate comprehensive summary of PCAP file"""
    parser = PCAPParser(verbose=False)
    
    with open(file_path, 'rb') as f:
        file_bytes = f.read()
    
    df = parser.parse(file_bytes, Path(file_path).name)
    
    if df is None or df.empty:
        return {'error': 'Failed to parse PCAP'}
    
    summary = {
        'total_packets': len(df),
        'protocols': parser.get_protocol_summary(df),
        'unique_src_ips': df['src_ip'].nunique() if 'src_ip' in df.columns else 0,
        'unique_dst_ips': df['dst_ip'].nunique() if 'dst_ip' in df.columns else 0,
        'top_connections': parser.get_connection_summary(df).head(10).to_dict('records'),
        'anomalies': parser.get_anomalies(),
        'time_range': {
            'start': df['datetime'].min() if 'datetime' in df.columns else None,
            'end': df['datetime'].max() if 'datetime' in df.columns else None
        }
    }
    
    return summary


# ============================================
# TESTING CODE
# ============================================

if __name__ == "__main__":
    print("🧪 Testing PCAP Parser Module")
    print("=" * 50)
    
    # Check dependencies
    print(f"Scapy available: {SCAPY_AVAILABLE}")
    print(f"dpkt available: {DPKT_AVAILABLE}")
    
    if not SCAPY_AVAILABLE:
        print("\n⚠️ Scapy not installed. Install with: pip install scapy")
        print("Creating simulated test data instead...\n")
        
        # Create simulated packet data for testing
        import random
        
        test_packets = []
        test_ips = ['192.168.1.1', '192.168.1.100', '10.0.0.1', '8.8.8.8', '1.1.1.1']
        
        for i in range(20):
            test_packets.append({
                'timestamp': datetime.now().timestamp() - i*60,
                'datetime': datetime.now(),
                'src_ip': random.choice(test_ips),
                'dst_ip': random.choice(test_ips),
                'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 53, 4444, 22]),
                'length': random.randint(64, 1500)
            })
        
        df = pd.DataFrame(test_packets)
        
        print("✅ Created simulated packet data for testing")
        print(f"   Packets: {len(df)}")
        
    else:
        print("✅ Scapy available - full PCAP parsing enabled")
        # Create a simple test PCAP if needed
        df = None
    
    if df is not None:
        print(f"\n📊 First 5 packets:")
        print(df.head())
        
        # Test connection summary
        parser = PCAPParser(verbose=True)
        connections = parser.get_connection_summary(df)
        
        if not connections.empty:
            print(f"\n🔗 Top Connections:")
            print(connections.head())
        
        # Test protocol summary
        protocols = parser.get_protocol_summary(df)
        print(f"\n📡 Protocol Distribution:")
        for proto, count in protocols.items():
            print(f"   {proto}: {count}")
        
        # Test anomaly detection
        print(f"\n🚨 Anomalies Detected: {len(parser.get_anomalies())}")
        for anomaly in parser.get_anomalies():
            print(f"   [{anomaly['severity']}] {anomaly['type']}: {anomaly['description']}")
    
    print("\n" + "=" * 50)
    print("✅ PCAP Parser Module Ready")