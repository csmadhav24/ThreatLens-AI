# app/parsers/log_parser.py
"""
Log Parser Module - Handles multiple log formats and converts to DataFrames
Supported formats: CSV, JSON, EVTX (Windows Event Logs), TXT, LOG
Includes custom application log format support for Wazuh, Syslog, etc.
"""

import pandas as pd
import json
import tempfile
import os
import re
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime
import hashlib

# Import config
import sys
sys.path.append(str(Path(__file__).parent.parent))
from config import FILE_LIMITS, WINDOWS_EVENT_IDS

# Try importing EVTX parser (optional dependency)
try:
    from evtx import PyEvtxParser
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False

# Try importing for Excel files (optional)
try:
    import openpyxl
    EXCEL_AVAILABLE = True
except ImportError:
    EXCEL_AVAILABLE = False


class LogParser:
    """
    Main log parser class that handles multiple formats
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.parse_stats = {}
        
    def parse(self, file_bytes: bytes, file_name: str) -> Optional[pd.DataFrame]:
        """
        Main parsing method - detects format and routes to appropriate parser
    
        Args:
            file_bytes: Raw file bytes
            file_name: Original file name (used to detect extension)
        
        Returns:
            pandas DataFrame or None if parsing fails
        """
        ext = Path(file_name).suffix.lower()
    
        if self.verbose:
            print(f"📄 Parsing {file_name} (extension: {ext})")
    
        start_time = datetime.now()
    
        try:
            if ext == '.csv':
                df = self._parse_csv(file_bytes)
            elif ext == '.json':
                df = self._parse_json(file_bytes)
            elif ext == '.evtx':
                df = self._parse_evtx(file_bytes)
            elif ext in ['.txt', '.log']:
                df = self._parse_raw_text(file_bytes)
            elif ext in ['.xlsx', '.xls'] and EXCEL_AVAILABLE:
                df = self._parse_excel(file_bytes)
            else:
                # Try auto-detection
                df = self._auto_detect(file_bytes)
        
            if df is not None and not df.empty:
            # FIRST: Parse custom log format columns (extract IPs, users, etc.)
            # This should happen BEFORE standardization so raw_log is still intact
                df = self._parse_custom_log_columns(df)
            
            # THEN: Clean and standardize
                df = self._standardize_dataframe(df)
            
            # Calculate hash for tracking
                file_hash = hashlib.md5(file_bytes).hexdigest()
            
                self.parse_stats = {
                    'file_name': file_name,
                    'file_size_mb': len(file_bytes) / (1024 * 1024),
                    'rows': len(df),
                    'columns': len(df.columns),
                    'parse_time_seconds': (datetime.now() - start_time).total_seconds(),
                    'file_hash': file_hash
                }
            
                if self.verbose:
                    print(f"✅ Parsed {len(df)} rows, {len(df.columns)} columns")
                    if 'timestamp' in df.columns:
                        print(f"   Timestamp range: {df['timestamp'].min()} to {df['timestamp'].max()}")
                    if 'severity' in df.columns:
                        print(f"   Severities found: {df['severity'].unique().tolist()}")
                    if 'source_ip' in df.columns:
                        ip_count = df['source_ip'].notna().sum()
                        print(f"   IP addresses extracted: {ip_count}")
                    if 'user' in df.columns:
                        user_count = df['user'].notna().sum()
                        print(f"   Users extracted: {user_count}")
            
                return df
            else:
                if self.verbose:
                    print(f"⚠️ No data parsed from {file_name}")
                return None
            
        except Exception as e:
            print(f"❌ Error parsing {file_name}: {str(e)}")
        return None
    
    def _parse_csv(self, file_bytes: bytes) -> pd.DataFrame:
        """Parse CSV file with auto-detection of delimiters"""
        encodings = ['utf-8', 'latin1', 'cp1252', 'iso-8859-1']
        
        for encoding in encodings:
            try:
                content = file_bytes.decode(encoding)
                first_line = content.split('\n')[0]
                delimiters = [',', ';', '\t', '|']
                detected_delim = ','
                
                for delim in delimiters:
                    if first_line.count(delim) > first_line.count(detected_delim):
                        detected_delim = delim
                
                from io import StringIO
                df = pd.read_csv(StringIO(content), delimiter=detected_delim, 
                                encoding=encoding, low_memory=False)
                
                if len(df) > 0:
                    return df
                    
            except Exception:
                continue
        
        try:
            from io import BytesIO
            df = pd.read_csv(BytesIO(file_bytes), low_memory=False)
            return df
        except:
            return pd.DataFrame()
    
    def _parse_json(self, file_bytes: bytes) -> pd.DataFrame:
        """Parse JSON file (array of objects or single object)"""
        try:
            content = file_bytes.decode('utf-8')
            data = json.loads(content)
            
            if isinstance(data, dict):
                data = [data]
            
            df = pd.json_normalize(data)
            return df
            
        except Exception as e:
            if self.verbose:
                print(f"JSON parse error: {e}")
            return pd.DataFrame()
    
    def _parse_evtx(self, file_bytes: bytes) -> pd.DataFrame:
        """Parse Windows Event Log (EVTX) files"""
        if not EVTX_AVAILABLE:
            if self.verbose:
                print("⚠️ python-evtx not installed. Install with: pip install python-evtx")
            return pd.DataFrame()
        
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix='.evtx', delete=False) as tmp:
                tmp.write(file_bytes)
                tmp_path = tmp.name
            
            parser = PyEvtxParser(tmp_path)
            records = []
            
            for idx, record in enumerate(parser.records()):
                if idx >= FILE_LIMITS['max_log_rows']:
                    break
                
                data = record.get('data', {})
                
                parsed_record = {
                    'event_id': data.get('Event', {}).get('System', {}).get('EventID', {}).get('#text', ''),
                    'timestamp': data.get('Event', {}).get('System', {}).get('TimeCreated', {}).get('@SystemTime', ''),
                    'provider': data.get('Event', {}).get('System', {}).get('Provider', {}).get('@Name', ''),
                    'level': data.get('Event', {}).get('System', {}).get('Level', ''),
                    'task': data.get('Event', {}).get('System', {}).get('Task', ''),
                    'computer': data.get('Event', {}).get('System', {}).get('Computer', ''),
                    'user_id': data.get('Event', {}).get('System', {}).get('Security', {}).get('@UserID', ''),
                    'description': data.get('Event', {}).get('RenderingInfo', {}).get('Message', ''),
                    'event_data': json.dumps(data.get('Event', {}).get('EventData', {}))
                }
                
                records.append(parsed_record)
            
            df = pd.DataFrame(records)
            
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            
            return df
            
        except Exception as e:
            if self.verbose:
                print(f"EVTX parse error: {e}")
            return pd.DataFrame()
            
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    def _parse_raw_text(self, file_bytes: bytes) -> pd.DataFrame:
        try:
            content = file_bytes.decode('utf-8', errors='ignore')
            lines = content.split('\n')
        
            if len(lines) > FILE_LIMITS['max_log_rows']:
                lines = lines[:FILE_LIMITS['max_log_rows']]
        
            parsed_lines = []
        
            # Compile regex patterns once for speed
            timestamp_pattern = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)')
            severity_pattern = re.compile(r'\[(\w+)\]')
            service_pattern = re.compile(r'service=([a-zA-Z0-9_-]+)')
            user_pattern = re.compile(r'user=([a-zA-Z0-9_-]+)')
            ip_pattern = re.compile(r'ip=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            status_pattern = re.compile(r'status=(\d{3})')
            latency_pattern = re.compile(r'latency_ms=(\d+)')
            event_pattern = re.compile(r'event="([^"]+)"')
        
            for line_num, line in enumerate(lines):
                if not line.strip():
                    continue
            
                # Initialize with raw log
                parsed = {
                    'line_number': line_num,
                    'raw_log': line,
                    'timestamp': None,
                    'severity': None,
                    'source': None,
                    'source_ip': None,
                    'user': None,
                    'status_code': None,
                    'latency_ms': None,
                    'event_type': None,
                    'message': line
                }
            
                # Extract using compiled patterns
                ts_match = timestamp_pattern.search(line)
                if ts_match:
                    parsed['timestamp'] = ts_match.group(1)
            
                sev_match = severity_pattern.search(line)
                if sev_match:
                    parsed['severity'] = sev_match.group(1)
            
                service_match = service_pattern.search(line)
                if service_match:
                    parsed['source'] = service_match.group(1)
            
                user_match = user_pattern.search(line)
                if user_match:
                    parsed['user'] = user_match.group(1)
            
                ip_match = ip_pattern.search(line)
                if ip_match:
                    parsed['source_ip'] = ip_match.group(1)
            
                status_match = status_pattern.search(line)
                if status_match:
                    parsed['status_code'] = status_match.group(1)
            
                latency_match = latency_pattern.search(line)
                if latency_match:
                    parsed['latency_ms'] = latency_match.group(1)
            
                event_match = event_pattern.search(line)
                if event_match:
                    parsed['event_type'] = event_match.group(1)
                    parsed['message'] = event_match.group(1)
            
                parsed_lines.append(parsed)
        
            df = pd.DataFrame(parsed_lines)
        
            # Convert timestamp to datetime
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        
            # Debug output
            if self.verbose:
                ip_count = df['source_ip'].notna().sum()
                user_count = df['user'].notna().sum()
                print(f"\n📊 EXTRACTION STATS:")
                print(f"   Total lines: {len(df)}")
                print(f"   IPs found: {ip_count} ({ip_count/len(df)*100:.1f}%)")
                print(f"   Users found: {user_count} ({user_count/len(df)*100:.1f}%)")
                if ip_count > 0:
                    print(f"   Sample IPs: {df['source_ip'].dropna().head(3).tolist()}")
                if user_count > 0:
                    print(f"   Sample Users: {df['user'].dropna().head(3).tolist()}")
        
            return df
        
        except Exception as e:
            if self.verbose:
                print(f"Text parse error: {e}")
            return pd.DataFrame()
    
    def _parse_custom_log_format(self, line: str, line_num: int) -> Optional[Dict]:
        """
        Parse custom application log formats
        Supports formats like:
        - 2026-06-05T08:00:01.125Z INFO | AUTH-SVC | message
        - 2026-06-05 08:00:01,125 INFO [source] message
        - HIGH | SECURITY | Excessive login failures
        - 2026-01-01T00:00:01Z [WARN] service=wazuh-agent user=user3364 ip=48.111.246.1
        """
        
        # Pattern 1: ISO timestamp with severity and pipe separators
        pattern1 = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)\s+(\w+)\s*\|\s*(\S+)\s*\|\s*(.*)'
        match = re.match(pattern1, line)
        if match:
            timestamp, severity, source, message = match.groups()
            return {
                'timestamp': timestamp,
                'severity': severity.upper(),
                'source': source,
                'message': message.strip(),
                'raw_log': line,
                'line_number': line_num
            }
        
        # Pattern 2: ISO timestamp without T (space instead)
        pattern2 = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}Z)\s+(\w+)\s*\|\s*(\S+)\s*\|\s*(.*)'
        match = re.match(pattern2, line)
        if match:
            timestamp, severity, source, message = match.groups()
            return {
                'timestamp': timestamp,
                'severity': severity.upper(),
                'source': source,
                'message': message.strip(),
                'raw_log': line,
                'line_number': line_num
            }
        
        # Pattern 3: Timestamp with comma milliseconds
        pattern3 = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})\s+(\w+)\s+\[(\S+)\]\s+(.*)'
        match = re.match(pattern3, line)
        if match:
            timestamp, severity, source, message = match.groups()
            timestamp = timestamp.replace(',', '.')
            return {
                'timestamp': timestamp,
                'severity': severity.upper(),
                'source': source,
                'message': message.strip(),
                'raw_log': line,
                'line_number': line_num
            }
        
        # Pattern 4: Severity first (no timestamp), pipe separators
        pattern4 = r'^(\w+)\s*\|\s*(\S+)\s*\|\s*(.*)'
        match = re.match(pattern4, line)
        if match:
            severity, source, message = match.groups()
            severity_upper = severity.upper()
            if severity_upper in ['INFO', 'WARN', 'ERROR', 'HIGH', 'CRITICAL', 'DEBUG', 'WARNING']:
                return {
                    'timestamp': None,
                    'severity': severity_upper,
                    'source': source,
                    'message': message.strip(),
                    'raw_log': line,
                    'line_number': line_num
                }
        
        # Pattern 5: Simple space-separated: timestamp severity source message
        pattern5 = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(\S+)\s+(.*)'
        match = re.match(pattern5, line)
        if match:
            timestamp, severity, source, message = match.groups()
            return {
                'timestamp': timestamp,
                'severity': severity.upper(),
                'source': source,
                'message': message.strip(),
                'raw_log': line,
                'line_number': line_num
            }
        
        # Pattern 6: Extract severity from anywhere in line
        severity_match = re.search(r'\b(INFO|WARN|ERROR|HIGH|CRITICAL|DEBUG|WARNING)\b', line, re.IGNORECASE)
        if severity_match:
            severity = severity_match.group(1).upper()
            timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}[.,]\d{3}Z?)', line)
            timestamp = timestamp_match.group(1) if timestamp_match else None
            if timestamp:
                timestamp = timestamp.replace(',', '.')
            
            return {
                'timestamp': timestamp,
                'severity': severity,
                'source': None,
                'message': line,
                'raw_log': line,
                'line_number': line_num
            }
        
        # Pattern 7: WAZUH / KEY=VALUE LOG FORMAT (NEW!)
        # Example: 2026-01-01T00:00:01Z [WARN] service=wazuh-agent user=user3364 ip=48.111.246.1 status=403 latency_ms=3569 event="Connection reset by peer"
        pattern7 = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)?\s*\[?(\w+)\]?\s+(.*)'
        match = re.match(pattern7, line)
        if match:
            timestamp = match.group(1)
            severity = match.group(2).upper()
            rest = match.group(3)
            
            result = {
                'timestamp': timestamp,
                'severity': severity,
                'raw_log': line,
                'line_number': line_num,
                'message': rest
            }
            
            # Parse key=value pairs
            kv_pattern = r'(\w+)=("([^"]*)"|(\S+))'
            kv_matches = re.findall(kv_pattern, rest)
            
            for kv_match in kv_matches:
                key = kv_match[0]
                value = kv_match[2] if kv_match[2] else kv_match[3]
                
                if key == 'service':
                    result['source'] = value
                elif key == 'user':
                    result['user'] = value
                elif key == 'ip':
                    result['source_ip'] = value
                elif key == 'status':
                    result['status_code'] = value
                elif key == 'latency_ms':
                    result['latency_ms'] = value
                elif key == 'event':
                    result['message'] = value
                    result['event_type'] = value
                else:
                    result[key] = value
            
            return result
        
        return None
    
    def _parse_custom_log_columns(self, df: pd.DataFrame) -> pd.DataFrame:

        if df is None or df.empty:
            return df
    
        # If we have raw_log but no timestamp/severity/source, try to extract them
        if 'raw_log' in df.columns:
        
            # Extract IP address - DIRECT PATTERN for ip=XXX
            if 'source_ip' not in df.columns or df['source_ip'].isnull().all():
                df['source_ip'] = df['raw_log'].str.extract(
                    r'ip[=:]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', expand=False
                )
                # Also try general IP pattern as fallback
                if df['source_ip'].isnull().all():
                    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                    df['source_ip'] = df['raw_log'].str.extract(f'({ip_pattern})', expand=False)
        
            # Extract username - DIRECT PATTERN for user=XXX
            if 'user' not in df.columns or df['user'].isnull().all():
                df['user'] = df['raw_log'].str.extract(
                    r'user[=:]\s*([a-zA-Z0-9_-]+)', expand=False
                )
                # Fallback to general user pattern
                if df['user'].isnull().all():
                    df['user'] = df['raw_log'].str.extract(
                        r'user(?:name)?[=:\s]+(\S+)', flags=re.IGNORECASE, expand=False
                    )
        
            # Extract timestamp
            if 'timestamp' not in df.columns or df['timestamp'].isnull().all():
                df['timestamp'] = df['raw_log'].str.extract(
                    r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}Z?)', expand=False
                )
        
            # Extract severity (supports [WARN], WARN, etc.)
            if 'severity' not in df.columns or df['severity'].isnull().all():
                df['severity'] = df['raw_log'].str.extract(
                    r'\[?(\b(?:INFO|WARN|ERROR|HIGH|CRITICAL|DEBUG|WARNING|ALERT|EMERGENCY|STACKTRACE)\b)\]?', 
                    flags=re.IGNORECASE, expand=False
                )
                if 'severity' in df.columns:
                    df['severity'] = df['severity'].str.upper()
        
            # Extract service/source
            if 'source' not in df.columns or df['source'].isnull().all():
                df['source'] = df['raw_log'].str.extract(
                    r'service[=:]\s*([a-zA-Z0-9_-]+)', expand=False
                )
                if df['source'].isnull().all():
                    df['source'] = df['raw_log'].str.extract(
                        r'\[([A-Za-z0-9_-]+)\]', expand=False
                    )
    
        # Convert timestamp to datetime
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    
        # Standardize severity levels
        if 'severity' in df.columns:
            severity_map = {
                'EMERGENCY': 'CRITICAL',
                'ALERT': 'CRITICAL',
                'CRITICAL': 'CRITICAL',
                'HIGH': 'HIGH',
                'ERROR': 'HIGH',
                'WARN': 'MEDIUM',
                'WARNING': 'MEDIUM',
                'INFO': 'LOW',
                'DEBUG': 'LOW',
                'TRACE': 'LOW',
                'STACKTRACE': 'MEDIUM'
            }
            df['severity_normalized'] = df['severity'].map(severity_map).fillna('MEDIUM')
    
        # Debug print
        if self.verbose:
            print(f"\n📊 Custom Extraction Results:")
            if 'source_ip' in df.columns:
                ip_count = df['source_ip'].notna().sum()
                print(f"   IPs extracted: {ip_count} / {len(df)}")
                if ip_count > 0:
                    print(f"   Sample IPs: {df['source_ip'].dropna().head(3).tolist()}")
            if 'user' in df.columns:
                user_count = df['user'].notna().sum()
                print(f"   Users extracted: {user_count} / {len(df)}")
            if user_count > 0:
                print(f"   Sample users: {df['user'].dropna().head(3).tolist()}")
    
        return df
    
    def _parse_excel(self, file_bytes: bytes) -> pd.DataFrame:
        """Parse Excel files"""
        if not EXCEL_AVAILABLE:
            return pd.DataFrame()
        
        try:
            from io import BytesIO
            df = pd.read_excel(BytesIO(file_bytes))
            return df
        except:
            return pd.DataFrame()
    
    def _parse_common_log_format(self, line: str) -> Optional[Dict]:
        """Parse common log formats like syslog, Apache, IIS"""
        
        # Pattern 1: Syslog format
        syslog_pattern = r'^<(\d+)>(\w+\s+\d+\s+\S+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$'
        match = re.match(syslog_pattern, line)
        if match:
            priority, timestamp, host, program, pid, message = match.groups()
            return {
                'timestamp': timestamp,
                'source': host,
                'program': program,
                'pid': pid,
                'message': message,
                'severity': self._get_syslog_severity(int(priority)),
                'raw_log': line
            }
        
        # Pattern 2: IIS Log format
        iis_pattern = r'^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)'
        match = re.match(iis_pattern, line)
        if match:
            date, time, method, uri, query, user, ip = match.groups()
            return {
                'timestamp': f"{date} {time}",
                'method': method,
                'uri': uri,
                'user': user,
                'source_ip': ip,
                'raw_log': line
            }
        
        # Pattern 3: Apache/Common Log Format
        apache_pattern = r'^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)'
        match = re.match(apache_pattern, line)
        if match:
            ip, user, datetime_str, method, uri, protocol, status, size = match.groups()
            return {
                'source_ip': ip,
                'user': user,
                'timestamp': datetime_str,
                'method': method,
                'uri': uri,
                'status_code': int(status),
                'size': int(size),
                'raw_log': line
            }
        
        return None
    
    def _get_syslog_severity(self, priority: int) -> str:
        """Convert syslog priority to severity string"""
        severity = priority & 0x07
        severity_map = {
            0: 'Emergency',
            1: 'Alert',
            2: 'Critical',
            3: 'Error',
            4: 'Warning',
            5: 'Notice',
            6: 'Informational',
            7: 'Debug'
        }
        return severity_map.get(severity, 'Unknown')
    
    def _auto_detect(self, file_bytes: bytes) -> pd.DataFrame:
        """Auto-detect file format based on content"""
        try:
            content = file_bytes[:1000].decode('utf-8', errors='ignore')
            if content.strip().startswith('{') or content.strip().startswith('['):
                return self._parse_json(file_bytes)
            
            if ',' in content or ';' in content or '\t' in content:
                return self._parse_csv(file_bytes)
            
            return self._parse_raw_text(file_bytes)
            
        except:
            return self._parse_raw_text(file_bytes)
    
    def _standardize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardize column names and types across all parsers"""
        
        df.columns = [str(col).lower().replace(' ', '_') for col in df.columns]
        
        column_mappings = {
            'timestamp': ['timestamp', 'time', 'datetime', 'date', '@timestamp', 'eventtime'],
            'source_ip': ['source_ip', 'src_ip', 'src', 'ip_src', 'client_ip', 'ip'],
            'destination_ip': ['dest_ip', 'dst_ip', 'dst', 'ip_dst', 'server_ip'],
            'user': ['user', 'username', 'user_name', 'account', 'subject_user_name'],
            'process': ['process', 'process_name', 'image', 'command_line_process'],
            'commandline': ['commandline', 'command_line', 'cmdline', 'args'],
            'event_id': ['event_id', 'eventid', 'event_code', 'eventid', 'id'],
            'severity': ['severity', 'level', 'priority', 'importance'],
            'source': ['source', 'service', 'component', 'module'],
            'message': ['message', 'msg', 'description', 'details'],
            'status_code': ['status_code', 'status', 'http_status'],
            'latency_ms': ['latency_ms', 'latency', 'response_time']
        }
        
        for standard_name, possible_names in column_mappings.items():
            for possible in possible_names:
                if possible in df.columns and standard_name not in df.columns:
                    df[standard_name] = df[possible]
                    break
        
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        
        if 'event_id' in df.columns:
            df['event_id'] = df['event_id'].astype(str)
        
        if 'event_id' in df.columns:
            df['event_description'] = df['event_id'].map(
                lambda x: WINDOWS_EVENT_IDS.get(int(x) if str(x).isdigit() else 0, f"Event {x}")
            )
        
        if 'severity' in df.columns:
            df['severity'] = df['severity'].str.upper()
        
        if 'timestamp' in df.columns:
            df = df.sort_values('timestamp').reset_index(drop=True)
        
        return df
    
    def get_stats(self) -> Dict[str, Any]:
        """Get parsing statistics from last parse operation"""
        return self.parse_stats
    
    def get_sample(self, df: pd.DataFrame, n: int = 5) -> pd.DataFrame:
        """Get sample of parsed data for preview"""
        return df.head(n) if df is not None else pd.DataFrame()
    
    def get_summary(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Generate summary statistics for parsed dataframe"""
        if df is None or df.empty:
            return {'error': 'No data available'}
        
        summary = {
            'total_rows': len(df),
            'total_columns': len(df.columns),
            'columns': list(df.columns),
            'memory_usage_mb': df.memory_usage(deep=True).sum() / (1024 * 1024),
            'null_percentage': (df.isnull().sum().sum() / (df.shape[0] * df.shape[1])) * 100
        }
        
        if 'timestamp' in df.columns and not df['timestamp'].isnull().all():
            summary['time_range_start'] = str(df['timestamp'].min())
            summary['time_range_end'] = str(df['timestamp'].max())
            summary['time_range_hours'] = (df['timestamp'].max() - df['timestamp'].min()).total_seconds() / 3600
        
        for col in ['source_ip', 'user', 'event_id', 'severity', 'source', 'status_code']:
            if col in df.columns:
                summary[f'unique_{col}'] = df[col].nunique()
        
        if 'severity' in df.columns:
            summary['severity_distribution'] = df['severity'].value_counts().to_dict()
        
        return summary


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def quick_parse(file_path: str) -> Optional[pd.DataFrame]:
    """Quick helper function to parse a log file from disk"""
    parser = LogParser(verbose=True)
    with open(file_path, 'rb') as f:
        file_bytes = f.read()
    return parser.parse(file_bytes, Path(file_path).name)


def parse_multiple_files(file_paths: List[str]) -> Dict[str, pd.DataFrame]:
    """Parse multiple log files"""
    parser = LogParser(verbose=False)
    results = {}
    
    for file_path in file_paths:
        with open(file_path, 'rb') as f:
            file_bytes = f.read()
        df = parser.parse(file_bytes, Path(file_path).name)
        if df is not None:
            results[Path(file_path).name] = df
    
    return results


# ============================================
# TESTING CODE
# ============================================

if __name__ == "__main__":
    print("🧪 Testing Log Parser Module")
    print("=" * 50)
    
    # Test Wazuh-style log format
    wazuh_log = b'2026-01-01T00:00:01Z [WARN] service=wazuh-agent user=user3364 ip=48.111.246.1 status=403 latency_ms=3569 event="Connection reset by peer"'
    
    parser = LogParser(verbose=True)
    df = parser.parse(wazuh_log, "wazuh_test.log")
    
    if df is not None:
        print("\n✅ Successfully parsed Wazuh log")
        print(f"   Rows: {len(df)}")
        print(f"   Columns: {list(df.columns)}")
        
        print("\n📊 Extracted Data:")
        for col in ['timestamp', 'severity', 'source_ip', 'user', 'source', 'status_code', 'latency_ms', 'event_type']:
            if col in df.columns:
                print(f"   {col}: {df[col].iloc[0]}")
    else:
        print("❌ Parsing failed")
    
    print("\n" + "=" * 50)
    print("✅ Log Parser Module Ready")