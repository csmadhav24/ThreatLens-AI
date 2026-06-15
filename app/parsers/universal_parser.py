# app/parsers/universal_parser.py
import re
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any, Optional
import json

class UniversalLogParser:
    """Parses ANY log format - JSON, CSV, Syslog, Wazuh, Custom, etc."""
    
    def __init__(self):
        self.supported_formats = ['json', 'csv', 'syslog', 'wazuh', 'generic']
    
    def parse(self, file_content: str, file_extension: str = None) -> pd.DataFrame:
        """Main parsing method - automatically detects format"""
        
        # Try different parsing strategies
        parsers = [
            self._parse_json,
            self._parse_csv,
            self._parse_syslog,
            self._parse_wazuh,
            self._parse_key_value,
            self._parse_generic
        ]
        
        for parser in parsers:
            try:
                df = parser(file_content)
                if df is not None and len(df) > 0:
                    print(f"Successfully parsed with {parser.__name__}")
                    return self._normalize_dataframe(df)
            except Exception as e:
                continue
        
        # Last resort - create a simple dataframe with raw lines
        return self._parse_raw_lines(file_content)
    
    def _parse_json(self, content: str) -> Optional[pd.DataFrame]:
        """Parse JSON lines or array"""
        try:
            # Try parsing as JSON array
            data = json.loads(content)
            if isinstance(data, list):
                return pd.DataFrame(data)
        except:
            pass
        
        try:
            # Try parsing as JSON lines (each line is JSON)
            records = []
            for line in content.strip().split('\n'):
                if line.strip():
                    records.append(json.loads(line))
            if records:
                return pd.DataFrame(records)
        except:
            pass
        
        return None
    
    def _parse_csv(self, content: str) -> Optional[pd.DataFrame]:
        """Parse CSV format"""
        try:
            # Try with header
            df = pd.read_csv(pd.io.common.StringIO(content))
            if len(df.columns) > 1:
                return df
        except:
            pass
        
        try:
            # Try without header
            df = pd.read_csv(pd.io.common.StringIO(content), header=None)
            return df
        except:
            pass
        
        return None
    
    def _parse_syslog(self, content: str) -> Optional[pd.DataFrame]:
        """Parse Syslog/Rsyslog format"""
        pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s*(.*)'
        records = []
        
        for line in content.strip().split('\n'):
            match = re.match(pattern, line)
            if match:
                records.append({
                    'timestamp': match.group(1),
                    'host': match.group(2),
                    'process': match.group(3),
                    'message': match.group(4),
                    'raw': line
                })
        
        if records:
            return pd.DataFrame(records)
        return None
    
    def _parse_wazuh(self, content: str) -> Optional[pd.DataFrame]:
        """Parse Wazuh/OSSEC log format"""
        pattern = r'(\d+-\d+-\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)\s+\[.*?\]\s+(.*)'
        records = []
        
        for line in content.strip().split('\n'):
            match = re.match(pattern, line)
            if match:
                records.append({
                    'timestamp': match.group(1),
                    'level': match.group(2),
                    'type': match.group(3),
                    'message': match.group(4),
                    'raw': line
                })
        
        if records:
            return pd.DataFrame(records)
        return None
    
    def _parse_key_value(self, content: str) -> Optional[pd.DataFrame]:
        """Parse key=value format (common in security logs)"""
        records = []
        
        for line in content.strip().split('\n'):
            if '=' in line:
                record = {'raw': line}
                # Extract timestamp if present
                timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
                if timestamp_match:
                    record['timestamp'] = timestamp_match.group(1)
                
                # Extract all key=value pairs
                pairs = re.findall(r'(\w+)=([^\s]+)', line)
                for key, value in pairs:
                    record[key] = value
                
                # Extract level/severity
                if 'CRITICAL' in line:
                    record['level'] = 'CRITICAL'
                elif 'ERROR' in line:
                    record['level'] = 'ERROR'
                elif 'WARN' in line:
                    record['level'] = 'WARN'
                elif 'ALERT' in line:
                    record['level'] = 'ALERT'
                else:
                    record['level'] = 'INFO'
                
                records.append(record)
        
        if records:
            return pd.DataFrame(records)
        return None
    
    def _parse_generic(self, content: str) -> Optional[pd.DataFrame]:
        """Generic parser for structured logs with brackets"""
        records = []
        
        for line in content.strip().split('\n'):
            record = {'raw': line}
            
            # Extract timestamp
            ts_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
            if ts_match:
                record['timestamp'] = ts_match.group(1)
            
            # Extract level
            for level in ['CRITICAL', 'ERROR', 'WARN', 'INFO', 'DEBUG', 'ALERT']:
                if f'[{level}]' in line or f' {level} ' in line:
                    record['level'] = level
                    break
            
            # Extract service
            service_match = re.search(r'service=(\w+)', line)
            if service_match:
                record['service'] = service_match.group(1)
            
            # Extract user
            user_match = re.search(r'user=(\S+)', line)
            if user_match:
                record['user'] = user_match.group(1)
            
            # Extract IP
            ip_match = re.search(r'ip=([0-9.]+)', line)
            if ip_match:
                record['ip'] = ip_match.group(1)
            
            # Extract event
            event_match = re.search(r'event="([^"]+)"', line)
            if event_match:
                record['event'] = event_match.group(1)
            
            # Extract status code
            status_match = re.search(r'status=(\d+)', line)
            if status_match:
                record['status_code'] = int(status_match.group(1))
            
            records.append(record)
        
        if records:
            return pd.DataFrame(records)
        return None
    
    def _parse_raw_lines(self, content: str) -> pd.DataFrame:
        """Last resort - just store raw lines"""
        lines = content.strip().split('\n')
        df = pd.DataFrame({'raw': lines, 'line_number': range(1, len(lines)+1)})
        return df
    
    def _normalize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Ensure DataFrame has consistent column names"""
        # Convert all column names to string and strip
        df.columns = [str(col).strip().lower() for col in df.columns]
        
        # Ensure required columns exist
        required_cols = ['timestamp', 'level', 'raw']
        for col in required_cols:
            if col not in df.columns:
                df[col] = ''
        
        # Convert timestamp to datetime if possible
        if 'timestamp' in df.columns:
            try:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='ignore')
            except:
                pass
        
        return df