# app/llm/query_engine.py
"""
Simple Query Engine with full error tracing
"""

import pandas as pd
import re
import traceback
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime


class LocalQueryEngine:
    """
    Simple pattern-based query engine for log analysis
    """
    
    def __init__(self, model_name: str = None, verbose: bool = False):
        self.verbose = verbose
        self.conversation_history = []
    
    def chat(self, question: str, df: pd.DataFrame) -> Dict[str, Any]:
        """Process user question with full error tracing"""
        
        if df is None or df.empty:
            return {
                'question': question,
                'results': pd.DataFrame(),
                'results_count': 0,
                'query_code': 'no_data',
                'insight': 'Please upload a log file first.',
                'timestamp': datetime.now().isoformat()
            }
        
        try:
            # Process the question
            result_df, query_type = self._process_question(question, df)
            
            # Generate insight
            if result_df is not None and not result_df.empty:
                insight = self._generate_insight(result_df, question)
            else:
                insight = "No matching events found."
            
            # Store history
            self.conversation_history.append({
                'timestamp': datetime.now().isoformat(),
                'question': question,
                'results_count': len(result_df) if result_df is not None else 0
            })
            
            return {
                'question': question,
                'results': result_df if result_df is not None else pd.DataFrame(),
                'results_count': len(result_df) if result_df is not None else 0,
                'query_code': query_type,
                'insight': insight,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            # Return full error details for debugging
            return {
                'question': question,
                'results': pd.DataFrame(),
                'results_count': 0,
                'query_code': 'error',
                'insight': f"Error: {str(e)}\n\nTraceback:\n{traceback.format_exc()}",
                'timestamp': datetime.now().isoformat()
            }
    
    def _process_question(self, question: str, df: pd.DataFrame) -> Tuple[Optional[pd.DataFrame], str]:
        """Process question using pattern matching - NO itertuples() here"""
        
        question_lower = question.lower()
        
        # Get column names (case-insensitive)
        columns_lower = {col.lower(): col for col in df.columns}
        
        # ============================================
        # SEVERITY-BASED QUERIES
        # ============================================
        if any(word in question_lower for word in ['critical', 'emergency', 'high severity', 'high-risk']):
            if 'severity' in columns_lower:
                col = columns_lower['severity']
                high_severities = ['EMERGENCY', 'CRITICAL', 'HIGH', 'ALERT', 'ERROR']
                # Using boolean indexing - NO itertuples()
                mask = df[col].astype(str).str.upper().isin(high_severities)
                result = df[mask].copy()
                if not result.empty:
                    return result, "High severity events"
        
        # ============================================
        # ERROR QUERIES
        # ============================================
        if any(word in question_lower for word in ['error', 'errors', 'failed', 'failure']):
            if 'severity' in columns_lower:
                col = columns_lower['severity']
                mask = df[col].astype(str).str.upper().isin(['ERROR', 'CRITICAL', 'HIGH', 'EMERGENCY'])
                result = df[mask].copy()
                if not result.empty:
                    return result, "Error events"
            
            # Search in raw_log or message
            for col_name in ['raw_log', 'message']:
                if col_name in columns_lower:
                    col = columns_lower[col_name]
                    mask = df[col].astype(str).str.contains('error|fail|exception', case=False, na=False)
                    result = df[mask].copy()
                    if not result.empty:
                        return result, "Error events (text search)"
        
        # ============================================
        # WARN QUERIES
        # ============================================
        if any(word in question_lower for word in ['warn', 'warning']):
            if 'severity' in columns_lower:
                col = columns_lower['severity']
                mask = df[col].astype(str).str.upper().isin(['WARN', 'WARNING'])
                result = df[mask].copy()
                if not result.empty:
                    return result, "Warning events"
        
        # ============================================
        # IP ADDRESS QUERIES
        # ============================================
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, question)
        if ips:
            target_ip = ips[0]
            if 'source_ip' in columns_lower:
                col = columns_lower['source_ip']
                mask = df[col].astype(str).str.contains(target_ip, na=False)
                result = df[mask].copy()
                if not result.empty:
                    return result, f"Events from IP {target_ip}"
            
            # Search in raw_log
            if 'raw_log' in columns_lower:
                col = columns_lower['raw_log']
                mask = df[col].astype(str).str.contains(target_ip, na=False)
                result = df[mask].copy()
                if not result.empty:
                    return result, f"Events containing IP {target_ip}"
        
        # ============================================
        # USER QUERIES - NO itertuples() here
        # ============================================
        if 'user' in question_lower:
            if 'user' in columns_lower:
                col = columns_lower['user']
                # Try to extract username from question
                user_match = re.search(r'user[:\s]+(\S+)', question_lower)
                if user_match:
                    username = user_match.group(1)
                    mask = df[col].astype(str).str.contains(username, case=False, na=False)
                    result = df[mask].copy()
                    if not result.empty:
                        return result, f"Events for user {username}"
                else:
                    # Show all users - using value_counts() which is safe
                    result = df[col].value_counts().reset_index()
                    result.columns = ['user', 'count']
                    return result, "User activity summary"
        
        # ============================================
        # SERVICE QUERIES
        # ============================================
        if any(word in question_lower for word in ['service', 'source', 'component']):
            for col_name in ['source', 'service']:
                if col_name in columns_lower:
                    col = columns_lower[col_name]
                    result = df[col].value_counts().reset_index()
                    result.columns = [col_name, 'count']
                    return result, f"Events by {col_name}"
        
        # ============================================
        # STATUS CODE QUERIES
        # ============================================
        if 'status' in question_lower:
            if 'status_code' in columns_lower:
                col = columns_lower['status_code']
                result = df[col].value_counts().reset_index()
                result.columns = ['status_code', 'count']
                return result, "Events by status code"
        
        # ============================================
        # SHOW ALL / SUMMARY
        # ============================================
        if any(word in question_lower for word in ['show all', 'all events', 'everything', 'all logs']):
            return df.head(50).copy(), "First 50 events"
        
        # ============================================
        # DEFAULT - Return sample with info
        # ============================================
        # Show available columns hint
        cols_hint = ", ".join(list(df.columns)[:5])
        insight = f"Try: 'show errors', 'critical events', or ask about these columns: {cols_hint}"
        
        # Return a small sample with a helpful message
        result = df.head(5).copy()
        # Add a help column as a DataFrame (safe way)
        help_df = pd.DataFrame([{
            'help': f"Available columns: {', '.join(df.columns)}",
            'example': 'Try: "show errors", "critical events", "status 403"'
        }])
        
        # Concatenate safely
        result = pd.concat([result, help_df], ignore_index=True)
        return result, f"Sample data - {insight}"
    
    def _generate_insight(self, df: pd.DataFrame, question: str) -> str:
        """Generate simple insight from results"""
        
        if df.empty:
            return "No matching events found."
        
        insights = []
        
        # Check severity column
        if 'severity' in df.columns:
            severity_counts = df['severity'].value_counts()
            high_count = sum(severity_counts.get(s, 0) for s in ['EMERGENCY', 'CRITICAL', 'HIGH', 'ALERT', 'ERROR'])
            if high_count > 0:
                insights.append(f"⚠️ {high_count} high-severity events detected")
        
        # Check for specific patterns in raw_log
        if 'raw_log' in df.columns:
            if df['raw_log'].astype(str).str.contains('error|fail', case=False, na=False).any():
                insights.append("⚠️ Errors/failures detected")
        
        # Add count
        insights.append(f"Found {len(df)} matching events")
        
        return " | ".join(insights) if insights else f"Found {len(df)} events."
    
    def suggest_questions(self, df: pd.DataFrame) -> List[str]:
        """Suggest relevant questions based on data"""
        suggestions = ["Show critical and error events", "Show warnings", "Show user activity summary"]
        
        if 'status_code' in df.columns:
            suggestions.append("Show status code distribution")
        if 'source_ip' in df.columns:
            suggestions.append("Show top IP addresses")
        
        return suggestions


def quick_query(question: str, df: pd.DataFrame) -> Dict[str, Any]:
    """Quick helper function"""
    engine = LocalQueryEngine()
    return engine.chat(question, df)