# app/reporting/chart_builder.py
"""
Professional Chart Builder for SOC Reports
Creates visualizations: timelines, severity distribution, network graphs, heatmaps
"""

import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import base64
from io import BytesIO
import warnings
warnings.filterwarnings('ignore')

# Import config
import sys
sys.path.append(str(Path(__file__).parent.parent))
from config import REPORT_CONFIG

# Try importing visualization libraries
try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.patches import Patch
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    import seaborn as sns
    SEABORN_AVAILABLE = True
except ImportError:
    SEABORN_AVAILABLE = False

try:
    import plotly.express as px
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

try:
    from wordcloud import WordCloud
    WORDCLOUD_AVAILABLE = True
except ImportError:
    WORDCLOUD_AVAILABLE = False


class ChartBuilder:
    """
    Professional chart builder for SOC incident reports
    Creates various visualizations for security findings
    """
    
    def __init__(self, theme: str = 'dark', style: str = 'professional'):
        """
        Initialize chart builder
        
        Args:
            theme: 'dark' or 'light'
            style: 'professional', 'modern', or 'simple'
        """
        self.theme = theme
        self.style = style
        self.colors = self._get_color_palette()
        
        # Setup matplotlib if available
        if MATPLOTLIB_AVAILABLE:
            self._setup_matplotlib()
    
    def _get_color_palette(self) -> Dict[str, str]:
        """Get professional color palette based on theme"""
        if self.theme == 'dark':
            return {
                'critical': '#FF0000',
                'high': '#FF6B00',
                'medium': '#FFD700',
                'low': '#00FF00',
                'info': '#00BFFF',
                'background': '#1E1E1E',
                'text': '#FFFFFF',
                'grid': '#333333',
                'primary': '#00BFFF',
                'secondary': '#FF6B00',
                'success': '#00FF00',
                'warning': '#FFD700',
                'danger': '#FF0000'
            }
        else:
            return {
                'critical': '#DC3545',
                'high': '#FD7E14',
                'medium': '#FFC107',
                'low': '#28A745',
                'info': '#17A2B8',
                'background': '#FFFFFF',
                'text': '#212529',
                'grid': '#DEE2E6',
                'primary': '#007BFF',
                'secondary': '#6C757D',
                'success': '#28A745',
                'warning': '#FFC107',
                'danger': '#DC3545'
            }
    
    def _setup_matplotlib(self):
        """Configure matplotlib for professional appearance"""
        if not MATPLOTLIB_AVAILABLE:
            return
        
        if self.theme == 'dark':
            plt.style.use('dark_background')
        else:
            plt.style.use('seaborn-v0_8')
        
        plt.rcParams['figure.figsize'] = (12, 6)
        plt.rcParams['figure.dpi'] = 100
        plt.rcParams['savefig.dpi'] = 150
        plt.rcParams['font.size'] = 10
        plt.rcParams['axes.labelsize'] = 12
        plt.rcParams['axes.titlesize'] = 14
        plt.rcParams['legend.fontsize'] = 10
        plt.rcParams['figure.titlesize'] = 16
    
    def create_severity_pie_chart(self, findings: Dict[str, Any]) -> Optional[BytesIO]:
        """
        Create severity distribution pie chart
        
        Args:
            findings: Findings dictionary from ThreatDetector
            
        Returns:
            BytesIO image buffer or None
        """
        if not MATPLOTLIB_AVAILABLE:
            return self._create_plotly_severity_chart(findings)
        
        summary = findings.get('summary', {})
        severity_counts = {
            'Critical': summary.get('critical_count', 0),
            'High': summary.get('high_count', 0),
            'Medium': summary.get('medium_count', 0),
            'Low': summary.get('low_count', 0)
        }
        
        # Remove zero values
        severity_counts = {k: v for k, v in severity_counts.items() if v > 0}
        
        if not severity_counts:
            return None
        
        fig, ax = plt.subplots(figsize=(8, 8))
        
        colors = [self.colors['critical'], self.colors['high'], 
                  self.colors['medium'], self.colors['low']]
        
        wedges, texts, autotexts = ax.pie(
            severity_counts.values(),
            labels=severity_counts.keys(),
            colors=colors[:len(severity_counts)],
            autopct='%1.1f%%',
            startangle=90,
            explode=[0.05] * len(severity_counts)
        )
        
        # Style the text
        for text in texts:
            text.set_color(self.colors['text'])
            text.set_fontsize(12)
            text.set_fontweight('bold')
        
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontsize(10)
            autotext.set_fontweight('bold')
        
        ax.set_title('Finding Severity Distribution', fontsize=16, fontweight='bold', 
                    color=self.colors['text'], pad=20)
        
        # Convert to bytes
        buf = BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format='png', bbox_inches='tight', facecolor=self.colors['background'])
        buf.seek(0)
        plt.close()
        
        return buf
    
    def _create_plotly_severity_chart(self, findings: Dict[str, Any]) -> Optional[BytesIO]:
    
        if MATPLOTLIB_AVAILABLE:
            return self.create_severity_pie_chart(findings)
            return None
        
        summary = findings.get('summary', {})
        severity_counts = {
            'Critical': summary.get('critical_count', 0),
            'High': summary.get('high_count', 0),
            'Medium': summary.get('medium_count', 0),
            'Low': summary.get('low_count', 0)
        }
        
        severity_counts = {k: v for k, v in severity_counts.items() if v > 0}
        
        if not severity_counts:
            return None
        
        fig = go.Figure(data=[go.Pie(
            labels=list(severity_counts.keys()),
            values=list(severity_counts.values()),
            hole=0.4,
            marker_colors=[self.colors['critical'], self.colors['high'], 
                          self.colors['medium'], self.colors['low']],
            textinfo='label+percent',
            textposition='auto'
        )])
        
        fig.update_layout(
            title='Finding Severity Distribution',
            template='plotly_dark' if self.theme == 'dark' else 'plotly_white',
            height=500,
            width=500,
            showlegend=True
        )
        
        # Convert to image
        img_bytes = fig.to_image(format='png')
        return BytesIO(img_bytes)
    
    def create_timeline_chart(self, df: pd.DataFrame, 
                              time_col: str = 'timestamp',
                              event_col: str = 'event_type') -> Optional[BytesIO]:
        """
        Create event timeline chart
        
        Args:
            df: DataFrame with timestamp column
            time_col: Name of timestamp column
            event_col: Name of event type column
            
        Returns:
            BytesIO image buffer
        """
        if not MATPLOTLIB_AVAILABLE or df is None or df.empty:
            return None
        
        if time_col not in df.columns:
            return None
        
        # Prepare data
        df_copy = df.copy()
        df_copy[time_col] = pd.to_datetime(df_copy[time_col], errors='coerce')
        df_copy = df_copy.dropna(subset=[time_col])
        
        if df_copy.empty:
            return None
        
        # Create time-based aggregations
        df_copy['hour'] = df_copy[time_col].dt.floor('H')
        hourly_counts = df_copy.groupby('hour').size()
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10), 
                                        gridspec_kw={'height_ratios': [2, 1]})
        
        # Top chart: Time series
        ax1.plot(hourly_counts.index, hourly_counts.values, 
                color=self.colors['primary'], linewidth=2, marker='o', markersize=4)
        ax1.fill_between(hourly_counts.index, hourly_counts.values, 
                         alpha=0.3, color=self.colors['primary'])
        ax1.set_xlabel('Time', fontsize=11)
        ax1.set_ylabel('Event Count', fontsize=11)
        ax1.set_title('Event Timeline Analysis', fontsize=14, fontweight='bold')
        ax1.grid(True, alpha=0.3)
        
        # Add spike annotations
        mean_count = hourly_counts.mean()
        spike_threshold = mean_count + (2 * hourly_counts.std())
        spikes = hourly_counts[hourly_counts > spike_threshold]
        
        for spike_time, spike_count in spikes.items():
            ax1.annotate(f'Spike: {spike_count}', 
                        xy=(spike_time, spike_count),
                        xytext=(10, 10), textcoords='offset points',
                        arrowprops=dict(arrowstyle='->', color=self.colors['danger']),
                        fontsize=9, color=self.colors['danger'])
        
        # Bottom chart: Hourly heatmap (if we have data)
        if event_col in df_copy.columns and len(df_copy) > 0:
            df_copy['hour_of_day'] = df_copy[time_col].dt.hour
            df_copy['date'] = df_copy[time_col].dt.date
            
            # Create pivot table
            pivot_data = df_copy.groupby(['date', 'hour_of_day']).size().unstack(fill_value=0)
            
            if not pivot_data.empty:
                im = ax2.imshow(pivot_data.values, aspect='auto', cmap='YlOrRd', 
                               interpolation='nearest')
                ax2.set_xlabel('Hour of Day', fontsize=11)
                ax2.set_ylabel('Date', fontsize=11)
                ax2.set_title('Event Heatmap by Hour', fontsize=12)
                ax2.set_xticks(range(24))
                ax2.set_xticklabels(range(24))
                ax2.set_yticks(range(len(pivot_data.index)))
                ax2.set_yticklabels([str(d)[:10] for d in pivot_data.index], fontsize=8)
                
                plt.colorbar(im, ax=ax2, label='Event Count')
        
        plt.tight_layout()
        
        buf = BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight', facecolor=self.colors['background'])
        buf.seek(0)
        plt.close()
        
        return buf
    
    def create_severity_bar_chart(self, findings: Dict[str, Any]) -> Optional[BytesIO]:
        """
        Create horizontal bar chart of findings by category
        
        Args:
            findings: Findings dictionary
            
        Returns:
            BytesIO image buffer
        """
        if not MATPLOTLIB_AVAILABLE:
            return None
        
        categories = findings.get('summary', {}).get('categories', {})
        
        if not categories:
            return None
        
        # Sort by count
        sorted_categories = dict(sorted(categories.items(), key=lambda x: x[1], reverse=True))
        
        fig, ax = plt.subplots(figsize=(10, 6))
        
        bars = ax.barh(list(sorted_categories.keys()), list(sorted_categories.values()),
                      color=self.colors['primary'], edgecolor=self.colors['text'], linewidth=1)
        
        # Add value labels
        for bar in bars:
            width = bar.get_width()
            ax.text(width + 0.5, bar.get_y() + bar.get_height()/2, 
                   f'{int(width)}', ha='left', va='center', fontsize=10,
                   color=self.colors['text'])
        
        ax.set_xlabel('Number of Events', fontsize=11)
        ax.set_ylabel('Finding Category', fontsize=11)
        ax.set_title('Findings by Category', fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3, axis='x')
        
        plt.tight_layout()
        
        buf = BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight', facecolor=self.colors['background'])
        buf.seek(0)
        plt.close()
        
        return buf
    
    def create_top_indicators_chart(self, indicators: List[Dict], 
                                    indicator_type: str = 'ip',
                                    limit: int = 10) -> Optional[BytesIO]:
        """
        Create chart for top indicators (IPs, users, commands)
        
        Args:
            indicators: List of indicator dictionaries
            indicator_type: 'ip', 'user', or 'command'
            limit: Number of top indicators to show
            
        Returns:
            BytesIO image buffer
        """
        if not MATPLOTLIB_AVAILABLE or not indicators:
            return None
        
        # Count occurrences
        from collections import Counter
        counts = Counter()
        
        for indicator in indicators:
            key = indicator.get(indicator_type, indicator.get('indicator', 'Unknown'))
            counts[key] += 1
        
        top_indicators = dict(counts.most_common(limit))
        
        fig, ax = plt.subplots(figsize=(10, max(6, len(top_indicators) * 0.4)))
        
        colors = [self.colors['danger'] if i < 3 else self.colors['warning'] 
                 for i in range(len(top_indicators))]
        
        bars = ax.barh(list(top_indicators.keys()), list(top_indicators.values()),
                      color=colors, edgecolor=self.colors['text'], linewidth=1)
        
        # Truncate long labels
        labels = [label[:30] + '...' if len(label) > 30 else label 
                 for label in top_indicators.keys()]
        ax.set_yticks(range(len(labels)))
        ax.set_yticklabels(labels, fontsize=9)
        
        ax.set_xlabel('Occurrences', fontsize=11)
        ax.set_title(f'Top {limit} {indicator_type.title()} Indicators', 
                    fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3, axis='x')
        
        plt.tight_layout()
        
        buf = BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight', facecolor=self.colors['background'])
        buf.seek(0)
        plt.close()
        
        return buf
    
    def create_wordcloud(self, text_data: List[str], title: str = "Key Terms Analysis") -> Optional[str]:
        """
        Create word cloud from text data
        
        Args:
            text_data: List of text strings
            title: Chart title
            
        Returns:
            Base64 encoded image string or None
        """
        if not WORDCLOUD_AVAILABLE or not text_data:
            return None
        
        # Combine all text
        all_text = ' '.join([str(t) for t in text_data if t])
        
        if not all_text:
            return None
        
        # Create word cloud
        wordcloud = WordCloud(
            width=800, height=400,
            background_color='black' if self.theme == 'dark' else 'white',
            colormap='Reds' if self.theme == 'dark' else 'viridis',
            max_words=50,
            contour_width=1,
            contour_color='steelblue'
        ).generate(all_text)
        
        # Convert to base64
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.imshow(wordcloud, interpolation='bilinear')
        ax.axis('off')
        ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
        
        buf = BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format='png', bbox_inches='tight', facecolor=self.colors['background'])
        buf.seek(0)
        plt.close()
        
        # Convert to base64 for HTML embedding
        img_base64 = base64.b64encode(buf.getvalue()).decode()
        return f'data:image/png;base64,{img_base64}'
    
    def create_attack_timeline(self, timeline_events: List[Dict]) -> Optional[BytesIO]:
        """
        Create attack timeline visualization
        
        Args:
            timeline_events: List of events with timestamp and severity
            
        Returns:
            BytesIO image buffer
        """
        if not MATPLOTLIB_AVAILABLE or not timeline_events:
            return None
        
        # Prepare data
        events_df = pd.DataFrame(timeline_events)
        events_df['timestamp'] = pd.to_datetime(events_df['timestamp'])
        events_df = events_df.sort_values('timestamp')
        
        # Assign y-positions based on severity
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        events_df['y_pos'] = events_df['severity'].map(lambda x: severity_order.get(x.upper(), 1))
        
        colors = {'CRITICAL': self.colors['danger'],
                 'HIGH': self.colors['warning'],
                 'MEDIUM': self.colors['primary'],
                 'LOW': self.colors['success']}
        
        fig, ax = plt.subplots(figsize=(14, 6))
        
        # Plot each event
        for idx, row in events_df.iterrows():
            color = colors.get(row['severity'].upper(), self.colors['primary'])
            ax.scatter(row['timestamp'], row['y_pos'], s=100, c=color, 
                      zorder=5, edgecolors='white', linewidth=1)
            
            # Add label
            ax.annotate(row['event_type'][:30], 
                       xy=(row['timestamp'], row['y_pos']),
                       xytext=(5, 5), textcoords='offset points',
                       fontsize=8, alpha=0.7, rotation=45)
        
        # Format axes
        ax.set_yticks([1, 2, 3, 4])
        ax.set_yticklabels(['Low', 'Medium', 'High', 'Critical'])
        ax.set_xlabel('Time', fontsize=11)
        ax.set_ylabel('Severity', fontsize=11)
        ax.set_title('Incident Timeline by Severity', fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3, axis='x')
        
        # Format x-axis dates
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
        plt.xticks(rotation=45)
        
        plt.tight_layout()
        
        buf = BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight', facecolor=self.colors['background'])
        buf.seek(0)
        plt.close()
        
        return buf
    
    def create_risk_gauge(self, risk_score: int) -> Optional[BytesIO]:
        """
        Create risk gauge chart
        
        Args:
            risk_score: Risk score (0-100)
            
        Returns:
            BytesIO image buffer
        """
        if not PLOTLY_AVAILABLE:
            return self._create_matplotlib_gauge(risk_score)
        
        # Determine color
        if risk_score >= 70:
            color = self.colors['danger']
            level = "CRITICAL"
        elif risk_score >= 40:
            color = self.colors['warning']
            level = "HIGH"
        elif risk_score >= 20:
            color = self.colors['primary']
            level = "MEDIUM"
        else:
            color = self.colors['success']
            level = "LOW"
        
        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=risk_score,
            title={'text': "Risk Score", 'font': {'size': 24}},
            delta={'reference': 50, 'increasing': {'color': "red"}},
            gauge={
                'axis': {'range': [0, 100], 'tickwidth': 1},
                'bar': {'color': color},
                'steps': [
                    {'range': [0, 20], 'color': self.colors['success']},
                    {'range': [20, 40], 'color': self.colors['primary']},
                    {'range': [40, 70], 'color': self.colors['warning']},
                    {'range': [70, 100], 'color': self.colors['danger']}
                ],
                'threshold': {
                    'line': {'color': "white", 'width': 4},
                    'thickness': 0.75,
                    'value': risk_score
                }
            }
        ))
        
        fig.update_layout(
            height=400,
            width=500,
            template='plotly_dark' if self.theme == 'dark' else 'plotly_white'
        )
        
        img_bytes = fig.to_image(format='png')
        return BytesIO(img_bytes)
    
    def _create_matplotlib_gauge(self, risk_score: int) -> Optional[BytesIO]:
        """Create matplotlib gauge as fallback"""
        if not MATPLOTLIB_AVAILABLE:
            return None
        
        fig, ax = plt.subplots(figsize=(8, 4))
        
        # Create a simple horizontal gauge
        ax.barh(0, risk_score, color=self.colors['danger'] if risk_score > 50 else self.colors['warning'])
        ax.barh(0, 100 - risk_score, left=risk_score, color=self.colors['success'])
        
        ax.set_xlim(0, 100)
        ax.set_ylim(-0.5, 0.5)
        ax.set_xlabel('Risk Score')
        ax.set_title(f'Risk Score: {risk_score}/100')
        ax.set_yticks([])
        
        # Add vertical line at 50
        ax.axvline(x=50, color='white', linestyle='--', alpha=0.5)
        
        plt.tight_layout()
        
        buf = BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight', facecolor=self.colors['background'])
        buf.seek(0)
        plt.close()
        
        return buf
    
    def create_comparison_chart(self, before_data: Dict, after_data: Dict) -> Optional[BytesIO]:
        """
        Create before/after remediation comparison chart
        
        Args:
            before_data: Findings before remediation
            after_data: Findings after remediation
            
        Returns:
            BytesIO image buffer
        """
        if not MATPLOTLIB_AVAILABLE:
            return None
        
        categories = list(before_data.get('summary', {}).get('categories', {}).keys())
        before_counts = [before_data.get('summary', {}).get('categories', {}).get(cat, 0) for cat in categories]
        after_counts = [after_data.get('summary', {}).get('categories', {}).get(cat, 0) for cat in categories]
        
        if not categories:
            return None
        
        x = np.arange(len(categories))
        width = 0.35
        
        fig, ax = plt.subplots(figsize=(12, 6))
        
        bars1 = ax.bar(x - width/2, before_counts, width, label='Before Remediation', 
                      color=self.colors['danger'])
        bars2 = ax.bar(x + width/2, after_counts, width, label='After Remediation',
                      color=self.colors['success'])
        
        ax.set_xlabel('Finding Category', fontsize=11)
        ax.set_ylabel('Count', fontsize=11)
        ax.set_title('Remediation Effectiveness', fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(categories, rotation=45, ha='right')
        ax.legend()
        ax.grid(True, alpha=0.3, axis='y')
        
        # Add value labels
        for bar in bars1:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}', ha='center', va='bottom', fontsize=9)
        
        for bar in bars2:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}', ha='center', va='bottom', fontsize=9)
        
        plt.tight_layout()
        
        buf = BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight', facecolor=self.colors['background'])
        buf.seek(0)
        plt.close()
        
        return buf
    
    def save_chart(self, chart_buffer: BytesIO, filename: str, output_dir: str = "reports/charts"):
        """Save chart to file"""
        from pathlib import Path
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        filepath = output_path / filename
        with open(filepath, 'wb') as f:
            f.write(chart_buffer.getvalue())
        
        return str(filepath)
    
    def chart_to_base64(self, chart_buffer: BytesIO) -> str:
        """Convert chart buffer to base64 string for embedding"""
        return base64.b64encode(chart_buffer.getvalue()).decode()


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def quick_charts(findings: Dict[str, Any], df: pd.DataFrame = None) -> Dict[str, Any]:
    """Generate all standard charts for a report"""
    builder = ChartBuilder(theme='dark')
    
    charts = {}
    
    # Severity pie chart
    pie_chart = builder.create_severity_pie_chart(findings)
    if pie_chart:
        charts['severity_pie'] = builder.chart_to_base64(pie_chart)
    
    # Severity bar chart
    bar_chart = builder.create_severity_bar_chart(findings)
    if bar_chart:
        charts['severity_bar'] = builder.chart_to_base64(bar_chart)
    
    # Timeline chart
    if df is not None:
        timeline = builder.create_timeline_chart(df)
        if timeline:
            charts['timeline'] = builder.chart_to_base64(timeline)
    
    # Risk gauge
    risk_score = findings.get('risk_score', 0)
    gauge = builder.create_risk_gauge(risk_score)
    if gauge:
        charts['risk_gauge'] = builder.chart_to_base64(gauge)
    
    return charts


# ============================================
# TESTING CODE
# ============================================

if __name__ == "__main__":
    print("📊 Testing Chart Builder Module")
    print("=" * 60)
    
    print(f"Matplotlib available: {MATPLOTLIB_AVAILABLE}")
    print(f"Plotly available: {PLOTLY_AVAILABLE}")
    print(f"WordCloud available: {WORDCLOUD_AVAILABLE}")
    
    # Test data
    test_findings = {
        'risk_score': 75,
        'summary': {
            'critical_count': 3,
            'high_count': 8,
            'medium_count': 12,
            'low_count': 5,
            'categories': {
                'failed_logins': 15,
                'suspicious_powershell': 3,
                'privilege_escalation': 5,
                'lateral_movement': 2,
                'anomalies': 8
            }
        }
    }
    
    # Test timeline data
    test_dates = pd.date_range('2025-03-20 08:00:00', periods=50, freq='30min')
    test_df = pd.DataFrame({
        'timestamp': test_dates,
        'event_type': ['failed_login', 'powershell', 'escalation', 'normal'] * 12 + ['failed_login'] * 2
    })
    
    # Create charts
    builder = ChartBuilder(theme='dark')
    
    print("\n📈 Generating Charts...")
    
    # 1. Severity pie chart
    pie_chart = builder.create_severity_pie_chart(test_findings)
    if pie_chart:
        print("   ✅ Severity pie chart created")
        # Save to file
        builder.save_chart(pie_chart, "test_severity_pie.png", ".")
    
    # 2. Bar chart
    bar_chart = builder.create_severity_bar_chart(test_findings)
    if bar_chart:
        print("   ✅ Bar chart created")
        builder.save_chart(bar_chart, "test_bar_chart.png", ".")
    
    # 3. Timeline
    timeline = builder.create_timeline_chart(test_df)
    if timeline:
        print("   ✅ Timeline chart created")
        builder.save_chart(timeline, "test_timeline.png", ".")
    
    # 4. Risk gauge
    gauge = builder.create_risk_gauge(75)
    if gauge:
        print("   ✅ Risk gauge created")
        builder.save_chart(gauge, "test_risk_gauge.png", ".")
    
    # 5. Word cloud
    text_list = [
        "powershell encoded command base64",
        "failed login admin from 10.0.2.45",
        "privilege escalation whoami priv",
        "lateral movement psexec detected",
        "suspicious process powershell exe"
    ] * 10
    wordcloud = builder.create_wordcloud(text_list, "Test Word Cloud")
    if wordcloud:
        print("   ✅ Word cloud created")
    
    print("\n" + "=" * 60)
    print("✅ Chart Builder Module Ready")
    print("\n📁 Generated test charts saved as:")
    print("   - test_severity_pie.png")
    print("   - test_bar_chart.png")
    print("   - test_timeline.png")
    print("   - test_risk_gauge.png")