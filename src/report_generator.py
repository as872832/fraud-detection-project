"""
Phase 5: Output and Reporting System
Creates professional, human-readable reports for fraud detection results
"""

import pandas as pd
import os
from datetime import datetime
import json


class ReportGenerator:
    """
    Generates comprehensive fraud detection reports in multiple formats
    """

    def __init__(self, reports_dir=None):
        """
        Initialize the report generator

        Parameters:
        -----------
        reports_dir : str, optional
            Directory to save reports (defaults to ./reports)
        """
        if reports_dir is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            reports_dir = os.path.join(os.path.dirname(script_dir), 'reports')

        self.reports_dir = reports_dir

        # Create reports directory if it doesn't exist
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)

    def generate_executive_summary(self, stats, config_name='Unknown'):
        """
        Generate executive summary report

        Parameters:
        -----------
        stats : dict
            Statistics from detection system
        config_name : str
            Name of configuration used

        Returns:
        --------
        str : Formatted executive summary text
        """
        report = []
        report.append("=" * 80)
        report.append("FRAUD DETECTION SYSTEM - EXECUTIVE SUMMARY")
        report.append("=" * 80)
        report.append("")
        report.append(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Detection Configuration: {config_name.upper()}")
        report.append("")

        report.append("-" * 80)
        report.append("KEY FINDINGS")
        report.append("-" * 80)
        report.append("")
        report.append(f"• Total Transactions Analyzed: {stats['total_transactions']:,}")
        report.append(f"• Suspicious Transactions Detected: {stats['flagged_count']:,} ({stats['flagged_percentage']}%)")
        report.append(f"• Clean Transactions: {stats['clean_count']:,} ({stats['clean_percentage']}%)")

        if 'avg_risk_score' in stats:
            report.append(f"• Average Risk Score: {stats['avg_risk_score']}")
            report.append(f"• Maximum Risk Score: {stats['max_risk_score']}")

        report.append("")
        report.append("-" * 80)
        report.append("FRAUD PATTERNS DETECTED")
        report.append("-" * 80)
        report.append("")

        if stats['violations_by_rule']:
            for rule, count in sorted(stats['violations_by_rule'].items(), key=lambda x: x[1], reverse=True):
                rule_name = rule.replace('_', ' ').title()
                report.append(f"• {rule_name}: {count} violations")
        else:
            report.append("• No violations detected")

        # Performance metrics if available
        if 'ground_truth' in stats:
            gt = stats['ground_truth']
            report.append("")
            report.append("-" * 80)
            report.append("SYSTEM PERFORMANCE")
            report.append("-" * 80)
            report.append("")
            report.append(f"• Actual Fraud Cases: {gt['actual_fraud_count']}")
            report.append(f"• Successfully Detected: {gt['true_positives']} ({gt['recall']:.1%} detection rate)")
            report.append(f"• Missed Fraud Cases: {gt['false_negatives']}")
            report.append(f"• False Alarms: {gt['false_positives']}")
            report.append("")
            report.append(f"System Accuracy Metrics:")
            report.append(f"  - Overall Accuracy: {gt['accuracy']:.1%}")
            report.append(f"  - Precision: {gt['precision']:.1%}")
            report.append(f"  - Recall: {gt['recall']:.1%}")
            report.append(f"  - F1-Score: {gt['f1_score']:.4f}")

        report.append("")
        report.append("-" * 80)
        report.append("RECOMMENDATIONS")
        report.append("-" * 80)
        report.append("")

        # Generate recommendations based on results
        if 'ground_truth' in stats:
            gt = stats['ground_truth']

            if gt['precision'] < 0.10:
                report.append("⚠ HIGH FALSE POSITIVE RATE")
                report.append("  Consider using a more lenient configuration to reduce false alarms.")
                report.append("")

            if gt['recall'] < 0.80:
                report.append("⚠ LOW FRAUD DETECTION RATE")
                report.append("  Consider using a stricter configuration to catch more fraud.")
                report.append("")

            if gt['false_negatives'] > 0:
                report.append(f"⚠ {gt['false_negatives']} FRAUD CASES MISSED")
                report.append("  Review missed cases to identify patterns not covered by current rules.")
                report.append("")

        report.append("✓ Review all flagged transactions in the detailed report.")
        report.append("✓ Adjust configuration thresholds based on business requirements.")
        report.append("✓ Monitor system performance over time.")

        report.append("")
        report.append("=" * 80)

        return "\n".join(report)

    def generate_detailed_report(self, df_analyzed, config_name='Unknown', max_transactions=50):
        """
        Generate detailed transaction report

        Parameters:
        -----------
        df_analyzed : DataFrame
            Analyzed transaction data
        config_name : str
            Name of configuration used
        max_transactions : int
            Maximum number of flagged transactions to include

        Returns:
        --------
        str : Formatted detailed report text
        """
        report = []
        report.append("=" * 80)
        report.append("FRAUD DETECTION SYSTEM - DETAILED TRANSACTION REPORT")
        report.append("=" * 80)
        report.append("")
        report.append(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Detection Configuration: {config_name.upper()}")
        report.append("")

        # Get flagged transactions
        flagged = df_analyzed[df_analyzed['suspicious'] == True].copy()

        # Sort by risk score (highest first)
        flagged = flagged.sort_values('risk_score', ascending=False)

        report.append("-" * 80)
        report.append(f"FLAGGED TRANSACTIONS: {len(flagged)} total")
        report.append("-" * 80)
        report.append("")

        if len(flagged) == 0:
            report.append("No suspicious transactions detected.")
            report.append("")
        else:
            # Limit number of transactions to display
            display_count = min(len(flagged), max_transactions)

            if len(flagged) > max_transactions:
                report.append(f"Showing top {max_transactions} highest risk transactions")
                report.append(f"(Total flagged: {len(flagged)})")
                report.append("")

            for idx, (_, row) in enumerate(flagged.head(max_transactions).iterrows(), 1):
                report.append(f"[{idx}] Transaction ID: {row['transaction_id']}")
                report.append(f"    User: {row['user_id']}")
                report.append(f"    Date/Time: {row['timestamp']}")
                report.append(f"    Amount: ${row['amount']:.2f}")
                report.append(f"    Merchant: {row['merchant']}")
                report.append(f"    Location: {row['location']}")
                report.append(f"    Risk Score: {row['risk_score']}")

                # Ground truth if available
                if 'is_fraud' in row:
                    actual_status = "ACTUAL FRAUD" if row['is_fraud'] else "False Alarm"
                    report.append(f"    Actual Status: {actual_status}")

                report.append(f"    Violations:")

                for violation in row['violations']:
                    report.append(f"      • [{violation['severity']}] {violation['message']}")

                report.append("")

        report.append("=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)

        return "\n".join(report)

    def generate_statistical_report(self, stats, config_name='Unknown'):
        """
        Generate comprehensive statistical report

        Parameters:
        -----------
        stats : dict
            Statistics from detection system
        config_name : str
            Name of configuration used

        Returns:
        --------
        str : Formatted statistical report text
        """
        report = []
        report.append("=" * 80)
        report.append("FRAUD DETECTION SYSTEM - STATISTICAL ANALYSIS REPORT")
        report.append("=" * 80)
        report.append("")
        report.append(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Detection Configuration: {config_name.upper()}")
        report.append("")

        # Overall Statistics
        report.append("-" * 80)
        report.append("TRANSACTION SUMMARY")
        report.append("-" * 80)
        report.append("")
        report.append(f"Total Transactions:        {stats['total_transactions']:>10,}")
        report.append(f"Flagged Transactions:      {stats['flagged_count']:>10,} ({stats['flagged_percentage']:>5}%)")
        report.append(f"Clean Transactions:        {stats['clean_count']:>10,} ({stats['clean_percentage']:>5}%)")
        report.append("")

        # Risk Score Distribution
        if 'risk_score_distribution' in stats:
            report.append("-" * 80)
            report.append("RISK SCORE DISTRIBUTION")
            report.append("-" * 80)
            report.append("")
            report.append(f"Average Risk Score: {stats['avg_risk_score']}")
            report.append(f"Maximum Risk Score: {stats['max_risk_score']}")
            report.append("")
            report.append("Distribution:")

            for score, count in sorted(stats['risk_score_distribution'].items()):
                percentage = (count / stats['flagged_count']) * 100
                bar = "█" * int(percentage / 2)
                report.append(f"  Score {score}: {count:>5} transactions {bar} ({percentage:.1f}%)")

            report.append("")

        # Rule Violations
        report.append("-" * 80)
        report.append("RULE VIOLATION ANALYSIS")
        report.append("-" * 80)
        report.append("")

        if stats['violations_by_rule']:
            total_violations = sum(stats['violations_by_rule'].values())

            for rule, count in sorted(stats['violations_by_rule'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_violations) * 100
                rule_name = rule.replace('_', ' ').title()
                bar = "█" * int(percentage / 2)
                report.append(f"{rule_name:<30} {count:>5} {bar} ({percentage:.1f}%)")
        else:
            report.append("No rule violations detected.")

        report.append("")

        # Performance Metrics
        if 'ground_truth' in stats:
            gt = stats['ground_truth']

            report.append("-" * 80)
            report.append("PERFORMANCE METRICS")
            report.append("-" * 80)
            report.append("")

            report.append("Confusion Matrix:")
            report.append(f"                    Predicted Fraud    Predicted Clean")
            report.append(f"  Actual Fraud:     {gt['true_positives']:>10}         {gt['false_negatives']:>10}")
            report.append(f"  Actual Clean:     {gt['false_positives']:>10}         {gt['true_negatives']:>10}")
            report.append("")

            report.append("Performance Metrics:")
            report.append(f"  Accuracy:   {gt['accuracy']:>8.2%}  (Correct predictions / Total)")
            report.append(f"  Precision:  {gt['precision']:>8.2%}  (True fraud / All flagged)")
            report.append(f"  Recall:     {gt['recall']:>8.2%}  (True fraud / All actual fraud)")
            report.append(f"  F1-Score:   {gt['f1_score']:>8.4f}  (Harmonic mean of precision & recall)")
            report.append("")

            # Interpretation
            report.append("Interpretation:")
            if gt['accuracy'] >= 0.90:
                report.append("  ✓ Excellent overall accuracy")
            elif gt['accuracy'] >= 0.75:
                report.append("  ✓ Good overall accuracy")
            else:
                report.append("  ⚠ Accuracy could be improved")

            if gt['precision'] >= 0.50:
                report.append("  ✓ High precision - low false alarm rate")
            elif gt['precision'] >= 0.20:
                report.append("  ~ Moderate precision - some false alarms")
            else:
                report.append("  ⚠ Low precision - many false alarms")

            if gt['recall'] >= 0.90:
                report.append("  ✓ Excellent detection rate - catching most fraud")
            elif gt['recall'] >= 0.70:
                report.append("  ✓ Good detection rate")
            else:
                report.append("  ⚠ Low detection rate - missing fraud cases")

        report.append("")
        report.append("=" * 80)

        return "\n".join(report)

    def generate_html_report(self, df_analyzed, stats, config_name='Unknown'):
        """
        Generate HTML report with styling

        Parameters:
        -----------
        df_analyzed : DataFrame
            Analyzed transaction data
        stats : dict
            Statistics from detection system
        config_name : str
            Name of configuration used

        Returns:
        --------
        str : HTML formatted report
        """
        # Get flagged transactions
        flagged = df_analyzed[df_analyzed['suspicious'] == True].copy()
        flagged = flagged.sort_values('risk_score', ascending=False).head(50)

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Fraud Detection Report - {config_name}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
            border-left: 4px solid #3498db;
            padding-left: 10px;
        }}
        .stat-box {{
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            margin: 10px;
            border-radius: 10px;
            min-width: 200px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 36px;
            font-weight: bold;
        }}
        .stat-label {{
            font-size: 14px;
            opacity: 0.9;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th {{
            background-color: #3498db;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .transaction {{
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
        }}
        .risk-high {{ color: #e74c3c; font-weight: bold; }}
        .risk-medium {{ color: #f39c12; font-weight: bold; }}
        .risk-low {{ color: #27ae60; font-weight: bold; }}
        .violation {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 8px;
            margin: 5px 0;
        }}
        .metric-good {{ color: #27ae60; }}
        .metric-warning {{ color: #f39c12; }}
        .metric-bad {{ color: #e74c3c; }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #ddd;
            text-align: center;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Fraud Detection System Report</h1>
        <p><strong>Configuration:</strong> {config_name.upper()}</p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h2>📊 Executive Summary</h2>
        <div>
            <div class="stat-box">
                <div class="stat-value">{stats['total_transactions']:,}</div>
                <div class="stat-label">Total Transactions</div>
            </div>
            <div class="stat-box" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                <div class="stat-value">{stats['flagged_count']:,}</div>
                <div class="stat-label">Flagged ({stats['flagged_percentage']}%)</div>
            </div>
            <div class="stat-box" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
                <div class="stat-value">{stats['clean_count']:,}</div>
                <div class="stat-label">Clean ({stats['clean_percentage']}%)</div>
            </div>
        </div>
        
        <h2>🎯 Fraud Patterns Detected</h2>
        <table>
            <tr>
                <th>Violation Type</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
"""

        if stats['violations_by_rule']:
            total_violations = sum(stats['violations_by_rule'].values())
            for rule, count in sorted(stats['violations_by_rule'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_violations) * 100
                rule_name = rule.replace('_', ' ').title()
                html += f"""
            <tr>
                <td>{rule_name}</td>
                <td>{count}</td>
                <td>{percentage:.1f}%</td>
            </tr>
"""

        html += """
        </table>
"""

        # Performance metrics if available
        if 'ground_truth' in stats:
            gt = stats['ground_truth']
            html += f"""
        <h2>📈 System Performance</h2>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
                <th>Status</th>
            </tr>
            <tr>
                <td>Accuracy</td>
                <td>{gt['accuracy']:.2%}</td>
                <td class="{'metric-good' if gt['accuracy'] >= 0.75 else 'metric-warning'}">{
                    '✓ Good' if gt['accuracy'] >= 0.75 else '⚠ Fair'
                }</td>
            </tr>
            <tr>
                <td>Precision</td>
                <td>{gt['precision']:.2%}</td>
                <td class="{'metric-good' if gt['precision'] >= 0.20 else 'metric-bad'}">{
                    '✓ Good' if gt['precision'] >= 0.20 else '⚠ Low'
                }</td>
            </tr>
            <tr>
                <td>Recall</td>
                <td>{gt['recall']:.2%}</td>
                <td class="{'metric-good' if gt['recall'] >= 0.80 else 'metric-warning'}">{
                    '✓ Excellent' if gt['recall'] >= 0.80 else '⚠ Fair'
                }</td>
            </tr>
            <tr>
                <td>F1-Score</td>
                <td>{gt['f1_score']:.4f}</td>
                <td>-</td>
            </tr>
        </table>
        
        <p><strong>Fraud Cases:</strong> {gt['actual_fraud_count']} actual, {gt['true_positives']} detected, {gt['false_negatives']} missed</p>
        <p><strong>False Alarms:</strong> {gt['false_positives']}</p>
"""

        # Top flagged transactions
        html += """
        <h2>⚠️ Top Flagged Transactions</h2>
"""

        if len(flagged) > 0:
            for idx, (_, row) in enumerate(flagged.head(20).iterrows(), 1):
                risk_class = 'risk-high' if row['risk_score'] >= 2 else 'risk-medium' if row['risk_score'] >= 1 else 'risk-low'

                html += f"""
        <div class="transaction">
            <strong>#{idx} - {row['transaction_id']}</strong>
            <span class="{risk_class}">Risk Score: {row['risk_score']}</span><br>
            <strong>User:</strong> {row['user_id']} | 
            <strong>Amount:</strong> ${row['amount']:.2f} | 
            <strong>Time:</strong> {row['timestamp']}<br>
            <strong>Merchant:</strong> {row['merchant']} | 
            <strong>Location:</strong> {row['location']}<br>
            <strong>Violations:</strong>
"""

                for violation in row['violations']:
                    html += f"""
            <div class="violation">
                <strong>[{violation['severity']}]</strong> {violation['message']}
            </div>
"""

                html += """
        </div>
"""
        else:
            html += "<p>No suspicious transactions detected.</p>"

        html += """
        <div class="footer">
            <p>Generated by Fraud Detection System | Phase 5: Reporting Module</p>
            <p>Project by Mia Bruno & Ashley Brookman</p>
        </div>
    </div>
</body>
</html>
"""

        return html

    def save_all_reports(self, df_analyzed, stats, config_name='Unknown'):
        """
        Generate and save all report types

        Parameters:
        -----------
        df_analyzed : DataFrame
            Analyzed transaction data
        stats : dict
            Statistics from detection system
        config_name : str
            Name of configuration used

        Returns:
        --------
        dict : Paths to all saved reports
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = f"report_{config_name}_{timestamp}"

        file_paths = {}

        # Executive Summary
        print("Generating executive summary...")
        exec_summary = self.generate_executive_summary(stats, config_name)
        exec_path = os.path.join(self.reports_dir, f"{base_filename}_executive.txt")
        with open(exec_path, 'w', encoding='utf-8') as f:
            f.write(exec_summary)
        file_paths['executive'] = exec_path

        # Detailed Report
        print("Generating detailed transaction report...")
        detailed_report = self.generate_detailed_report(df_analyzed, config_name)
        detail_path = os.path.join(self.reports_dir, f"{base_filename}_detailed.txt")
        with open(detail_path, 'w', encoding='utf-8') as f:
            f.write(detailed_report)
        file_paths['detailed'] = detail_path

        # Statistical Report
        print("Generating statistical analysis...")
        stat_report = self.generate_statistical_report(stats, config_name)
        stat_path = os.path.join(self.reports_dir, f"{base_filename}_statistics.txt")
        with open(stat_path, 'w', encoding='utf-8') as f:
            f.write(stat_report)
        file_paths['statistics'] = stat_path

        # HTML Report
        print("Generating HTML report...")
        html_report = self.generate_html_report(df_analyzed, stats, config_name)
        html_path = os.path.join(self.reports_dir, f"{base_filename}.html")
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_report)
        file_paths['html'] = html_path

        # CSV Export of flagged transactions
        print("Exporting flagged transactions...")
        flagged = df_analyzed[df_analyzed['suspicious'] == True].copy()
        flagged['violations_str'] = flagged['violations'].apply(lambda x: str(x) if x else '')
        flagged_export = flagged.drop('violations', axis=1)
        csv_path = os.path.join(self.reports_dir, f"{base_filename}_flagged.csv")
        flagged_export.to_csv(csv_path, index=False)
        file_paths['flagged_csv'] = csv_path

        return file_paths


def main():
    """Test the reporting system"""
    print("="*80)
    print("PHASE 5: OUTPUT AND REPORTING SYSTEM")
    print("="*80)

    # For testing, we need to load some detection results
    # In real use, this would be called from the detection system

    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    data_dir = os.path.join(project_dir, 'data')

    # Check if we have analyzed data
    analyzed_file = os.path.join(data_dir, 'analyzed_transactions.csv')

    if not os.path.exists(analyzed_file):
        print("\n⚠ No analyzed transactions found!")
        print("Please run Phase 4 (detection_system.py) first to generate detection results.")
        print("\nAlternatively, run Phase 2 (rule_engine.py) to create analyzed_transactions.csv")
        return

    print(f"\nLoading analyzed data from: {analyzed_file}")
    df_analyzed = pd.read_csv(analyzed_file)

    # Reconstruct violations column (it was converted to string for CSV)
    # For demonstration, we'll work with what we have
    print(f"✓ Loaded {len(df_analyzed)} transactions")

    # Create sample statistics (in real use, this comes from detection system)
    stats = {
        'total_transactions': len(df_analyzed),
        'flagged_count': int(df_analyzed['suspicious'].sum()),
        'flagged_percentage': round((df_analyzed['suspicious'].sum() / len(df_analyzed)) * 100, 2),
        'clean_count': int(len(df_analyzed) - df_analyzed['suspicious'].sum()),
        'clean_percentage': round((1 - df_analyzed['suspicious'].sum() / len(df_analyzed)) * 100, 2)
    }

    # Add violations if we can parse them
    if 'violations_str' in df_analyzed.columns:
        # This is a simplified version
        stats['violations_by_rule'] = {}
    else:
        stats['violations_by_rule'] = {}

    # Risk scores
    if stats['flagged_count'] > 0:
        flagged = df_analyzed[df_analyzed['suspicious'] == True]
        stats['avg_risk_score'] = round(flagged['risk_score'].mean(), 2)
        stats['max_risk_score'] = int(flagged['risk_score'].max())
        stats['risk_score_distribution'] = flagged['risk_score'].value_counts().to_dict()

    # Ground truth if available
    if 'is_fraud' in df_analyzed.columns:
        actual_fraud = df_analyzed['is_fraud'].sum()
        true_positives = len(df_analyzed[(df_analyzed['suspicious'] == True) & (df_analyzed['is_fraud'] == True)])
        false_positives = len(df_analyzed[(df_analyzed['suspicious'] == True) & (df_analyzed['is_fraud'] == False)])
        false_negatives = len(df_analyzed[(df_analyzed['suspicious'] == False) & (df_analyzed['is_fraud'] == True)])
        true_negatives = len(df_analyzed[(df_analyzed['suspicious'] == False) & (df_analyzed['is_fraud'] == False)])

        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (true_positives + true_negatives) / len(df_analyzed)

        stats['ground_truth'] = {
            'actual_fraud_count': int(actual_fraud),
            'true_positives': true_positives,
            'false_positives': false_positives,
            'false_negatives': false_negatives,
            'true_negatives': true_negatives,
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1_score, 4),
            'accuracy': round(accuracy, 4)
        }

    # Mock violations data for the report
    # Count approximate violations by looking at violation string patterns
    if 'violations_str' in df_analyzed.columns:
        for _, row in df_analyzed[df_analyzed['suspicious'] == True].iterrows():
            viol_str = str(row['violations_str'])
            if 'HIGH_FREQUENCY' in viol_str:
                stats['violations_by_rule']['HIGH_FREQUENCY'] = stats['violations_by_rule'].get('HIGH_FREQUENCY', 0) + 1
            if 'HIGH_AMOUNT' in viol_str:
                stats['violations_by_rule']['HIGH_AMOUNT'] = stats['violations_by_rule'].get('HIGH_AMOUNT', 0) + 1
            if 'IMPOSSIBLE_TRAVEL' in viol_str:
                stats['violations_by_rule']['IMPOSSIBLE_TRAVEL'] = stats['violations_by_rule'].get('IMPOSSIBLE_TRAVEL', 0) + 1
            if 'UNUSUAL_TIME' in viol_str:
                stats['violations_by_rule']['UNUSUAL_TIME'] = stats['violations_by_rule'].get('UNUSUAL_TIME', 0) + 1

    # Create violations list if not present
    if 'violations' not in df_analyzed.columns:
        df_analyzed['violations'] = [[] for _ in range(len(df_analyzed))]

    # Initialize report generator
    generator = ReportGenerator()

    print("\n" + "="*80)
    print("GENERATING REPORTS")
    print("="*80)

    # Generate all reports
    file_paths = generator.save_all_reports(df_analyzed, stats, config_name='demonstration')

    print("\n" + "="*80)
    print("✓ REPORTS GENERATED SUCCESSFULLY!")
    print("="*80)
    print("\nGenerated Files:")
    print(f"  📄 Executive Summary:  {file_paths['executive']}")
    print(f"  📄 Detailed Report:    {file_paths['detailed']}")
    print(f"  📄 Statistical Report: {file_paths['statistics']}")
    print(f"  🌐 HTML Report:        {file_paths['html']}")
    print(f"  💾 Flagged CSV:        {file_paths['flagged_csv']}")

    print("\n" + "="*80)
    print("✓ PHASE 5 COMPLETE!")
    print("="*80)
    print("\nYou can now:")
    print("  • Open the HTML report in your browser for a visual overview")
    print("  • Review text reports for detailed analysis")
    print("  • Share reports with stakeholders")
    print("  • Use CSV exports for further analysis")


if __name__ == "__main__":
    main()