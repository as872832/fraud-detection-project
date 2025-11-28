"""
Phase 4: Detection and Scoring System
Integrated fraud detection engine that processes transactions and generates scores
"""

import pandas as pd
import os
import sys
import json
from datetime import datetime

# Import from other phases
# Adjust import based on your folder structure
try:
    from rule_engine import FraudRuleEngine
    from config_manager import ConfigurationManager
except ImportError:
    # If running as standalone, try to import from same directory
    import importlib.util

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Load rule_engine
    rule_engine_path = os.path.join(script_dir, 'rule_engine.py')
    spec = importlib.util.spec_from_file_location("rule_engine", rule_engine_path)
    rule_engine = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rule_engine)
    FraudRuleEngine = rule_engine.FraudRuleEngine

    # Load config_manager
    config_manager_path = os.path.join(script_dir, 'config_manager.py')
    spec = importlib.util.spec_from_file_location("config_manager", config_manager_path)
    config_manager = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config_manager)
    ConfigurationManager = config_manager.ConfigurationManager


class FraudDetectionSystem:
    """
    Unified fraud detection system
    Integrates data loading, configuration management, and rule-based detection
    """

    def __init__(self, project_dir=None):
        """
        Initialize the fraud detection system

        Parameters:
        -----------
        project_dir : str, optional
            Root directory of the project (defaults to parent of script directory)
        """
        if project_dir is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_dir = os.path.dirname(script_dir)

        self.project_dir = project_dir
        self.data_dir = os.path.join(project_dir, 'data')
        self.config_dir = os.path.join(project_dir, 'config')
        self.reports_dir = os.path.join(project_dir, 'reports')

        # Create directories if they don't exist
        for directory in [self.data_dir, self.config_dir, self.reports_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)

        # Initialize components
        self.config_manager = ConfigurationManager(config_dir=self.config_dir)
        self.engine = None
        self.current_config = None
        self.results = None

    def load_transactions(self, filename='transactions.csv'):
        """
        Load transaction data

        Parameters:
        -----------
        filename : str
            Name of the CSV file containing transactions

        Returns:
        --------
        DataFrame : Loaded transaction data
        """
        filepath = os.path.join(self.data_dir, filename)

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Transaction file not found: {filepath}")

        df = pd.read_csv(filepath)
        print(f"✓ Loaded {len(df)} transactions from {filename}")

        return df

    def load_configuration(self, config_name='moderate'):
        """
        Load a fraud detection configuration

        Parameters:
        -----------
        config_name : str
            Name of configuration to load (without .json extension)
            Options: 'strict', 'moderate', 'lenient', 'default', or custom name

        Returns:
        --------
        dict : Configuration dictionary
        """
        filename = f"{config_name}_config.json"
        config = self.config_manager.load_config(filename)
        self.current_config = config

        print(f"✓ Loaded configuration: {config['name']}")
        print(f"  Description: {config['description']}")

        return config

    def run_detection(self, df, config=None):
        """
        Run fraud detection on transaction data

        Parameters:
        -----------
        df : DataFrame
            Transaction data to analyze
        config : dict, optional
            Configuration to use (uses currently loaded config if None)

        Returns:
        --------
        DataFrame : Analyzed transaction data with fraud flags
        """
        if config is None:
            if self.current_config is None:
                raise ValueError("No configuration loaded. Call load_configuration() first.")
            config = self.current_config

        print("\n" + "=" * 80)
        print(f"RUNNING FRAUD DETECTION: {config['name'].upper()} MODE")
        print("=" * 80)

        # Create rule engine with configuration
        self.engine = FraudRuleEngine(config=config['rules'])

        # Display active rules
        print("\nActive Rules:")
        for rule_name, rule_config in config['rules'].items():
            status = "ENABLED" if rule_config.get('enabled', True) else "DISABLED"
            print(f"  • {rule_name.upper()}: {status}")

        # Run analysis
        print("\nAnalyzing transactions...")
        df_analyzed = self.engine.analyze_dataset(df.copy())

        self.results = df_analyzed

        return df_analyzed

    def calculate_statistics(self, df_analyzed):
        """
        Calculate detection statistics and performance metrics

        Parameters:
        -----------
        df_analyzed : DataFrame
            Analyzed transaction data with fraud flags

        Returns:
        --------
        dict : Statistics dictionary
        """
        total_transactions = len(df_analyzed)
        flagged_transactions = df_analyzed['suspicious'].sum()
        flagged_percentage = (flagged_transactions / total_transactions) * 100

        # If we have ground truth (is_fraud column), calculate accuracy metrics
        has_ground_truth = 'is_fraud' in df_analyzed.columns

        stats = {
            'total_transactions': total_transactions,
            'flagged_count': int(flagged_transactions),
            'flagged_percentage': round(flagged_percentage, 2),
            'clean_count': int(total_transactions - flagged_transactions),
            'clean_percentage': round(100 - flagged_percentage, 2)
        }

        # Risk score distribution
        if flagged_transactions > 0:
            risk_scores = df_analyzed[df_analyzed['suspicious'] == True]['risk_score']
            stats['avg_risk_score'] = round(risk_scores.mean(), 2)
            stats['max_risk_score'] = int(risk_scores.max())
            stats['risk_score_distribution'] = risk_scores.value_counts().to_dict()

        # Rule violation breakdown
        rule_counts = {}
        for _, row in df_analyzed[df_analyzed['suspicious'] == True].iterrows():
            for violation in row['violations']:
                rule_name = violation['rule']
                rule_counts[rule_name] = rule_counts.get(rule_name, 0) + 1

        stats['violations_by_rule'] = rule_counts

        # Ground truth comparison (if available)
        if has_ground_truth:
            actual_fraud = df_analyzed['is_fraud'].sum()

            # True Positives: Flagged as suspicious AND actually fraud
            true_positives = len(df_analyzed[
                                     (df_analyzed['suspicious'] == True) &
                                     (df_analyzed['is_fraud'] == True)
                                     ])

            # False Positives: Flagged as suspicious BUT not actually fraud
            false_positives = len(df_analyzed[
                                      (df_analyzed['suspicious'] == True) &
                                      (df_analyzed['is_fraud'] == False)
                                      ])

            # False Negatives: NOT flagged BUT actually fraud
            false_negatives = len(df_analyzed[
                                      (df_analyzed['suspicious'] == False) &
                                      (df_analyzed['is_fraud'] == True)
                                      ])

            # True Negatives: NOT flagged AND not fraud
            true_negatives = len(df_analyzed[
                                     (df_analyzed['suspicious'] == False) &
                                     (df_analyzed['is_fraud'] == False)
                                     ])

            # Calculate metrics
            precision = true_positives / (true_positives + false_positives) if (
                                                                                           true_positives + false_positives) > 0 else 0
            recall = true_positives / (true_positives + false_negatives) if (
                                                                                        true_positives + false_negatives) > 0 else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            accuracy = (true_positives + true_negatives) / total_transactions

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

        return stats

    def display_statistics(self, stats):
        """
        Display statistics in a readable format

        Parameters:
        -----------
        stats : dict
            Statistics dictionary from calculate_statistics()
        """
        print("\n" + "=" * 80)
        print("DETECTION STATISTICS")
        print("=" * 80)

        print(f"\nOverall Results:")
        print(f"  Total Transactions: {stats['total_transactions']:,}")
        print(f"  Flagged as Suspicious: {stats['flagged_count']:,} ({stats['flagged_percentage']}%)")
        print(f"  Marked as Clean: {stats['clean_count']:,} ({stats['clean_percentage']}%)")

        if 'avg_risk_score' in stats:
            print(f"\nRisk Scores:")
            print(f"  Average Risk Score: {stats['avg_risk_score']}")
            print(f"  Maximum Risk Score: {stats['max_risk_score']}")
            print(f"\n  Distribution:")
            for score, count in sorted(stats['risk_score_distribution'].items()):
                print(f"    Risk Score {score}: {count} transactions")

        print(f"\nViolations by Rule:")
        if stats['violations_by_rule']:
            for rule, count in sorted(stats['violations_by_rule'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {rule}: {count}")
        else:
            print("  No violations detected")

        # Display ground truth metrics if available
        if 'ground_truth' in stats:
            gt = stats['ground_truth']
            print("\n" + "-" * 80)
            print("PERFORMANCE METRICS (vs Ground Truth)")
            print("-" * 80)
            print(f"\nActual Fraud in Dataset: {gt['actual_fraud_count']}")
            print(f"\nConfusion Matrix:")
            print(f"  True Positives:  {gt['true_positives']:4d}  (Correctly identified fraud)")
            print(f"  False Positives: {gt['false_positives']:4d}  (False alarms)")
            print(f"  False Negatives: {gt['false_negatives']:4d}  (Missed fraud)")
            print(f"  True Negatives:  {gt['true_negatives']:4d}  (Correctly identified legitimate)")

            print(f"\nMetrics:")
            print(f"  Accuracy:  {gt['accuracy']:.2%}  (Overall correctness)")
            print(f"  Precision: {gt['precision']:.2%}  (Of flagged, how many were actually fraud)")
            print(f"  Recall:    {gt['recall']:.2%}  (Of actual fraud, how many we caught)")
            print(f"  F1-Score:  {gt['f1_score']:.4f}  (Harmonic mean of precision & recall)")

        print("\n" + "=" * 80)

    def save_results(self, df_analyzed, stats, output_filename=None):
        """
        Save detection results and statistics

        Parameters:
        -----------
        df_analyzed : DataFrame
            Analyzed transaction data
        stats : dict
            Statistics dictionary
        output_filename : str, optional
            Custom filename for results

        Returns:
        --------
        dict : Paths to saved files
        """
        if output_filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            config_name = self.current_config['name'] if self.current_config else 'unknown'
            output_filename = f"detection_results_{config_name}_{timestamp}"

        # Save analyzed transactions
        csv_path = os.path.join(self.reports_dir, f"{output_filename}.csv")

        # Convert violations list to string for CSV
        df_save = df_analyzed.copy()
        df_save['violations_str'] = df_save['violations'].apply(lambda x: str(x) if x else '')
        df_save = df_save.drop('violations', axis=1)

        df_save.to_csv(csv_path, index=False)

        # Save statistics as JSON
        json_path = os.path.join(self.reports_dir, f"{output_filename}_stats.json")

        # Add metadata
        full_stats = {
            'detection_run': {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'configuration': self.current_config['name'] if self.current_config else 'unknown',
                'configuration_description': self.current_config['description'] if self.current_config else 'N/A'
            },
            'statistics': stats
        }

        with open(json_path, 'w') as f:
            json.dump(full_stats, f, indent=4)

        print("\n" + "=" * 80)
        print("RESULTS SAVED")
        print("=" * 80)
        print(f"✓ Transaction results: {csv_path}")
        print(f"✓ Statistics report:   {json_path}")

        return {
            'csv': csv_path,
            'json': json_path
        }

    def run_full_detection(self, transaction_file='transactions.csv', config_name='lenient', save_results=True):
        """
        Run complete detection pipeline

        Parameters:
        -----------
        transaction_file : str
            Name of transaction CSV file
        config_name : str
            Name of configuration to use
        save_results : bool
            Whether to save results to files

        Returns:
        --------
        tuple : (analyzed_df, statistics, file_paths)
        """
        print("=" * 80)
        print("FRAUD DETECTION SYSTEM - FULL PIPELINE")
        print("=" * 80)

        # Step 1: Load data
        print("\n[1/5] Loading transaction data...")
        df = self.load_transactions(transaction_file)

        # Step 2: Load configuration
        print("\n[2/5] Loading detection configuration...")
        config = self.load_configuration(config_name)

        # Step 3: Run detection
        print("\n[3/5] Running fraud detection...")
        df_analyzed = self.run_detection(df, config)

        # Step 4: Calculate statistics
        print("\n[4/5] Calculating statistics...")
        stats = self.calculate_statistics(df_analyzed)
        self.display_statistics(stats)

        # Step 5: Save results
        file_paths = None
        if save_results:
            print("\n[5/5] Saving results...")
            file_paths = self.save_results(df_analyzed, stats)

        print("\n" + "=" * 80)
        print("✓ DETECTION COMPLETE!")
        print("=" * 80)

        return df_analyzed, stats, file_paths


def main():
    """Test the integrated detection system"""
    print("=" * 80)
    print("PHASE 4: INTEGRATED DETECTION & SCORING SYSTEM")
    print("=" * 80)

    # Initialize the system
    system = FraudDetectionSystem()

    # Run detection with different configurations
    configs_to_test = ['strict', 'moderate', 'lenient']

    results_summary = []

    for config_name in configs_to_test:
        print("\n\n" + "=" * 80)
        print(f"TESTING CONFIGURATION: {config_name.upper()}")
        print("=" * 80)

        df_analyzed, stats, file_paths = system.run_full_detection(
            transaction_file='transactions.csv',
            config_name=config_name,
            save_results=True
        )

        # Store summary for comparison
        results_summary.append({
            'config': config_name,
            'flagged': stats['flagged_count'],
            'percentage': stats['flagged_percentage'],
            'stats': stats
        })

    # Display comparison
    print("\n\n" + "=" * 80)
    print("CONFIGURATION COMPARISON SUMMARY")
    print("=" * 80)

    print(f"\n{'Configuration':<15} {'Flagged':<12} {'Percentage':<12} {'Precision':<12} {'Recall':<12}")
    print("-" * 63)

    for result in results_summary:
        config = result['config']
        flagged = result['flagged']
        percentage = result['percentage']

        # Get precision and recall if available
        if 'ground_truth' in result['stats']:
            precision = result['stats']['ground_truth']['precision']
            recall = result['stats']['ground_truth']['recall']
            print(f"{config:<15} {flagged:<12} {percentage:<12.1f} {precision:<12.2%} {recall:<12.2%}")
        else:
            print(f"{config:<15} {flagged:<12} {percentage:<12.1f} {'N/A':<12} {'N/A':<12}")

    print("\n" + "=" * 80)
    print("✓ PHASE 4 COMPLETE!")
    print("=" * 80)
    print("\nAll detection results have been saved to the 'reports' directory.")
    print("You can now:")
    print("  • Review flagged transactions in the CSV files")
    print("  • Analyze statistics in the JSON files")
    print("  • Compare performance across configurations")
    print("  • Move to Phase 5 for enhanced reporting")


if __name__ == "__main__":
    main()