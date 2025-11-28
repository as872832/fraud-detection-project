"""
Phase 2: Rule Engine
Core fraud detection logic with 4 configurable rules
"""

import pandas as pd
import math
from datetime import datetime, timedelta


class FraudRuleEngine:
    """
    Rule-based fraud detection engine
    Applies configurable rules to detect suspicious transaction patterns
    """

    def __init__(self, config=None):
        """
        Initialize the rule engine with configuration

        Parameters:
        -----------
        config : dict, optional
            Configuration dictionary with rule thresholds
        """
        # Default configuration (can be overridden)
        self.config = config if config else {
            'frequency': {
                'enabled': True,
                'max_transactions': 5,  # Max transactions allowed
                'time_window_minutes': 60  # Within this many minutes
            },
            'amount': {
                'enabled': True,
                'single_transaction_limit': 1000,  # Max for one transaction
                'daily_cumulative_limit': 3000  # Max per day total
            },
            'travel': {
                'enabled': True,
                'max_speed_mph': 600  # Maximum travel speed (even by plane)
            },
            'time': {
                'enabled': True,
                'unusual_hours_start': 2,  # 2 AM
                'unusual_hours_end': 5  # 5 AM
            }
        }

        # Store violations for reporting
        self.violations = []

    def calculate_distance(self, lat1, lon1, lat2, lon2):
        """
        Calculate distance between two GPS coordinates in miles

        Parameters:
        -----------
        lat1, lon1 : float
            Coordinates of first location
        lat2, lon2 : float
            Coordinates of second location

        Returns:
        --------
        float : Distance in miles
        """
        # Radius of Earth in miles
        R = 3959

        # Convert to radians
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)

        # Haversine formula
        a = (math.sin(delta_lat / 2) ** 2 +
             math.cos(lat1_rad) * math.cos(lat2_rad) *
             math.sin(delta_lon / 2) ** 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        distance = R * c

        return distance

    def check_frequency_rule(self, df, transaction_idx):
        """
        Rule 1: High Frequency Detection
        Flags if too many transactions occur within a short time window

        Parameters:
        -----------
        df : DataFrame
            Transaction data
        transaction_idx : int
            Index of current transaction to check

        Returns:
        --------
        dict : Violation details if rule is violated, None otherwise
        """
        if not self.config['frequency']['enabled']:
            return None

        current_txn = df.iloc[transaction_idx]
        user_id = current_txn['user_id']
        current_time = pd.to_datetime(current_txn['timestamp'])

        # Get time window
        time_window = timedelta(minutes=self.config['frequency']['time_window_minutes'])
        window_start = current_time - time_window

        # Find all transactions by this user in the time window
        user_txns = df[
            (df['user_id'] == user_id) &
            (pd.to_datetime(df['timestamp']) >= window_start) &
            (pd.to_datetime(df['timestamp']) <= current_time)
            ]

        # Check if exceeds threshold
        max_allowed = self.config['frequency']['max_transactions']
        if len(user_txns) > max_allowed:
            return {
                'rule': 'HIGH_FREQUENCY',
                'severity': 'HIGH',
                'message': f"{len(user_txns)} transactions in {self.config['frequency']['time_window_minutes']} minutes (max allowed: {max_allowed})",
                'details': {
                    'transaction_count': len(user_txns),
                    'time_window_minutes': self.config['frequency']['time_window_minutes'],
                    'threshold': max_allowed
                }
            }

        return None

    def check_amount_rule(self, df, transaction_idx):
        """
        Rule 2: High Amount Detection
        Flags unusually high transaction amounts (individual or cumulative daily)

        Parameters:
        -----------
        df : DataFrame
            Transaction data
        transaction_idx : int
            Index of current transaction to check

        Returns:
        --------
        dict : Violation details if rule is violated, None otherwise
        """
        if not self.config['amount']['enabled']:
            return None

        current_txn = df.iloc[transaction_idx]
        user_id = current_txn['user_id']
        amount = current_txn['amount']
        current_time = pd.to_datetime(current_txn['timestamp'])

        violations = []

        # Check single transaction limit
        single_limit = self.config['amount']['single_transaction_limit']
        if amount > single_limit:
            violations.append({
                'rule': 'HIGH_AMOUNT_SINGLE',
                'severity': 'HIGH',
                'message': f"Transaction amount ${amount:.2f} exceeds single transaction limit of ${single_limit:.2f}",
                'details': {
                    'amount': amount,
                    'threshold': single_limit,
                    'excess': amount - single_limit
                }
            })

        # Check daily cumulative limit
        day_start = current_time.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)

        daily_txns = df[
            (df['user_id'] == user_id) &
            (pd.to_datetime(df['timestamp']) >= day_start) &
            (pd.to_datetime(df['timestamp']) < day_end)
            ]

        daily_total = daily_txns['amount'].sum()
        daily_limit = self.config['amount']['daily_cumulative_limit']

        if daily_total > daily_limit:
            violations.append({
                'rule': 'HIGH_AMOUNT_CUMULATIVE',
                'severity': 'MEDIUM',
                'message': f"Daily spending ${daily_total:.2f} exceeds daily limit of ${daily_limit:.2f}",
                'details': {
                    'daily_total': daily_total,
                    'threshold': daily_limit,
                    'transaction_count': len(daily_txns),
                    'excess': daily_total - daily_limit
                }
            })

        # Return the first violation if any
        return violations[0] if violations else None

    def check_travel_rule(self, df, transaction_idx):
        """
        Rule 3: Impossible Travel Detection
        Flags if travel speed between consecutive transactions is impossible

        Parameters:
        -----------
        df : DataFrame
            Transaction data
        transaction_idx : int
            Index of current transaction to check

        Returns:
        --------
        dict : Violation details if rule is violated, None otherwise
        """
        if not self.config['travel']['enabled']:
            return None

        if transaction_idx == 0:
            return None  # First transaction, nothing to compare

        current_txn = df.iloc[transaction_idx]
        user_id = current_txn['user_id']

        # Find previous transaction by same user
        previous_user_txns = df[
            (df['user_id'] == user_id) &
            (df.index < transaction_idx)
            ]

        if len(previous_user_txns) == 0:
            return None  # No previous transaction for this user

        previous_txn = previous_user_txns.iloc[-1]

        # Calculate distance
        distance_miles = self.calculate_distance(
            previous_txn['latitude'], previous_txn['longitude'],
            current_txn['latitude'], current_txn['longitude']
        )

        # Calculate time difference
        time1 = pd.to_datetime(previous_txn['timestamp'])
        time2 = pd.to_datetime(current_txn['timestamp'])
        time_diff_hours = (time2 - time1).total_seconds() / 3600

        # Avoid division by zero
        if time_diff_hours < 0.01:  # Less than ~36 seconds
            time_diff_hours = 0.01

        # Calculate required speed
        required_speed = distance_miles / time_diff_hours

        # Check if exceeds maximum possible speed
        max_speed = self.config['travel']['max_speed_mph']
        if required_speed > max_speed and distance_miles > 50:  # Only flag if significant distance
            return {
                'rule': 'IMPOSSIBLE_TRAVEL',
                'severity': 'CRITICAL',
                'message': f"Impossible travel: {distance_miles:.0f} miles in {time_diff_hours:.2f} hours (speed: {required_speed:.0f} mph, max allowed: {max_speed} mph)",
                'details': {
                    'distance_miles': distance_miles,
                    'time_hours': time_diff_hours,
                    'required_speed_mph': required_speed,
                    'max_speed_mph': max_speed,
                    'previous_location': previous_txn['location'],
                    'current_location': current_txn['location']
                }
            }

        return None

    def check_time_rule(self, df, transaction_idx):
        """
        Rule 4: Unusual Time Detection
        Flags transactions during unusual hours (typically 2 AM - 5 AM)

        Parameters:
        -----------
        df : DataFrame
            Transaction data
        transaction_idx : int
            Index of current transaction to check

        Returns:
        --------
        dict : Violation details if rule is violated, None otherwise
        """
        if not self.config['time']['enabled']:
            return None

        current_txn = df.iloc[transaction_idx]
        timestamp = pd.to_datetime(current_txn['timestamp'])
        hour = timestamp.hour

        unusual_start = self.config['time']['unusual_hours_start']
        unusual_end = self.config['time']['unusual_hours_end']

        # Check if transaction is during unusual hours
        if unusual_start <= hour <= unusual_end:
            return {
                'rule': 'UNUSUAL_TIME',
                'severity': 'MEDIUM',
                'message': f"Transaction at unusual hour: {hour}:00 (unusual hours: {unusual_start}:00 - {unusual_end}:00)",
                'details': {
                    'transaction_hour': hour,
                    'unusual_start': unusual_start,
                    'unusual_end': unusual_end
                }
            }

        return None

    def analyze_transaction(self, df, transaction_idx):
        """
        Analyze a single transaction against all rules

        Parameters:
        -----------
        df : DataFrame
            Transaction data
        transaction_idx : int
            Index of transaction to analyze

        Returns:
        --------
        list : List of violations found
        """
        violations = []

        # Apply all rules
        rules_to_check = [
            self.check_frequency_rule,
            self.check_amount_rule,
            self.check_travel_rule,
            self.check_time_rule
        ]

        for rule_func in rules_to_check:
            violation = rule_func(df, transaction_idx)
            if violation:
                violations.append(violation)

        return violations

    def analyze_dataset(self, df):
        """
        Analyze entire dataset and flag all suspicious transactions

        Parameters:
        -----------
        df : DataFrame
            Transaction data to analyze

        Returns:
        --------
        DataFrame : Original data with added columns for violations
        """
        print("Analyzing transactions for fraud patterns...")
        print(f"Total transactions to analyze: {len(df)}\n")

        # Add columns for results
        df['suspicious'] = False
        df['risk_score'] = 0
        df['violations'] = [[] for _ in range(len(df))]

        # Analyze each transaction
        for idx in range(len(df)):
            violations = self.analyze_transaction(df, idx)

            if violations:
                df.at[idx, 'suspicious'] = True
                df.at[idx, 'risk_score'] = len(violations)
                df.at[idx, 'violations'] = violations

                # Store for reporting
                self.violations.append({
                    'transaction_idx': idx,
                    'transaction_id': df.iloc[idx]['transaction_id'],
                    'user_id': df.iloc[idx]['user_id'],
                    'timestamp': df.iloc[idx]['timestamp'],
                    'amount': df.iloc[idx]['amount'],
                    'violations': violations
                })

        # Summary statistics
        total_suspicious = df['suspicious'].sum()
        print(f"\n✓ Analysis complete!")
        print(
            f"Suspicious transactions detected: {total_suspicious} out of {len(df)} ({total_suspicious / len(df) * 100:.1f}%)")
        print(f"\nRisk score distribution:")
        print(df[df['suspicious'] == True]['risk_score'].value_counts().sort_index())

        return df


def main():
    """Test the rule engine with the generated data"""
    print("=" * 80)
    print("PHASE 2: RULE ENGINE TEST")
    print("=" * 80)

    # Load the data
    df = pd.read_csv('C:/Users/prncs/OneDrive/Desktop/PythonProject4/data/transactions.csv')
    print(f"\nLoaded {len(df)} transactions")

    # Create rule engine
    engine = FraudRuleEngine()

    # Display configuration
    print("\nRule Engine Configuration:")
    print(
        f"  Frequency: Max {engine.config['frequency']['max_transactions']} transactions in {engine.config['frequency']['time_window_minutes']} minutes")
    print(
        f"  Amount: Single limit ${engine.config['amount']['single_transaction_limit']}, Daily limit ${engine.config['amount']['daily_cumulative_limit']}")
    print(f"  Travel: Max speed {engine.config['travel']['max_speed_mph']} mph")
    print(
        f"  Time: Unusual hours {engine.config['time']['unusual_hours_start']}:00 - {engine.config['time']['unusual_hours_end']}:00")
    print()

    # Analyze dataset
    df_analyzed = engine.analyze_dataset(df)

    # Show some flagged transactions
    print("\n" + "=" * 80)
    print("SAMPLE FLAGGED TRANSACTIONS")
    print("=" * 80)

    suspicious_df = df_analyzed[df_analyzed['suspicious'] == True].head(10)
    for idx, row in suspicious_df.iterrows():
        print(f"\nTransaction: {row['transaction_id']}")
        print(f"  User: {row['user_id']}")
        print(f"  Time: {row['timestamp']}")
        print(f"  Amount: ${row['amount']:.2f}")
        print(f"  Location: {row['location']}")
        print(f"  Risk Score: {row['risk_score']}")
        print(f"  Violations:")
        for violation in row['violations']:
            print(f"    - [{violation['rule']}] {violation['message']}")

    # Save results
    output_path = 'C:/Users/prncs/OneDrive/Desktop/PythonProject4/data/analyzed_transactions.csv'
    # Convert violations list to string for CSV
    df_analyzed['violations_str'] = df_analyzed['violations'].apply(lambda x: str(x) if x else '')
    df_analyzed.drop('violations', axis=1).to_csv(output_path, index=False)
    print(f"\n✓ Results saved to: {output_path}")

    return df_analyzed, engine


if __name__ == "__main__":
    df_analyzed, engine = main()