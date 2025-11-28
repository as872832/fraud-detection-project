"""
Phase 1: Synthetic Transaction Data Generator
Creates realistic credit card transaction data with both legitimate and fraudulent patterns
"""

import pandas as pd
import random
from datetime import datetime, timedelta
import json

# Set random seed for reproducibility
random.seed(42)

# Define major cities with coordinates (lat, lon)
LOCATIONS = {
    'New York, NY': (40.7128, -74.0060),
    'Los Angeles, CA': (34.0522, -118.2437),
    'Chicago, IL': (41.8781, -87.6298),
    'Houston, TX': (29.7604, -95.3698),
    'Miami, FL': (25.7617, -80.1918),
    'Seattle, WA': (47.6062, -122.3321),
    'Boston, MA': (42.3601, -71.0589),
    'Denver, CO': (39.7392, -104.9903),
    'Atlanta, GA': (33.7490, -84.3880),
    'San Francisco, CA': (37.7749, -122.4194)
}

# Merchant categories
MERCHANTS = [
    'Amazon.com', 'Walmart', 'Target', 'Starbucks', 'Shell Gas Station',
    'Whole Foods', 'CVS Pharmacy', 'Home Depot', 'Best Buy', 'Chipotle',
    'McDonald\'s', 'Uber', 'Netflix', 'Apple Store', 'Delta Airlines',
    'Hilton Hotels', 'Local Restaurant', 'Local Grocery', 'Gas Station',
    'Online Retailer'
]

class TransactionDataGenerator:
    def __init__(self, num_users=50, num_transactions=2000):
        self.num_users = num_users
        self.num_transactions = num_transactions
        self.transactions = []
        self.transaction_id_counter = 1

    def generate_normal_transactions(self, user_id, home_location, num_transactions):
        """Generate normal transaction patterns for a user"""
        transactions = []
        current_date = datetime.now() - timedelta(days=90)  # Start 90 days ago

        for _ in range(num_transactions):
            # Normal transactions during business hours (6 AM - 11 PM)
            hour = random.choices(
                range(24),
                weights=[1,1,1,1,1,2,8,10,12,10,10,12,12,10,10,8,8,10,12,10,8,6,4,2]
            )[0]

            current_date += timedelta(
                days=random.randint(0, 3),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )

            # Normal transaction amounts
            amount = round(random.choices(
                [random.uniform(5, 50), random.uniform(50, 200), random.uniform(200, 500)],
                weights=[60, 30, 10]
            )[0], 2)

            # Usually at home location, occasionally traveling
            if random.random() < 0.9:
                location = home_location
            else:
                location = random.choice(list(LOCATIONS.keys()))

            transactions.append({
                'transaction_id': f'TXN{self.transaction_id_counter:06d}',
                'user_id': user_id,
                'timestamp': current_date.strftime('%Y-%m-%d %H:%M:%S'),
                'amount': amount,
                'merchant': random.choice(MERCHANTS),
                'location': location,
                'latitude': LOCATIONS[location][0],
                'longitude': LOCATIONS[location][1],
                'is_fraud': False,
                'fraud_type': None
            })
            self.transaction_id_counter += 1

        return transactions

    def generate_fraudulent_transactions(self, user_id, home_location):
        """Generate various types of fraudulent transaction patterns"""
        fraudulent_txns = []
        base_date = datetime.now() - timedelta(days=random.randint(10, 80))

        # Type 1: Rapid-fire transactions (high frequency)
        if random.random() < 0.3:
            num_rapid = random.randint(5, 10)
            rapid_date = base_date + timedelta(days=random.randint(0, 10))

            for i in range(num_rapid):
                fraudulent_txns.append({
                    'transaction_id': f'TXN{self.transaction_id_counter:06d}',
                    'user_id': user_id,
                    'timestamp': (rapid_date + timedelta(minutes=i*2)).strftime('%Y-%m-%d %H:%M:%S'),
                    'amount': round(random.uniform(100, 500), 2),
                    'merchant': random.choice(MERCHANTS),
                    'location': home_location,
                    'latitude': LOCATIONS[home_location][0],
                    'longitude': LOCATIONS[home_location][1],
                    'is_fraud': True,
                    'fraud_type': 'high_frequency'
                })
                self.transaction_id_counter += 1

        # Type 2: Geographically impossible transactions
        if random.random() < 0.3:
            impossible_date = base_date + timedelta(days=random.randint(0, 10))

            # Transaction in home location
            fraudulent_txns.append({
                'transaction_id': f'TXN{self.transaction_id_counter:06d}',
                'user_id': user_id,
                'timestamp': impossible_date.strftime('%Y-%m-%d %H:%M:%S'),
                'amount': round(random.uniform(50, 200), 2),
                'merchant': random.choice(MERCHANTS),
                'location': home_location,
                'latitude': LOCATIONS[home_location][0],
                'longitude': LOCATIONS[home_location][1],
                'is_fraud': True,
                'fraud_type': 'impossible_travel'
            })
            self.transaction_id_counter += 1

            # Transaction across the country 30 minutes later
            far_location = random.choice([loc for loc in LOCATIONS.keys() if loc != home_location])
            fraudulent_txns.append({
                'transaction_id': f'TXN{self.transaction_id_counter:06d}',
                'user_id': user_id,
                'timestamp': (impossible_date + timedelta(minutes=30)).strftime('%Y-%m-%d %H:%M:%S'),
                'amount': round(random.uniform(50, 200), 2),
                'merchant': random.choice(MERCHANTS),
                'location': far_location,
                'latitude': LOCATIONS[far_location][0],
                'longitude': LOCATIONS[far_location][1],
                'is_fraud': True,
                'fraud_type': 'impossible_travel'
            })
            self.transaction_id_counter += 1

        # Type 3: Unusually high amounts
        if random.random() < 0.3:
            high_amount_date = base_date + timedelta(days=random.randint(0, 10))

            for _ in range(random.randint(1, 3)):
                fraudulent_txns.append({
                    'transaction_id': f'TXN{self.transaction_id_counter:06d}',
                    'user_id': user_id,
                    'timestamp': (high_amount_date + timedelta(hours=random.randint(1, 5))).strftime('%Y-%m-%d %H:%M:%S'),
                    'amount': round(random.uniform(2000, 5000), 2),
                    'merchant': random.choice(['Online Retailer', 'Best Buy', 'Apple Store']),
                    'location': home_location,
                    'latitude': LOCATIONS[home_location][0],
                    'longitude': LOCATIONS[home_location][1],
                    'is_fraud': True,
                    'fraud_type': 'high_amount'
                })
                self.transaction_id_counter += 1

        # Type 4: Unusual time transactions (2 AM - 5 AM)
        if random.random() < 0.3:
            odd_date = base_date + timedelta(days=random.randint(0, 10))
            odd_hour = random.randint(2, 5)

            for _ in range(random.randint(2, 4)):
                fraudulent_txns.append({
                    'transaction_id': f'TXN{self.transaction_id_counter:06d}',
                    'user_id': user_id,
                    'timestamp': (odd_date.replace(hour=odd_hour) + timedelta(minutes=random.randint(0, 59))).strftime('%Y-%m-%d %H:%M:%S'),
                    'amount': round(random.uniform(100, 800), 2),
                    'merchant': random.choice(MERCHANTS),
                    'location': home_location,
                    'latitude': LOCATIONS[home_location][0],
                    'longitude': LOCATIONS[home_location][1],
                    'is_fraud': True,
                    'fraud_type': 'unusual_time'
                })
                self.transaction_id_counter += 1

        return fraudulent_txns

    def generate_dataset(self):
        """Generate complete dataset with normal and fraudulent transactions"""
        print(f"Generating dataset for {self.num_users} users...")

        # Assign each user a home location
        user_locations = {}
        for user_id in range(1, self.num_users + 1):
            user_locations[f'USER{user_id:04d}'] = random.choice(list(LOCATIONS.keys()))

        # Generate transactions for each user
        for user_id_num in range(1, self.num_users + 1):
            user_id = f'USER{user_id_num:04d}'
            home_location = user_locations[user_id]

            # Most transactions are normal
            num_normal = random.randint(30, 50)
            normal_txns = self.generate_normal_transactions(user_id, home_location, num_normal)
            self.transactions.extend(normal_txns)

            # Some users have fraudulent activity (about 30% of users)
            if random.random() < 0.3:
                fraud_txns = self.generate_fraudulent_transactions(user_id, home_location)
                self.transactions.extend(fraud_txns)

        # Convert to DataFrame and sort by timestamp
        df = pd.DataFrame(self.transactions)
        df = df.sort_values('timestamp').reset_index(drop=True)

        print(f"\nDataset generated successfully!")
        print(f"Total transactions: {len(df)}")
        print(f"Legitimate transactions: {len(df[df['is_fraud'] == False])}")
        print(f"Fraudulent transactions: {len(df[df['is_fraud'] == True])}")
        print(f"\nFraud types breakdown:")
        print(df[df['is_fraud'] == True]['fraud_type'].value_counts())

        return df

def main():
    """Main function to generate and save the dataset"""
    generator = TransactionDataGenerator(num_users=50, num_transactions=2000)
    df = generator.generate_dataset()

    # Save to CSV
    csv_path = 'C:/Users/prncs/OneDrive/Desktop/PythonProject4/data/transactions.csv'
    df.to_csv(csv_path, index=False)
    print(f"\n✓ Dataset saved to: {csv_path}")

    # Display sample data
    print("\n" + "="*80)
    print("SAMPLE TRANSACTIONS")
    print("="*80)
    print("\nFirst 5 transactions:")
    print(df.head())

    print("\n\nSample fraudulent transactions:")
    print(df[df['is_fraud'] == True].head(10))

    return df

if __name__ == "__main__":
    df = main()