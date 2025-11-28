
import sqlite3
import pandas as pd
import os
from datetime import datetime

class DatabaseManager:

    
    def __init__(self, db_path=None):
        """
        Initialize the database manager

        Parameters:
        -----------
        db_path : str, optional
            Path to SQLite database file
        """
        if db_path is None:
            # Get script directory and go up one level to project root
            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_dir = os.path.dirname(script_dir)
            db_path = os.path.join(project_dir, 'data', 'fraud_detection.db')
        
        self.db_path = db_path
        self.conn = None
        
        # Create database and tables
        self.connect()
        self.create_tables()
    
    def connect(self):
        """Connect to SQLite database"""
        # Create data directory if it doesn't exist
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        self.conn = sqlite3.connect(self.db_path)
        print(f"✓ Connected to database: {self.db_path}")
        return self.conn
    
    def create_tables(self):
        """Create database tables if they don't exist"""
        cursor = self.conn.cursor()
        
        # Transactions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                transaction_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                amount REAL NOT NULL,
                merchant TEXT,
                location TEXT,
                latitude REAL,
                longitude REAL,
                is_fraud BOOLEAN,
                fraud_type TEXT
            )
        ''')
        
        # Detection results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detection_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT NOT NULL,
                suspicious BOOLEAN NOT NULL,
                risk_score INTEGER,
                config_used TEXT,
                detection_timestamp DATETIME,
                violations TEXT,
                FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id)
            )
        ''')
        
        # Configuration history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS config_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                config_name TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                transactions_analyzed INTEGER,
                flagged_count INTEGER,
                precision REAL,
                recall REAL,
                accuracy REAL
            )
        ''')
        
        self.conn.commit()
        print("✓ Database tables created/verified")
    
    def save_transactions(self, df):
        """
        Save transactions DataFrame to database
        
        Parameters:
        -----------
        df : DataFrame
            Transaction data to save
            
        Returns:
        --------
        int : Number of transactions saved
        """
        # Save to database
        df.to_sql('transactions', self.conn, if_exists='replace', index=False)
        count = len(df)
        print(f"✓ Saved {count} transactions to database")
        return count
    
    def get_transactions(self):
        """
        Load transactions from database
        
        Returns:
        --------
        DataFrame : Transaction data
        """
        query = "SELECT * FROM transactions"
        df = pd.read_sql_query(query, self.conn)
        print(f"✓ Loaded {len(df)} transactions from database")
        return df
    
    def save_detection_results(self, df, config_name):
        """
        Save detection results to database
        
        Parameters:
        -----------
        df : DataFrame
            Detection results with suspicious flags
        config_name : str
            Name of configuration used
        """
        # Prepare data for saving
        results = []
        for _, row in df.iterrows():
            results.append({
                'transaction_id': row['transaction_id'],
                'suspicious': row['suspicious'],
                'risk_score': row['risk_score'],
                'config_used': config_name,
                'detection_timestamp': datetime.now().isoformat(),
                'violations': str(row['violations']) if 'violations' in row else ''
            })
        
        results_df = pd.DataFrame(results)
        results_df.to_sql('detection_results', self.conn, if_exists='append', index=False)
        
        flagged_count = df['suspicious'].sum()
        print(f"✓ Saved detection results: {flagged_count} flagged transactions")
    
    def save_config_performance(self, config_name, stats):
        """
        Save configuration performance metrics
        
        Parameters:
        -----------
        config_name : str
            Configuration name
        stats : dict
            Performance statistics
        """
        cursor = self.conn.cursor()
        
        cursor.execute('''
            INSERT INTO config_history 
            (config_name, timestamp, transactions_analyzed, flagged_count, precision, recall, accuracy)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            config_name,
            datetime.now().isoformat(),
            stats.get('total_transactions', 0),
            stats.get('flagged_count', 0),
            stats.get('ground_truth', {}).get('precision', 0),
            stats.get('ground_truth', {}).get('recall', 0),
            stats.get('ground_truth', {}).get('accuracy', 0)
        ))
        
        self.conn.commit()
        print(f"✓ Saved performance metrics for {config_name}")
    
    def get_suspicious_transactions(self, config_name=None):
        """
        Get all suspicious transactions from database
        
        Parameters:
        -----------
        config_name : str, optional
            Filter by configuration name
            
        Returns:
        --------
        DataFrame : Suspicious transactions
        """
        if config_name:
            query = '''
                SELECT t.*, dr.risk_score, dr.config_used, dr.detection_timestamp
                FROM transactions t
                JOIN detection_results dr ON t.transaction_id = dr.transaction_id
                WHERE dr.suspicious = 1 AND dr.config_used = ?
            '''
            df = pd.read_sql_query(query, self.conn, params=(config_name,))
        else:
            query = '''
                SELECT t.*, dr.risk_score, dr.config_used, dr.detection_timestamp
                FROM transactions t
                JOIN detection_results dr ON t.transaction_id = dr.transaction_id
                WHERE dr.suspicious = 1
            '''
            df = pd.read_sql_query(query, self.conn)
        
        return df
    
    def get_user_transactions(self, user_id):
        """
        Get all transactions for a specific user
        
        Parameters:
        -----------
        user_id : str
            User ID to query
            
        Returns:
        --------
        DataFrame : User's transactions
        """
        query = "SELECT * FROM transactions WHERE user_id = ?"
        df = pd.read_sql_query(query, self.conn, params=(user_id,))
        return df
    
    def get_high_amount_transactions(self, threshold=1000):
        """
        Get transactions above a certain amount
        
        Parameters:
        -----------
        threshold : float
            Amount threshold
            
        Returns:
        --------
        DataFrame : Transactions above threshold
        """
        query = "SELECT * FROM transactions WHERE amount > ? ORDER BY amount DESC"
        df = pd.read_sql_query(query, self.conn, params=(threshold,))
        return df
    
    def get_statistics(self):
        """
        Get database statistics
        
        Returns:
        --------
        dict : Database statistics
        """
        cursor = self.conn.cursor()
        
        # Total transactions
        cursor.execute("SELECT COUNT(*) FROM transactions")
        total_txns = cursor.fetchone()[0]
        
        # Total fraud
        cursor.execute("SELECT COUNT(*) FROM transactions WHERE is_fraud = 1")
        total_fraud = cursor.fetchone()[0]
        
        # Unique users
        cursor.execute("SELECT COUNT(DISTINCT user_id) FROM transactions")
        unique_users = cursor.fetchone()[0]
        
        # Detection runs
        cursor.execute("SELECT COUNT(*) FROM config_history")
        detection_runs = cursor.fetchone()[0]
        
        return {
            'total_transactions': total_txns,
            'total_fraud': total_fraud,
            'unique_users': unique_users,
            'detection_runs': detection_runs
        }
    
    def execute_custom_query(self, query, params=None):
        """
        Execute a custom SQL query
        
        Parameters:
        -----------
        query : str
            SQL query to execute
        params : tuple, optional
            Query parameters
            
        Returns:
        --------
        DataFrame : Query results
        """
        if params:
            df = pd.read_sql_query(query, self.conn, params=params)
        else:
            df = pd.read_sql_query(query, self.conn)
        return df
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            print("✓ Database connection closed")


def demo_sql_queries():
    """
    Demonstrate useful SQL queries for fraud detection
    Use these in your video presentation!
    """
    print("="*80)
    print("SQL QUERY EXAMPLES FOR VIDEO DEMONSTRATION")
    print("="*80)
    
    db = DatabaseManager()
    
    print("\n1. Get all suspicious transactions:")
    print("-" * 80)
    query1 = "SELECT * FROM transactions t JOIN detection_results dr ON t.transaction_id = dr.transaction_id WHERE dr.suspicious = 1"
    result1 = db.execute_custom_query(query1)
    print(f"Query: {query1}")
    print(f"Results: {len(result1)} suspicious transactions found")
    print(result1.head())
    
    print("\n2. Count transactions by user:")
    print("-" * 80)
    query2 = "SELECT user_id, COUNT(*) as transaction_count FROM transactions GROUP BY user_id ORDER BY transaction_count DESC LIMIT 5"
    result2 = db.execute_custom_query(query2)
    print(f"Query: {query2}")
    print(result2)
    
    print("\n3. Find high-value transactions:")
    print("-" * 80)
    query3 = "SELECT transaction_id, user_id, amount, merchant FROM transactions WHERE amount > 1000 ORDER BY amount DESC"
    result3 = db.execute_custom_query(query3)
    print(f"Query: {query3}")
    print(f"Results: {len(result3)} transactions over $1000")
    print(result3.head())
    
    print("\n4. Get fraud detection performance history:")
    print("-" * 80)
    query4 = "SELECT config_name, transactions_analyzed, flagged_count, ROUND(precision, 4) as precision, ROUND(recall, 4) as recall FROM config_history"
    result4 = db.execute_custom_query(query4)
    print(f"Query: {query4}")
    print(result4)
    
    print("\n5. Find transactions by location:")
    print("-" * 80)
    query5 = "SELECT location, COUNT(*) as count FROM transactions GROUP BY location ORDER BY count DESC"
    result5 = db.execute_custom_query(query5)
    print(f"Query: {query5}")
    print(result5)
    
    db.close()


if __name__ == "__main__":
    print("="*80)
    print("DATABASE MANAGER - SIMPLE SQL INTEGRATION")
    print("="*80)
    
    # Initialize database
    db = DatabaseManager()
    
    # Check if transactions exist
    try:
        df = db.get_transactions()
        print(f"\nDatabase contains {len(df)} transactions")
    except:
        print("\nNo transactions in database yet")
        print("Run detection_system_with_db.py to populate the database")
    
    # Show statistics
    stats = db.get_statistics()
    print("\nDatabase Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    db.close()
    
    print("\n" + "="*80)
    print("To see SQL query examples, run: demo_sql_queries()")
    print("="*80)
