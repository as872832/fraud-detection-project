"""
Phase 6: Flask Web Application
Interactive GUI for the Fraud Detection System
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
import os
import pandas as pd
import json
from datetime import datetime
from werkzeug.utils import secure_filename

# Import our modules
try:
    from rule_engine import FraudRuleEngine
    from config_manager import ConfigurationManager
    from detection_system import FraudDetectionSystem
    from report_generator import ReportGenerator
except ImportError:
    import sys
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.append(script_dir)
    from rule_engine import FraudRuleEngine
    from config_manager import ConfigurationManager
    from detection_system import FraudDetectionSystem
    from report_generator import ReportGenerator

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'fraud_detection_secret_key_2024'  # Change this in production

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv'}

# Create necessary directories
script_dir = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.dirname(script_dir)

app.config['UPLOAD_FOLDER'] = os.path.join(project_dir, UPLOAD_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure directories exist
for directory in [app.config['UPLOAD_FOLDER'], 
                  os.path.join(project_dir, 'data'),
                  os.path.join(project_dir, 'config'),
                  os.path.join(project_dir, 'reports')]:
    if not os.path.exists(directory):
        os.makedirs(directory)

# Initialize system components
detection_system = FraudDetectionSystem(project_dir=project_dir)
report_generator = ReportGenerator(reports_dir=os.path.join(project_dir, 'reports'))

# Global state (in production, use a database)
current_session = {
    'data_loaded': False,
    'data_file': None,
    'df': None,
    'config_name': 'moderate',
    'results': None,
    'stats': None
}


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    """Home page / Dashboard"""
    # Get available configurations
    config_mgr = ConfigurationManager()
    configs = config_mgr.list_configs()
    
    # Get session status
    status = {
        'data_loaded': current_session['data_loaded'],
        'data_file': current_session['data_file'],
        'config': current_session['config_name'],
        'has_results': current_session['results'] is not None
    }
    
    return render_template('index.html', status=status, configs=configs)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """Upload transaction data"""
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Try to load the file
            try:
                df = pd.read_csv(filepath)
                
                # Validate required columns
                required_cols = ['transaction_id', 'user_id', 'timestamp', 'amount', 'location']
                missing_cols = [col for col in required_cols if col not in df.columns]
                
                if missing_cols:
                    flash(f'Missing required columns: {", ".join(missing_cols)}', 'error')
                    return redirect(request.url)
                
                # Store in session
                current_session['data_loaded'] = True
                current_session['data_file'] = filename
                current_session['df'] = df
                
                flash(f'Successfully loaded {len(df)} transactions from {filename}', 'success')
                return redirect(url_for('configure'))
                
            except Exception as e:
                flash(f'Error loading file: {str(e)}', 'error')
                return redirect(request.url)
        else:
            flash('Invalid file type. Please upload a CSV file.', 'error')
            return redirect(request.url)
    
    return render_template('upload.html')


@app.route('/configure', methods=['GET', 'POST'])
def configure():
    """Configure detection rules"""
    if not current_session['data_loaded']:
        flash('Please upload transaction data first', 'warning')
        return redirect(url_for('upload'))
    
    config_mgr = ConfigurationManager()
    
    if request.method == 'POST':
        config_name = request.form.get('config_name', 'moderate')
        current_session['config_name'] = config_name
        
        flash(f'Configuration set to: {config_name}', 'success')
        return redirect(url_for('detect'))
    
    # Get all available configurations
    configs = {}
    for config_file in config_mgr.list_configs():
        config_name = config_file.replace('_config.json', '')
        try:
            config = config_mgr.load_config(config_file)
            configs[config_name] = config
        except:
            pass
    
    return render_template('configure.html', 
                         configs=configs, 
                         current_config=current_session['config_name'])


@app.route('/detect', methods=['GET', 'POST'])
def detect():
    """Run fraud detection"""
    if not current_session['data_loaded']:
        flash('Please upload transaction data first', 'warning')
        return redirect(url_for('upload'))
    
    if request.method == 'POST':
        try:
            # Load configuration
            config = detection_system.load_configuration(current_session['config_name'])
            
            # Run detection
            df_analyzed = detection_system.run_detection(current_session['df'], config)
            
            # Calculate statistics
            stats = detection_system.calculate_statistics(df_analyzed)
            
            # Store results
            current_session['results'] = df_analyzed
            current_session['stats'] = stats
            
            flash('Fraud detection completed successfully!', 'success')
            return redirect(url_for('results'))
            
        except Exception as e:
            flash(f'Error during detection: {str(e)}', 'error')
            return redirect(request.url)
    
    return render_template('detect.html', config=current_session['config_name'])


@app.route('/results')
def results():
    """View detection results"""
    if current_session['results'] is None:
        flash('No detection results available. Please run detection first.', 'warning')
        return redirect(url_for('detect'))
    
    df = current_session['results']
    stats = current_session['stats']
    
    # Get flagged transactions
    flagged = df[df['suspicious'] == True].sort_values('risk_score', ascending=False).head(50)
    
    # Convert to dict for template
    flagged_list = []
    for _, row in flagged.iterrows():
        flagged_list.append({
            'transaction_id': row['transaction_id'],
            'user_id': row['user_id'],
            'timestamp': row['timestamp'],
            'amount': row['amount'],
            'merchant': row.get('merchant', 'N/A'),
            'location': row['location'],
            'risk_score': row['risk_score'],
            'violations': row.get('violations', [])
        })
    
    return render_template('results.html', 
                         stats=stats, 
                         flagged_transactions=flagged_list,
                         config=current_session['config_name'])


@app.route('/download_report/<report_type>')
def download_report(report_type):
    """Download generated reports"""
    if current_session['results'] is None:
        flash('No results available', 'error')
        return redirect(url_for('index'))
    
    try:
        # Generate reports
        file_paths = report_generator.save_all_reports(
            current_session['results'],
            current_session['stats'],
            current_session['config_name']
        )
        
        # Determine which file to send
        if report_type == 'executive':
            file_path = file_paths['executive']
        elif report_type == 'detailed':
            file_path = file_paths['detailed']
        elif report_type == 'statistics':
            file_path = file_paths['statistics']
        elif report_type == 'html':
            file_path = file_paths['html']
        elif report_type == 'csv':
            file_path = file_paths['flagged_csv']
        else:
            flash('Invalid report type', 'error')
            return redirect(url_for('results'))
        
        return send_file(file_path, as_attachment=True)
        
    except Exception as e:
        flash(f'Error generating report: {str(e)}', 'error')
        return redirect(url_for('results'))


@app.route('/api/stats')
def api_stats():
    """API endpoint for statistics (for charts)"""
    if current_session['stats'] is None:
        return jsonify({'error': 'No statistics available'}), 404
    
    stats = current_session['stats']
    
    # Prepare data for charts
    response = {
        'total': stats['total_transactions'],
        'flagged': stats['flagged_count'],
        'clean': stats['clean_count'],
        'violations': stats.get('violations_by_rule', {}),
        'risk_distribution': stats.get('risk_score_distribution', {}),
        'performance': stats.get('ground_truth', {})
    }
    
    return jsonify(response)


@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500


if __name__ == '__main__':
    print("="*80)
    print("FRAUD DETECTION SYSTEM - WEB APPLICATION")
    print("="*80)
    print("\nStarting Flask server...")
    print("Open your browser and go to: http://127.0.0.1:5000")
    print("\nPress Ctrl+C to stop the server")
    print("="*80)
    
    app.run(debug=True, host='127.0.0.1', port=5000)
