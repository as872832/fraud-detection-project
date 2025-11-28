"""
Phase 3: Configuration System
Manages rule configurations with save/load capabilities and preset profiles
"""

import json
import os
from datetime import datetime


class ConfigurationManager:
    """
    Manages fraud detection rule configurations
    Provides preset profiles and custom configuration capabilities
    """

    def __init__(self, config_dir='C:/Users/prncs/OneDrive/Desktop/PythonProject4/config'):
        """
        Initialize the configuration manager

        Parameters:
        -----------
        config_dir : str
            Directory to store configuration files
        """
        self.config_dir = config_dir

        # Create config directory if it doesn't exist
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)

    def get_default_config(self):
        """
        Get the default/baseline configuration

        Returns:
        --------
        dict : Default configuration settings
        """
        return {
            'name': 'default',
            'description': 'Balanced fraud detection settings',
            'created_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'rules': {
                'frequency': {
                    'enabled': True,
                    'max_transactions': 5,
                    'time_window_minutes': 60,
                    'description': 'Detects rapid-fire transaction patterns'
                },
                'amount': {
                    'enabled': True,
                    'single_transaction_limit': 1000,
                    'daily_cumulative_limit': 3000,
                    'description': 'Flags unusually high spending amounts'
                },
                'travel': {
                    'enabled': True,
                    'max_speed_mph': 600,
                    'description': 'Detects geographically impossible transactions'
                },
                'time': {
                    'enabled': True,
                    'unusual_hours_start': 2,
                    'unusual_hours_end': 5,
                    'description': 'Flags transactions during unusual hours'
                }
            }
        }

    def get_strict_config(self):
        """
        Get strict fraud detection configuration
        Lower thresholds = more sensitive = catches more fraud (but more false positives)

        Returns:
        --------
        dict : Strict configuration settings
        """
        return {
            'name': 'strict',
            'description': 'Highly sensitive fraud detection - catches more but may have false positives',
            'created_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'rules': {
                'frequency': {
                    'enabled': True,
                    'max_transactions': 3,  # Lower: Only 3 transactions allowed
                    'time_window_minutes': 30,  # Shorter window: 30 minutes
                    'description': 'Very sensitive to rapid transactions'
                },
                'amount': {
                    'enabled': True,
                    'single_transaction_limit': 500,  # Lower: $500 limit
                    'daily_cumulative_limit': 2000,  # Lower: $2000 daily
                    'description': 'Strict spending limits'
                },
                'travel': {
                    'enabled': True,
                    'max_speed_mph': 400,  # Lower: 400 mph (catches more)
                    'description': 'Conservative travel speed threshold'
                },
                'time': {
                    'enabled': True,
                    'unusual_hours_start': 1,  # Wider window: 1 AM
                    'unusual_hours_end': 6,  # to 6 AM
                    'description': 'Broader unusual hours window'
                }
            }
        }

    def get_moderate_config(self):
        """
        Get moderate fraud detection configuration
        Balanced approach - good for most use cases

        Returns:
        --------
        dict : Moderate configuration settings
        """
        return {
            'name': 'moderate',
            'description': 'Balanced fraud detection with reasonable thresholds',
            'created_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'rules': {
                'frequency': {
                    'enabled': True,
                    'max_transactions': 5,
                    'time_window_minutes': 60,
                    'description': 'Moderate frequency detection'
                },
                'amount': {
                    'enabled': True,
                    'single_transaction_limit': 1000,
                    'daily_cumulative_limit': 3000,
                    'description': 'Reasonable spending limits'
                },
                'travel': {
                    'enabled': True,
                    'max_speed_mph': 600,
                    'description': 'Realistic travel speed limit'
                },
                'time': {
                    'enabled': True,
                    'unusual_hours_start': 2,
                    'unusual_hours_end': 5,
                    'description': 'Standard unusual hours'
                }
            }
        }

    def get_lenient_config(self):
        """
        Get lenient fraud detection configuration
        Higher thresholds = less sensitive = fewer false positives (but might miss some fraud)

        Returns:
        --------
        dict : Lenient configuration settings
        """
        return {
            'name': 'lenient',
            'description': 'Relaxed fraud detection - fewer false positives but may miss some fraud',
            'created_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'rules': {
                'frequency': {
                    'enabled': True,
                    'max_transactions': 10,  # Higher: 10 transactions allowed
                    'time_window_minutes': 120,  # Longer window: 2 hours
                    'description': 'Relaxed frequency limits'
                },
                'amount': {
                    'enabled': True,
                    'single_transaction_limit': 2000,  # Higher: $2000 limit
                    'daily_cumulative_limit': 5000,  # Higher: $5000 daily
                    'description': 'Higher spending limits'
                },
                'travel': {
                    'enabled': True,
                    'max_speed_mph': 800,  # Higher: 800 mph (very lenient)
                    'description': 'Lenient travel speed threshold'
                },
                'time': {
                    'enabled': True,
                    'unusual_hours_start': 3,  # Narrower window: 3 AM
                    'unusual_hours_end': 4,  # to 4 AM only
                    'description': 'Narrow unusual hours window'
                }
            }
        }

    def save_config(self, config, filename=None):
        """
        Save configuration to a JSON file

        Parameters:
        -----------
        config : dict
            Configuration dictionary to save
        filename : str, optional
            Custom filename (defaults to config name)

        Returns:
        --------
        str : Path to saved file
        """
        if filename is None:
            filename = f"{config['name']}_config.json"

        filepath = os.path.join(self.config_dir, filename)

        with open(filepath, 'w') as f:
            json.dump(config, f, indent=4)

        return filepath

    def load_config(self, filename):
        """
        Load configuration from a JSON file

        Parameters:
        -----------
        filename : str
            Name of the configuration file to load

        Returns:
        --------
        dict : Loaded configuration
        """
        filepath = os.path.join(self.config_dir, filename)

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Configuration file not found: {filepath}")

        with open(filepath, 'r') as f:
            config = json.load(f)

        return config

    def list_configs(self):
        """
        List all available configuration files

        Returns:
        --------
        list : List of configuration filenames
        """
        if not os.path.exists(self.config_dir):
            return []

        config_files = [f for f in os.listdir(self.config_dir) if f.endswith('.json')]
        return sorted(config_files)

    def create_custom_config(self, name, description, rules):
        """
        Create a custom configuration

        Parameters:
        -----------
        name : str
            Name for the configuration
        description : str
            Description of the configuration
        rules : dict
            Dictionary of rule settings

        Returns:
        --------
        dict : Custom configuration
        """
        return {
            'name': name,
            'description': description,
            'created_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'rules': rules
        }

    def display_config(self, config):
        """
        Display configuration in a readable format

        Parameters:
        -----------
        config : dict
            Configuration to display
        """
        print("\n" + "=" * 80)
        print(f"CONFIGURATION: {config['name'].upper()}")
        print("=" * 80)
        print(f"Description: {config['description']}")
        print(f"Created: {config.get('created_date', 'N/A')}")
        print("\nRULE SETTINGS:")
        print("-" * 80)

        for rule_name, rule_settings in config['rules'].items():
            print(f"\n{rule_name.upper()} Rule:")
            print(f"  Status: {'ENABLED' if rule_settings.get('enabled', True) else 'DISABLED'}")

            if 'description' in rule_settings:
                print(f"  Description: {rule_settings['description']}")

            # Display settings (skip 'enabled' and 'description')
            for key, value in rule_settings.items():
                if key not in ['enabled', 'description']:
                    print(f"  {key}: {value}")

        print("\n" + "=" * 80)

    def compare_configs(self, config1, config2):
        """
        Compare two configurations side by side

        Parameters:
        -----------
        config1 : dict
            First configuration
        config2 : dict
            Second configuration
        """
        print("\n" + "=" * 80)
        print(f"CONFIGURATION COMPARISON: {config1['name'].upper()} vs {config2['name'].upper()}")
        print("=" * 80)

        for rule_name in config1['rules'].keys():
            print(f"\n{rule_name.upper()} Rule:")
            print(f"  {'Parameter':<30} {config1['name']:<20} {config2['name']:<20}")
            print(f"  {'-' * 30} {'-' * 20} {'-' * 20}")

            rule1 = config1['rules'][rule_name]
            rule2 = config2['rules'][rule_name]

            # Get all unique keys
            all_keys = set(rule1.keys()) | set(rule2.keys())
            all_keys.discard('description')  # Don't compare descriptions

            for key in sorted(all_keys):
                val1 = rule1.get(key, 'N/A')
                val2 = rule2.get(key, 'N/A')

                # Highlight differences
                marker = " ←" if val1 != val2 else ""
                print(f"  {key:<30} {str(val1):<20} {str(val2):<20}{marker}")

        print("\n" + "=" * 80)


def main():
    """Test the configuration manager"""
    print("=" * 80)
    print("PHASE 3: CONFIGURATION SYSTEM TEST")
    print("=" * 80)

    # Create configuration manager
    config_mgr = ConfigurationManager()

    # Create and save all preset configurations
    print("\nCreating preset configurations...")

    presets = {
        'default': config_mgr.get_default_config(),
        'strict': config_mgr.get_strict_config(),
        'moderate': config_mgr.get_moderate_config(),
        'lenient': config_mgr.get_lenient_config()
    }

    for name, config in presets.items():
        filepath = config_mgr.save_config(config)
        print(f"✓ Saved {name} configuration: {filepath}")

    # Display each configuration
    print("\n" + "=" * 80)
    print("PRESET CONFIGURATIONS")
    print("=" * 80)

    for name, config in presets.items():
        config_mgr.display_config(config)

    # Compare strict vs lenient
    print("\n\n" + "=" * 80)
    print("COMPARISON: Strict vs Lenient")
    print("=" * 80)
    config_mgr.compare_configs(presets['strict'], presets['lenient'])

    # List all saved configs
    print("\n" + "=" * 80)
    print("AVAILABLE CONFIGURATIONS")
    print("=" * 80)
    configs = config_mgr.list_configs()
    print(f"\nFound {len(configs)} configuration files:")
    for config_file in configs:
        print(f"  • {config_file}")

    # Test loading a config
    print("\n" + "=" * 80)
    print("TESTING: Load Configuration")
    print("=" * 80)
    loaded_config = config_mgr.load_config('moderate_config.json')
    print(f"\n✓ Successfully loaded: {loaded_config['name']}")
    print(f"  Description: {loaded_config['description']}")

    # Example: Create a custom configuration
    print("\n" + "=" * 80)
    print("EXAMPLE: Custom Configuration")
    print("=" * 80)

    custom_rules = {
        'frequency': {
            'enabled': True,
            'max_transactions': 7,
            'time_window_minutes': 90,
            'description': 'Custom frequency settings'
        },
        'amount': {
            'enabled': True,
            'single_transaction_limit': 1500,
            'daily_cumulative_limit': 4000,
            'description': 'Custom amount limits'
        },
        'travel': {
            'enabled': True,
            'max_speed_mph': 650,
            'description': 'Custom travel speed'
        },
        'time': {
            'enabled': False,  # Disabled in this custom config
            'unusual_hours_start': 2,
            'unusual_hours_end': 5,
            'description': 'Time rule disabled'
        }
    }

    custom_config = config_mgr.create_custom_config(
        name='custom_example',
        description='Example custom configuration with time rule disabled',
        rules=custom_rules
    )

    filepath = config_mgr.save_config(custom_config)
    print(f"\n✓ Created custom configuration: {filepath}")
    config_mgr.display_config(custom_config)

    print("\n" + "=" * 80)
    print("✓ PHASE 3 COMPLETE!")
    print("=" * 80)
    print("\nYou can now:")
    print("  • Use preset configurations (strict, moderate, lenient)")
    print("  • Create custom configurations")
    print("  • Save and load configurations")
    print("  • Compare different settings")


if __name__ == "__main__":
    main()