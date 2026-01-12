#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tool script to generate password hash value and manage users

Usage:
    python generate_password_hash.py

Or specify password directly:
    python generate_password_hash.py --password "your_password"

Or interactive input:
    python generate_password_hash.py --interactive
"""

import sys
import getpass
import argparse
import json
import os

try:
    import bcrypt
except ImportError:
    print("Error: bcrypt library not installed")
    print("Please run: pip install bcrypt")
    sys.exit(1)


def generate_password_hash(password: str) -> str:
    """Generate bcrypt hash value for password

    Args:
        password: Plain text password

    Returns:
        str: bcrypt hash value
    """
    # Use bcrypt to generate hash, rounds=12 is the recommended default value (balances security and performance)
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)
    password_hash = bcrypt.hashpw(password_bytes, salt)
    return password_hash.decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """Verify if password matches hash value

    Args:
        password: Plain text password
        password_hash: Stored password hash value (bcrypt format)

    Returns:
        bool: Returns True if password matches, otherwise False
    """
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception as e:
        print(f'Error: Password verification failed: {e!r}')
        return False


def load_users(key_file_path: str) -> dict:
    """Load users from key file

    Args:
        key_file_path: Path to key file

    Returns:
        dict: Dictionary mapping username to password hash
    """
    if not os.path.exists(key_file_path):
        return {}

    try:
        with open(key_file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return {}

            # Try to parse as JSON (new format)
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                # Old format: single hash value, migrate to admin user
                print('Detected old format password file, migrating to admin user...')
                users = {'admin': content}
                save_users(key_file_path, users)
                print('Migration completed: existing password is now assigned to user "admin"')
                return users
    except Exception as e:
        print(f'Error: Failed to read user file: {e!r}')
        return {}


def save_users(key_file_path: str, users: dict):
    """Save users to key file

    Args:
        key_file_path: Path to key file
        users: Dictionary mapping username to password hash
    """
    try:
        with open(key_file_path, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f'Error: Failed to write user file: {e!r}')
        raise


def main():
    parser = argparse.ArgumentParser(
        description='Manage users and generate password hash values for docker-monitor restart functionality',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive user management
  python generate_password_hash.py

  # Create or update user with password
  python generate_password_hash.py --username admin --password "your_password"

  # Interactive password input
  python generate_password_hash.py --username admin --interactive
        """
    )
    parser.add_argument(
        '--username', '-u',
        type=str,
        help='Username (required for creating or updating user)'
    )
    parser.add_argument(
        '--password', '-p',
        type=str,
        help='Plain text password (not recommended, password will appear in command history)'
    )
    parser.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='Interactive password input (recommended, password will not be displayed on screen)'
    )
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Output file path (default: key.json in script directory)'
    )

    args = parser.parse_args()

    # Determine output file
    if args.output:
        output_file = args.output
    else:
        output_file = os.path.join(os.path.dirname(__file__), 'key.json')

    # Load existing users
    users = load_users(output_file)

    # Get username
    username = args.username
    if not username:
        username = input('Enter username: ').strip()
        if not username:
            print('Error: Username cannot be empty')
            sys.exit(1)

    # Check if user exists
    user_exists = username in users

    if user_exists:
        print(f'User "{username}" already exists.')
        print('To update password, you need to verify the current password first.')
        current_password = getpass.getpass('Enter current password: ')

        if not verify_password(current_password, users[username]):
            print('Error: Current password verification failed')
            sys.exit(1)

        print('Current password verified. Please enter new password.')
    else:
        print(f'User "{username}" does not exist. Creating new user...')

    # Get new password
    password = None

    if args.password:
        password = args.password
    elif args.interactive:
        password = getpass.getpass('Enter password: ')
        password_confirm = getpass.getpass('Enter password again to confirm: ')
        if password != password_confirm:
            print('Error: Passwords do not match')
            sys.exit(1)
    else:
        # Default to interactive
        password = getpass.getpass('Enter password: ')
        password_confirm = getpass.getpass('Enter password again to confirm: ')
        if password != password_confirm:
            print('Error: Passwords do not match')
            sys.exit(1)

    if not password:
        print('Error: No password provided')
        sys.exit(1)

    # Generate hash
    print('Generating password hash value...')
    password_hash = generate_password_hash(password)

    # Update users dictionary
    users[username] = password_hash

    # Save users
    try:
        save_users(output_file, users)
        action = 'updated' if user_exists else 'created'
        print(f'\n✓ User "{username}" {action} successfully!')
        print(f'✓ Password hash saved to: {output_file}')
        print('\nNote: Please keep this file secure and do not commit it to version control!')
    except Exception as e:
        print(f'\nError: Unable to write to file {output_file}: {e}')
        sys.exit(1)


if __name__ == '__main__':
    main()
