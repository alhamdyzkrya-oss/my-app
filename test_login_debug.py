#!/usr/bin/env python3
"""
Debug login functionality
"""

from database import db

def debug_login():
    # Check what users exist in database
    users = []
    try:
        with db.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT * FROM users')
                users = cursor.fetchall()
        
        print('Users in database:')
        for user in users:
            print(f'  ID: {user["id"]}, Username: {user["username"]}, Email: {user["email"]}')
        
        # Test the lookup method directly
        print('\nTesting user lookup:')
        user_by_username = db.get_user_by_username_or_email('admin')
        print(f'  By username "admin": {user_by_username is not None}')
        
        user_by_email = db.get_user_by_username_or_email('admin@example.com')
        print(f'  By email "admin@example.com": {user_by_email is not None}')
        
    except Exception as e:
        print(f'Error: {e}')

if __name__ == "__main__":
    debug_login()
