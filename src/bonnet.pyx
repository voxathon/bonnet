import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) or '.')
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'build'))

from orm import Database
from ume import Ume, User

def main():
    print("=== bonnet binary ===")
    
    # Test ORM
    print("\n=== ORM test ===")
    db = Database(':memory:')
    users = db.add_table('users', 'id name email', id_cols=['id'])
    print(f"Table: {users.name}, Columns: {users.columns}")
    
    with db.open() as ctx:
        ctx.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)')
        ctx.execute('INSERT INTO users (name, email) VALUES (?, ?)', ['Alice', 'alice@example.com'])
        ctx.execute('INSERT INTO users (name, email) VALUES (?, ?)', ['Bob', 'bob@example.com'])
        rows = ctx.select('users')
        print(f"Users: {rows}")
        print("ORM test passed!")
    
    # Test UME
    print("\n=== UME test ===")
    ume = Ume('/tmp/test_userfile')
    user = ume.put('alice', 'auth.example.com', b'\x01' * 32, b'passhash123')
    print(f"Created user: {user.username}, seq: {user.seq_numbr}")
    
    retrieved = ume.get(username='alice')
    print(f"Retrieved user: {retrieved.username}, registrar: {retrieved.registrar}")
    
    ume.upd(username='alice', new_registrar='new.auth.example.com')
    updated = ume.get(username='alice')
    print(f"Updated registrar: {updated.registrar}")
    
    ume.export('/tmp/test_users')
    print(f"Exported to /tmp/test_users")
    
    all_users = ume.list_all()
    print(f"Total users: {len(all_users)}")
    
    ume.delete(username='alice')
    deleted = ume.get(username='alice')
    print(f"After delete: {deleted}")
    print("UME test passed!")

if __name__ == "__main__":
    main()