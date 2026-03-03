import sys
import os

_ = sys.path.insert(0, os.path.join(os.path.dirname(__file__) or '.', 'build'))

from module1 import process_data
from module2 import calculate
from module3 import Container
from orm import Database

def main():
    print("=== bonnet binary ===")
    print(process_data("test input"))
    print(f"Calculation result: {calculate(5, 10)}")
    c = Container("example")
    print(f"Container object: {c}")
    
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

if __name__ == "__main__":
    main()