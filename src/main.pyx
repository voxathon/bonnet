import sys
import os

_ = sys.path.insert(0, os.path.join(os.path.dirname(__file__) or '.', 'build'))

from module1 import process_data
from module2 import calculate
from module3 import Container

def main():
    print("=== bonnet binary ===")
    print(process_data("test input"))
    print(f"Calculation result: {calculate(5, 10)}")
    c = Container("example")
    print(f"Container object: {c}")

if __name__ == "__main__":
    main()