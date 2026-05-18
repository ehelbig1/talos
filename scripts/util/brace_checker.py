import sys

def check_braces(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
        
    stack = []
    
    for i, line in enumerate(lines):
        for j, char in enumerate(line):
            if char in "{[(":
                stack.append((char, i+1, j+1))
            elif char in "}])":
                if not stack:
                    print(f"Unmatched closing '{char}' at line {i+1}, col {j+1}")
                    continue
                
                top_char, top_line, top_col = stack.pop()
                if (top_char == '{' and char != '}') or \
                   (top_char == '[' and char != ']') or \
                   (top_char == '(' and char != ')'):
                    print(f"Mismatched closing '{char}' at line {i+1}, col {j+1} - matches '{top_char}' from line {top_line}")

    if stack:
        print("Unclosed delimiters:")
        for char, line, col in stack:
            print(f"  '{char}' from line {line}, col {col}")

check_braces('controller/src/main.rs')
