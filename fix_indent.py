with open('backend/app/main.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Indices of lines that need indentation (0-based)
indices = [227, 228, 242, 243, 257, 258]

for i in indices:
    line = lines[i]
    # If line already starts with four spaces, skip? But we know they don't.
    # However, to be safe, we can check if it starts with '    '
    if not line.startswith('    '):
        lines[i] = '    ' + line

with open('backend/app/main.py', 'w', encoding='utf-8') as f:
    f.writelines(lines)
print('Indented the six lines.')