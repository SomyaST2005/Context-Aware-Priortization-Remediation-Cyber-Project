with open('backend/app/main.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find indices of the three problematic lines
indices = []
for i, line in enumerate(lines):
    stripped = line.strip()
    if stripped.startswith('assets = db.query(Asset)') or \
       stripped.startswith('findings = db.query(Finding)') or \
       stripped.startswith('edges = db.query(Edge)'):
        indices.append(i)

# Process in reverse order to avoid index shifting
for i in reversed(indices):
    line = lines[i]
    # Remove leading/trailing spaces to get the core
    stripped = line.strip()
    # Split at 'return' (assuming there is a return)
    # Find the position of 'return'
    ret_pos = stripped.find('return')
    if ret_pos == -1:
        continue
    first = stripped[:ret_pos].rstrip()  # e.g., "assets = db.query(Asset).filter(Asset.scenario_id == scenario_id).all()"
    second = stripped[ret_pos:]          # e.g., "return assets"
    # Indentation: we want 4 spaces
    indent = '    '
    new_line1 = indent + first + '\n'
    new_line2 = indent + second + '\n'
    # Replace the line at i with new_line1
    lines[i] = new_line1
    # Insert new_line2 at i+1
    lines.insert(i+1, new_line2)

with open('backend/app/main.py', 'w', encoding='utf-8') as f:
    f.writelines(lines)
print('Fixed return statements with proper indentation.')