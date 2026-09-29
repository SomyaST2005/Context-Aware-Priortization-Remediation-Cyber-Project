with open('backend/app/main.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Function to fix a line at given index
def fix_line(idx):
    line = lines[idx]
    # Expected pattern: something like "assets = db.query(Asset).filter(Asset.scenario_id == scenario_id).all()    return assets"
    # We'll split at "    return" (four spaces then return)
    # But the line may have missing indentation.
    # We'll strip leading spaces to get the content.
    stripped = line.lstrip()
    # Find the position of "    return" in stripped
    ret_pos = stripped.find('    return')
    if ret_pos == -1:
        # Maybe there is no spaces? Just return
        ret_pos = stripped.find('return')
        if ret_pos == -1:
            return
    # Split into two parts
    first_part = stripped[:ret_pos].rstrip()
    second_part = stripped[ret_pos:].lstrip()  # includes 'return ...'
    # Indentation: for function body, use 4 spaces
    indent = '    '
    # Build new lines
    new_line1 = indent + first_part + '\n'
    new_line2 = indent + second_part + '\n'
    # Replace the line at idx with new_line1, and insert new_line2 at idx+1
    lines[idx] = new_line1
    lines.insert(idx+1, new_line2)

# Fix assets line (around line 227)
# We'll find the line that contains "assets = db.query(Asset)"
for i, line in enumerate(lines):
    if line.strip().startswith('assets = db.query(Asset)'):
        fix_line(i)
        break

# Fix findings line
for i, line in enumerate(lines):
    if line.strip().startswith('findings = db.query(Finding)'):
        fix_line(i)
        break

# Fix edges line
for i, line in enumerate(lines):
    if line.strip().startswith('edges = db.query(Edge)'):
        fix_line(i)
        break

with open('backend/app/main.py', 'w', encoding='utf-8') as f:
    f.writelines(lines)
print('Fixed return statements.')