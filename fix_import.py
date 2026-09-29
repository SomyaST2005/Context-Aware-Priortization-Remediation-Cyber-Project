with open('backend/app/main.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find the line index
for i, line in enumerate(lines):
    if line.startswith('from backend.app.models.database.import'):
        # Replace this line with the correct import block
        del lines[i]
        # Insert the new lines
        lines.insert(i, 'from backend.app.models.database import (\\n')
        lines.insert(i+1, '    Base,\\n')
        lines.insert(i+2, '    Scenario,\\n')
        lines.insert(i+3, '    Asset,\\n')
        lines.insert(i+4, '    Finding,\\n')
        lines.insert(i+5, '    Edge,\\n')
        lines.insert(i+6, ')\\n')
        break

with open('backend/app/main.py', 'w', encoding='utf-8') as f:
    f.writelines(lines)