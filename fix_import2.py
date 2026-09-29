with open('backend/app/main.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find the start of the problematic import line
marker = 'from backend.app.models.database.import'
start = content.find(marker)
if start == -1:
    print('Marker not found')
    exit(1)
# Find the end of the line (next newline after start)
end = content.find('\n', start)
if end == -1:
    end = len(content)
# Extract the line to replace
old_line = content[start:end]
print('Old line:', repr(old_line))

# We'll replace it with the correct import block.
# Build the block with actual newline characters using \n in the string.
new_block = 'from backend.app.models.database.import (\\n    Base,\\n    Scenario,\\n    Asset,\\n    Finding,\\n    Edge,\\n)\\n'
# However, this still has literal backslash-n. We need to double-check.
# Let's instead write the block by concatenating strings with explicit newline characters.
# We'll do:
new_block = 'from backend.app.models.database.import (\\n'
new_block += '    Base,\\n'
new_block += '    Scenario,\\n'
new_block += '    Asset,\\n'
new_block += '    Finding,\\n'
new_block += '    Edge,\\n'
new_block += ')\\n'
# Still same.
# Actually, we need to realize that in the string literal, to get a newline character we need to write \n.
# But when we write that in the source code, we need to escape the backslash? No.
# Let's test by writing a small string and printing its repr.
# We'll do a quick test in the same script.
test = 'a\\nb'
print('test repr:', repr(test))
# If test contains a newline, repr will show 'a\\nb' (backslash-n) or 'a\\nb'? Actually, if test contains a newline, repr will show 'a\\nb' (where \\n is two chars: backslash and n) because the newline is represented as \\n in repr.
# Let's just compute: we want new_block to contain actual newline characters.
# We'll write new_block using actual newline characters by typing them in the source? That would break the line.
# Instead, we'll use a list of lines and join with newline.
lines = [
    'from backend.app.models.database.import (',
    '    Base,',
    '    Scenario,',
    '    Asset,',
    '    Finding,',
    '    Edge,',
    ')'
]
new_block = '\\n'.join(lines) + '\\n'
print('new_block repr:', repr(new_block))

# Replace the old line with new_block
new_content = content[:start] + new_block + content[end:]
with open('backend/app/main.py', 'w', encoding='utf-8') as f:
    f.write(new_content)
print('Replacement done.')
EOF