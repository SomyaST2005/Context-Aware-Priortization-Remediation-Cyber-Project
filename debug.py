with open('backend/app/main.py', 'rb') as f:
    data = f.read()
# Find the position of the import line
idx = data.find(b'from backend.app.models.database.import')
print('Index:', idx)
print('Surrounding bytes:')
for i in range(idx-10, idx+100):
    b = data[i:i+1]
    # Printable representation
    if b < b' ':
        reprb = repr(b)[2:-1]  # remove b''
    else:
        reprb = chr(b[0])
    print(f'{i:04d}: {b[0]:03d} {reprb}')