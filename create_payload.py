with open('test64_crypted.exe', 'rb') as f:
    data = f.read()
    size = len(data)
    
with open('payload_data.h', 'w') as out:
    out.write('unsigned char PAYLOAD_iTXRctv6[] = {')
    out.write(','.join(str(b) for b in data))
    out.write('};\n')
    out.write(f'unsigned int PAYLOAD_iTXRctv6_SIZE = {size};\n') 