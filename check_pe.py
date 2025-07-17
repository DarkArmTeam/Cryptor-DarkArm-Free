import pefile

try:
    pe = pefile.PE('lumitest86.exe')
    print('Architecture:', 'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86')
    print('Sections:', len(pe.sections))
    print('Entry point:', pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    print('Image base:', hex(pe.OPTIONAL_HEADER.ImageBase))
    print('Size of image:', pe.OPTIONAL_HEADER.SizeOfImage)
except Exception as e:
    print('Error:', e) 