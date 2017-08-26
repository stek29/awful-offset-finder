import json

with open('all.json') as f:
    all = json.loads(f.read())

def tohexarr(s):
    v = list()
    while s:
        v.append('\\x%s'%s[0:2])
        s = s[2:]
    return '"%s"'%''.join(v)

pads, pods, phones = [],[],[]

for build in all:
    for device in build:
        dev = device
        device = build[dev]
        if dev.startswith('iPad'):
            addto = pads
            dev = dev[4:]
        elif dev.startswith('iPod'):
            addto = pods
            dev = dev[4:]
        elif dev.startswith('iPhone'):
            addto = phones
            dev = dev[6:]
        else:
            continue
        addto.append('\n'.join((
                '  {',
                '    "%s", "%s",'%(dev, device["build"]),
                '    %s,'%tohexarr(device["kernelcache"]["iv"]),
                '    %s'%tohexarr(device["kernelcache"]["key"]),
                '  },\n'
        )))


with open('keys_gen.h', 'w') as f:
    f.write('struct devinfo info_Pad[] = {\n')
    for i in pads:
        f.write(i)
    f.write('  { NULL, NULL, NULL, NULL }\n')
    f.write('};\n\n')

    f.write('struct devinfo info_Pod[] = {\n')
    for i in pods:
        f.write(i)
    f.write('  { NULL, NULL, NULL, NULL }\n')
    f.write('};\n\n')

    f.write('struct devinfo info_Phone[] = {\n')
    for i in phones:
        f.write(i)
    f.write('  { NULL, NULL, NULL, NULL }\n')
    f.write('};\n\n')
 
