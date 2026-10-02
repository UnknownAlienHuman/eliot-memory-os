import re, codecs, collections

R = 'C:\\Development\\Rust\\projects\\eliot-swarm\\MC-18\\'
d = open(R + 'crates\\eliot-app\\src\\disposition.rs', encoding='utf-8').read()

surfs = re.findall(r'path: "(.*?)",\s*live_reference: ("(?:[^"\\]|\\.)*")', d)
print('surfaces:', len(surfs))
ok = True
for path, lit in surfs:
    ref = codecs.decode(lit[1:-1], 'unicode_escape')
    body = open(R + path.replace('/', '\\'), encoding='utf-8', errors='replace').read()
    if ref not in body:
        ok = False
        print('MISSING:', path, repr(ref))
print('all surfaces live:', ok)

inv = re.findall(r'proof: "(.*?)"',
                 d.split('pub fn current_consumer_inventory')[1].split('pub fn consumer_disposition_guard')[0])
spaths = [p for p, _ in surfs]
print('inventory:', len(inv), 'unbaked:', [x for x in inv if x not in spaths])
c = collections.Counter(inv)
print('dup-entry paths:', [k for k, v in c.items() if v > 1])
print('surfaces w/o entry:', [p for p in spaths if p not in c])

mig = re.findall(r'consumer: "(.*?)",\s*proof: "(.*?)",\s*legacy_reference: ("(?:[^"\\]|\\.)*"),\s*current_owner_reference: ("(?:[^"\\]|\\.)*")', d)
print('migrated:', len(mig))
for consumer, path, leg, cur in mig:
    leg = codecs.decode(leg[1:-1], 'unicode_escape')
    cur = codecs.decode(cur[1:-1], 'unicode_escape')
    body = open(R + path.replace('/', '\\'), encoding='utf-8', errors='replace').read()
    print(consumer, '| legacy-gone:', leg not in body, '| owner-live:', cur in body)
