import re
import sys

src, dst = sys.argv[1], sys.argv[2]
lines = open(src).read().split('\n')


def indent(line):
    return len(line) - len(line.lstrip(' '))


# 1. Limit eve.json output to alert, flow and stats events
i = next(k for k, l in enumerate(lines) if re.match(r'^  - eve-log:\s*$', l))
t = next(k for k in range(i + 1, len(lines)) if re.match(r'^      types:\s*$', lines[k]))
e = t + 1
while e < len(lines):
    l = lines[e]
    if l.strip() and not l.lstrip().startswith('#') and indent(l) <= 6:
        break
    e += 1

new = [
    '      types:',
    '        - alert:',
    '            tagged-packets: no',
    '        - flow',
    '        - stats:',
    '            totals: yes',
    '            threads: no',
    '            deltas: no',
]
lines = lines[:t] + new + lines[e:]
print('eve-log found at line %d; types block lines %d-%d replaced (%d lines removed)' % (i + 1, t + 1, e, e - t))

# 2. EXTERNAL_NET = any (all hosts in the testbed, attackers included, use private addresses)
for k, l in enumerate(lines):
    if re.match(r'^\s+EXTERNAL_NET:', l):
        print('EXTERNAL_NET before: ' + l.strip())
        lines[k] = ' ' * indent(l) + 'EXTERNAL_NET: "any"'
        print('EXTERNAL_NET after : ' + lines[k].strip())
        break
else:
    sys.exit('EXTERNAL_NET line not found')
for l in lines:
    if re.match(r'^\s+HOME_NET:', l):
        print('HOME_NET           : ' + l.strip())
        break

open(dst, 'w').write('\n'.join(lines))
