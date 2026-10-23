import re
import sys

src, dst = sys.argv[1], sys.argv[2]
lines = open(src).read().split('\n')


def indent(line):
    return len(line) - len(line.lstrip(' '))


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
out = lines[:t] + new + lines[e:]
open(dst, 'w').write('\n'.join(out))
print('eve-log found at line %d; types block lines %d-%d replaced (%d lines removed)' % (i + 1, t + 1, e, e - t))
print('Resulting eve-log types:')
for l in new:
    print(l)
