import re
p = 'scripts/07_analyze.py'
s = open(p).read()
old1 = """                ev = json.loads(line)
                ep_flows += 1
                ep_detail[json.dumps(ev.get('exception_policy'), sort_keys=True)] += 1
"""
new1 = """                ev = json.loads(line)
                eps = ev.get('flow', {}).get('exception_policy') or []
                if eps:
                    ep_flows += 1
                for ep in eps:
                    ep_detail['%s:%s' % (ep.get('target'), ep.get('policy'))] += 1
"""
assert s.count(old1) == 1, 'block 1 not found'
s = s.replace(old1, new1)
old2 = "ep_detail.most_common(3)"
assert s.count(old2) == 1, 'block 2 not found'
s = s.replace(old2, "ep_detail.most_common(6)")
open(p, 'w').write(s)
print('patched 07_analyze.py (v6)')
