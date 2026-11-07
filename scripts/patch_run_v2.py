p = 'scripts/06_run.sh'
s = open(p).read()

# 1. container command: run suricata in the background and record the peak resident memory (VmHWM)
old = """        'suricata "$@"; rc=$?; chown -R "$OWN" "$OUTDIR"; exit $rc' sh"""
new = """        'suricata "$@" & pid=$!; peak=0
         while kill -0 "$pid" 2>/dev/null; do
           if [ -r "/proc/$pid/status" ]; then
             while read -r k v r; do if [ "$k" = "VmHWM:" ]; then peak=$v; break; fi; done < "/proc/$pid/status"
           fi
           sleep 0.5
         done
         wait "$pid"; rc=$?
         echo "$peak" > "$OUTDIR/peak_mem_kb.txt"
         chown -R "$OWN" "$OUTDIR"; exit $rc' sh"""
assert s.count(old) == 1, 'container command not found'
s = s.replace(old, new)

# 2. summary header: new files get the column; an existing file gets it added once
old = """[ -f "$SUMMARY" ] || echo "capture,level,policy,rep,exit,wall_s,packets,sessions,ssn_memcap_drop,seg_memcap_drop,reassembly_gap,alerts" > "$SUMMARY\""""
new = """[ -f "$SUMMARY" ] || echo "capture,level,policy,rep,exit,wall_s,packets,sessions,ssn_memcap_drop,seg_memcap_drop,reassembly_gap,alerts,peak_mem_kb" > "$SUMMARY"
if ! head -n 1 "$SUMMARY" | grep -q peak_mem_kb; then
  awk 'NR==1{print $0",peak_mem_kb"; next} {print $0","}' "$SUMMARY" > "$SUMMARY.tmp" && mv "$SUMMARY.tmp" "$SUMMARY"
fi"""
assert s.count(old) == 1, 'header not found'
s = s.replace(old, new)

# 3. read the peak value and append it to the summary row and the progress line
old = """      alerts="$(grep -c '"event_type":"alert"' "$dir/eve.json" || true)\""""
new = """      alerts="$(grep -c '"event_type":"alert"' "$dir/eve.json" || true)"
      peak="$(cat "$dir/peak_mem_kb.txt" 2>/dev/null || true)\""""
assert s.count(old) == 1, 'alerts line not found'
s = s.replace(old, new)

old = """$(cnt tcp.reassembly_gap),$alerts" >> "$SUMMARY\""""
new = """$(cnt tcp.reassembly_gap),$alerts,$peak" >> "$SUMMARY\""""
assert s.count(old) == 1, 'summary row not found'
s = s.replace(old, new)

old = """sessions=%s ssn_drop=%s alerts=%s\\n' "$cap" "$name" "$wall" "$(cnt tcp.sessions)" "$(cnt tcp.ssn_memcap_drop)" "$alerts\""""
new = """sessions=%s ssn_drop=%s alerts=%s peak=%sMB\\n' "$cap" "$name" "$wall" "$(cnt tcp.sessions)" "$(cnt tcp.ssn_memcap_drop)" "$alerts" "$((${peak:-0} / 1024))\""""
assert s.count(old) == 1, 'progress line not found'
s = s.replace(old, new)

open(p, 'w').write(s)
print('patched 06_run.sh (v2: peak memory)')
