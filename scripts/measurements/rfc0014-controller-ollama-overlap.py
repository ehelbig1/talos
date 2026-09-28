#!/usr/bin/env python3
"""RFC 0014 P3a — how the controller's own Ollama calls meet the backend.

Joins two sources, both read-only:

1. The host Ollama's request log (``~/.ollama/logs/server*.log``, local time):
   one ``[GIN]`` line per ``/api/chat`` request with its end time, status and
   duration, so each request's interval is known.
2. The controller's own calls, from ``llm_usage`` (controller calls carry no
   ``execution_id``). Extract first, from the repository root::

     docker exec talos-postgres psql -U talos talos -At -F'|' -c \\
       "select to_char(recorded_at at time zone 'America/New_York', \\
        'YYYY/MM/DD HH24:MI:SS.MS'), model, (execution_id is null) \\
        from llm_usage where recorded_at > now() - interval '30 days' \\
        and provider='ollama' order by recorded_at" > "$TMPDIR/usage.txt"

   The time zone must be the one the Ollama host logs in.

A usage row is matched to the successful Ollama request ending within 2 s
before / 1 s after it. Reports the controller calls' duration distribution,
worker requests that arrived while a controller call held the backend, and
controller calls that overlapped each other (what P3a's per-process gate
removes; controller-vs-worker overlap needs P3b).
"""
import re,glob,os,datetime as dt,bisect,collections
rx=re.compile(r'\[GIN\] (\S+) - (\S+) \| (\d+) \|\s+(\S+) \|.*POST\s+"/api/chat"')
def secs(t):
    m=re.fullmatch(r'(?:(\d+)m)?([\d.]+)(µs|ms|s)',t)
    if not m: return None
    return int(m.group(1) or 0)*60+float(m.group(2))*{'µs':1e-6,'ms':1e-3,'s':1}[m.group(3)]
reqs=[]
for f in glob.glob(os.path.expanduser('~/.ollama/logs/server*.log')):
    for line in open(f,errors='replace'):
        m=rx.search(line)
        if m:
            d=secs(m.group(4))
            if d is None: continue
            end=dt.datetime.strptime(m.group(1)+' '+m.group(2),'%Y/%m/%d %H:%M:%S')
            reqs.append([end-dt.timedelta(seconds=d), end, int(m.group(3)), d, 'w'])
reqs.sort(key=lambda r:r[1])
start=dt.datetime(2026,8,29,16,0)
reqs=[r for r in reqs if r[1]>=start]
ends=[r[1] for r in reqs]
ctl=[]
for line in open(os.environ['TMPDIR']+'/usage.txt'):
    ts,model,noexec=line.strip().split('|')
    if noexec!='t': continue
    t=dt.datetime.strptime(ts,'%Y/%m/%d %H:%M:%S.%f')
    i=bisect.bisect_left(ends,t-dt.timedelta(seconds=2))
    best=None
    while i<len(reqs) and reqs[i][1]<=t+dt.timedelta(seconds=1):
        if reqs[i][4]=='w' and reqs[i][2]==200: best=i
        i+=1
    if best is not None: reqs[best][4]='c'; ctl.append(best)
print('ollama requests',len(reqs),'controller-matched',len(ctl),'of',sum(1 for l in open(os.environ['TMPDIR']+'/usage.txt') if l.strip().endswith('|t')))
cd=sorted(reqs[i][3] for i in ctl)
q=lambda a,p:a[int(p*(len(a)-1))]
print('controller call secs p50 %.1f p90 %.1f p99 %.1f max %.1f total_h %.2f'%(q(cd,.5),q(cd,.9),q(cd,.99),cd[-1],sum(cd)/3600))
# worker requests starting while a controller request in flight
cint=sorted((reqs[i][0],reqs[i][1]) for i in ctl)
blocked=0;blocked_s=0.0;cut=0
for r in reqs:
    if r[4]!='w': continue
    for s,e in cint:
        if s < r[0] < e:
            blocked+=1; blocked_s+=(e-r[0]).total_seconds()
            if r[2]!=200: cut+=1
            break
print('worker requests arriving during a controller call',blocked,'sum overlap s %.0f'%blocked_s,'of which failed',cut)
# also: worker requests cut at 60 s that overlapped a controller call
w60=[r for r in reqs if r[4]=='w' and r[2]==500 and 59.5<=r[3]<=60.01]
ov=sum(1 for r in w60 if any(s<r[1] and e>r[0] for s,e in cint))
print('60s cuts',len(w60),'overlapping a controller call',ov)
# controller calls cut at 60s: 500s at 60 not matched (controller failures not in llm_usage) -> unknown
by=collections.Counter(reqs[i][1].strftime('%H') for i in ctl)
print('controller calls by hour',sorted(by.items()))
cc=sorted(cint)
self_ov=sum(1 for i in range(1,len(cc)) if cc[i][0] < max(e for s,e in cc[:i]))
print('controller calls starting while another controller call in flight',self_ov)
