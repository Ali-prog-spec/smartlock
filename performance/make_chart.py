import csv, statistics as st
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# handshake
hs={}
for r in csv.DictReader(open('/home/kali/assignment2/work/handshake.csv')):
    hs.setdefault(r['version'],[]).append(float(r['seconds'])*1000)
hs_mean=[st.mean(hs['v1']), st.mean(hs['v2'])]
hs_sd=[st.pstdev(hs['v1']), st.pstdev(hs['v2'])]

# throughput
tp={}
for r in csv.DictReader(open('/home/kali/assignment2/work/perf.csv')):
    tp[r['metric']]=(float(r['mean']), float(r['sd']))

fig,(ax1,ax2)=plt.subplots(1,2,figsize=(11,4.2))
c1,c2='#4C78A8','#F58518'

# (a) handshake
ax1.bar(['v1','v2'],hs_mean,yerr=hs_sd,capsize=6,color=[c1,c2])
ax1.set_title('Handshake / full-session wall-clock\n(30 runs, mean ± sd)')
ax1.set_ylabel('milliseconds')
for i,(m,s) in enumerate(zip(hs_mean,hs_sd)):
    ax1.text(i,m+s+0.2,f'{m:.1f} ms',ha='center',fontsize=9)

# (b) throughput
labels=['seal','open']
v1=[tp['v1 seal'][0],tp['v1 open'][0]]; v1e=[tp['v1 seal'][1],tp['v1 open'][1]]
v2=[tp['v2 seal'][0],tp['v2 open'][0]]; v2e=[tp['v2 seal'][1],tp['v2 open'][1]]
import numpy as np
x=np.arange(2); w=0.35
ax2.bar(x-w/2,v1,w,yerr=v1e,capsize=5,label='v1 (raw key, static nonce)',color=c1)
ax2.bar(x+w/2,v2,w,yerr=v2e,capsize=5,label='v2 (HKDF, seq-bound AEAD)',color=c2)
ax2.set_xticks(x); ax2.set_xticklabels(labels)
ax2.set_ylabel('MB/s (1 KiB records)')
ax2.set_title('Record throughput\n(10000 records × 7 runs, mean ± sd)')
ax2.legend(fontsize=8)

fig.suptitle('SmartLock v1 vs v2 — cost of security (Intel i7-9750H, g++ -O2, OpenSSL 3.x)',fontsize=11)
fig.tight_layout(rect=[0,0,1,0.95])
out='/home/kali/assignment2/23i-0008-E/performance/perf_chart.png'
fig.savefig(out,dpi=130)
print('wrote',out)
