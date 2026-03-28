#!/usr/bin/env python3
import json, math, sys
from collections import defaultdict
from pathlib import Path
import numpy as np
try:
    from scipy.stats import wilcoxon
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
plt.rcParams.update({'font.family':'serif','font.size':10,'figure.dpi':300})
 
COLORS = {'Scan-Only':'#808080','Naive-Latest':'#E8922A','Copacetic':'#5B9BD5',
          'Docker-Scout':'#C05DCC','AutoPatch':'#2E7D32'}
ORDER = ['Scan-Only','Naive-Latest','Copacetic','Docker-Scout','AutoPatch']
 
def infer_os(name):
    n=name.lower()
    if 'alpine' in n: return 'Alpine'
    if any(k in n for k in ['debian','buster','bullseye','bookworm','stretch']): return 'Debian'
    if 'ubuntu' in n: return 'Ubuntu'
    if any(k in n for k in ['centos','rhel','rocky','alma','fedora']): return 'RHEL-family'
    if 'distroless' in n: return 'Distroless'
    if 'scratch' in n: return 'Scratch'
    return 'Other'
 
def cohens_d(g1,g2):
    n1,n2=len(g1),len(g2)
    if n1<2 or n2<2: return 0.0
    sp=math.sqrt(((n1-1)*np.std(g1,ddof=1)**2+(n2-1)*np.std(g2,ddof=1)**2)/(n1+n2-2))
    return (np.mean(g1)-np.mean(g2))/sp if sp>0 else 0.0
 
def main(rf,od,fd):
    with open(rf) as f: data=json.load(f)
    results=data["results"]
    out=Path(od); figs=Path(fd); figs.mkdir(parents=True,exist_ok=True)
 
    by_strat=defaultdict(list); by_img=defaultdict(dict)
    for r in results:
        by_strat[r["strategy"]].append(r)
        by_img[r["image_name"]][r["strategy"]]=r
 
    ss={}
    for strat in ORDER:
        es=by_strat.get(strat,[])
        ok=[e for e in es if e["build_success"]]; fl=[e for e in es if not e["build_success"]]
        vrs=[e["reduction_pct"] for e in ok if e["vulns_before_total"]>0]
        s={"strategy":strat,"total":len(es),"success":len(ok),"failures":len(fl),
           "fail_rate":round(len(fl)/max(len(es),1)*100,1)}
        if vrs:
            s["vr_mean"]=round(np.mean(vrs),2); s["vr_median"]=round(np.median(vrs),2)
            s["vr_std"]=round(np.std(vrs,ddof=1),2) if len(vrs)>1 else 0
            s["vr_min"]=round(min(vrs),2); s["vr_max"]=round(max(vrs),2)
        else: s["vr_mean"]=s["vr_median"]=s["vr_std"]=s["vr_min"]=s["vr_max"]=0
        s["new_vulns"]=sum(e.get("new_vulns_introduced",0) for e in ok)
        s["accepted"]=sum(1 for e in ok if e.get("acceptance"))
        s["zero_after"]=sum(1 for e in ok if e["vulns_after_total"]==0)
        ss[strat]=s
 
    comps={}
    for bl in ["Naive-Latest","Copacetic","Docker-Scout"]:
        pa,pb=[],[]
        for img,strats in by_img.items():
            if "AutoPatch" in strats and bl in strats:
                a,b=strats["AutoPatch"],strats[bl]
                if a["build_success"] and b["build_success"] and a["vulns_before_total"]>0:
                    pa.append(a["reduction_pct"]); pb.append(b["reduction_pct"])
        comp={"baseline":bl,"paired":len(pa)}
        if len(pa)>=5:
            comp["cohen_d"]=round(cohens_d(pa,pb),3)
            if HAS_SCIPY:
                diffs=[a-b for a,b in zip(pa,pb)]
                nz=[d for d in diffs if d!=0]
                if len(nz)>=5:
                    st,pv=wilcoxon(nz)
                    comp["wilcoxon"]=round(float(st),4)
                    comp["p_value"]=round(float(pv),6)
                    comp["sig_005"]=pv<0.05; comp["sig_001"]=pv<0.01
        comps[bl]=comp
 
    osd=defaultdict(lambda:{"n":0,"vrs":[],"fails":0})
    for r in by_strat.get("AutoPatch",[]):
        f2=infer_os(r["image_name"]); osd[f2]["n"]+=1
        if r["build_success"] and r["vulns_before_total"]>0: osd[f2]["vrs"].append(r["reduction_pct"])
        elif not r["build_success"]: osd[f2]["fails"]+=1
    os_stats={f:{"images":d["n"],"fails":d["fails"],
                 "vr_mean":round(np.mean(d["vrs"]),2) if d["vrs"] else 0,
                 "vr_std":round(np.std(d["vrs"],ddof=1),2) if len(d["vrs"])>1 else 0}
              for f,d in sorted(osd.items())}
 
    output={"metadata":data.get("metadata",{}),"strategy_statistics":ss,
            "pairwise_comparisons":comps,"os_family_breakdown":os_stats}
    with open(out/"statistics.json","w") as f: json.dump(output,f,indent=2)
 
    # ── FIGURES ──────────────────────────────────────────────────────
    ap_ok=sorted([r for r in by_strat.get("AutoPatch",[]) if r["build_success"] and r["vulns_before_total"]>20],
                 key=lambda x:x["vulns_before_total"], reverse=True)
    legacy=[r["image_name"] for r in ap_ok[:6]]
    if legacy:
        fig,ax=plt.subplots(figsize=(7.16,3.5))
        x=np.arange(len(legacy)); w=0.16
        for si,strat in enumerate(ORDER):
            vals=[]
            for img in legacy:
                r=by_img.get(img,{}).get(strat)
                if r and r["build_success"]:
                    vals.append(r["sev_after"].get("CRITICAL",0)+r["sev_after"].get("HIGH",0))
                elif r:
                    vals.append(r["sev_before"].get("CRITICAL",0)+r["sev_before"].get("HIGH",0))
                else: vals.append(0)
            ax.bar(x+(si-2)*w,vals,w,label=strat,color=COLORS.get(strat,'#888'),
                   edgecolor='black',linewidth=0.4)
        labels=[n.replace("-","\n",1) if len(n)>12 else n for n in legacy]
        ax.set_ylabel('Critical+High Vulns'); ax.set_xticks(x)
        ax.set_xticklabels(labels,fontsize=8)
        ax.legend(loc='upper right',ncol=2,fontsize=7); ax.grid(axis='y',alpha=0.25,ls='--')
        fig.tight_layout()
        fig.savefig(figs/'fig2_effectiveness.pdf',dpi=300,bbox_inches='tight')
        fig.savefig(figs/'fig2_effectiveness.png',dpi=300,bbox_inches='tight')
        plt.close()
 
    fig,ax=plt.subplots(figsize=(3.5,2.8))
    for strat in ['AutoPatch','Docker-Scout','Naive-Latest','Copacetic']:
        vrs=sorted([e["reduction_pct"] for e in by_strat.get(strat,[])
                    if e["build_success"] and e["vulns_before_total"]>0])
        if not vrs: continue
        ax.plot(vrs,np.arange(1,len(vrs)+1)/len(vrs),lw=1.8,label=strat,color=COLORS.get(strat))
    ax.axvline(x=0,lw=1.5,label='Scan-Only',color=COLORS['Scan-Only'],ls='--')
    ax.set_xlabel('Vulnerability Reduction (%)'); ax.set_ylabel('Cumulative Probability')
    ax.set_xlim(-10,105); ax.set_ylim(0,1.05)
    ax.legend(loc='lower right',fontsize=6.5); ax.grid(True,alpha=0.25,ls=':')
    fig.tight_layout()
    fig.savefig(figs/'fig3_cdf.pdf',dpi=300,bbox_inches='tight')
    fig.savefig(figs/'fig3_cdf.png',dpi=300,bbox_inches='tight')
    plt.close()
 
    ap_s=sorted([r for r in by_strat.get("AutoPatch",[]) if r["build_success"] and r["vulns_before_total"]>0],
                key=lambda x:x["vulns_before_total"],reverse=True)
    if ap_s:
        n=len(ap_s)
        sc={'CRITICAL':'#d32f2f','HIGH':'#f57c00','MEDIUM':'#fbc02d','LOW':'#4caf50','UNKNOWN':'#9e9e9e'}
        sevs=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN']
        fig,(a1,a2)=plt.subplots(2,1,figsize=(7.16,4),sharex=True)
        idx=np.arange(n)
        for ax,key,title in [(a1,"sev_before","Pre-Patch"),(a2,"sev_after","Post-Patch")]:
            bot=np.zeros(n)
            for sev in sevs:
                vals=np.array([r[key].get(sev,0) for r in ap_s])
                ax.bar(idx,vals,bottom=bot,color=sc[sev],width=1.0,
                       label=sev if ax is a1 else None,linewidth=0)
                bot+=vals
            ax.set_ylabel('Vulns'); ax.set_title(title,fontsize=10,fontweight='bold')
        a1.legend(loc='upper right',ncol=5,fontsize=7)
        a2.set_xlabel('Images (sorted by pre-patch total)')
        fig.tight_layout()
        fig.savefig(figs/'fig4_severity_panels.pdf',dpi=300,bbox_inches='tight')
        fig.savefig(figs/'fig4_severity_panels.png',dpi=300,bbox_inches='tight')
        plt.close()
 
    # ── PRINT ─────────────────────────────────────────────────────────
    print("\n"+"="*70)
    print("  EXPERIMENT v3 RESULTS — NUMBERS FOR THE PAPER")
    print("="*70)
    for strat in ORDER:
        s=ss.get(strat,{})
        print(f"\n  {strat}:")
        print(f"    Total:       {s.get('total',0)}")
        print(f"    Success:     {s.get('success',0)} ({100-s.get('fail_rate',0):.1f}%)")
        print(f"    Failures:    {s.get('failures',0)} ({s.get('fail_rate',0):.1f}%)")
        print(f"    VR mean:     {s.get('vr_mean',0):.1f}%")
        print(f"    VR median:   {s.get('vr_median',0):.1f}%")
        print(f"    VR std:      {s.get('vr_std',0):.1f}%")
        print(f"    VR range:    [{s.get('vr_min',0):.1f}%, {s.get('vr_max',0):.1f}%]")
        print(f"    New vulns:   {s.get('new_vulns',0)}")
        print(f"    Accepted:    {s.get('accepted',0)}")
        print(f"    Zero-after:  {s.get('zero_after',0)}")
 
    print(f"\n  Pairwise: AutoPatch vs baselines:")
    for bl,c in comps.items():
        print(f"\n    vs {bl} ({c.get('paired',0)} paired):")
        if 'cohen_d' in c: print(f"      Cohen's d:  {c['cohen_d']}")
        if 'p_value' in c:
            print(f"      Wilcoxon p: {c['p_value']}")
            print(f"      Sig @0.05:  {c.get('sig_005')}")
            print(f"      Sig @0.01:  {c.get('sig_001')}")
 
    print(f"\n  OS Family Breakdown (AutoPatch):")
    for f2,s in sorted(os_stats.items()):
        print(f"    {f2:14s}: {s['images']:3d} imgs, VR={s['vr_mean']:5.1f}% ± {s['vr_std']:5.1f}%, fails={s['fails']}")
 
    print("\n"+"="*70)
    print(f"  Results:    {out/'results.json'}")
    print(f"  CSV:        {out/'results.csv'}")
    print(f"  Stats:      {out/'statistics.json'}")
    print(f"  Figures:    {figs}/")
    print("="*70)
 
if __name__=="__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv)>3 else str(Path(sys.argv[1]).parent.parent/"figures_v3"))
