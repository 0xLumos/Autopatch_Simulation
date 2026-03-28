#!/usr/bin/env python3
"""AutoPatch 5-strategy experiment runner v3 (standalone)."""
import argparse, csv, json, logging, math, os, re, shutil
import subprocess, sys, tempfile, time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
 
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("exp_v3")
 
# ═══════════════════════════════════════════════════════════════════════
# Shell helpers
# ═══════════════════════════════════════════════════════════════════════
def run(cmd, timeout=600):
    log.debug(f"  $ {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired: return -1, "", "TIMEOUT"
    except FileNotFoundError: return -2, "", f"NOT_FOUND: {cmd[0]}"
 
def docker_build(tag, dockerfile, context=".", timeout=600):
    start = time.time()
    code, out, err = run(["docker","build","--pull","-t",tag,"-f",dockerfile,context], timeout=timeout)
    elapsed = time.time() - start
    if code == 0: return True, elapsed, ""
    combined = (out+err).lower()
    for kw, cat in [("timeout","TIMEOUT"),("network","NETWORK"),("connection","NETWORK"),
                     ("could not resolve","NETWORK"),("toomanyrequests","RATE_LIMITED"),("rate limit","RATE_LIMITED"),("429","RATE_LIMITED"),("returned a non-zero code","RUN_FAILURE"),
                     ("not found","IMAGE_NOT_FOUND"),("no such","IMAGE_NOT_FOUND"),
                     ("manifest unknown","IMAGE_NOT_FOUND"),("manifest not found","IMAGE_NOT_FOUND"),
                     ("permission denied","PERMISSION")]:
        if kw in combined: return False, elapsed, cat
    return False, elapsed, "BUILD_ERROR"
 
def image_size_mb(tag):
    c, o, _ = run(["docker","image","inspect",tag,"--format","{{.Size}}"])
    try: return int(o.strip())/(1024*1024) if c==0 else 0.0
    except: return 0.0
 
def rmi(tag): run(["docker","rmi","-f",tag], timeout=30)
 
def trivy_scan(image, out_file):
    code, _, err = run([
        "trivy","image","--format","json","--output",out_file,
        "--severity","CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN",
        "--scanners","vuln","--timeout","10m",image
    ], timeout=660)
    if code != 0:
        log.warning(f"  Trivy scan FAILED for {image}: {err[:150]}")
        return None
    try:
        with open(out_file) as f: return json.load(f)
    except:
        log.warning(f"  Trivy output not valid JSON for {image}")
        return None
 
def trivy_sbom(image, out_file):
    code, _, err = run([
        "trivy","image","--format","cyclonedx","--output",out_file,
        "--timeout","10m",image
    ], timeout=660)
    if code != 0: return None
    try:
        with open(out_file) as f: return json.load(f)
    except: return None
 
def extract_vulns(scan):
    counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0}
    cves = set()
    if not scan: return counts, []
    for r in scan.get("Results",[]):
        for v in r.get("Vulnerabilities",[]):
            s = v.get("Severity","UNKNOWN").upper()
            if s not in counts: s = "UNKNOWN"
            counts[s] += 1
            vid = v.get("VulnerabilityID","")
            if vid: cves.add(vid)
    return counts, sorted(cves)
 
# ═══════════════════════════════════════════════════════════════════════
# OS inference from SBOM
# ═══════════════════════════════════════════════════════════════════════
def detect_os_family(sbom):
    if not sbom: return "unknown"
    components = sbom.get("components",[])
    if not components:
        if not sbom.get("metadata",{}).get("component",{}): return "scratch"
    purls = set()
    names = []
    for c in components:
        if "purl" in c: purls.add(c["purl"])
        if "name" in c: names.append(c["name"].lower())
    meta_name = sbom.get("metadata",{}).get("component",{}).get("name","").lower()
    if "distroless" in meta_name:
        return "distroless"
    if any("ubuntu" in n for n in names) and any("pkg:deb/" in p for p in purls): return "ubuntu"
    if any("pkg:apk/" in p for p in purls) or any(n in names for n in ["apk-tools","musl","alpine-baselayout"]): return "alpine"
    if any("pkg:deb/" in p for p in purls):
        if len(components) < 15 and not any("apt" in n for n in names):
            return "distroless"
        return "debian"
    if any("pkg:rpm/" in p for p in purls):
        if any("rocky" in n for n in names) or "rocky" in meta_name: return "rocky"
        if any("alma" in n for n in names) or "alma" in meta_name: return "alma"
        if any("centos" in n for n in names) or "centos" in meta_name: return "centos"
        return "rhel"
    if len(components) < 5: return "distroless"
    return "unknown"
 
# ═══════════════════════════════════════════════════════════════════════
# Base image chooser — v3: preserve language version, change OS to alpine
# ═══════════════════════════════════════════════════════════════════════
def _extract_ver(tag, default=""):
    m = re.search(r':(\d+(?:\.\d+)*)', tag)
    return m.group(1) if m else default
 
def _extract_major(tag, default=""):
    m = re.search(r':(\d+)', tag)
    return m.group(1) if m else default
 
def choose_base(family, orig_base=""):
    """
    v3 strategy: keep SAME language version, switch OS to alpine.
    This isolates OS-level vulnerability reduction without introducing
    new language runtime CVEs from version upgrades.
    """
    o = orig_base.lower()
 
    # --- v4 FIX: databases FIRST (mongo contains "go:" substring) ---
    if "mongo" in o:    return "mongo:7"
    if "redis" in o:    return "redis:7-alpine"
    if "postgres" in o: return "postgres:17-alpine"
    if "mysql" in o:    return "mysql:8.4"
    if "mariadb" in o:  return "mariadb:11"
 
    # Language runtimes → SAME version, alpine OS
    if "python" in o:
        ver = _extract_ver(orig_base, "3.12")
        return f"python:{ver}-alpine"
 
    if "node" in o:
        ver = _extract_major(orig_base, "22")
        return f"node:{ver}-alpine"
 
    if "golang" in o or re.search(r'\bgo:', o):
        ver = _extract_ver(orig_base, "1.22")
        return f"golang:{ver}-alpine"
 
    if "ruby" in o:
        ver = _extract_ver(orig_base, "3.3")
        return f"ruby:{ver}-alpine"
 
    if "php" in o:
        ver = _extract_ver(orig_base, "8.3")
        if "apache" in o: return f"php:{ver}-apache"
        if "fpm" in o:    return f"php:{ver}-fpm-alpine"
        return f"php:{ver}-alpine"
 
    if "temurin" in o or "adoptopenjdk" in o:
        major = _extract_major(orig_base, "21")
        return f"eclipse-temurin:{major}-jre-alpine"
 
    if "openjdk" in o:
        major = _extract_major(orig_base, "17")
        return f"eclipse-temurin:{major}-jre-alpine"
 
    if "maven" in o:
        return "maven:3.9-eclipse-temurin-21-alpine"
 
    # Infrastructure → latest + alpine (safe to upgrade)
    if "nginx" in o:   return "nginx:stable-alpine"
    if "httpd" in o:   return "httpd:2.4-alpine"
    if "traefik" in o: return "traefik:v3.3"
    if "caddy" in o:   return "caddy:2-alpine"
    if "haproxy" in o: return "haproxy:3.1-alpine"
 
    # (databases moved above — v4)
 
    # Message queues
    if "rabbitmq" in o:       return "rabbitmq:4-alpine"
    if "elasticsearch" in o:  return "docker.elastic.co/elasticsearch/elasticsearch:8.17.0"
    if "kafka" in o:          return "bitnami/kafka:3.9"
 
    # CI/CD
    if "jenkins" in o:   return "jenkins/jenkins:lts-alpine"
    if "vault" in o:     return "hashicorp/vault:latest"
    if "consul" in o:    return "hashicorp/consul:latest"
    if "sonarqube" in o: return "sonarqube:lts-community"
    if "gitlab" in o:    return "gitlab/gitlab-runner:alpine"
 
    # CMS
    if "wordpress" in o:  return "wordpress:6-php8.3-apache"
    if "nextcloud" in o:  return "nextcloud:29-apache"
    if "drupal" in o:     return "drupal:11-php8.3-apache"
    if "ghost" in o:      return "ghost:5-alpine"
    if "joomla" in o:     return "joomla:5-php8.3-apache"
    if "docker" in o:     return "docker:27-cli"
 
    # Pure OS
    f = family.lower()
    MAP = {
        "alpine":"alpine:3.21", "debian":"debian:bookworm-slim",
        "ubuntu":"ubuntu:24.04", "centos":"rockylinux:9-minimal",
        "rhel":"rockylinux:9-minimal", "rocky":"rockylinux:9-minimal",
        "alma":"almalinux:9-minimal", "fedora":"fedora:41",
        "distroless":"gcr.io/distroless/static-debian12:nonroot",
        "scratch":"scratch",
    }
    return MAP.get(f, "alpine:3.21")
 
# ═══════════════════════════════════════════════════════════════════════
# Rewriters
# ═══════════════════════════════════════════════════════════════════════
def rewrite_from_latest(text):
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if s.upper().startswith("FROM "):
            parts = s.split(None,1)
            if len(parts)==2:
                rest = parts[1]
                m = re.match(r'^(.+?)\s+(AS\s+\S+)$', rest, re.I)
                base_part = m.group(1) if m else rest
                alias_part = m.group(2) if m else ""
                base_name = base_part.split("@")[0].split(":")[0] if ("@" in base_part or ":" in base_part) else base_part
                if base_name.lower() == "scratch":
                    lines.append(line)
                else:
                    new = f"FROM {base_name}:latest"
                    if alias_part: new += f" {alias_part}"
                    lines.append(new)
            else: lines.append(line)
        else: lines.append(line)
    return "\n".join(lines)+"\n"
 
def rewrite_autopatch(text, sbom_data):
    family = detect_os_family(sbom_data)
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if s.upper().startswith("FROM "):
            parts = s.split(None,1)
            if len(parts)==2:
                rest = parts[1]
                m = re.match(r'^(.+?)\s+(AS\s+\S+)$', rest, re.I)
                base_part = m.group(1) if m else rest
                alias_part = m.group(2) if m else ""
                if base_part.lower() == "scratch":
                    lines.append(line); continue
                if not (":" in base_part or "/" in base_part or "." in base_part):
                    lines.append(line); continue
                new_base = choose_base(family, base_part)
                if new_base.lower() == "scratch":
                    lines.append(line); continue
                new_from = f"FROM {new_base}"
                if alias_part: new_from += f" {alias_part}"
                lines.append(new_from)
            else: lines.append(line)
        else: lines.append(line)
    return "\n".join(lines)+"\n"
 
# ═══════════════════════════════════════════════════════════════════════
@dataclass
class R:
    image_name: str; strategy: str; dockerfile: str = ""
    build_success: bool = False; build_time_sec: float = 0.0; error_category: str = ""
    vulns_before_total: int = 0; vulns_after_total: int = 0
    sev_before: Dict[str,int] = field(default_factory=dict)
    sev_after: Dict[str,int] = field(default_factory=dict)
    reduction_pct: float = 0.0; new_vulns_introduced: int = 0
    size_before_mb: float = 0.0; size_after_mb: float = 0.0; size_delta_mb: float = 0.0
    acceptance: bool = False
    cves_before: List[str] = field(default_factory=list)
    cves_after: List[str] = field(default_factory=list)
    base_before: str = ""; base_after: str = ""
    os_family: str = ""
    notes: str = ""; ts: str = field(default_factory=lambda: datetime.now().isoformat())
 
class Experiment:
    def __init__(self, df_dir, out_dir, strategies, max_images=0, copa_bk=""):
        self.df_dir = Path(df_dir)
        self.out = Path(out_dir); self.out.mkdir(parents=True, exist_ok=True)
        for d in ["scans","sboms","patched"]: (self.out/d).mkdir(exist_ok=True)
        self.strategies = strategies
        self.max_images = max_images
        self.copa_bk = copa_bk
        self.results = []
        self.tmp = Path(tempfile.mkdtemp(prefix="apv3_"))
        # Crash recovery
        prev = self.out/"results.json"
        if prev.exists():
            try:
                with open(prev) as f: old = json.load(f)
                self.done = {(r["image_name"],r["strategy"]) for r in old.get("results",[])}
                log.info(f"Crash recovery: {len(self.done)} results from previous run")
                for r in old.get("results",[]):
                    safe_fields = {k:v for k,v in r.items() if k in R.__dataclass_fields__}
                    self.results.append(R(**safe_fields))
            except: self.done = set()
        else: self.done = set()
 
    def discover(self):
        dfs = sorted(self.df_dir.glob("Dockerfile.*"))
        dfs = [d for d in dfs if not d.name.endswith((".md",".patched",".bak"))]
        if self.max_images > 0: dfs = dfs[:self.max_images]
        log.info(f"Found {len(dfs)} Dockerfiles")
        return dfs
 
    def safe_tag(self, name, strat):
        return f"v3-{re.sub(r'[^a-z0-9._-]','-',name.lower())}-{strat}"
 
    def vr(self, before, after):
        if before == 0:
            if after == 0: return 0.0
            return -100.0
        return ((before - after) / before) * 100.0
 
    def process(self, df_path):
        name = df_path.name.replace("Dockerfile.","")
        log.info(f"\n{'='*60}\n  Processing: {name}\n{'='*60}")
        with open(df_path) as f: text = f.read()
 
        orig_base = ""
        for line in text.splitlines():
            if line.strip().upper().startswith("FROM "):
                parts = line.strip().split(None,1)
                if len(parts)==2: orig_base = parts[1].split()[0]
                break
 
        results = []
 
        # Build & scan original
        orig_tag = self.safe_tag(name,"orig")
        log.info(f"  Building original: {orig_tag}")
        ok, bt, berr = docker_build(orig_tag, str(df_path), str(df_path.parent))
        if not ok:
            log.warning(f"  ORIGINAL BUILD FAILED ({berr})")
            for s in self.strategies:
                sn = {"scan-only":"Scan-Only","naive":"Naive-Latest","copacetic":"Copacetic",
                      "scout":"Docker-Scout","autopatch":"AutoPatch"}.get(s,s)
                if (name,sn) not in self.done:
                    results.append(R(image_name=name,strategy=sn,error_category=berr,
                                     base_before=orig_base,notes=f"Original build failed: {berr}"))
            return results
 
        scan_file = str(self.out/"scans"/f"{name}_orig.json")
        log.info(f"  Scanning original...")
        scan_data = trivy_scan(orig_tag, scan_file)
        sev_b, cves_b = extract_vulns(scan_data)
        total_b = sum(sev_b.values())
        size_b = image_size_mb(orig_tag)
        log.info(f"  Baseline: {total_b} vulns (C={sev_b['CRITICAL']}, H={sev_b['HIGH']}, M={sev_b['MEDIUM']}, L={sev_b['LOW']})")
 
        sbom_file = str(self.out/"sboms"/f"{name}.json")
        sbom = trivy_sbom(orig_tag, sbom_file)
        os_fam = detect_os_family(sbom)
        log.info(f"  OS family: {os_fam}")
 
        # ── A: Scan-Only ─────────────────────────────────────────────
        sn = "Scan-Only"
        if "scan-only" in self.strategies and (name,sn) not in self.done:
            results.append(R(image_name=name,strategy=sn,build_success=True,
                             build_time_sec=bt,vulns_before_total=total_b,vulns_after_total=total_b,
                             sev_before=dict(sev_b),sev_after=dict(sev_b),
                             size_before_mb=size_b,size_after_mb=size_b,
                             cves_before=cves_b,cves_after=cves_b,base_before=orig_base,os_family=os_fam))
 
        # ── B: Naive :latest ─────────────────────────────────────────
        sn = "Naive-Latest"
        if "naive" in self.strategies and (name,sn) not in self.done:
            log.info(f"  [B] Naive :latest")
            r = R(image_name=name,strategy=sn,vulns_before_total=total_b,
                  sev_before=dict(sev_b),size_before_mb=size_b,cves_before=cves_b,base_before=orig_base,os_family=os_fam)
            patched = rewrite_from_latest(text)
            pf = self.tmp/f"Df.{name}.naive"; pf.write_text(patched)
            tag = self.safe_tag(name,"naive")
            ok2,t2,e2 = docker_build(tag,str(pf),str(df_path.parent))
            r.build_success=ok2; r.build_time_sec=t2; r.error_category=e2
            if ok2:
                sf = str(self.out/"scans"/f"{name}_naive.json")
                sd = trivy_scan(tag,sf)
                if sd is None:
                    r.build_success=False; r.error_category="RESCAN_FAILED"
                    r.sev_after=dict(sev_b); r.vulns_after_total=total_b; r.cves_after=cves_b
                else:
                    sa,ca = extract_vulns(sd)
                    r.sev_after=sa; r.vulns_after_total=sum(sa.values()); r.cves_after=ca
                    r.size_after_mb=image_size_mb(tag); r.size_delta_mb=r.size_after_mb-size_b
                    r.reduction_pct=self.vr(total_b,r.vulns_after_total)
                    r.new_vulns_introduced=len(set(ca)-set(cves_b))
                rmi(tag)
            log.info(f"    Naive: {total_b}→{r.vulns_after_total} ({r.reduction_pct:.1f}%)")
            results.append(r)
 
        # ── C: Copacetic ─────────────────────────────────────────────
        sn = "Copacetic"
        if "copacetic" in self.strategies and (name,sn) not in self.done:
            log.info(f"  [C] Copacetic")
            r = R(image_name=name,strategy=sn,vulns_before_total=total_b,
                  sev_before=dict(sev_b),size_before_mb=size_b,cves_before=cves_b,base_before=orig_base,os_family=os_fam)
            ptag = self.safe_tag(name,"copa")
            copa_cmd = ["copa","patch","-i",orig_tag,"-r",scan_file,"-t",ptag]
            if self.copa_bk:
                copa_cmd.extend(["-a",f"docker-container://{self.copa_bk}"])
            start=time.time()
            code,out2,err2 = run(copa_cmd, timeout=600)
            r.build_time_sec = time.time()-start
 
            if code != 0:
                r.build_success=False; r.error_category="COPA_FAILURE"
                r.vulns_after_total=total_b; r.sev_after=dict(sev_b); r.cves_after=cves_b
                r.notes=f"Copa error: {err2[:150]}"
                log.info(f"    Copa: FAILED ({err2[:80]})")
            else:
                sf = str(self.out/"scans"/f"{name}_copa.json")
                sd = trivy_scan(ptag, sf)
                if sd is None:
                    # CRITICAL FIX: Trivy re-scan failed → NOT fake 100%
                    r.build_success=False; r.error_category="COPA_RESCAN_FAILED"
                    r.vulns_after_total=total_b; r.sev_after=dict(sev_b); r.cves_after=cves_b
                    r.notes="Copa patched but Trivy re-scan failed — not counted as success"
                    log.info(f"    Copa: patched but RESCAN FAILED (keeping original counts)")
                else:
                    r.build_success=True
                    sa,ca = extract_vulns(sd)
                    r.sev_after=sa; r.vulns_after_total=sum(sa.values()); r.cves_after=ca
                    r.size_after_mb=image_size_mb(ptag); r.size_delta_mb=r.size_after_mb-size_b
                    r.reduction_pct=self.vr(total_b,r.vulns_after_total)
                    r.new_vulns_introduced=len(set(ca)-set(cves_b))
                    log.info(f"    Copa: {total_b}→{r.vulns_after_total} ({r.reduction_pct:.1f}%)")
                rmi(ptag)
            results.append(r)
 
        # ── D: Docker Scout ──────────────────────────────────────────
        sn = "Docker-Scout"
        if "scout" in self.strategies and (name,sn) not in self.done:
            log.info(f"  [D] Docker Scout")
            r = R(image_name=name,strategy=sn,vulns_before_total=total_b,
                  sev_before=dict(sev_b),size_before_mb=size_b,cves_before=cves_b,base_before=orig_base,os_family=os_fam)
 
            rec_tag = None
            code,out2,err2 = run(["docker","scout","recommendations",orig_tag,"--format","json"], timeout=120)
            if code == 0:
                try:
                    jd = json.loads(out2)
                    for key in ["recommendations","current","target"]:
                        if isinstance(jd, dict) and key in jd: jd = jd[key]
                    if isinstance(jd, dict) and "tag" in jd: rec_tag = jd["tag"]
                    elif isinstance(jd, list) and jd: rec_tag = jd[0].get("tag") or jd[0].get("name")
                except: pass
 
            if not rec_tag:
                code2,out2,err2 = run(["docker","scout","recommendations",orig_tag], timeout=120)
                if code2 == 0:
                    for line in out2.splitlines():
                        for pattern in [r'(\d+\.\d+[\w.-]*)\s*(?:→|->)\s*(\d+\.\d+[\w.-]*)',
                                        r'[Rr]ecommended.*?:\s*(\S+)',
                                        r'[Tt]ag.*?:\s*(\S+)']:
                            m = re.search(pattern, line)
                            if m: rec_tag = m.group(m.lastindex); break
                        if rec_tag: break
 
            if not rec_tag:
                r.build_success=False; r.error_category="SCOUT_NO_REC"
                r.vulns_after_total=total_b; r.sev_after=dict(sev_b); r.cves_after=cves_b
                r.notes="No recommendation"
                log.info(f"    Scout: no recommendation")
            else:
                log.info(f"    Scout recommends: {rec_tag}")
                new_lines = []
                for line in text.splitlines():
                    s2 = line.strip()
                    if s2.upper().startswith("FROM ") and "scratch" not in s2.lower():
                        parts = s2.split(None,1)
                        if len(parts)==2:
                            rest = parts[1]
                            m2 = re.match(r'^(.+?)\s+(AS\s+\S+)$', rest, re.I)
                            bp = m2.group(1) if m2 else rest
                            ap = m2.group(2) if m2 else ""
                            bn = bp.split("@")[0].split(":")[0] if ("@" in bp or ":" in bp) else bp
                            new = f"FROM {bn}:{rec_tag}"
                            if ap: new += f" {ap}"
                            new_lines.append(new)
                        else: new_lines.append(line)
                    else: new_lines.append(line)
                patched = "\n".join(new_lines)+"\n"
                pf = self.tmp/f"Df.{name}.scout"; pf.write_text(patched)
                tag = self.safe_tag(name,"scout")
                ok2,t2,e2 = docker_build(tag,str(pf),str(df_path.parent))
                r.build_success=ok2; r.build_time_sec=t2; r.error_category=e2
                if ok2:
                    sf = str(self.out/"scans"/f"{name}_scout.json")
                    sd = trivy_scan(tag,sf)
                    if sd is None:
                        r.build_success=False; r.error_category="SCOUT_RESCAN_FAILED"
                        r.vulns_after_total=total_b; r.sev_after=dict(sev_b); r.cves_after=cves_b
                    else:
                        sa,ca = extract_vulns(sd)
                        r.sev_after=sa; r.vulns_after_total=sum(sa.values()); r.cves_after=ca
                        r.size_after_mb=image_size_mb(tag); r.size_delta_mb=r.size_after_mb-size_b
                        r.reduction_pct=self.vr(total_b,r.vulns_after_total)
                        r.new_vulns_introduced=len(set(ca)-set(cves_b))
                    rmi(tag)
                log.info(f"    Scout: {total_b}→{r.vulns_after_total} ({r.reduction_pct:.1f}%)")
            results.append(r)
 
        # ── E: AutoPatch ─────────────────────────────────────────────
        sn = "AutoPatch"
        if "autopatch" in self.strategies and (name,sn) not in self.done:
            log.info(f"  [E] AutoPatch")
            new_base = choose_base(os_fam, orig_base)
            log.info(f"    Mapping: {orig_base} → {new_base}")
            r = R(image_name=name,strategy=sn,vulns_before_total=total_b,
                  sev_before=dict(sev_b),size_before_mb=size_b,cves_before=cves_b,
                  base_before=orig_base,base_after=new_base,os_family=os_fam,notes=f"os={os_fam}")
 
            patched = rewrite_autopatch(text, sbom)
            pf = self.tmp/f"Df.{name}.ap"; pf.write_text(patched)
            (self.out/"patched"/f"Dockerfile.{name}").write_text(patched)
 
            tag = self.safe_tag(name,"ap")
            ok2,t2,e2 = docker_build(tag,str(pf),str(df_path.parent))
            r.build_success=ok2; r.build_time_sec=t2; r.error_category=e2
            if ok2:
                sf = str(self.out/"scans"/f"{name}_ap.json")
                sd = trivy_scan(tag,sf)
                if sd is None:
                    r.build_success=False; r.error_category="AP_RESCAN_FAILED"
                    r.vulns_after_total=total_b; r.sev_after=dict(sev_b); r.cves_after=cves_b
                else:
                    sa,ca = extract_vulns(sd)
                    r.sev_after=sa; r.vulns_after_total=sum(sa.values()); r.cves_after=ca
                    r.size_after_mb=image_size_mb(tag); r.size_delta_mb=r.size_after_mb-size_b
                    r.reduction_pct=self.vr(total_b,r.vulns_after_total)
                    r.new_vulns_introduced=len(set(ca)-set(cves_b))
                    r.acceptance = (
                        r.vulns_after_total < total_b and
                        sa.get("CRITICAL",0) <= sev_b.get("CRITICAL",0) and
                        sa.get("HIGH",0) <= sev_b.get("HIGH",0)
                    )
                rmi(tag)
            log.info(f"    AutoPatch: {total_b}→{r.vulns_after_total} ({r.reduction_pct:.1f}%), accept={r.acceptance}")
            results.append(r)
 
        rmi(orig_tag)
        return results
 
    def save(self):
        def ver(cmd):
            c,o,_ = run(cmd.split(), timeout=10)
            return o.strip().split("\n")[0] if c==0 else "unknown"
        data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "script_version": "v3-standalone",
                "trivy_version": ver("trivy --version"),
                "docker_version": ver("docker --version"),
                "total_results": len(self.results),
                "strategies": self.strategies,
            },
            "results": [asdict(r) for r in self.results]
        }
        with open(self.out/"results.json","w") as f: json.dump(data,f,indent=2,default=str)
        if self.results:
            flds = ["image_name","strategy","build_success","build_time_sec","error_category",
                    "vulns_before_total","vulns_after_total","reduction_pct","new_vulns_introduced",
                    "crit_before","high_before","med_before","low_before",
                    "crit_after","high_after","med_after","low_after",
                    "size_before_mb","size_after_mb","acceptance","base_before","base_after","os_family","notes"]
            with open(self.out/"results.csv","w",newline="") as f:
                w = csv.DictWriter(f,fieldnames=flds); w.writeheader()
                for r in self.results:
                    w.writerow({
                        "image_name":r.image_name,"strategy":r.strategy,
                        "build_success":r.build_success,"build_time_sec":round(r.build_time_sec,2),
                        "error_category":r.error_category,
                        "vulns_before_total":r.vulns_before_total,"vulns_after_total":r.vulns_after_total,
                        "reduction_pct":round(r.reduction_pct,2),
                        "new_vulns_introduced":r.new_vulns_introduced,
                        "crit_before":r.sev_before.get("CRITICAL",0),
                        "high_before":r.sev_before.get("HIGH",0),
                        "med_before":r.sev_before.get("MEDIUM",0),
                        "low_before":r.sev_before.get("LOW",0),
                        "crit_after":r.sev_after.get("CRITICAL",0),
                        "high_after":r.sev_after.get("HIGH",0),
                        "med_after":r.sev_after.get("MEDIUM",0),
                        "low_after":r.sev_after.get("LOW",0),
                        "size_before_mb":round(r.size_before_mb,2),
                        "size_after_mb":round(r.size_after_mb,2),
                        "acceptance":r.acceptance,
                        "base_before":r.base_before,"base_after":r.base_after,
                        "os_family":r.os_family,"notes":r.notes,
                    })
 
    def run_all(self):
        dfs = self.discover()
        total = len(dfs)
        t0 = time.time()
        for i,df in enumerate(dfs,1):
            elapsed = time.time()-t0
            eta = (elapsed/(i-1))*(total-i+1)/60 if i>1 else 0
            log.info(f"\n[{i}/{total}] ETA: ~{int(eta)} min remaining")
            pf = os.environ.get("PROGRESS_FILE","")
            if pf:
                with open(pf,"a") as f: f.write(f"  [{i}/{total}] {df.name} [{datetime.now().strftime('%H:%M:%S')}]\n")
            try:
                res = self.process(df)
                self.results.extend(res)
                self.save()
                if i%5==0: run(["docker","system","prune","-f"],timeout=60)
            except Exception as e:
                log.error(f"FATAL: {df.name}: {e}", exc_info=True)
        total_min = (time.time()-t0)/60
        log.info(f"\nDONE: {len(self.results)} results in {total_min:.1f} minutes")
        self.save()
        shutil.rmtree(self.tmp, ignore_errors=True)
 
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dockerfile-dir", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--strategies", nargs="+", default=["scan-only","naive","copacetic","scout","autopatch"])
    p.add_argument("--max-images", type=int, default=0)
    p.add_argument("--copa-buildkit", default="")
    a = p.parse_args()
    Experiment(a.dockerfile_dir, a.output_dir, a.strategies, a.max_images, a.copa_buildkit).run_all()
 
if __name__ == "__main__": main()
