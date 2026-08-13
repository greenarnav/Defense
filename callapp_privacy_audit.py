#!/usr/bin/env python3
"""Focused static audit for CallApp/PICO privacy-API reproduction.

Accepts APK, XAPK, APKM, APKS, or ZIP bundles. It extracts the base APK,
indexes DEX strings, optionally decompiles with JADX, and records evidence for
the privacy-API interactions discussed in section 3.2 of the PICO paper.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import time
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

TOOL_VERSION = "1.2.0"
TEXT_EXTENSIONS = {".java", ".kt", ".xml", ".smali", ".txt", ".json", ".properties"}
MAX_TEXT_BYTES = 16 * 1024 * 1024

CHECKS = [
    {"id":"applovin_consent","sdk":"AppLovin MAX","law":"GDPR","markers":[r"AppLovinPrivacySettings",r"setHasUserConsent"],"description":"Host/wrapper consent configuration through AppLovin."},
    {"id":"meta_ccpa","sdk":"Meta Audience Network","law":"CCPA/US state privacy","markers":[r"setDataProcessingOptions",r"AdSettings"],"description":"Meta data-processing option configuration, including Limited Data Use."},
    {"id":"ogury_child_privacy","sdk":"Ogury/Presage","law":"COPPA","markers":[r"applyChildPrivacy",r"childPrivacy"],"description":"Ogury child-directed privacy configuration."},
    {"id":"inmobi_age_restricted","sdk":"InMobi","law":"COPPA","markers":[r"setIsAgeRestricted",r"isAgeRestricted"],"description":"InMobi age-restricted-user configuration."},
    {"id":"vungle_privacy","sdk":"Vungle/Liftoff","law":"GDPR/CCPA/COPPA","markers":[r"setCOPPAStatus",r"setGDPRStatus",r"setCCPAStatus",r"VunglePrivacySettings"],"description":"Vungle/Liftoff privacy status APIs."},
    {"id":"ironsource_privacy","sdk":"ironSource/Unity LevelPlay","law":"GDPR/CCPA/COPPA","markers":[r"is_child_directed",r"do_not_sell",r"setConsent",r"setMetaData"],"description":"ironSource/LevelPlay consent and metadata configuration."},
    {"id":"unity_privacy","sdk":"Unity Ads","law":"GDPR/COPPA","markers":[r"privacy\.consent",r"gdpr\.consent",r"user\.nonBehavioral",r"UnityAds"],"description":"Unity privacy metadata and non-behavioral advertising settings."},
    {"id":"google_child_flags","sdk":"Google Mobile Ads/AdMob","law":"COPPA/GDPR age","markers":[r"setTagForChildDirectedTreatment",r"TAG_FOR_CHILD_DIRECTED_TREATMENT",r"setTagForUnderAgeOfConsent",r"RequestConfiguration"],"description":"Google child-directed and under-age-of-consent request flags."},
    {"id":"chartboost_privacy","sdk":"Chartboost","law":"COPPA/US privacy","markers":[r"setPIDataUseConsent",r"setCoppa",r"DataUseConsent"],"description":"Chartboost privacy and COPPA settings."},
]

SDK_NAMESPACES = {
    "AppLovin MAX":["com/applovin","com.applovin","applvn.com","AppLovinSdk"],
    "Meta Audience Network":["com/facebook/ads","com.facebook.ads","AudienceNetworkAds"],
    "Ogury/Presage":["com/ogury","com.ogury","presage.io","ogury.co"],
    "InMobi":["com/inmobi","com.inmobi","InMobiSdk"],
    "Vungle/Liftoff":["com/vungle","com.vungle","com/liftoff","Vungle"],
    "ironSource/Unity LevelPlay":["com/ironsource","com.ironsource","IronSource","LevelPlay"],
    "Unity Ads":["com/unity3d/ads","com.unity3d.ads","unityads.unity3d.com"],
    "Google Mobile Ads/AdMob":["com/google/android/gms/ads","com.google.android.gms.ads","doubleclick.net"],
    "Chartboost":["com/chartboost","com.chartboost","chartboost.com"],
    "Mintegral/MBridge":["com/mbridge","com.mbridge","com/mintegral","rayjump.com"],
    "Yandex Ads":["com/yandex/mobile/ads","com.yandex.mobile.ads"],
    "Kidoz":["com/kidoz","com.kidoz"],
}

@dataclass
class Evidence:
    sample: str
    source: str
    check_id: str
    sdk: str
    law: str
    marker: str
    status: str
    location: str
    line: int | None
    argument_classification: str
    confidence: str
    context: str
    note: str

@dataclass
class SampleResult:
    label: str
    input_path: str
    input_size: int
    input_hashes: dict[str,str]
    base_apk_path: str
    base_apk_size: int
    base_apk_hashes: dict[str,str]
    archive_entries: int
    dex_files: list[str]
    dex_string_count: int
    jadx_status: str
    sdk_presence: dict[str,bool]
    check_status: dict[str,str]
    warnings: list[str]


def hash_file(path: Path) -> dict[str,str]:
    ds={name:hashlib.new(name) for name in ("md5","sha1","sha256")}
    with path.open("rb") as fh:
        for chunk in iter(lambda:fh.read(1024*1024),b""):
            for d in ds.values(): d.update(chunk)
    return {name:d.hexdigest() for name,d in ds.items()}


def parse_sample(value: str) -> tuple[str,Path]:
    if "=" not in value: raise argparse.ArgumentTypeError("sample must be LABEL=/path/to/file")
    label,raw=value.split("=",1); p=Path(raw).expanduser().resolve()
    if not label.strip() or not p.is_file(): raise argparse.ArgumentTypeError(f"bad sample: {value}")
    return label.strip(),p


def choose_base_apk(bundle: Path, extract_dir: Path) -> tuple[Path,int,list[str]]:
    if bundle.suffix.lower()==".apk": return bundle,0,[]
    if not zipfile.is_zipfile(bundle): raise ValueError(f"Unsupported input: {bundle}")
    with zipfile.ZipFile(bundle) as zf:
        infos=[i for i in zf.infolist() if not i.is_dir()]
        apks=[i for i in infos if i.filename.lower().endswith(".apk")]
        if not apks: raise ValueError("Bundle contains no APK")
        def score(i: zipfile.ZipInfo) -> float:
            n=i.filename.lower().replace("\\","/"); b=Path(n).name; s=i.file_size/(1024*1024)
            if b=="base.apk": s+=2000
            if b=="com.callapp.contacts.apk": s+=1900
            if "base-master" in b or "/base/" in n: s+=1700
            if b.startswith("base-"): s+=1400
            if "base" in b: s+=700
            if any(t in b for t in ("config.","config_","split_config","dpi","arm64","armeabi","x86")): s-=1800
            return s
        sel=max(apks,key=score); extract_dir.mkdir(parents=True,exist_ok=True); out=extract_dir/Path(sel.filename).name
        with zf.open(sel) as src,out.open("wb") as dst: shutil.copyfileobj(src,dst)
        return out,len(infos),[i.filename for i in apks]


def read_uleb128(data: bytes, off: int) -> tuple[int,int]:
    val=0; shift=0
    for _ in range(5):
        if off>=len(data): raise ValueError("truncated ULEB128")
        b=data[off]; off+=1; val|=(b&0x7f)<<shift
        if b&0x80==0: return val,off
        shift+=7
    raise ValueError("invalid ULEB128")


def dex_strings(data: bytes) -> list[str]:
    if len(data)<0x70 or not data.startswith(b"dex\n"): return []
    count=struct.unpack_from("<I",data,0x38)[0]; ids_off=struct.unpack_from("<I",data,0x3c)[0]
    if count>5_000_000 or ids_off+count*4>len(data): return []
    out=[]
    for i in range(count):
        off=struct.unpack_from("<I",data,ids_off+i*4)[0]
        if off>=len(data): continue
        try: _,pos=read_uleb128(data,off)
        except ValueError: continue
        end=data.find(b"\x00",pos,min(len(data),pos+2_000_000))
        if end<0: continue
        raw=data[pos:end]
        text=raw.decode("utf-8",errors="replace")
        if text: out.append(text)
    return out


def collect_dex_strings(apk: Path) -> tuple[list[str],list[str],list[str]]:
    names=[]; strings=[]; warnings=[]
    if not zipfile.is_zipfile(apk): return names,strings,["Base APK is not a ZIP"]
    with zipfile.ZipFile(apk) as zf:
        for i in zf.infolist():
            if re.search(r"(^|/)classes\d*\.dex$",i.filename):
                names.append(i.filename)
                try: strings.extend(dex_strings(zf.read(i)))
                except Exception as exc: warnings.append(f"Could not parse {i.filename}: {exc}")
    return names,strings,warnings


def locate_jadx(explicit: str|None) -> str|None:
    if explicit:
        p=Path(explicit).expanduser()
        if p.is_dir():
            for c in (p/"bin"/"jadx",p/"jadx"):
                if c.exists(): return str(c.resolve())
        elif p.exists(): return str(p.resolve())
        return None
    return shutil.which("jadx")


def run_jadx(jadx: str, apk: Path, output: Path, timeout: int) -> tuple[str,str]:
    output.mkdir(parents=True,exist_ok=True)
    cmds=[[jadx,"--deobf","--show-bad-code","--threads-count","4","-d",str(output),str(apk)],
          [jadx,"--deobf","--threads-count","4","-d",str(output),str(apk)],
          [jadx,"--threads-count","4","-d",str(output),str(apk)]]
    logs=[]
    for idx,cmd in enumerate(cmds):
        try:
            p=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
            logs.append(f"$ {' '.join(cmd)}\n{p.stdout}")
            if p.returncode==0:
                return "completed","\n\n".join(logs)
            # JADX often exits nonzero when some classes fail while still producing
            # a usable decompilation. Accept the partial tree instead of deleting it.
            generated = any(output.rglob("*.java")) or any(output.rglob("*.kt"))
            if generated:
                return "completed_with_errors","\n\n".join(logs)
            if idx<len(cmds)-1:
                shutil.rmtree(output,ignore_errors=True); output.mkdir(parents=True,exist_ok=True)
        except subprocess.TimeoutExpired as exc: return "timed_out","\n\n".join(logs+[str(exc)])
        except OSError as exc: return "failed","\n\n".join(logs+[str(exc)])
    return "failed","\n\n".join(logs)


def classify_argument(marker: str, context: str) -> str:
    name=marker.replace("\\","")
    m=re.search(rf"{name}\s*\((.*?)\)",context,flags=re.I|re.S); arg=m.group(1).strip() if m else ""; low=(arg or context).lower()
    if name.lower()=="setdataprocessingoptions":
        if '"ldu"' in low or "'ldu'" in low: return "literal LDU option present"
        if re.search(r"new\s+string\s*\[\s*0\s*\]",low) or "collections.empty" in low: return "hard-coded empty options (potential opt-in/default)"
    if re.search(r"(^|[,\s(])true([,\s)]|$)",low) and not re.search(r"(^|[,\s(])false([,\s)]|$)",low): return "literal true"
    if re.search(r"(^|[,\s(])false([,\s)]|$)",low) and not re.search(r"(^|[,\s(])true([,\s)]|$)",low): return "literal false"
    if "?" in arg and ":" in arg: return "conditional expression"
    if arg: return "variable/expression; trace data flow"
    return "symbol/reference only"


def iter_text_files(root: Path) -> Iterator[Path]:
    for p in root.rglob("*"):
        try:
            if p.is_file() and p.suffix.lower() in TEXT_EXTENSIONS and p.stat().st_size<=MAX_TEXT_BYTES: yield p
        except OSError: pass


def scan_decompiled(sample: str, root: Path) -> list[Evidence]:
    out=[]; compiled=[(c,[(m,re.compile(m,re.I)) for m in c["markers"]]) for c in CHECKS]
    for p in iter_text_files(root):
        try: lines=p.read_text(encoding="utf-8",errors="replace").splitlines()
        except OSError: continue
        for idx,line in enumerate(lines):
            for c,patterns in compiled:
                for marker,pat in patterns:
                    if not pat.search(line): continue
                    lo,hi=max(0,idx-5),min(len(lines),idx+6)
                    ctx="\n".join(f"{n+1}: {lines[n]}" for n in range(lo,hi)); ac=classify_argument(marker,ctx)
                    status="API_CALL_OR_REFERENCE_FOUND"; note="Inspect caller, reachability, value flow, and ordering."
                    if c["id"]=="meta_ccpa" and "hard-coded empty" in ac:
                        status="POTENTIAL_HARDCODED_OPT_IN"; note="High-priority match for the paper's Meta CCPA finding."
                    out.append(Evidence(sample,"jadx",c["id"],c["sdk"],c["law"],marker,status,str(p.relative_to(root)),idx+1,ac,"high for text match; semantics require tracing",ctx[:12000],note))
    return out


def scan_dex(sample: str, strings: Sequence[str]) -> tuple[list[Evidence],dict[str,bool]]:
    out=[]; presence={}; lowered=[(s,s.lower()) for s in strings]
    for sdk,markers in SDK_NAMESPACES.items():
        hits=[s for s,low in lowered if any(m.lower() in low for m in markers)]; presence[sdk]=bool(hits)
        for h in hits[:5]: out.append(Evidence(sample,"dex_strings","sdk_presence",sdk,"n/a",h,"SDK_SYMBOL_FOUND","DEX string pool",None,"n/a","medium","SDK/package marker: "+h[:1000],"Presence does not prove reachability."))
    for c in CHECKS:
        for marker in c["markers"]:
            pat=re.compile(marker,re.I); hits=[s for s in strings if pat.search(s)]
            for h in hits[:10]: out.append(Evidence(sample,"dex_strings",c["id"],c["sdk"],c["law"],marker,"API_SYMBOL_FOUND","DEX string pool",None,"symbol/reference only","medium",h[:1000],"Use JADX for call semantics."))
    return out,presence


def dedupe(rows: Iterable[Evidence]) -> list[Evidence]:
    seen=set(); out=[]
    for r in rows:
        k=(r.sample,r.source,r.check_id,r.marker,r.location,r.line,r.context)
        if k not in seen: seen.add(k); out.append(r)
    return out


def build_status(ev: Sequence[Evidence], presence: dict[str,bool]) -> dict[str,str]:
    out={}
    for c in CHECKS:
        rows=[e for e in ev if e.check_id==c["id"]]; j=[e for e in rows if e.source=="jadx"]
        if any(e.status=="POTENTIAL_HARDCODED_OPT_IN" for e in rows): out[c["id"]]="potential hard-coded opt-in match"
        elif j: out[c["id"]]="call/reference found in JADX"
        elif rows: out[c["id"]]="symbol found in DEX; semantics unverified"
        elif presence.get(c["sdk"],False): out[c["id"]]="SDK present; privacy API not found"
        else: out[c["id"]]="not found; absence is not proof"
    return out


def analyze(label: str,path: Path,output: Path,jadx: str|None,timeout: int) -> tuple[SampleResult,list[Evidence]]:
    so=output/label; so.mkdir(parents=True,exist_ok=True); base,entries,bundle_apks=choose_base_apk(path,so/"extracted")
    dex_names,strings,warnings=collect_dex_strings(base)
    if bundle_apks: (so/"bundle_apks.txt").write_text("\n".join(bundle_apks))
    ev,presence=scan_dex(label,strings); js="not_found"
    if jadx:
        jd=so/"jadx"; js,log=run_jadx(jadx,base,jd,timeout); (so/"jadx.log").write_text(log,errors="replace")
        if js in {"completed","completed_with_errors"}: ev.extend(scan_decompiled(label,jd))
        else: warnings.append("JADX "+js)
    else: warnings.append("JADX not found")
    ev=dedupe(ev)
    return SampleResult(label,str(path),path.stat().st_size,hash_file(path),str(base),base.stat().st_size,hash_file(base),entries,dex_names,len(strings),js,presence,build_status(ev,presence),warnings),ev


def write_outputs(output: Path,results: Sequence[SampleResult],evidence: Sequence[Evidence]) -> None:
    manifest={"tool":"callapp_privacy_audit","tool_version":TOOL_VERSION,"generated_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"samples":[asdict(r) for r in results],"limitations":["Static evidence is not a legal verdict.","Symbols do not prove reachable calls.","Missing matches may result from reflection, dynamic delivery, native code, or obfuscation."]}
    (output/"manifest.json").write_text(json.dumps(manifest,indent=2)); (output/"evidence.json").write_text(json.dumps([asdict(e) for e in evidence],indent=2))
    fields=list(asdict(Evidence("","","","","","","","",None,"","","","")).keys())
    with (output/"evidence.csv").open("w",newline="",encoding="utf-8") as fh:
        w=csv.DictWriter(fh,fieldnames=fields); w.writeheader(); w.writerows(asdict(e) for e in evidence)
    lines=["# CallApp privacy reproduction","",f"Generated: {manifest['generated_utc']}","","## Samples","","| Version | Input SHA-256 | Base APK SHA-256 | JADX |","|---|---|---|---|"]
    for r in results: lines.append(f"| {r.label} | `{r.input_hashes['sha256']}` | `{r.base_apk_hashes['sha256']}` | {r.jadx_status} |")
    lines += ["","## Result matrix","","| Check | "+" | ".join(r.label for r in results)+" |","|---|"+"---|"*len(results)]
    for c in CHECKS: lines.append(f"| {c['sdk']}: {c['description']} | "+" | ".join(r.check_status[c['id']] for r in results)+" |")
    lines += ["","## SDK families detected",""]
    for r in results: lines.append(f"- **{r.label}:** "+", ".join(s for s,v in r.sdk_presence.items() if v))
    lines += ["","## Evidence",""]
    for e in evidence[:700]:
        where=f"{e.location}:{e.line}" if e.line else e.location
        lines += [f"### {e.sample} · {e.sdk} · {e.status}","",f"- Marker: `{e.marker}`",f"- Location: `{where}`",f"- Argument: {e.argument_classification}",f"- Note: {e.note}","","```text",e.context[:6000],"```",""]
    (output/"audit_report.md").write_text("\n".join(lines))


def main() -> int:
    ap=argparse.ArgumentParser(); ap.add_argument("--sample",action="append",required=True,type=parse_sample); ap.add_argument("--output",type=Path,default=Path("results")); ap.add_argument("--jadx"); ap.add_argument("--timeout",type=int,default=2400); a=ap.parse_args()
    out=a.output.resolve(); out.mkdir(parents=True,exist_ok=True); jadx=locate_jadx(a.jadx); rs=[]; es=[]
    for label,path in a.sample:
        print(f"[+] {label}: {path}",file=sys.stderr); r,e=analyze(label,path,out,jadx,a.timeout); rs.append(r); es.extend(e)
    write_outputs(out,rs,dedupe(es)); print(f"[+] wrote {out/'audit_report.md'}",file=sys.stderr); return 0

if __name__=="__main__": raise SystemExit(main())
