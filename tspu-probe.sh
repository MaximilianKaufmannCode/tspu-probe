#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# =============================================================================
#  tspu-probe — comprehensive ТСПУ/DPI censorship-measurement probe (RU nets)
#  Copyright (c) 2026 Maximilian Kaufmann. Licensed under the Apache License 2.0.
#
#  Single-run diagnostic of how a network path filters traffic: DNS interference
#  (incl. answer injection), SNI/TLS blocking, RST injection + DPI localisation,
#  desync-bypass strategy matrix, HTTP host-blocking, ECH, UDP/QUIC suppression,
#  throttling, mobile TCP-freeze and behavioural freeze thresholds.
#  Run `bash tspu-probe.sh -h` for usage.
# =============================================================================
set -u
VERSION="2.1.2"

# --------------------------- CLI / config ----------------------------------
usage(){ cat <<EOF
tspu-probe $VERSION — ТСПУ/DPI censorship-measurement probe (Russian networks)

Usage: sudo bash tspu-probe.sh [options]
  --quick          short run: fewer canaries, no hop/freeze stages
  --no-freeze      skip the behavioural freeze stage (§11)
  --json           also write <out>/tspu-report-<ts>.json
  --out DIR        report directory (default: .)
  --timeout N      base network timeout in seconds, 1-600 (default: 10)
  --targets FILE   canary hosts, one per line ('#' comments allowed)
  --force          continue despite a failed vantage/platform/tool check
  --version        print version and exit
  -h, --help       this help

Run with ALL VPN/proxy tunnels disabled. Root is recommended (raw-socket
RST-TTL analysis). Needs Linux, bash >= 4, python3 >= 3.8, curl, dig,
openssl, ip, timeout.
EOF
}
die(){ printf 'tspu-probe: %s\n' "$*" >&2; exit 2; }
need_val(){ case "${2:-}" in ""|--*) die "option $1 requires a value";; esac; }

QUICK=0; NOFREEZE=0; JSON=0; OUTDIR="."; TIMEOUT=10; TARGETS_FILE=""; FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --quick) QUICK=1;;
    --no-freeze) NOFREEZE=1;;
    --json) JSON=1;;
    --force) FORCE=1;;
    --out) need_val "$1" "${2:-}"; OUTDIR="$2"; shift;;
    --timeout) need_val "$1" "${2:-}"; TIMEOUT="$2"; shift;;
    --targets) need_val "$1" "${2:-}"; TARGETS_FILE="$2"; shift;;
    --version) echo "tspu-probe $VERSION"; exit 0;;
    -h|--help) usage; exit 0;;
    *) printf 'tspu-probe: unknown argument: %s (use -h)\n' "$1" >&2; exit 2;;
  esac; shift
done
if [ "$QUICK" = 1 ]; then NOFREEZE=1; fi

case "$TIMEOUT" in ""|*[!0-9]*) die "--timeout must be an integer, got '$TIMEOUT'";; esac
T="${TIMEOUT#"${TIMEOUT%%[!0]*}"}"      # drop leading zeros (also avoids octal parsing)
if [ -z "$T" ] || [ "${#T}" -gt 3 ] || [ "$T" -gt 600 ]; then die "--timeout must be 1-600 seconds"; fi
TIMEOUT=$T
tm(){ local v=$(( TIMEOUT * $1 / 10 )); if [ "$v" -lt 1 ]; then v=1; fi; echo "$v"; }  # scale a 10s-based limit

# --targets: validate before any environment check or network access
if [ -n "$TARGETS_FILE" ]; then
  if [ ! -f "$TARGETS_FILE" ] || [ ! -r "$TARGETS_FILE" ]; then die "--targets: cannot read file '$TARGETS_FILE'"; fi
  CANARY=""
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"; line="${line//$'\r'/}"
    line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
    if [ -z "$line" ]; then continue; fi
    printf '%s' "$line" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' || die "--targets: invalid host '$line'"
    CANARY="$CANARY $line"
  done < "$TARGETS_FILE"
  CANARY="${CANARY# }"
  if [ -z "$CANARY" ]; then die "--targets: no hosts in '$TARGETS_FILE'"; fi
fi

have(){ command -v "$1" >/dev/null 2>&1; }
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  die "bash >= 4 is required (running ${BASH_VERSION:-unknown}); on macOS: brew install bash"
fi
have python3 || die "python3 is required"
have curl || die "curl is required"
python3 -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null || die "python >= 3.8 is required"
preflight_fail(){ if [ "$FORCE" = 1 ]; then echo "tspu-probe: WARNING (--force): $*" >&2; else die "$* (override with --force)"; fi; }
[ "$(uname -s 2>/dev/null)" = Linux ] || preflight_fail "Linux is required (ip route, AF_PACKET)"
for t in dig openssl ip timeout; do have "$t" || preflight_fail "required tool missing: $t"; done

# --------------------------- output / temp files ---------------------------
umask 077
TS="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo run)"
OUTDIR_NEW=0
if [ ! -d "$OUTDIR" ]; then mkdir -p "$OUTDIR" 2>/dev/null || die "cannot create output dir '$OUTDIR'"; OUTDIR_NEW=1; fi
[ -w "$OUTDIR" ] || die "output dir '$OUTDIR' is not writable"
OUT="${OUTDIR%/}/tspu-report-${TS}.txt"
JOUT="${OUTDIR%/}/tspu-report-${TS}.json"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tspu.XXXXXX")" || die "cannot create temp dir"
PY="$WORK/engine.py"; RESOLVED="$WORK/resolved"; JSONF="$WORK/json"   # JSONF accumulates "key\tvalue" fragments
# under sudo, hand the reports back to the invoking user
own(){ if [ "$(id -u)" = 0 ] && [ -n "${SUDO_UID:-}" ]; then chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$@" 2>/dev/null; fi; return 0; }
cleanup(){
  own "$OUT" "$JOUT"; if [ "$OUTDIR_NEW" = 1 ]; then own "$OUTDIR"; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
: > "$OUT"; : > "$JSONF"; : > "$RESOLVED"

log(){ printf '%s\n' "$*" | tee -a "$OUT"; }
sec(){ log ""; log "==== $* ===================================================="; }
jput(){ printf '%s\t%s\n' "$1" "$2" >> "$JSONF"; }   # record for JSON summary
ver(){ if have "$1"; then "$@" 2>&1 | head -1; else echo missing; fi; }

log "tspu-probe $VERSION  ts=$TS host=$(hostname 2>/dev/null) uid=$(id -u) quick=$QUICK"
log "local=$(date 2>/dev/null) utc=$(date -u 2>/dev/null) timeout=${TIMEOUT}s"
if [ "$(id -u)" = 0 ]; then log "ROOT: yes"; ROOT=1; else log "ROOT: no (raw tests skipped; rerun with sudo)"; ROOT=0; fi
log "tools: curl=[$(ver curl --version)] python=[$(ver python3 -I -V)] openssl=[$(ver openssl version)] dig=[$(ver dig -v)]"

# --------------------------- embedded python -------------------------------
cat > "$PY" <<'PYEOF'
import sys, socket, ssl, time, json, os, re, collections

TMO = float(os.environ.get("TPTMO","10"))

def build_ch(sni):
    ctx = ssl._create_unverified_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try: ctx.set_alpn_protocols(["h2","http/1.1"])
    except Exception: pass
    ib=ssl.MemoryBIO(); ob=ssl.MemoryBIO()
    obj=ctx.wrap_bio(ib,ob,server_hostname=(sni or None))
    try: obj.do_handshake()
    except ssl.SSLWantReadError: pass
    except Exception: pass
    return ob.read()

def frag_records(ch, off):
    # re-frame a single TLS record's handshake body into two TLS records at body-offset `off`
    if len(ch) < 6: return [ch]
    ctype=ch[0:1]; ver=ch[1:3]; body=ch[5:]
    if off<=0 or off>=len(body): off=len(body)//2
    a,b=body[:off],body[off:]
    return [ctype+ver+len(a).to_bytes(2,'big')+a, ctype+ver+len(b).to_bytes(2,'big')+b]

def classify(sock,t0):
    sock.settimeout(TMO)
    try: d=sock.recv(4096)
    except socket.timeout: return {"status":"TIMEOUT","t":round(time.time()-t0,3)}
    except ConnectionResetError: return {"status":"RST","t":round(time.time()-t0,3)}
    except Exception as e: return {"status":"ERR","detail":str(e),"t":round(time.time()-t0,3)}
    if not d: return {"status":"EOF","t":round(time.time()-t0,3)}
    if len(d)>=2 and d[0]==0x16 and d[1]==0x03: return {"status":"OK","t":round(time.time()-t0,3),"bytes":len(d)}
    if len(d)>=1 and d[0]==0x15: return {"status":"TLS_ALERT","t":round(time.time()-t0,3)}
    return {"status":"DATA","t":round(time.time()-t0,3),"head":d[:3].hex()}

def tls_probe(ip, sni, frag="none", port=443, delay=0.03):
    s=None
    try:
        ch=build_ch(sni)
        if not ch: return {"status":"CTXERR"}
        t0=time.time()
        s=socket.create_connection((ip,port),timeout=TMO)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if frag=="none": s.sendall(ch)
        elif frag=="s1": s.send(ch[:1]); time.sleep(delay); s.send(ch[1:])
        elif frag=="s4": s.send(ch[:4]); time.sleep(delay); s.send(ch[4:])
        elif frag=="sni":
            sb=(sni or "").encode(); p=ch.find(sb); p=(p+max(1,len(sb)//2)) if p>=0 else len(ch)//2
            s.send(ch[:p]); time.sleep(delay); s.send(ch[p:])
        elif frag=="trec":
            sb=(sni or "").encode(); p=ch.find(sb)
            off=(p-5+max(1,len(sb)//2)) if p>=5 else (len(ch)-5)//2
            for rec in frag_records(ch, off): s.send(rec); time.sleep(delay)
        else: s.sendall(ch)
        return classify(s,t0)
    except ConnectionResetError: return {"status":"RST","t":0.0}
    except socket.timeout: return {"status":"TIMEOUT","t":0.0}
    except ConnectionRefusedError: return {"status":"REFUSED","t":0.0}
    except Exception as e: return {"status":"ERR","detail":str(e)}
    finally:
        try: s.close()
        except Exception: pass

def vote(statuses):
    # strict majority, otherwise MIXED: a tie must never be reported as the first status seen
    n=len(statuses)
    if n==0: return "ERR(0/0)"
    top,k=collections.Counter(statuses).most_common(1)[0]
    if k*2>n: return "%s(%d/%d)"%(top,k,n)
    return "MIXED(%s)"%"/".join(statuses)

def tls_vote(ip, sni, frag="none", tries=3, port=443):
    return vote([tls_probe(ip,sni,frag,port=port).get("status","ERR") for _ in range(tries)])

def tcp_syn(ip, port):
    t0=time.time()
    try:
        s=socket.create_connection((ip,int(port)),timeout=TMO); s.close()
        return {"status":"OPEN","t":round(time.time()-t0,3)}
    except ConnectionResetError: return {"status":"RST","t":round(time.time()-t0,3)}
    except socket.timeout: return {"status":"TIMEOUT","t":round(time.time()-t0,3)}
    except ConnectionRefusedError: return {"status":"REFUSED","t":round(time.time()-t0,3)}
    except Exception as e: return {"status":"ERR","detail":str(e)}

def hop(ip, sni, maxttl=24, port=443):
    # locate DPI: TCP handshake at default TTL, then send ClientHello at rising IP_TTL.
    # smallest TTL that yields an injected RST ~= DPI hop distance.
    ch=build_ch(sni); trace=[]; dpi=None
    for ttl in range(1, maxttl+1):
        s=None; res="?"
        try:
            s=socket.create_connection((ip,port),timeout=min(TMO,5))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                s.sendall(ch); s.settimeout(min(TMO,4))
                d=s.recv(64); res="OK" if (d[:1]==b'\x16') else ("EOF" if not d else "DATA")
            except (ConnectionResetError, BrokenPipeError): res="RST"
            except socket.timeout: res="TO"
            except OSError as e: res="ERR%d"%(e.errno or 0)
        except (ConnectionResetError, BrokenPipeError): res="RSTc"
        except socket.timeout: res="TOc"
        except Exception as e: res="ERRc:"+type(e).__name__
        finally:
            try: s.close()
            except Exception: pass
        trace.append([ttl,res])
        if res in ("RST","RSTc") and dpi is None: dpi=ttl; break
        time.sleep(0.25)
    return {"dpi_hop":dpi, "trace":trace, "note":("possible-residual-contamination" if dpi and dpi<=2 else "")}

def _dns_query(domain):
    q=os.urandom(2)+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    for p in domain.split('.'): q+=bytes([len(p)])+p.encode()
    return q+b'\x00\x00\x01\x00\x01'

def _parse_a(d):
    try:
        qd=int.from_bytes(d[4:6],'big'); an=int.from_bytes(d[6:8],'big'); off=12
        for _ in range(qd):
            while d[off]!=0: off+=1+d[off]
            off+=5
        ips=[]
        for _ in range(an):
            if d[off]&0xc0==0xc0: off+=2
            else:
                while d[off]!=0: off+=1+d[off]
                off+=1
            rt=int.from_bytes(d[off:off+2],'big'); off+=8
            rl=int.from_bytes(d[off:off+2],'big'); off+=2
            if rt==1 and rl==4: ips.append(socket.inet_ntoa(d[off:off+4]))
            off+=rl
        return ips
    except Exception: return []

def dnsmulti(resolver, domain, window=3.0, port=53):
    # detect answer injection: collect ALL responses to one query
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2.0)
        s.connect((resolver,port)); s.send(_dns_query(domain))
    except Exception as e: return {"error":str(e)}
    ans=[]; t0=time.time()
    while time.time()-t0<window:
        try: d=s.recv(2048)
        except socket.timeout: break
        except Exception: break
        ans.append({"t":round(time.time()-t0,3),"ips":_parse_a(d)})
    s.close()
    uniq={tuple(a["ips"]) for a in ans}
    return {"count":len(ans),"responses":ans,"injected":len(uniq)>1}

def _recvn(s, n):
    buf=b""
    while len(buf)<n:
        c=s.recv(n-len(buf))
        if not c: raise EOFError("closed after %d of %d bytes"%(len(buf),n))
        buf+=c
    return buf

def dns_tcp(resolver, domain, port=53):
    s=None
    try:
        q=_dns_query(domain); s=socket.create_connection((resolver,port),timeout=TMO)
        s.sendall(len(q).to_bytes(2,'big')+q)
        # the 2-byte length prefix often arrives as its own segment: read exactly, don't rely on one recv()
        d=_recvn(s,int.from_bytes(_recvn(s,2),'big'))
        return {"status":"OK","ips":_parse_a(d)}
    except ConnectionResetError: return {"status":"RST"}
    except socket.timeout: return {"status":"TIMEOUT"}
    except EOFError: return {"status":"EOF"}
    except Exception as e: return {"status":"ERR","detail":str(e)}
    finally:
        try: s.close()
        except Exception: pass

def stun(host, port=3478):
    try:
        m=b'\x00\x01\x00\x00\x21\x12\xa4\x42'+os.urandom(12)
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(min(TMO,5.0))
        s.sendto(m,(socket.gethostbyname(host),port)); d,_=s.recvfrom(2048); s.close()
        return {"status":"OK","len":len(d)}
    except socket.timeout: return {"status":"TIMEOUT"}
    except Exception as e: return {"status":"ERR","detail":str(e)}

def ntp(host):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(min(TMO,5.0))
        s.sendto(b'\x1b'+47*b'\0',(socket.gethostbyname(host),123)); d,_=s.recvfrom(1024); s.close()
        return {"status":"OK","len":len(d)}
    except socket.timeout: return {"status":"TIMEOUT"}
    except Exception as e: return {"status":"ERR","detail":str(e)}

def raw_rst(ip, sni, iface=None, dur=10.0):
    import threading
    try:
        s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        if iface:
            try: s.bind((iface,0))
            except Exception: pass
        s.settimeout(1.0)
    except Exception as e: return {"error":"raw socket: "+str(e)}
    def fire():
        for _ in range(4):
            try:
                c=socket.create_connection((ip,443),timeout=5); c.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
                c.sendall(build_ch(sni))
                try: c.recv(2048)
                except Exception: pass
                c.close()
            except Exception: pass
            time.sleep(0.6)
    time.sleep(0.2)
    threading.Thread(target=fire,daemon=True).start()
    out={"SYNACK":set(),"RST":set(),"other":set()}; t0=time.time(); n=0
    while time.time()-t0<dur:
        try: pkt=s.recv(2000)
        except socket.timeout: continue
        except Exception: break
        if len(pkt)<34 or pkt[12:14]!=b'\x08\x00': continue
        ipd=pkt[14:]; ihl=(ipd[0]&0x0f)*4; ttl=ipd[8]; proto=ipd[9]
        if proto!=6 or socket.inet_ntoa(ipd[12:16])!=ip: continue
        tcp=ipd[ihl:]
        if len(tcp)<14: continue
        fl=tcp[13]; n+=1
        if fl&0x04: out["RST"].add(ttl)
        elif fl&0x02: out["SYNACK"].add(ttl)
        else: out["other"].add(ttl)
    r={k:sorted(v) for k,v in out.items()}; r["pkts"]=n
    if n==0: r["note"]="0 pkts: target in drop-mode or wrong iface"
    return r

_SNI_RE=re.compile(r"^sni (\S+) \(([^)]*)\): normal=(\S+) split1=(\S+) split4=(\S+) splitSNI=(\S+) TLSrec=(\S+)\s*$")
_HOP_RE=re.compile(r"^\s*hop \S+ \([^)]*\): (\{.*\})\s*$")
_VOTE_RE=re.compile(r"^([A-Z_]+)\((\d+)/(\d+)\)$")
_BLOCK={"RST","TIMEOUT","EOF","DATA"}
_MODES=("split1","split4","splitSNI","TLSrec")

def _status(v):
    # MIXED(...) and anything unparsable -> None (inconclusive)
    m=_VOTE_RE.match(v)
    return m.group(1) if m else None

def verdict_data(path):
    """Derive the desync verdict from the report's own `sni ...` lines.
    A mode only counts as a bypass on domains whose normal ClientHello was blocked."""
    blocked=[]; clean=[]; unclear=[]; no_ip=0; dpi=None; hop_seen=False
    bypass={m:[] for m in _MODES}; failed={m:[] for m in _MODES}; broke={m:[] for m in _MODES}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if re.match(r"^sni \S+: NO-IP", line): no_ip+=1; continue
            m=_SNI_RE.match(line)
            if m:
                dom=m.group(1); normal=_status(m.group(3))
                modes=dict(zip(_MODES,[_status(m.group(i)) for i in (4,5,6,7)]))
                if normal in _BLOCK:
                    blocked.append(dom)
                    for k,v in modes.items():
                        if v=="OK": bypass[k].append(dom)
                        else: failed[k].append(dom)
                elif normal=="OK":
                    clean.append(dom)
                    for k,v in modes.items():
                        if v in _BLOCK: broke[k].append(dom)
                else: unclear.append(dom)
                continue
            h=_HOP_RE.match(line)
            if h:
                try: hop_seen=True; dpi=json.loads(h.group(1)).get("dpi_hop")
                except ValueError: pass
    return {"blocked":blocked,"unblocked":clean,"inconclusive":unclear,"no_ip":no_ip,
            "bypass":bypass,"failed":failed,"breaks_unblocked":broke,
            "dpi_hop":dpi,"hop_measured":hop_seen}

def verdict_text(d):
    out=[]; nb=len(d["blocked"]); tested=nb+len(d["unblocked"])+len(d["inconclusive"])
    out.append("SNI matrix: %d tested, %d blocked, %d unblocked, %d inconclusive, %d without IP"%(
        tested,nb,len(d["unblocked"]),len(d["inconclusive"]),d["no_ip"]))
    if nb==0:
        out.append("desync verdict: n/a — no SNI blocking observed on the tested domains")
    else:
        out.append("blocked (normal ClientHello failed): "+" ".join(d["blocked"]))
        ranked=sorted(((len(v),k) for k,v in d["bypass"].items() if v), reverse=True)
        if ranked:
            out.append("desync that bypassed a block (mode: bypassed/blocked):")
            for n,k in ranked: out.append("  %s: %d/%d  [%s]"%(k,n,nb," ".join(d["bypass"][k])))
        else:
            out.append("desync that bypassed at least one block: none-observed")
    for k,v in d["breaks_unblocked"].items():
        if v: out.append("warning: %s failed on unblocked domains [%s] — strategy may break normal traffic"%(k," ".join(v)))
    if d["dpi_hop"]:
        out.append("dpi_hop=%s: fake/TTL-limited packets (zapret/byedpi) need TTL >= %s and below the server distance"%(d["dpi_hop"],d["dpi_hop"]))
    elif d["hop_measured"]: out.append("dpi_hop: not located")
    else: out.append("dpi_hop: not measured")
    return "\n".join(out)

if __name__=="__main__":
    c=sys.argv[1]; a=sys.argv[2:]
    if   c=="tls":     print(json.dumps(tls_probe(a[0],a[1],a[2] if len(a)>2 else "none")))
    elif c=="tls3":    print(tls_vote(a[0],a[1],a[2] if len(a)>2 else "none"))
    elif c=="syn":     print(json.dumps(tcp_syn(a[0],a[1])))
    elif c=="hop":     print(json.dumps(hop(a[0],a[1],port=int(a[2]) if len(a)>2 else 443)))
    elif c=="dnsmulti":print(json.dumps(dnsmulti(a[0],a[1],port=int(a[2]) if len(a)>2 else 53)))
    elif c=="dnstcp":  print(json.dumps(dns_tcp(a[0],a[1],port=int(a[2]) if len(a)>2 else 53)))
    elif c=="stun":    print(json.dumps(stun(a[0],int(a[1]) if len(a)>1 else 3478)))
    elif c=="ntp":     print(json.dumps(ntp(a[0])))
    elif c=="rawrst":  print(json.dumps(raw_rst(a[0],a[1],a[2] if len(a)>2 else None)))
    elif c=="verdict": print(verdict_text(verdict_data(a[0])))
    elif c=="verdict-json": print(json.dumps(verdict_data(a[0]),ensure_ascii=False))
PYEOF
export TPTMO="$TIMEOUT"
py(){ python3 -I "$PY" "$@"; }     # -I: ignore PYTHON* env and the script dir (no sys.path shadowing)
pytls(){ py tls "$1" "$2" "${3:-none}"; }
st(){ python3 -I -c "import sys,json;print(json.load(sys.stdin).get('status','?'))" 2>/dev/null || echo ERR; }

# DoH resolver via resolver IPs (no system DNS — robust to broken systemd-resolved after tunnel teardown).
# Cache lines are "host ip" or "host -" (negative). Provenance goes straight to $OUT, never to stdout.
resolve(){
  local d="$1" ip="" u p c
  c=$(awk -v d="$d" '$1==d {print $2; exit}' "$RESOLVED" 2>/dev/null)
  if [ -n "$c" ]; then if [ "$c" != "-" ]; then echo "$c"; fi; return 0; fi
  for p in 1.1.1.1 8.8.8.8; do
    if [ "$p" = 1.1.1.1 ]; then u="https://1.1.1.1/dns-query?name=${d}&type=A"; else u="https://8.8.8.8/resolve?name=${d}&type=A"; fi
    ip=$(curl -s --max-time "$(tm 8)" -H 'accept: application/dns-json' "$u" 2>/dev/null | grep -oE '"data":"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"' | grep -oE '[0-9.]+' | head -1)
    if [ -n "$ip" ]; then break; fi
  done
  if [ -n "$ip" ]; then
    echo "${d} ${ip}" >> "$RESOLVED"; echo "[doh] ${d} -> ${ip} via ${p}" >> "$OUT"
  else
    echo "${d} -" >> "$RESOLVED"; echo "[doh] ${d} -> no answer (1.1.1.1, 8.8.8.8)" >> "$OUT"
  fi
  echo "$ip"
}
# curl that resolves host via DoH-by-IP and pins it (robust to broken system DNS)
curlr(){
  local host="$1" port="$2"; shift 2; local ip; ip=$(resolve "$host")
  if [ -n "$ip" ]; then curl --resolve "${host}:${port}:${ip}" "$@"; else curl "$@"; fi
}

# canaries (override with --targets FILE; validated above)
if [ -z "$TARGETS_FILE" ]; then
  if [ "$QUICK" = 1 ]; then CANARY="rutracker.org www.torproject.org x.com discord.com www.youtube.com"
  else CANARY="rutracker.org www.torproject.org bridges.torproject.org x.com www.instagram.com www.facebook.com discord.com proton.me protonvpn.com www.youtube.com signal.org twitter.com"; fi
fi

# ======================= 0. VANTAGE =======================
sec "0. VANTAGE (tunnels must be OFF)"
EIF=$(ip route get 1.1.1.1 2>/dev/null | grep -oE 'dev [^ ]+' | awk '{print $2}' | head -1)
V=$(curlr ip-api.com 80 -s --max-time "$(tm 12)" "http://ip-api.com/json/?fields=status,country,regionName,city,isp,as,mobile,proxy,query" 2>/dev/null)
log "ip-api: $V"
CC=$(printf '%s' "$V"|grep -oE '"country":"[^"]*"'|cut -d'"' -f4); ASN=$(printf '%s' "$V"|grep -oE '"as":"[^"]*"'|cut -d'"' -f4)
MOB=$(printf '%s' "$V"|grep -oE '"mobile":[a-z]+'|cut -d: -f2)
if ip -6 route get 2606:4700:4700::1111 >/dev/null 2>&1; then
  V6=$(curl -s6 --max-time "$(tm 8)" "https://api64.ipify.org" 2>/dev/null); V6="${V6:-unreachable}"
else V6="no-ipv6-route"; fi
log "egress-if: ${EIF:-?}  mtu: $(ip link show "${EIF:-lo}" 2>/dev/null|grep -oE 'mtu [0-9]+')"
log "ipv4=$(printf '%s' "$V"|grep -oE '"query":"[^"]*"'|cut -d'"' -f4)  ipv6=${V6}  mobile=$MOB"
jput vantage.country "$CC"; jput vantage.asn "$ASN"; jput vantage.mobile "$MOB"; jput vantage.iface "${EIF:-}"
VALID=true
if [ -z "$CC" ]; then
  VALID=unknown
  log "!!! WARNING: egress country could not be determined (ip-api unreachable) — vantage NOT verified."
elif [ "$CC" != "Russia" ]; then
  VALID=false
  log "!!! WARNING: egress country=$CC (not Russia) — a VPN/tunnel is likely still ON."
  log "!!! Disable all tunnels and re-run; results are invalid otherwise."
  if [ "$FORCE" = 1 ]; then log "!!! --force given: continuing, results are NOT valid for RU DPI."
  else log "!!! Aborting (exit 3); use --force to run anyway."; jput vantage.valid "false"; exit 3; fi
else log ">>> OK vantage: $CC / $ASN"; fi
jput vantage.valid "$VALID"

# ======================= 1. CONTROL =======================
sec "1. CONTROL connectivity + baseline latency"
for d in ya.ru mail.ru gosuslugi.ru dzen.ru example.com cloudflare.com wikipedia.org; do
  log "control $d : $(curlr "$d" 443 -s -o /dev/null --max-time "$(tm 12)" -w 'code=%{http_code} tcp=%{time_connect} tls=%{time_appconnect} ttfb=%{time_starttransfer}' "https://$d/" 2>/dev/null || echo FAIL)"
done

# ======================= 2. DNS =======================
sec "2. DNS interference (poisoning / refusal / INJECTION / DoT / TCP-53)"
GW=$(ip route show default 2>/dev/null|grep -oE 'via [0-9.]+'|awk '{print $2}'|head -1)
SYSDNS=$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf 2>/dev/null)
log "gateway=${GW:-?} sys-resolver=${SYSDNS:-?}"
for d in rutracker.org www.torproject.org x.com discord.com; do
  sys=$(dig +short +time="$(tm 3)" +tries=1 "$d" A 2>/dev/null|tr '\n' ',')
  u8=$(dig +short +time="$(tm 3)" +tries=1 @8.8.8.8 "$d" A 2>/dev/null|tr '\n' ',')
  ya=$(dig +short +time="$(tm 3)" +tries=1 @77.88.8.8 "$d" A 2>/dev/null|tr '\n' ',')
  doh=$(resolve "$d")
  log "dns $d : sys=[${sys:-x}] udp8.8.8.8=[${u8:-x}] udpYandex=[${ya:-x}] DoH=[${doh:-x}]"
done
log "-- answer INJECTION (multiple responses to one query) --"
for d in www.torproject.org rutracker.org; do
  log "  inject @8.8.8.8 $d: $(py dnsmulti 8.8.8.8 "$d")"
done
log "-- DNS over TCP:53 (fallback path) --"
for r in 8.8.8.8 1.1.1.1; do log "  dns-tcp @$r torproject: $(py dnstcp "$r" www.torproject.org)"; done
log "-- DoT tcp:853 --"
DOT=$(echo | timeout "$(tm 8)" openssl s_client -connect 1.1.1.1:853 -servername one.one.one.one -brief 2>&1 | grep -iE 'protocol|connected|error' | tr '\n' ';')
log "  dot 1.1.1.1: ${DOT:-FAILED}"

# ======================= 3. IP REACHABILITY =======================
sec "3. IP reachability (TCP SYN :443/:80 — IP-block vs SNI-block)"
for d in $CANARY; do
  ip=$(resolve "$d"); [ -z "$ip" ] && { log "reach $d: NO-IP"; continue; }
  s443=$(py syn "$ip" 443); s80=$(py syn "$ip" 80)
  log "reach $d ($ip): 443=$s443 80=$s80"
done

# ======================= 4. SNI FILTERING + DESYNC MATRIX =======================
sec "4. SNI filtering + DESYNC matrix (normal/split@1/@4/@SNI/TLS-rec, x3)"
log "OK=ServerHello · RST=inject · TIMEOUT=drop | 3 tries: strict majority STATUS(k/3), otherwise MIXED(a/b/c) = inconclusive"
for d in $CANARY; do
  ip=$(resolve "$d"); [ -z "$ip" ] && { log "sni $d: NO-IP"; continue; }
  declare -A R=()
  for m in none s1 s4 sni trec; do R[$m]=$(py tls3 "$ip" "$d" "$m"); done
  log "sni $d ($ip): normal=${R[none]:-ERR} split1=${R[s1]:-ERR} split4=${R[s4]:-ERR} splitSNI=${R[sni]:-ERR} TLSrec=${R[trec]:-ERR}"
  jput "sni.$d" "normal=${R[none]:-ERR};s1=${R[s1]:-ERR};s4=${R[s4]:-ERR};sni=${R[sni]:-ERR};trec=${R[trec]:-ERR}"
done

# ======================= 5. SNI-vs-IP ISOLATION =======================
sec "5. SNI-vs-IP isolation (benign/empty SNI to blocked IP)"
for d in www.torproject.org discord.com rutracker.org protonvpn.com; do
  ip=$(resolve "$d"); [ -z "$ip" ] && { log "iso $d: NO-IP"; continue; }
  log "iso $d ($ip): blockedSNI=$(pytls "$ip" "$d" none|st) benign=$(pytls "$ip" example.com none|st) emptySNI=$(pytls "$ip" '' none|st)"
done
log "(benign/empty=OK & blocked!=OK -> keyed on SNI, not IP)"

# ======================= 6. HTTP:80 =======================
sec "6. HTTP:80 Host-block + RKN stub"
for d in rutracker.org www.torproject.org x.com; do
  h=$(curlr "$d" 80 -s -D - -o /dev/null --max-time "$(tm 10)" "http://$d/" 2>/dev/null | tr -d '\r' | grep -iE '^HTTP/|^location:' | tr '\n' ';')
  body=$(curlr "$d" 80 -s --max-time "$(tm 10)" "http://$d/" 2>/dev/null | grep -aoiE 'заблокирован|ограничен доступ|единый реестр|blocklist|заглушк|warning' | head -1)
  log "http80 $d : ${h:-no-response} :: stub=[${body:-none}]"
done

# ======================= 7. ECH =======================
sec "7. ECH / Encrypted ClientHello (DoH-bootstrap)"
ECHFLAG=$(curl --help all 2>&1 | grep -oE '\-\-ech <config>' | head -1)
log "curl ECH: ${ECHFLAG:-none}"
for d in crypto.cloudflare.com cloudflare.com; do
  rr=$(curl -s --max-time "$(tm 10)" "https://8.8.8.8/resolve?name=${d}&type=HTTPS" 2>/dev/null | grep -oE '"data":"[^"]*ech[^"]*"' | head -1)
  log "  https-rr $d : $(if [ -n "$rr" ]; then echo 'ECHConfig-present'; else echo none; fi)"
done
if curl --help all 2>&1|grep -q '\-\-ech'; then
  for d in crypto.cloudflare.com cloudflare.com; do
    r=$(curl -s --max-time "$(tm 15)" --ech true --doh-url https://1.1.1.1/dns-query "https://$d/cdn-cgi/trace" 2>&1 | grep -iE 'sni=|http/' | tr '\n' ' ')
    log "  ech-live $d : ${r:-FAILED}"
  done
  log "  (sni=encrypted -> ECH passed through; else -> ECH not usable on this path)"
else log "  curl без --ech"; fi

# ======================= 8. UDP PORT-PROFILE =======================
sec "8. UDP port-profile (DNS:53 / NTP:123 / STUN:19302,3478 / QUIC:443)"
for r in 1.1.1.1 8.8.8.8 77.88.8.8; do
  log "udp53 @$r: $(dig +time="$(tm 4)" +tries=1 @$r example.com A 2>&1|grep -oE 'status: [A-Z]+|timed out'|head -1)"
done
NTPIP=$(resolve time.google.com); STUNG=$(resolve stun.l.google.com); STUNC=$(resolve stun.cloudflare.com)
log "udp123 NTP time.google.com: $(py ntp "${NTPIP:-time.google.com}")"
log "udp19302 STUN stun.l.google.com: $(py stun "${STUNG:-stun.l.google.com}" 19302)"
log "udp3478 STUN stun.cloudflare.com: $(py stun "${STUNC:-stun.cloudflare.com}" 3478)"
if curl --version 2>/dev/null|grep -qi HTTP3; then
  for d in cloudflare-quic.com www.google.com; do
    log "udp443 QUIC $d: $(curl -sI --http3-only --max-time "$(tm 12)" "https://$d/" -o /dev/null -w 'code=%{http_code} t=%{time_total}' 2>&1||echo FAIL)"
  done
fi
log "(DNS/NTP/STUN pass but QUIC:443 fails -> QUIC/port-443-UDP targeting, not all-UDP)"

# ======================= 9. THROTTLE + 16KB FREEZE =======================
sec "9. Throughput / throttle + mobile 16KB TCP-freeze (Range 256KB)"
# host|port|url — reliable endpoints; curlr resolves host via DoH-by-IP
declare -A DL=( [RU_yandex]="mirror.yandex.ru|443|https://mirror.yandex.ru/debian/ls-lR.gz" \
                [RU_tele2]="speedtest.tele2.net|80|http://speedtest.tele2.net/1MB.zip" \
                [FOR_cachefly]="cachefly.cachefly.net|443|https://cachefly.cachefly.net/10mb.test" \
                [FOR_thinkbb]="ipv4.download.thinkbroadband.com|80|http://ipv4.download.thinkbroadband.com/5MB.zip" )
for k in $(printf '%s\n' "${!DL[@]}" | sort); do
  IFS='|' read -r h p u <<< "${DL[$k]}"
  r=$(curlr "$h" "$p" -s -o /dev/null --max-time "$(tm 25)" -r 0-262143 -w 'got=%{size_download}B time=%{time_total}s spd=%{speed_download}B/s' "$u" 2>/dev/null)
  log "dl $k : ${r:-FAILED}"
  jput "throughput.$k" "${r:-FAILED}"
done
log "(foreign got~16-64KB & time~=max -> mobile freeze; got=256KB slow -> throttle; RU fast -> ok)"

# ======================= 10. DPI FINGERPRINT: RST-TTL + HOP-DISTANCE + RESIDUAL =======================
sec "10. DPI fingerprint: RST-injection TTL, hop-distance, residual"
log "-- hop-distance (smallest IP_TTL that still triggers injected RST ~= DPI hop) --"
if [ "$QUICK" = 0 ]; then
  ip=$(resolve rutracker.org)
  [ -n "$ip" ] && log "  hop rutracker ($ip): $(py hop "$ip" rutracker.org)"
else log "  (skipped in --quick)"; fi
if [ "$ROOT" = 1 ]; then
  log "-- injected-RST TTL vs genuine (SYNACK) --"
  for d in www.torproject.org rutracker.org; do
    ip=$(resolve "$d"); [ -z "$ip" ] && continue
    log "  rst-ttl $d ($ip): $(py rawrst "$ip" "$d" "${EIF:-}")"
  done
  log "  (RST TTL != SYNACK TTL -> middlebox injection; ignorable by TTL)"
else log "  (RST-TTL needs root)"; fi
log "-- residual/stateful hold after RST --"
ip=$(resolve www.torproject.org)
if [ -n "$ip" ]; then
  T0=$SECONDS
  log "  trigger: $(pytls "$ip" www.torproject.org none|st)"
  for t in 0 2 5; do sleep "$t"; log "  +$((SECONDS-T0))s after trigger, benign->same-ip: $(pytls "$ip" example.com none|st)"; done
fi

# ======================= 11. BEHAVIORAL FREEZE =======================
if [ "$NOFREEZE" = 0 ]; then
sec "11. Behavioral freeze — N-sweep + repeat (ADVERSARIAL, LAST)"
CTRL="https://ya.ru/"; TSNI="www.youtube.com"; TIP=$(resolve "$TSNI"); CTRL_IP=$(resolve ya.ru)
log "trigger=$TSNI ip=${TIP:-x} control=$CTRL ctrl_ip=${CTRL_IP:-x}"
pc(){   # control-request latency, or the single token FREEZE on any curl failure
  local t
  # shellcheck disable=SC2086  # CTRL_IP is digits-and-dots only; word splitting is intended
  if t=$(curl ${CTRL_IP:+--resolve ya.ru:443:$CTRL_IP} -s -o /dev/null --max-time 4 -w '%{time_total}' "$CTRL" 2>/dev/null); then echo "$t"; else echo FREEZE; fi
}
log "baseline ctrl: $(pc) $(pc) $(pc)"
ROUND_FROZEN=0
run_round(){
  local N=$1 tag="${2:-}" frozen=0 onset="" recov="" k c pt fs="" fe=0 dur=0
  if [ -n "${TIP:-}" ]; then for _ in $(seq 1 "$N"); do ( py tls "$TIP" "$TSNI" none >/dev/null 2>&1 ) & done; fi
  for k in $(seq 1 18); do
    pt=$SECONDS; c=$(pc)
    if [ "$c" = FREEZE ]; then
      frozen=$((frozen+1)); if [ -z "$onset" ]; then onset=$k; fs=$pt; fi; fe=$SECONDS
    elif [ "$frozen" -gt 0 ] && [ -z "$recov" ]; then recov=$k; fi
    sleep 1.5
  done
  wait 2>/dev/null
  ROUND_FROZEN=$frozen
  if [ "$frozen" -gt 0 ]; then
    dur=$((fe-fs))
    log "  N=$N: FREEZE (onset_poll=${onset} frozen_polls=${frozen} span≈${dur}s recov_poll=${recov:-'>18'})"; jput "freeze.${tag}N$N" "yes(${frozen}poll)"
  else log "  N=$N: no-freeze"; jput "freeze.${tag}N$N" "no"; fi
}
FIRST_FREEZE_N=""
for N in 4 8 12 16 20; do
  log "-- round N=$N --"; run_round "$N"
  if [ -z "$FIRST_FREEZE_N" ] && [ "$ROUND_FROZEN" -gt 0 ]; then FIRST_FREEZE_N=$N; fi
  log "  settle 12s"; sleep 12
done
if [ -n "$FIRST_FREEZE_N" ]; then log "-- repeat first freezing level N=$FIRST_FREEZE_N --"; run_round "$FIRST_FREEZE_N" repeat.
else log "-- repeat skipped: no freezing level found --"; fi
else sec "11. Behavioral freeze — SKIPPED (--no-freeze/--quick)"; fi

# ======================= SUMMARY + VERDICT =======================
sec "SUMMARY + VERDICT"
log "vantage: $CC / $ASN / mobile=$MOB (valid=$VALID)"
if [ "$VALID" != true ]; then log "WARNING: vantage not verified as Russian — the verdict may not reflect RU DPI"; fi
VT=$(py verdict "$OUT" 2>&1) || VT="verdict: engine error: $VT"
log "$VT"
log "see also: §8 (UDP/QUIC survival), §9 (throttle/freeze), §10 (dpi_hop), §11 (behavioural freeze)"
log "DONE. Report: $OUT"

if [ "$JSON" = 1 ]; then
  VJ=$(py verdict-json "$OUT" 2>/dev/null); VJ="${VJ:-null}"
  python3 -I - "$JSONF" "$TS" "$CC" "$ASN" "$VERSION" "$VALID" "$VJ" > "$JOUT" <<'P'
import sys,json
rows=[l.rstrip('\n').split('\t',1) for l in open(sys.argv[1]) if '\t' in l]
o={"version":sys.argv[5],"ts":sys.argv[2],"country":sys.argv[3],"asn":sys.argv[4],
   "vantage_valid":sys.argv[6],"verdict":json.loads(sys.argv[7]),"data":{}}
for k,v in rows: o["data"][k]=v
json.dump(o,sys.stdout,ensure_ascii=False,indent=2)
P
  log "JSON: $JOUT"
fi
