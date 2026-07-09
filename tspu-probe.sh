#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# =============================================================================
#  tspu-probe 2.0 — comprehensive ТСПУ/DPI censorship-measurement probe (RU nets)
#  Copyright (c) 2026 Maximilian Kaufmann. Licensed under the Apache License 2.0.
#
#  Single-run diagnostic of how a network path filters traffic: DNS interference
#  (incl. answer injection), SNI/TLS blocking, RST injection + DPI localisation,
#  desync-bypass strategy matrix, HTTP host-blocking, ECH, UDP/QUIC suppression,
#  throttling, mobile TCP-freeze and behavioural freeze thresholds.
#
#  Run with ALL VPN/proxy tunnels DISABLED (host must egress via the net tested).
#  Root recommended (raw-socket RST-TTL analysis).   Usage:
#      sudo bash tspu-probe.sh [--quick] [--no-freeze] [--json] [--out DIR]
#                              [--timeout N] [--targets FILE] [-h]
#  Output: <out>/tspu-report-<ts>.txt (+ .json with --json). Read-only on host.
# =============================================================================
set -u

# --------------------------- CLI / config ----------------------------------
QUICK=0; NOFREEZE=0; JSON=0; OUTDIR="."; TIMEOUT=10; TARGETS_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --quick) QUICK=1;;
    --no-freeze) NOFREEZE=1;;
    --json) JSON=1;;
    --out) OUTDIR="${2:-.}"; shift;;
    --timeout) TIMEOUT="${2:-10}"; shift;;
    --targets) TARGETS_FILE="${2:-}"; shift;;
    -h|--help)
      grep -E '^#( |!)' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown arg: $1 (use -h)"; exit 2;;
  esac; shift
done
[ "$QUICK" = 1 ] && NOFREEZE=1

TS="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo run)"
mkdir -p "$OUTDIR" 2>/dev/null
OUT="${OUTDIR%/}/tspu-report-${TS}.txt"
JOUT="${OUTDIR%/}/tspu-report-${TS}.json"
PY="$(mktemp /tmp/tspu_py.XXXXXX.py)"
RESOLVED="$(mktemp /tmp/tspu_res.XXXXXX)"
JSONF="$(mktemp /tmp/tspu_json.XXXXXX)"    # accumulates "key\tvalue" json fragments
trap 'rm -f "$PY" "$RESOLVED" "$JSONF"' EXIT
: > "$OUT"; : > "$JSONF"

log(){ printf '%s\n' "$*" | tee -a "$OUT"; }
sec(){ log ""; log "==== $* ===================================================="; }
have(){ command -v "$1" >/dev/null 2>&1; }
jput(){ printf '%s\t%s\n' "$1" "$2" >> "$JSONF"; }   # record for JSON summary

log "tspu-probe 2.0  ts=$TS host=$(hostname 2>/dev/null) uid=$(id -u) quick=$QUICK"
log "local=$(date 2>/dev/null) utc=$(date -u 2>/dev/null) timeout=${TIMEOUT}s"
[ "$(id -u)" = 0 ] && { log "ROOT: yes"; ROOT=1; } || { log "ROOT: no (raw tests skipped; rerun with sudo)"; ROOT=0; }
for t in python3 curl dig openssl; do have "$t" && log "tool $t ok" || log "tool $t MISSING"; done

# --------------------------- embedded python -------------------------------
cat > "$PY" <<'PYEOF'
import sys, socket, ssl, time, json, os

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
        except: pass

def tcp_syn(ip, port):
    t0=time.time()
    try:
        s=socket.create_connection((ip,int(port)),timeout=TMO); s.close()
        return {"status":"OPEN","t":round(time.time()-t0,3)}
    except ConnectionResetError: return {"status":"RST","t":round(time.time()-t0,3)}
    except socket.timeout: return {"status":"TIMEOUT","t":round(time.time()-t0,3)}
    except ConnectionRefusedError: return {"status":"REFUSED","t":round(time.time()-t0,3)}
    except Exception as e: return {"status":"ERR","detail":str(e)}

def hop(ip, sni, maxttl=24):
    # locate DPI: TCP handshake at default TTL, then send ClientHello at rising IP_TTL.
    # smallest TTL that yields an injected RST ~= DPI hop distance.
    ch=build_ch(sni); trace=[]; dpi=None
    for ttl in range(1, maxttl+1):
        s=None; res="?"
        try:
            s=socket.create_connection((ip,443),timeout=min(TMO,5))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.sendall(ch); s.settimeout(min(TMO,4))
            try:
                d=s.recv(64); res="OK" if (d[:1]==b'\x16') else ("EOF" if not d else "DATA")
            except ConnectionResetError: res="RST"
            except socket.timeout: res="TO"
        except ConnectionResetError: res="RST0"
        except Exception: res="ERR"
        finally:
            try: s.close()
            except: pass
        trace.append([ttl,res])
        if res=="RST" and dpi is None: dpi=ttl; break
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

def dnsmulti(resolver, domain, window=3.0):
    # detect answer injection: collect ALL responses to one query
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2.0)
        s.connect((resolver,53)); s.send(_dns_query(domain))
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

def dns_tcp(resolver, domain):
    try:
        q=_dns_query(domain); s=socket.create_connection((resolver,53),timeout=TMO)
        s.sendall(len(q).to_bytes(2,'big')+q); d=s.recv(2048); s.close()
        return {"status":"OK","ips":_parse_a(d[2:])}
    except ConnectionResetError: return {"status":"RST"}
    except socket.timeout: return {"status":"TIMEOUT"}
    except Exception as e: return {"status":"ERR","detail":str(e)}

def stun(host, port=19302):
    try:
        m=b'\x00\x01\x00\x00\x21\x12\xa4\x42'+os.urandom(12)
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(5.0)
        s.sendto(m,(socket.gethostbyname(host),port)); d,_=s.recvfrom(2048); s.close()
        return {"status":"OK","len":len(d)}
    except socket.timeout: return {"status":"TIMEOUT"}
    except Exception as e: return {"status":"ERR","detail":str(e)}

def ntp(host):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(5.0)
        s.sendto(b'\x1b'+47*b'\0',(socket.gethostbyname(host),123)); d,_=s.recvfrom(1024); s.close()
        return {"status":"OK","len":len(d)}
    except socket.timeout: return {"status":"TIMEOUT"}
    except Exception as e: return {"status":"ERR","detail":str(e)}

def raw_rst(ip, sni, dur=8.0):
    try:
        s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)); s.settimeout(1.0)
    except Exception as e: return {"error":"raw socket: "+str(e)}
    import threading
    def fire():
        try:
            c=socket.create_connection((ip,443),timeout=5); c.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            c.sendall(build_ch(sni))
            try: c.recv(2048)
            except Exception: pass
            c.close()
        except Exception: pass
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
    r={k:sorted(v) for k,v in out.items()}; r["pkts"]=n; return r

if __name__=="__main__":
    c=sys.argv[1]; a=sys.argv[2:]
    if   c=="tls":     print(json.dumps(tls_probe(a[0],a[1],a[2] if len(a)>2 else "none")))
    elif c=="syn":     print(json.dumps(tcp_syn(a[0],a[1])))
    elif c=="hop":     print(json.dumps(hop(a[0],a[1])))
    elif c=="dnsmulti":print(json.dumps(dnsmulti(a[0],a[1])))
    elif c=="dnstcp":  print(json.dumps(dns_tcp(a[0],a[1])))
    elif c=="stun":    print(json.dumps(stun(a[0])))
    elif c=="ntp":     print(json.dumps(ntp(a[0])))
    elif c=="rawrst":  print(json.dumps(raw_rst(a[0],a[1])))
PYEOF
export TPTMO="$TIMEOUT"
py(){ python3 "$PY" "$@"; }
pytls(){ python3 "$PY" tls "$1" "$2" "${3:-none}"; }
st(){ python3 -c "import sys,json;print(json.load(sys.stdin).get('status','?'))" 2>/dev/null; }

# DoH resolver with fallbacks + file cache (survives subshells)
resolve(){
  local d="$1" ip
  ip=$(grep -m1 "^${d} " "$RESOLVED" 2>/dev/null | awk '{print $2}')
  [ -n "$ip" ] && { echo "$ip"; return; }
  for u in "https://dns.google/resolve?name=${d}&type=A" \
           "https://cloudflare-dns.com/dns-query?name=${d}&type=A" \
           "https://dns.quad9.net:5053/dns-query?name=${d}&type=A"; do
    ip=$(curl -s --max-time 8 -H 'accept: application/dns-json' "$u" 2>/dev/null | grep -oE '"data":"[0-9.]+"' | grep -oE '[0-9.]+' | head -1)
    [ -n "$ip" ] && break
  done
  [ -n "$ip" ] && echo "${d} ${ip}" >> "$RESOLVED"
  echo "$ip"
}

# canaries (override with --targets FILE : one host per line)
if [ -n "$TARGETS_FILE" ] && [ -f "$TARGETS_FILE" ]; then
  CANARY="$(grep -vE '^\s*#|^\s*$' "$TARGETS_FILE" | tr '\n' ' ')"
else
  CANARY="rutracker.org www.torproject.org bridges.torproject.org x.com www.instagram.com www.facebook.com discord.com proton.me protonvpn.com www.youtube.com signal.org twitter.com"
fi
[ "$QUICK" = 1 ] && CANARY="rutracker.org www.torproject.org x.com discord.com www.youtube.com"

# ======================= 0. VANTAGE =======================
sec "0. VANTAGE (tunnels must be OFF)"
EIF=$(ip route get 1.1.1.1 2>/dev/null | grep -oE 'dev [^ ]+' | awk '{print $2}' | head -1)
V=$(curl -s --max-time 12 "http://ip-api.com/json/?fields=status,country,regionName,city,isp,as,mobile,proxy,query" 2>/dev/null)
log "ip-api: $V"
CC=$(printf '%s' "$V"|grep -oE '"country":"[^"]*"'|cut -d'"' -f4); ASN=$(printf '%s' "$V"|grep -oE '"as":"[^"]*"'|cut -d'"' -f4)
MOB=$(printf '%s' "$V"|grep -oE '"mobile":[a-z]+'|cut -d: -f2)
V6=$(curl -s6 --max-time 8 https://api64.ipify.org 2>/dev/null)
log "egress-if: ${EIF:-?}  mtu: $(ip link show "${EIF:-lo}" 2>/dev/null|grep -oE 'mtu [0-9]+')"
log "ipv4=$(printf '%s' "$V"|grep -oE '"query":"[^"]*"'|cut -d'"' -f4)  ipv6=${V6:-none}  mobile=$MOB"
jput vantage.country "$CC"; jput vantage.asn "$ASN"; jput vantage.mobile "$MOB"; jput vantage.iface "${EIF:-}"
if [ "$CC" != "Russia" ]; then
  log "!!! WARNING: egress country=$CC (not Russia) — a VPN/tunnel is likely still ON."
  log "!!! Disable all tunnels and re-run; results are invalid otherwise."
  jput vantage.valid "false"
else log ">>> OK vantage: $CC / $ASN"; jput vantage.valid "true"; fi

# ======================= 1. CONTROL =======================
sec "1. CONTROL connectivity + baseline latency"
for d in ya.ru mail.ru gosuslugi.ru dzen.ru example.com cloudflare.com wikipedia.org; do
  log "control $d : $(curl -s -o /dev/null --max-time 12 -w 'code=%{http_code} tcp=%{time_connect} tls=%{time_appconnect} ttfb=%{time_starttransfer}' "https://$d/" 2>/dev/null || echo FAIL)"
done

# ======================= 2. DNS =======================
sec "2. DNS interference (poisoning / refusal / INJECTION / DoT / TCP-53)"
GW=$(ip route show default 2>/dev/null|grep -oE 'via [0-9.]+'|awk '{print $2}'|head -1); log "gateway=$GW sys=127.0.0.53"
for d in rutracker.org www.torproject.org x.com discord.com; do
  sys=$(dig +short +time=3 +tries=1 "$d" A 2>/dev/null|tr '\n' ',')
  u8=$(dig +short +time=3 +tries=1 @8.8.8.8 "$d" A 2>/dev/null|tr '\n' ',')
  ya=$(dig +short +time=3 +tries=1 @77.88.8.8 "$d" A 2>/dev/null|tr '\n' ',')
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
log "  dot 1.1.1.1: $(timeout 8 bash -c \"echo | openssl s_client -connect 1.1.1.1:853 -servername one.one.one.one -brief 2>&1 | grep -iE 'protocol|CONNECTED|error' | tr '\\n' ' '\" 2>/dev/null || echo FAIL)"

# ======================= 3. IP REACHABILITY =======================
sec "3. IP reachability (TCP SYN :443/:80 — IP-block vs SNI-block)"
for d in $CANARY; do
  ip=$(resolve "$d"); [ -z "$ip" ] && { log "reach $d: NO-IP"; continue; }
  s443=$(py syn "$ip" 443); s80=$(py syn "$ip" 80)
  log "reach $d ($ip): 443=$s443 80=$s80"
done

# ======================= 4. SNI FILTERING + DESYNC MATRIX =======================
sec "4. SNI filtering + DESYNC matrix (normal/split@1/@4/@SNI/TLS-rec, x3)"
log "OK=ServerHello · RST=inject · TIMEOUT=drop | 3 tries -> consistency"
maj(){ python3 - "$@" <<'P'
import sys,collections
c=collections.Counter(sys.argv[1:]); v,n=c.most_common(1)[0]; print(f"{v}({n}/{len(sys.argv)-1})")
P
}
for d in $CANARY; do
  ip=$(resolve "$d"); [ -z "$ip" ] && { log "sni $d: NO-IP"; continue; }
  declare -A R=()
  for m in none s1 s4 sni trec; do
    a=$(pytls "$ip" "$d" "$m"|st); b=$(pytls "$ip" "$d" "$m"|st); c=$(pytls "$ip" "$d" "$m"|st)
    R[$m]=$(maj "$a" "$b" "$c")
  done
  log "sni $d ($ip): normal=${R[none]} split1=${R[s1]} split4=${R[s4]} splitSNI=${R[sni]} TLSrec=${R[trec]}"
  jput "sni.$d" "normal=${R[none]};s1=${R[s1]};s4=${R[s4]};sni=${R[sni]};trec=${R[trec]}"
done

# ======================= 5. SNI-vs-IP ISOLATION =======================
sec "5. SNI-vs-IP isolation (benign/empty SNI to blocked IP)"
for d in www.torproject.org discord.com rutracker.org protonvpn.com; do
  ip=$(resolve "$d"); [ -z "$ip" ] && { log "iso $d: NO-IP"; continue; }
  log "iso $d ($ip): blockedSNI=$(pytls "$ip" "$d" none|st) benign=$(pytls "$ip" example.com none|st) emptySNI=$(pytls "$ip" '' none|st)"
done
log "(benign/empty=OK & blocked!=OK -> keyed on SNI, not IP)"

# ======================= 6. HTTP:80 + FRONTING =======================
sec "6. HTTP:80 Host-block + RKN stub + domain-fronting probe"
for d in rutracker.org www.torproject.org x.com; do
  h=$(curl -s -D - -o /dev/null --max-time 10 "http://$d/" 2>/dev/null | tr -d '\r' | grep -iE '^HTTP/|^location:' | tr '\n' ' | ')
  body=$(curl -s --max-time 10 "http://$d/" 2>/dev/null | grep -aoiE 'заблокирован|ограничен доступ|единый реестр|blocklist|заглушк|warning' | head -1)
  log "http80 $d : ${h:-no-response} :: stub=[${body:-none}]"
done
log "-- domain-fronting (TLS-SNI=allowed, HTTP-Host=blocked, same CDN) --"
log "  front cloudflare.com->x.com: $(curl -s -o /dev/null --max-time 10 -w 'code=%{http_code}' --resolve x.com:443:$(resolve cloudflare.com) https://cloudflare.com/ -H 'Host: x.com' 2>/dev/null||echo FAIL)"

# ======================= 7. ECH =======================
sec "7. ECH / Encrypted ClientHello (DoH-bootstrap)"
log "curl ECH: $(curl --help all 2>&1|grep -oE '\-\-ech <config>'|head -1||echo none)"
for d in crypto.cloudflare.com cloudflare.com; do
  rr=$(curl -s --max-time 10 "https://dns.google/resolve?name=${d}&type=HTTPS" 2>/dev/null | grep -oE '"data":"[^"]*ech[^"]*"' | head -1)
  log "  https-rr $d : $([ -n "$rr" ] && echo 'ECHConfig-present' || echo none)"
done
if curl --help all 2>&1|grep -q '\-\-ech'; then
  for d in crypto.cloudflare.com cloudflare.com; do
    r=$(curl -s --max-time 15 --ech true --doh-url https://cloudflare-dns.com/dns-query "https://$d/cdn-cgi/trace" 2>&1 | grep -iE 'sni=|http/' | tr '\n' ' ')
    log "  ech-live $d : ${r:-FAILED}"
  done
  log "  (sni=encrypted -> ECH passed through; else -> ECH not usable on this path)"
else log "  curl без --ech"; fi

# ======================= 8. UDP PORT-PROFILE =======================
sec "8. UDP port-profile (DNS:53 / NTP:123 / STUN:3478 / QUIC:443)"
for r in 1.1.1.1 8.8.8.8 77.88.8.8; do
  log "udp53 @$r: $(dig +time=4 +tries=1 @$r example.com A 2>&1|grep -oE 'status: [A-Z]+|timed out'|head -1)"
done
log "udp123 NTP: $(py ntp time.google.com)   udp3478 STUN: $(py stun stun.l.google.com)"
if curl --version 2>/dev/null|grep -qi HTTP3; then
  for d in cloudflare-quic.com www.google.com; do
    log "udp443 QUIC $d: $(curl -sI --http3-only --max-time 12 "https://$d/" -o /dev/null -w 'code=%{http_code} t=%{time_total}' 2>&1||echo FAIL)"
  done
fi
log "(DNS/NTP/STUN pass but QUIC:443 fails -> QUIC/port-443-UDP targeting, not all-UDP)"

# ======================= 9. THROTTLE + 16KB FREEZE =======================
sec "9. Throughput / throttle + mobile 16KB TCP-freeze (Range 256KB)"
declare -A DL=( [RU_yandex]="https://mirror.yandex.ru/debian/ls-lR.gz" \
                [RU_mailru]="https://limitpg.mail.ru/cgi-bin/readmsg" \
                [FOR_ovh]="https://proof.ovh.net/files/1Mb.dat" \
                [FOR_hetzner]="https://fsn1-speed.hetzner.com/100MB.bin" \
                [FOR_cachefly]="https://cachefly.cachefly.net/10mb.test" )
for k in "${!DL[@]}"; do
  r=$(curl -s -o /dev/null --max-time 25 -r 0-262143 -w 'got=%{size_download}B time=%{time_total}s spd=%{speed_download}B/s' "${DL[$k]}" 2>/dev/null)
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
    log "  rst-ttl $d ($ip): $(py rawrst "$ip" "$d")"
  done
  log "  (RST TTL != SYNACK TTL -> middlebox injection; ignorable by TTL)"
else log "  (RST-TTL needs root)"; fi
log "-- residual/stateful hold after RST --"
ip=$(resolve www.torproject.org)
if [ -n "$ip" ]; then
  log "  trigger: $(pytls "$ip" www.torproject.org none|st)"
  for t in 0 2 5; do sleep "$t"; log "  +cum${t}s benign->same-ip: $(pytls "$ip" example.com none|st)"; done
fi

# ======================= 11. BEHAVIORAL FREEZE =======================
if [ "$NOFREEZE" = 0 ]; then
sec "11. Behavioral freeze — N-sweep + repeat (ADVERSARIAL, LAST)"
CTRL="https://ya.ru/"; TSNI="www.youtube.com"; TIP=$(resolve "$TSNI")
log "trigger=$TSNI ip=${TIP:-x} control=$CTRL"
pc(){ curl -s -o /dev/null --max-time 4 -w '%{time_total}' "$CTRL" 2>/dev/null || echo FREEZE; }
log "baseline ctrl: $(pc) $(pc) $(pc)"
run_round(){
  local N=$1 frozen=0 onset="" recov="" k c
  [ -n "${TIP:-}" ] && for i in $(seq 1 "$N"); do ( python3 "$PY" tls "$TIP" "$TSNI" none >/dev/null 2>&1 ) & done
  for k in $(seq 1 18); do
    c=$(pc); if printf '%s' "$c"|grep -q FREEZE; then frozen=$((frozen+1)); [ -z "$onset" ] && onset=$k; else [ "$frozen" -gt 0 ] && [ -z "$recov" ] && recov=$k; fi
    sleep 1.5
  done
  wait 2>/dev/null
  if [ "$frozen" -gt 0 ]; then log "  N=$N: FREEZE (onset_poll=${onset} dur≈$((frozen*3/2))s recov_poll=${recov:-'>18'})"; jput "freeze.N$N" "yes(${frozen}poll)"
  else log "  N=$N: no-freeze"; jput "freeze.N$N" "no"; fi
}
for N in 4 8 12 16 20; do log "-- round N=$N --"; run_round "$N"; log "  settle 12s"; sleep 12; done
log "-- repeat first freezing level --"; for N in 16; do run_round "$N"; done
else sec "11. Behavioral freeze — SKIPPED (--no-freeze/--quick)"; fi

# ======================= SUMMARY + VERDICT =======================
sec "SUMMARY + VERDICT"
DESYNC_WIN=$(grep -E '^sni ' "$OUT" | grep -oE 'splitSNI=OK|TLSrec=OK|split1=OK|split4=OK' | sort -u | tr '\n' ' ')
log "vantage: $CC / $ASN / mobile=$MOB"
log "desync that bypassed at least one block: ${DESYNC_WIN:-none-observed}"
log "verdict hints: см. §4 (какой desync=OK на заблокированных доменах -> рабочая стратегия обхода),"
log "               §8 (жив ли UDP), §9 (троттл/freeze), §10 (dpi_hop -> fake-TTL для zapret/byedpi)"
log "DONE. Report: $OUT"

if [ "$JSON" = 1 ]; then
  python3 - "$JSONF" "$TS" "$CC" "$ASN" > "$JOUT" <<'P'
import sys,json
rows=[l.rstrip('\n').split('\t',1) for l in open(sys.argv[1]) if '\t' in l]
o={"ts":sys.argv[2],"country":sys.argv[3],"asn":sys.argv[4],"data":{}}
for k,v in rows: o["data"][k]=v
json.dump(o,sys.stdout,ensure_ascii=False,indent=2)
P
  log "JSON: $JOUT"
fi
