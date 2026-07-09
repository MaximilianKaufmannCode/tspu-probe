#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# =============================================================================
#  tspu-probe — single-run ТСПУ/DPI censorship-measurement probe (RU networks)
#  Copyright (c) 2026 Maximilian Kaufmann. Licensed under the MIT License.
#
#  Run with ALL VPN/proxy tunnels DISABLED (the host must egress via the network
#  under test). Root recommended (enables raw-socket RST-TTL analysis):
#      sudo bash tspu-probe.sh
#  Output: ./tspu-report-<timestamp>.txt | traffic ~3-5 MB | runtime ~10-13 min
#  Read-only: makes no changes to the host; temp files are removed on exit.
# =============================================================================
set -u
TS="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo run)"
OUT="tspu-report-${TS}.txt"
PY="$(mktemp /tmp/tspu2_py.XXXXXX.py)"
RESOLVED="$(mktemp /tmp/tspu2_res.XXXXXX)"
trap 'rm -f "$PY" "$RESOLVED"' EXIT
log(){ printf '%s\n' "$*" | tee -a "$OUT"; }
sec(){ log ""; log "==== $* ===================================================="; }
have(){ command -v "$1" >/dev/null 2>&1; }
: > "$OUT"

log "TSPU PROBE v2  ts=$TS host=$(hostname 2>/dev/null) uid=$(id -u)"
log "local=$(date 2>/dev/null) utc=$(date -u 2>/dev/null)"
[ "$(id -u)" = 0 ] && log "ROOT: yes" || log "ROOT: no (raw tests skipped; rerun with sudo)"
for t in python3 curl dig openssl socat; do have "$t" && log "tool $t ok" || log "tool $t MISSING"; done

# ------------------------- embedded python ---------------------------------
cat > "$PY" <<'PYEOF'
import sys, socket, ssl, time, json, struct, os

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

def classify_recv(sock, t0, timeout):
    sock.settimeout(timeout)
    try:
        d = sock.recv(4096)
    except socket.timeout:
        return {"status":"TIMEOUT","t":round(time.time()-t0,3)}
    except ConnectionResetError:
        return {"status":"RST","t":round(time.time()-t0,3)}
    except Exception as e:
        return {"status":"ERR","detail":str(e),"t":round(time.time()-t0,3)}
    if not d:
        return {"status":"EOF","t":round(time.time()-t0,3)}
    # 0x16 0x03 = TLS handshake (ServerHello) -> not blocked
    if len(d)>=2 and d[0]==0x16 and d[1]==0x03:
        return {"status":"OK","t":round(time.time()-t0,3),"bytes":len(d)}
    if len(d)>=2 and d[0]==0x15:
        return {"status":"TLS_ALERT","t":round(time.time()-t0,3)}
    return {"status":"DATA","t":round(time.time()-t0,3),"head":d[:3].hex()}

def tls_probe(ip, sni, frag="none", port=443, timeout=10.0, delay=0.03):
    s=None
    try:
        ch=build_ch(sni)
        if not ch: return {"status":"CTXERR"}
        t0=time.time()
        s=socket.create_connection((ip,port),timeout=timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if frag=="none":
            s.sendall(ch)
        elif frag=="s1":
            s.send(ch[:1]); time.sleep(delay); s.send(ch[1:])
        elif frag=="sni":
            sb=(sni or "").encode()
            p=ch.find(sb)
            if p<0: p=len(ch)//2
            else: p=p+max(1,len(sb)//2)   # split inside the hostname
            s.send(ch[:p]); time.sleep(delay); s.send(ch[p:])
        else:
            s.sendall(ch)
        return classify_recv(s,t0,timeout)
    except ConnectionResetError: return {"status":"RST","t":0.0}
    except socket.timeout: return {"status":"TIMEOUT","t":0.0}
    except ConnectionRefusedError: return {"status":"REFUSED","t":0.0}
    except Exception as e: return {"status":"ERR","detail":str(e)}
    finally:
        try: s.close()
        except: pass

def tcp_syn(ip, port, timeout=6.0):
    t0=time.time()
    try:
        s=socket.create_connection((ip,int(port)),timeout=timeout); s.close()
        return {"status":"OPEN","t":round(time.time()-t0,3)}
    except ConnectionResetError: return {"status":"RST","t":round(time.time()-t0,3)}
    except socket.timeout: return {"status":"TIMEOUT","t":round(time.time()-t0,3)}
    except ConnectionRefusedError: return {"status":"REFUSED","t":round(time.time()-t0,3)}
    except Exception as e: return {"status":"ERR","detail":str(e)}

def stun(host, port=19302, timeout=5.0):
    # STUN binding request (RFC5389), magic cookie
    try:
        msg = b'\x00\x01\x00\x00\x21\x12\xa4\x42' + os.urandom(12)
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(timeout)
        ip=socket.gethostbyname(host)
        t0=time.time(); s.sendto(msg,(ip,int(port)))
        d,_=s.recvfrom(2048); s.close()
        return {"status":"OK","t":round(time.time()-t0,3),"len":len(d)}
    except socket.timeout: return {"status":"TIMEOUT"}
    except Exception as e: return {"status":"ERR","detail":str(e)}

def ntp(host, timeout=5.0):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(timeout)
        ip=socket.gethostbyname(host)
        t0=time.time(); s.sendto(b'\x1b'+47*b'\0',(ip,123))
        d,_=s.recvfrom(1024); s.close()
        return {"status":"OK","t":round(time.time()-t0,3),"len":len(d)}
    except socket.timeout: return {"status":"TIMEOUT"}
    except Exception as e: return {"status":"ERR","detail":str(e)}

def raw_rst(ip, sni, dur=8.0):
    # capture TTL of packets from ip:443 while firing a ClientHello; distinguish injected RST
    try:
        s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)); s.settimeout(1.0)
    except Exception as e:
        return {"error":"raw socket: "+str(e)}
    import threading
    def fire():
        try:
            c=socket.create_connection((ip,443),timeout=5); c.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            c.sendall(build_ch(sni));
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
        src=socket.inet_ntoa(ipd[12:16])
        if proto!=6 or src!=ip: continue
        tcp=ipd[ihl:];
        if len(tcp)<14: continue
        fl=tcp[13]; n+=1
        if fl&0x04: out["RST"].add(ttl)
        elif fl&0x02: out["SYNACK"].add(ttl)
        else: out["other"].add(ttl)
    r={k:sorted(v) for k,v in out.items()}; r["pkts"]=n; return r

if __name__=="__main__":
    c=sys.argv[1]
    if c=="tls":   print(json.dumps(tls_probe(sys.argv[2],sys.argv[3],sys.argv[4] if len(sys.argv)>4 else "none")))
    elif c=="syn": print(json.dumps(tcp_syn(sys.argv[2],sys.argv[3])))
    elif c=="stun":print(json.dumps(stun(sys.argv[2])))
    elif c=="ntp": print(json.dumps(ntp(sys.argv[2])))
    elif c=="rawrst": print(json.dumps(raw_rst(sys.argv[2],sys.argv[3])))
PYEOF
pytls(){ python3 "$PY" tls "$1" "$2" "${3:-none}"; }

# DoH resolver with retries + file cache (bypasses ISP DNS interference, survives subshells)
resolve(){
  local d="$1" ip
  ip=$(grep -m1 "^${d} " "$RESOLVED" 2>/dev/null | awk '{print $2}')
  [ -n "$ip" ] && { echo "$ip"; return; }
  for attempt in 1 2 3; do
    ip=$(curl -s --max-time 8 "https://dns.google/resolve?name=${d}&type=A" 2>/dev/null | grep -oE '"data":"[0-9.]+"' | grep -oE '[0-9.]+' | head -1)
    [ -z "$ip" ] && ip=$(curl -s --max-time 8 -H 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=${d}&type=A" 2>/dev/null | grep -oE '"data":"[0-9.]+"' | grep -oE '[0-9.]+' | head -1)
    [ -n "$ip" ] && break; sleep 1
  done
  [ -n "$ip" ] && echo "${d} ${ip}" >> "$RESOLVED"
  echo "$ip"
}

CANARY="rutracker.org www.torproject.org bridges.torproject.org x.com www.instagram.com www.facebook.com discord.com proton.me protonvpn.com www.youtube.com signal.org twitter.com"

# ======================= 0. VANTAGE =======================
sec "0. VANTAGE (tunnels must be OFF)"
V=$(curl -s --max-time 12 "http://ip-api.com/json/?fields=status,country,regionName,city,isp,as,mobile,proxy,query" 2>/dev/null)
log "ip-api: $V"
CC=$(printf '%s' "$V"|grep -oE '"country":"[^"]*"'|cut -d'"' -f4); ASN=$(printf '%s' "$V"|grep -oE '"as":"[^"]*"'|cut -d'"' -f4)
log "egress-if: $(ip route get 1.1.1.1 2>/dev/null|head -1)"
log "wlan0 MTU: $(ip link show wlan0 2>/dev/null|grep -oE 'mtu [0-9]+')"
if [ "$CC" != "Russia" ]; then
  log "!!! WARNING: egress country=$CC (not Russia) — a VPN/tunnel is likely still ON."
  log "!!! Disable all tunnels and re-run; results are invalid otherwise."
else log ">>> OK vantage: $CC / $ASN"; fi

# ======================= 1. CONTROL =======================
sec "1. CONTROL connectivity + baseline latency"
for d in ya.ru mail.ru gosuslugi.ru dzen.ru example.com cloudflare.com wikipedia.org; do
  log "control $d : $(curl -s -o /dev/null --max-time 12 -w 'code=%{http_code} tcp=%{time_connect} tls=%{time_appconnect} ttfb=%{time_starttransfer}' "https://$d/" 2>/dev/null || echo FAIL)"
done

# ======================= 2. DNS =======================
sec "2. DNS resolution/poisoning (sys vs UDP-foreign vs UDP-RU vs DoH)"
GW=$(ip route show default 2>/dev/null|grep -oE 'via [0-9.]+'|awk '{print $2}'|head -1); log "gateway=$GW sys=127.0.0.53"
for d in rutracker.org www.torproject.org x.com discord.com; do
  sys=$(dig +short +time=3 +tries=1 "$d" A 2>/dev/null|tr '\n' ',')
  u8=$(dig +short +time=3 +tries=1 @8.8.8.8 "$d" A 2>/dev/null|tr '\n' ',')
  ya=$(dig +short +time=3 +tries=1 @77.88.8.8 "$d" A 2>/dev/null|tr '\n' ',')
  doh=$(resolve "$d")
  log "dns $d : sys=[${sys:-x}] udp8.8.8.8=[${u8:-x}] udpYandex=[${ya:-x}] DoH=[${doh:-x}]"
done
log "(poisoning=RU/sys отдаёт IP != DoH или приватный/blockpage; refusal=пусто)"

# ======================= 3. IP-REACHABILITY of canaries =======================
sec "3. IP reachability (TCP SYN to :443/:80 — IP-block vs SNI-block)"
for d in $CANARY; do
  ip=$(resolve "$d"); [ -z "$ip" ] && { log "reach $d: NO-IP"; continue; }
  log "reach $d ($ip): syn443=$(python3 "$PY" syn "$ip" 443) syn80=$(python3 "$PY" syn "$ip" 80)"
done

# ======================= 4. SNI FILTERING + FRAG =======================
sec "4. SNI filtering: normal vs split@1 vs split@SNI (desync)"
log "OK=ServerHello получен · RST=инъекция · TIMEOUT=drop"
for d in $CANARY; do
  ip=$(resolve "$d"); [ -z "$ip" ] && { log "sni $d: NO-IP"; continue; }
  log "sni $d ($ip): normal=$(pytls "$ip" "$d" none) | split1=$(pytls "$ip" "$d" s1) | splitSNI=$(pytls "$ip" "$d" sni)"
done

# ======================= 5. SNI-vs-IP ISOLATION =======================
sec "5. SNI-vs-IP isolation (benign/empty SNI to blocked IP)"
for d in www.torproject.org discord.com rutracker.org protonvpn.com; do
  ip=$(resolve "$d"); [ -z "$ip" ] && { log "iso $d: NO-IP"; continue; }
  log "iso $d ($ip): blockedSNI=$(pytls "$ip" "$d" none) | benign(example.com)=$(pytls "$ip" example.com none) | emptySNI=$(pytls "$ip" '' none)"
done
log "(benign/empty=OK & blocked=RST/TIMEOUT -> блок по SNI, не по IP)"

# ======================= 6. HTTP:80 Host-blocking + RKN stub =======================
sec "6. HTTP:80 Host-based blocking + RKN stub-page detection"
for d in rutracker.org www.torproject.org x.com; do
  h=$(curl -s -D - -o /dev/null --max-time 10 "http://$d/" 2>/dev/null | tr -d '\r' | grep -iE '^HTTP/|^location:|^server:' | tr '\n' ' | ')
  body=$(curl -s --max-time 10 "http://$d/" 2>/dev/null | grep -aoiE 'заблокирован|ограничен доступ|единый реестр|warning|blocklist|rkn|заглушк' | head -1)
  log "http80 $d : ${h:-no-response} :: stub=[${body:-none}]"
done
log "(302 на warning/blockpage или 'доступ ограничен' -> HTTP-цензура заглушкой; RST/timeout -> тот же DPI)"

# ======================= 7. ECH (fixed: DoH bootstrap) =======================
sec "7. ECH / Encrypted ClientHello (DoH-bootstrap)"
log "curl ECH: $(curl --help all 2>&1|grep -oE '\-\-ech <config>'|head -1||echo none) | openssl ech: $(openssl s_client -help 2>&1|grep -ic ech)"
log "ECHConfig via DoH (HTTPS RR / type=65):"
for d in crypto.cloudflare.com cloudflare.com www.cloudflare.com; do
  rr=$(curl -s --max-time 10 "https://dns.google/resolve?name=${d}&type=HTTPS" 2>/dev/null | grep -oE '"data":"[^"]*ech[^"]*"' | head -1)
  log "  https-rr $d : ${rr:-none}"
done
if curl --help all 2>&1|grep -q '\-\-ech'; then
  for d in crypto.cloudflare.com cloudflare.com; do
    r=$(curl -s --max-time 15 --ech true --doh-url https://cloudflare-dns.com/dns-query "https://$d/cdn-cgi/trace" 2>&1 | grep -iE 'sni=|http/2|http/3' | tr '\n' ' ')
    log "  ech-live $d : ${r:-FAILED(no-trace)}"
  done
  log "  (sni=encrypted -> ECH сработал сквозь ТСПУ; sni=plaintext/FAILED -> ECH не прошёл)"
else log "  curl без --ech"; fi

# ======================= 8. UDP PORT-PROFILE =======================
sec "8. UDP port-profile (что из UDP реально проходит)"
log "udp53 DNS  @1.1.1.1: $(dig +time=4 +tries=1 @1.1.1.1 example.com A 2>&1|grep -oE 'status: [A-Z]+|timed out'|head -1)"
log "udp53 DNS  @8.8.8.8: $(dig +time=4 +tries=1 @8.8.8.8 example.com A 2>&1|grep -oE 'status: [A-Z]+|timed out'|head -1)"
log "udp53 DNS  @77.88.8.8(RU): $(dig +time=4 +tries=1 @77.88.8.8 example.com A 2>&1|grep -oE 'status: [A-Z]+|timed out'|head -1)"
log "udp123 NTP time.google.com: $(python3 "$PY" ntp time.google.com)"
log "udp123 NTP pool.ntp.org:     $(python3 "$PY" ntp pool.ntp.org)"
log "udp3478 STUN google:         $(python3 "$PY" stun stun.l.google.com)"
if curl --version 2>/dev/null|grep -qi HTTP3; then
  for d in cloudflare-quic.com www.google.com; do
    log "udp443 QUIC $d: $(curl -sI --http3-only --max-time 12 "https://$d/" -o /dev/null -w 'code=%{http_code} t=%{time_total}' 2>&1||echo FAIL)"
  done
fi
log "(если DNS/NTP/STUN проходят, а QUIC:443 нет -> таргетинг QUIC-сигнатуры/порт-443-UDP, а не весь UDP)"

# ======================= 9. MOBILE LARGE-TRANSFER / 16KB-FREEZE =======================
sec "9. Mobile 16KB TCP-freeze (Range-capped 256KB; allowed RU + neutral foreign)"
declare -A DL=( [RU_yandex]="https://mirror.yandex.ru/debian/ls-lR.gz" [RU_vk]="https://vk.com/images/upload.gif" [FOR_ovh]="https://proof.ovh.net/files/1Mb.dat" [FOR_hetzner]="https://ash-speed.hetzner.com/100MB.bin" [FOR_cachefly]="https://cachefly.cachefly.net/10mb.test" )
for k in "${!DL[@]}"; do
  r=$(curl -s -o /dev/null --max-time 25 -r 0-262143 -w 'got=%{size_download} time=%{time_total} spd=%{speed_download}' "${DL[$k]}" 2>/dev/null)
  log "dl $k : ${r:-FAILED} url=${DL[$k]}"
done
log "(foreign got~16-64KB при time~=max -> mobile freeze на зарубежном; RU got=256KB -> норм)"

# ======================= 10. RST-INJECTION + RESIDUAL (root) =======================
sec "10. RST-injection TTL fingerprint + residual/stateful censorship"
if [ "$(id -u)" = 0 ]; then
  for d in www.torproject.org rutracker.org protonvpn.com; do
    ip=$(resolve "$d"); [ -z "$ip" ] && continue
    log "rst-ttl $d ($ip): $(python3 "$PY" rawrst "$ip" "$d")"
  done
  log "(RST TTL != SYNACK TTL -> инъекция middlebox'а; можно фильтровать инжектированные RST по TTL)"
else log "  (not root — skip TTL)"; fi
# residual: after a blocked-SNI RST, is benign SNI to same IP also blocked for a window?
log "-- residual censorship (4-tuple/IP hold after RST) --"
ip=$(resolve www.torproject.org)
if [ -n "$ip" ]; then
  log "  trigger blocked: $(pytls "$ip" www.torproject.org none)"
  for t in 0 1 3 6; do sleep "$t"; log "  +${t}s benign->same-ip: $(pytls "$ip" example.com none)"; done
fi

# ======================= 11. BEHAVIORAL FREEZE (fine sweep) =======================
sec "11. Behavioral freeze — fine N-sweep + repeat (ADVERSARIAL, LAST test)"
CTRL="https://ya.ru/"; TSNI="www.youtube.com"; TIP=$(resolve "$TSNI")
log "trigger=$TSNI ip=${TIP:-x} control=$CTRL"
pc(){ curl -s -o /dev/null --max-time 4 -w '%{time_total}' "$CTRL" 2>/dev/null || echo FREEZE; }
log "baseline ctrl: $(pc) $(pc) $(pc)"
run_round(){
  local N=$1
  [ -n "${TIP:-}" ] && for i in $(seq 1 "$N"); do ( python3 "$PY" tls "$TIP" "$TSNI" none >/dev/null 2>&1 ) & done
  local frozen=0 onset="" recov="" k
  for k in $(seq 1 18); do
    c=$(pc); if printf '%s' "$c"|grep -q FREEZE; then frozen=$((frozen+1)); [ -z "$onset" ] && onset=$k; else [ "$frozen" -gt 0 ] && [ -z "$recov" ] && recov=$k; fi
    sleep 1.5
  done
  wait 2>/dev/null
  if [ "$frozen" -gt 0 ]; then log "  N=$N: FREEZE (onset≈$(printf %.0f $(echo "$onset*1.5"|bc 2>/dev/null||echo $onset))s dur≈$((frozen))*1.5s recov_poll=${recov:-'>18'})"
  else log "  N=$N: no-freeze"; fi
}
for N in 4 8 12 16 20; do log "-- round N=$N --"; run_round "$N"; log "  settle 12s"; sleep 12; done
log "-- confirm repeat of first freezing N --"; for N in 16 16; do run_round "$N"; sleep 12; done

# ======================= SUMMARY =======================
sec "SUMMARY (machine-readable)"
log "vantage=$CC/$ASN mobile=$(printf '%s' "$V"|grep -oE '"mobile":[a-z]+'|cut -d: -f2)"
log "DONE — пришли весь файл: $OUT"
