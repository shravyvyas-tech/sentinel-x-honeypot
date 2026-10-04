#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SENTINEL-X ULTIMATE + SHIELD
Anti-detection honeypot with locked fingerprint + scanner detection.
"""
import socket,threading,json,os,time,re,hashlib,secrets,queue,sys,collections,urllib.request,ipaddress,subprocess,traceback,random,struct,math
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from urllib.parse import urlparse,parse_qs
try:
    import geoip2.database
    _HAS_GEOIP2=True
except ImportError:
    _HAS_GEOIP2=False

DATA=os.path.join(os.path.dirname(os.path.abspath(__file__)),"sx_data")
os.makedirs(DATA,exist_ok=True)
CFG_F,AUTH_F,EV_F=(os.path.join(DATA,n) for n in("config.json","auth.json","events.jsonl"))
SHIELD_F=os.path.join(DATA,"shield.json")
GEOIP_DB_PATH=os.path.join(DATA,"GeoLite2-City.mmdb")
IPINFO_TOKEN=os.environ.get("IPINFO_TOKEN","")
SEV=["INFO","LOW","MEDIUM","HIGH","CRITICAL"]
LOCK=threading.RLock()

# ═══════════════════════════════════════════════════════════════════
#  SHIELD STATE — anti-detection layer
# ═══════════════════════════════════════════════════════════════════
SCAN_LOCK=threading.RLock()
SHIELD={
    "enabled": False,
    "locked_signature": None,   # {port: {"transport":"tcp","banner":"...","service":"HTTP"}}
    "locked_at": 0,
    "lock_note": "",
    "scanners": {},             # ip -> {"hits":[ts,...], "ports":{port:first_ts}, "banned_until":ts, "reason":""}
    "jitter": True,             # random delays
    "tarpit": True,             # slow down scanners
    "decoy_scan_response": True # give fake banner to scanners
}
SCAN_PORTS_THRESHOLD=8
SCAN_RATE_THRESHOLD=15
BAN_DURATION=300
JITTER_MAX_MS=280
TARPIT_DELAY=1.5

def shield_load():
    global SHIELD
    try:
        with open(SHIELD_F) as f:
            d=json.load(f)
        for k,v in d.items():
            if k in SHIELD: SHIELD[k]=v
    except:pass
def shield_save():
    try:
        with open(SHIELD_F,"w") as f:json.dump(SHIELD,f,indent=2,default=str)
        os.chmod(SHIELD_F,0o600)
    except:pass

def shield_record(ip,port):
    with SCAN_LOCK:
        now=time.time()
        s=SHIELD["scanners"].setdefault(ip,{"hits":[],"ports":{},"banned_until":0,"reason":"","first":now})
        s["hits"].append(now)
        if port not in s["ports"]:s["ports"][port]=now
        # Prune
        s["hits"]=[h for h in s["hits"] if now-h<60]
        s["ports"]={p:t for p,t in s["ports"].items() if now-t<60}
        # Detect
        if len(s["hits"])>=SCAN_RATE_THRESHOLD or len(s["ports"])>=SCAN_PORTS_THRESHOLD:
            if s["banned_until"]<now:
                s["banned_until"]=now+BAN_DURATION
                s["reason"]="Scanner: %d ports, %d hits/60s"%(len(s["ports"]),len(s["hits"]))
                return "NEW_BAN"
        return None

def shield_status(ip):
    with SCAN_LOCK:
        s=SHIELD["scanners"].get(ip)
        if not s:return {"banned":False,"hits":0,"ports":0}
        now=time.time()
        return {
            "banned":s.get("banned_until",0)>now,
            "banned_until":s.get("banned_until",0),
            "hits":len([h for h in s["hits"] if now-h<60]),
            "ports":len([p for p,t in s["ports"].items() if now-t<60]),
            "reason":s.get("reason","")
        }

def shield_jitter():
    """Add random micro-delay to confuse timing-based detection."""
    if SHIELD["jitter"]:
        time.sleep(random.uniform(0.005,JITTER_MAX_MS/1000))

def shield_tarpit():
    """Slow down attacker — mimics real service latency."""
    if SHIELD["tarpit"]:
        time.sleep(random.uniform(0.8,TARPIT_DELAY))

def shield_lock_current():
    """Snapshot current services config as the locked external fingerprint."""
    sig={}
    for n,c in CFG["services"].items():
        if c["enabled"]:
            sig[str(c["port"])]={
                "transport":c["transport"],
                "service":n,
                "banner":c["banner"],
                "hostname":c["hostname"]
            }
    SHIELD["locked_signature"]=sig
    SHIELD["locked_at"]=time.time()
    SHIELD["enabled"]=True
    shield_save()
    return sig

def shield_unlock():
    SHIELD["enabled"]=False
    shield_save()

def shield_get_decoy_for(port):
    """If shield enabled, return locked signature entry for this port."""
    if not SHIELD["enabled"] or not SHIELD["locked_signature"]:return None
    return SHIELD["locked_signature"].get(str(port))

def shield_should_serve_decoy(ip):
    """Should this connection get decoy treatment?"""
    st=shield_status(ip)
    if st["banned"]:return True
    if not SHIELD["enabled"]:return False
    # Aggressive behavior = decoy
    return st["hits"]>=5 or st["ports"]>=4

# ═══════════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════════
def svc(en,tr,port,banner,host="gateway",sens=1,maxc=50,to=30):
    return dict(enabled=en,transport=tr,port=port,banner=banner,hostname=host,
                sensitivity=sens,max_conn=maxc,timeout=to)
DEFAULT={"allow_signup":True,"listen_address":"0.0.0.0","web_port":8080,
    "web_session_timeout":1800,
    "alert":{"threshold":3,"brute":5,"conn_rate":20,"webhook":""},
    "web_lockout":{"attempts":6,"window":300,"ban":900},
    "geo":{"enabled":True,"endpoint":"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,proxy,hosting,query"},
    "services":{
        "HTTP":svc(True,"tcp",8081,"Apache/2.4.54 (Ubuntu)"),
        "HTTPS":svc(True,"tcp",8443,"nginx/1.22.1"),
        "FTP":svc(True,"tcp",2121,"220 (vsFTPd 3.0.5)"),
        "SSH":svc(True,"tcp",2222,"SSH-2.0-OpenSSH_8.9p1 Ubuntu"),
        "TELNET":svc(True,"tcp",2323,"Ubuntu 22.04 LTS"),
        "SMTP":svc(True,"tcp",2525,"220 mail.corp.local ESMTP"),
        "MYSQL":svc(True,"tcp",3307,"8.0.32-Ubuntu"),
        "REDIS":svc(True,"tcp",6380,"Redis 7.0.11"),
        "POSTGRES":svc(True,"tcp",5433,"PostgreSQL 15.3"),
        "POP3":svc(True,"tcp",1110,"+OK Dovecot ready."),
        "IMAP":svc(True,"tcp",1143,"* OK Dovecot ready."),
        "DNS":svc(True,"udp",5353,"BIND 9.18.12"),
        "SNMP":svc(True,"udp",1161,"Cisco IOS 15.2"),
        "TFTP":svc(True,"udp",6969,"tftpd-hpa"),
    }}

def _load(p,d):
    try:
        with open(p) as f:return json.load(f)
    except:return d
def _merge(a,b):
    for k,v in b.items():
        if isinstance(v,dict) and isinstance(a.get(k),dict):_merge(a[k],v)
        else:a[k]=v
    return a
CFG=_merge(json.loads(json.dumps(DEFAULT)),_load(CFG_F,{}))
def save_cfg():
    with open(CFG_F,"w") as f:json.dump(CFG,f,indent=2)
    try:os.chmod(CFG_F,0o600)
    except:pass

def send_webhook(ev):
    """Fire-and-forget alert to a Discord/Slack-compatible webhook on HIGH/CRITICAL events."""
    url=CFG["alert"].get("webhook","")
    if not url or not url.startswith(("http://","https://")):return
    try:
        txt="🚨 **%s** %s/%d from `%s` — %s"%(ev["sev"],ev["proto"],ev["dport"],ev["src"],ev["reason"])
        body=json.dumps({"content":txt,"text":txt}).encode()
        req=urllib.request.Request(url,data=body,headers={"Content-Type":"application/json"})
        urllib.request.urlopen(req,timeout=5)
    except:pass

# ═══════════════════════════════════════════════════════════════════
#  AUTH
# ═══════════════════════════════════════════════════════════════════
def _hpw(pw,salt):return hashlib.scrypt(pw.encode(),salt=salt,n=2**14,r=8,p=1).hex()
SESS={};SESSU={}
WEB_FAIL=collections.defaultdict(collections.deque);WEB_BAN={}
def _users():
    a=_load(AUTH_F,None) or {}
    if "user" in a:a={"users":{a["user"]:{"salt":a["salt"],"hash":a["hash"]}}}
    return a.get("users",{})
def auth_exists():return bool(_users())
def add_user(u,pw):
    s=secrets.token_bytes(16);us=_users();us[u]={"salt":s.hex(),"hash":_hpw(pw,s)}
    with open(AUTH_F,"w") as f:json.dump({"users":us},f)
    try:os.chmod(AUTH_F,0o600)
    except:pass
def check_auth(u,pw):
    r=_users().get(u)
    return bool(r) and secrets.compare_digest(r["hash"],_hpw(pw,bytes.fromhex(r["salt"])))

# ═══════════════════════════════════════════════════════════════════
#  RULES
# ═══════════════════════════════════════════════════════════════════
RULES=[(re.compile(p,re.I),s,r,c) for p,s,r,c in[
    (r"(wget|curl|tftp)\s+\S*(http|ftp|\d+\.\d+)",4,"Downloader","Command execution"),
    (r"(/bin/(ba)?sh|busybox|nc\s+-e|bash\s+-i|powershell|cmd\.exe)",4,"Shell payload","Command execution"),
    (r"(mirai|botnet|xmrig|stratum\+tcp)",4,"Malware","Malware delivery"),
    (r"(\$\{jndi:|%2e%2e|\.\./\.\./|struts|phpunit|/actuator|boaform)",3,"Exploit probe","Exploitation"),
    (r"(union\s+select|or\s+1=1|sleep\(|information_schema|xp_cmdshell)",3,"SQL injection","Exploitation"),
    (r"(;|\|\||&&)\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b",3,"Command injection","Command execution"),
    (r"(c99|r57|shell\.php|cmd\.php|webshell)",3,"Webshell","Exploitation"),
    (r"(/etc/passwd|/etc/shadow|\.env|\.git/|wp-config|id_rsa)",3,"File probe","Reconnaissance"),
    (r"(config\s+set|slaveof|flushall|module\s+load)",3,"Redis abuse","Exploitation"),
    (r"(/admin|/phpmyadmin|/wp-login|/manager/html)",2,"Admin probe","Reconnaissance"),
    (r"(nmap|masscan|zgrab|nikto|sqlmap|MpMap)",2,"Scanner","Reconnaissance")]]

# ═══════════════════════════════════════════════════════════════════
#  STORE
# ═══════════════════════════════════════════════════════════════════
EVENTS=collections.deque(maxlen=5000)
ATT={};STATS=collections.Counter();SVCSTAT=collections.defaultdict(collections.Counter)
PORTS=collections.Counter();SUBS=[];TIMES=collections.deque(maxlen=20000)
BRUTE=collections.defaultdict(collections.deque);RATE=collections.defaultdict(collections.deque)
GEO={};ERR={}
MY_LOC={"lat":None,"lon":None,"city":"","regionName":"","country":"","countryCode":"","isp":"","ip":"","src":""}
ARP_CACHE={};ARP_LOCK=threading.RLock()

def _clean(s,n=2000):
    if isinstance(s,bytes):s=s.decode("latin-1")
    return re.sub(r"[\x00-\x1f\x7f]",lambda m:"\\x%02x"%ord(m.group()),str(s))[:n]
def is_public(ip):
    try:return ipaddress.ip_address(ip).is_global
    except:return False

# ═══════════════════════════════════════════════════════════════════
#  MULTI-SOURCE GEOIP — MaxMind (offline) + ip-api + ipinfo, cross-checked
# ═══════════════════════════════════════════════════════════════════
_GEOIP_READER=None
def geoip_init():
    """Load local MaxMind GeoLite2-City.mmdb if present. Free account + license key
    needed from maxmind.com -> download GeoLite2-City.mmdb -> place in sx_data/.
    Fully optional: online sources (ip-api, ipinfo) still work without it."""
    global _GEOIP_READER
    if not _HAS_GEOIP2:
        print("  GeoIP: 'geoip2' package not installed (pip install geoip2) — online sources only");return
    if os.path.exists(GEOIP_DB_PATH):
        try:
            _GEOIP_READER=geoip2.database.Reader(GEOIP_DB_PATH)
            print("  GeoIP: MaxMind GeoLite2 loaded (offline, unlimited, primary source)")
        except Exception as e:print("  GeoIP: failed to load MaxMind DB:",e)
    else:
        print("  GeoIP: no MaxMind DB at %s — using online sources only"%GEOIP_DB_PATH)

def _geo_maxmind(ip):
    if not _GEOIP_READER:return None
    try:
        r=_GEOIP_READER.city(ip)
        if r.location.latitude is None:return None
        sub=r.subdivisions.most_specific
        return dict(src="MaxMind",city=r.city.name or "",regionName=(sub.name if sub else "") or "",
            country=r.country.name or "",countryCode=r.country.iso_code or "",
            lat=r.location.latitude,lon=r.location.longitude,isp="",org="",asn="",
            proxy=None,hosting=None)
    except Exception:return None

def _geo_ipapi(ip):
    try:
        url=CFG["geo"]["endpoint"].format(ip=ip)
        with urllib.request.urlopen(url,timeout=6) as resp:j=json.load(resp)
        if j.get("status")=="success":
            return dict(src="ip-api",city=j.get("city","") or "",regionName=j.get("regionName","") or "",
                country=j.get("country","") or "",countryCode=j.get("countryCode","") or "",
                lat=j.get("lat"),lon=j.get("lon"),isp=j.get("isp","") or "",org=j.get("org","") or "",
                asn=j.get("as","") or "",proxy=bool(j.get("proxy")),hosting=bool(j.get("hosting")))
    except Exception:pass
    return None

def _geo_ipinfo(ip):
    try:
        url="https://ipinfo.io/%s/json"%ip+("?token=%s"%IPINFO_TOKEN if IPINFO_TOKEN else "")
        req=urllib.request.Request(url,headers={"User-Agent":"SentinelX"})
        with urllib.request.urlopen(req,timeout=6) as resp:j=json.load(resp)
        loc=j.get("loc","");lat=lon=None
        if "," in loc:
            try:lat,lon=[float(x) for x in loc.split(",")]
            except:pass
        priv=j.get("privacy",{}) if isinstance(j.get("privacy"),dict) else {}
        return dict(src="ipinfo",city=j.get("city","") or "",regionName=j.get("region","") or "",
            country=j.get("country","") or "",countryCode=j.get("country","") or "",
            lat=lat,lon=lon,isp=j.get("org","") or "",org=j.get("org","") or "",asn="",
            proxy=bool(priv.get("vpn") or priv.get("proxy") or priv.get("tor")),
            hosting=bool(priv.get("hosting")))
    except Exception:pass
    return None

def _haversine_km(lat1,lon1,lat2,lon2):
    R=6371.0
    p1,p2=math.radians(lat1),math.radians(lat2)
    dp,dl=math.radians(lat2-lat1),math.radians(lon2-lon1)
    a=math.sin(dp/2)**2+math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return R*2*math.atan2(math.sqrt(a),math.sqrt(1-a))

def geo_lookup(ip):
    """Query MaxMind (offline) + ip-api + ipinfo in parallel, cross-check the
    results, and return one merged record with a confidence rating based on
    how closely the independent sources agree."""
    if not is_public(ip):return None
    fns=(_geo_maxmind,_geo_ipapi,_geo_ipinfo)
    results=[None]*len(fns)
    def run(i,fn):results[i]=fn(ip)
    threads=[threading.Thread(target=run,args=(i,fn),daemon=True) for i,fn in enumerate(fns)]
    for t in threads:t.start()
    for t in threads:t.join(timeout=8)
    results=[r for r in results if r and r.get("lat") is not None and r.get("lon") is not None]
    if not results:return None
    base=dict(results[0])
    base["sources"]=[r["src"] for r in results]
    base["source_count"]=len(results)
    if len(results)>1:
        dists=[_haversine_km(results[0]["lat"],results[0]["lon"],r["lat"],r["lon"]) for r in results[1:]]
        maxd=max(dists)
        base["agreement_km"]=round(maxd,1)
        base["confidence"]="HIGH" if maxd<25 else "MEDIUM" if maxd<150 else "LOW"
    else:
        base["agreement_km"]=None
        base["confidence"]="LOW (single source)"
    for r in results[1:]:
        for k,v in r.items():
            if not base.get(k) and v:base[k]=v
    base["proxy"]=any(bool(r.get("proxy")) for r in results)
    base["hosting"]=any(bool(r.get("hosting")) for r in results)
    base["query"]=ip;base["status"]="success"
    return base

def get_mac(ip):
    now=time.time()
    with ARP_LOCK:
        if ip in ARP_CACHE and now-ARP_CACHE[ip][1]<60:return ARP_CACHE[ip][0]
    mac=None
    try:
        if sys.platform.startswith("win"):
            out=subprocess.check_output(["arp","-a",ip],timeout=3,stderr=subprocess.DEVNULL).decode('cp1252','ignore')
            m=re.search(r"([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}",out)
            if m:mac=m.group().replace("-",":").upper()
        elif sys.platform=="darwin":
            out=subprocess.check_output(["arp","-n",ip],timeout=3).decode()
            m=re.search(r"at ([0-9a-f:]+)",out)
            if m and "incomplete" not in m.group(1):mac=m.group(1).upper()
        else:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    p=line.split()
                    if len(p)>=4 and p[0]==ip and p[3]!="00:00:00:00:00:00":mac=p[3].upper()
    except:pass
    with ARP_LOCK:ARP_CACHE[ip]=(mac,now)
    return mac

def reverse_dns(ip):
    try:return socket.gethostbyaddr(ip)[0]
    except:return ""

def emit(src,sport,dport,proto,kind,data="",resp="",conn="",sess="",user=None,pw=None,dur=0,extra=None,ua=None,shielded=False):
    now=time.time();sev,reasons,cat=0,[],"Normal"
    sens=CFG["services"].get(proto,{}).get("sensitivity",1)
    if kind=="connect":
        d=RATE[src];d.append(now)
        while d and now-d[0]>60:d.popleft()
        if len(d)>=CFG["alert"]["conn_rate"]:sev,reasons,cat=2,["High connection rate"],"Reconnaissance"
    if kind=="auth":
        sev,cat=1,"Credential abuse";d=BRUTE[src];d.append(now)
        while d and now-d[0]>60:d.popleft()
        if len(d)>=CFG["alert"]["brute"]:sev=3;reasons.append("Brute %d/60s"%len(d))
    for rx,s,r,c in RULES:
        if rx.search(str(data)):sev=max(sev,s);reasons.append(r);cat=c if s>=3 else cat
    if shielded:reasons.append("SHIELD: scanner detected");sev=max(sev,3);cat="Reconnaissance"
    if kind=="input" and sev==0 and proto in("TELNET","SSH"):sev,cat=1,"Suspicious"
    sev=min(4,sev+(1 if sens>=3 and sev>=2 else 0))
    udp=CFG["services"].get(proto,{}).get("transport")=="udp"
    if udp:reasons.append("UDP: source IP is spoofable, not handshake-verified")
    ev=dict(ts=round(now,3),iso=time.strftime("%Y-%m-%dT%H:%M:%S",time.gmtime(now)),
            id=secrets.token_hex(4),conn=conn,sess=sess,src=src,sport=sport,dport=dport,
            proto=proto,kind=kind,data=_clean(data),resp=_clean(resp,500),
            user=_clean(user,100) if user else None,pw=_clean(pw,100) if pw else None,
            ua=_clean(ua,300) if ua else None,transport="udp" if udp else "tcp",
            dur=round(dur,2),sev=SEV[sev],sevn=sev,reason="; ".join(reasons) or "-",cat=cat,
            shielded=shielded)
    if extra:ev["extra"]=extra
    with LOCK:
        EVENTS.append(ev);TIMES.append(now);STATS["events"]+=1;SVCSTAT[proto]["events"]+=1
        if kind=="connect":STATS["conns"]+=1;SVCSTAT[proto]["conns"]+=1;PORTS[dport]+=1
        a=ATT.setdefault(src,dict(ip=src,first=now,last=now,conns=0,events=0,alerts=0,maxsev=0,inputs=[],ports=set(),mac=None,dns="",ua=None,shielded=False,udp_hits=0,tcp_hits=0))
        a["last"]=now;a["events"]+=1;a["ports"].add(dport);a["conns"]+=kind=="connect"
        a["maxsev"]=max(a["maxsev"],sev)
        if shielded:a["shielded"]=True
        if udp:a["udp_hits"]=a.get("udp_hits",0)+1
        else:a["tcp_hits"]=a.get("tcp_hits",0)+1
        if ua and not a.get("ua"):a["ua"]=_clean(ua,300)
        if kind!="connect" and ev["data"]:a["inputs"]=(a["inputs"]+[ev["data"][:120]])[-30:]
        if sev>=CFG["alert"]["threshold"]:a["alerts"]+=1;STATS["alerts"]+=1;SVCSTAT[proto]["alerts"]+=1
        if sev>=4:STATS["critical"]+=1
        try:
            if os.path.exists(EV_F) and os.path.getsize(EV_F)>50*1048576:os.replace(EV_F,EV_F+".old")
            with open(EV_F,"a") as f:f.write(json.dumps(ev)+"\n")
            os.chmod(EV_F,0o600)
        except:pass
        for q in list(SUBS):
            try:q.put_nowait(ev)
            except queue.Full:pass
    if sev>=CFG["alert"]["threshold"]:threading.Thread(target=send_webhook,args=(ev,),daemon=True).start()
    threading.Thread(target=_enrich,args=(src,),daemon=True).start()
    return ev

def _enrich(ip):
    a=ATT.get(ip)
    if not a:return
    if a.get("mac") is None:
        mac=get_mac(ip)
        if mac:a["mac"]=mac
    if not a.get("dns") and not is_public(ip):
        a["dns"]=reverse_dns(ip)
    if CFG["geo"]["enabled"] and is_public(ip) and ip not in GEO:
        g=geo_lookup(ip)
        if g:GEO[ip]=g

def analyze(ev):
    with LOCK:rel=[e for e in EVENTS if e["src"]==ev["src"]]
    ind=sorted({r for e in rel for r in e["reason"].split("; ") if r!="-"})
    auths=sum(e["kind"]=="auth" for e in rel);protos={e["proto"] for e in rel}
    conf=min(99,35+12*len(ind)+3*min(auths,8)+4*len(protos)+8*ev["sevn"])
    if ev.get("shielded"):conf=min(99,conf+15)
    verdict="LIKELY MALICIOUS" if ev["sevn"]>=3 or conf>75 else "SUSPICIOUS" if ev["sevn"]>=1 else "BENIGN"
    return dict(verdict=verdict,confidence=conf,indicators=ind or["none"],
        what="%s on %s/%d from %s — %s"%(ev["kind"],ev["proto"],ev["dport"],ev["src"],ev["reason"]),
        evidence=[e["data"][:100] for e in rel if e["data"]][-6:],related=len(rel),protocols=sorted(protos),
        recon=len(protos)>=3,creds=auths>=3,
        exploit=any(w in ind for w in("Exploit","SQL","Webshell")),
        exec_attempt=any("ommand" in w or "Shell" in w or "Downloader" in w for w in ind),
        shield=ev.get("shielded",False),
        actions=["Block %s at firewall"%ev["src"],"Review related events","Check infra for same IOCs",
                 "Never reuse captured creds","Feed IOCs to SIEM"])

# ═══════════════════════════════════════════════════════════════════
#  PROTOCOLS
# ═══════════════════════════════════════════════════════════════════
class Ctx:
    def __init__(s,sock,addr,name,dport,decoy=False,decoy_info=None):
        s.sock,s.src,s.sport,s.name,s.dport=sock,addr[0],addr[1],name,dport
        s.conn,s.sess,s.t0,s.state=secrets.token_hex(4),secrets.token_hex(4),time.time(),{}
        s.decoy,s.decoy_info=decoy,decoy_info
        # Use locked banner if decoy
        if decoy and decoy_info:
            s.banner=decoy_info.get("banner","")
            s.hostname=decoy_info.get("hostname","gateway")
        else:
            s.banner=None;s.hostname=None
    def send(s,t):
        try:s.sock.sendall(t if isinstance(t,bytes) else t.encode())
        except:pass
    def ev(s,kind,data="",resp="",**k):
        return emit(s.src,s.sport,s.dport,s.name,kind,data,resp,s.conn,s.sess,dur=time.time()-s.t0,shielded=s.decoy,**k)

def _h_ftp(c,l):
    u=l.split(" ",1);cmd=u[0].upper();arg=u[1] if len(u)>1 else ""
    if cmd=="USER":c.state["u"]=arg;return "331 Password required"
    if cmd=="PASS":c.ev("auth","PASS","530 Login incorrect.",user=c.state.get("u",""),pw=arg);return "530 Login incorrect."
    if cmd=="QUIT":return None
    return "530 Please login."
def _h_smtp(c,l):
    cmd=l.split(" ")[0].upper()
    if cmd in("EHLO","HELO"):return "250-gateway\r\n250-AUTH LOGIN PLAIN\r\n250 8BITMIME"
    if cmd=="AUTH":c.ev("auth",l,"535 Auth failed",user=l);return "535 5.7.8 Auth failed"
    if cmd=="QUIT":return None
    return "250 2.0.0 Ok" if cmd in("MAIL","RCPT","RSET","NOOP") else "354 End data" if cmd=="DATA" else "502 Error"
def _h_telnet(c,l):
    s=c.state
    if "u" not in s:s["u"]=l;return "Password: "
    c.ev("auth","login","Login incorrect",user=s.pop("u"),pw=l)
    return "\r\nLogin incorrect\r\n\r\ngateway login: "
def _h_pop(c,l):
    cmd,_,arg=l.partition(" ")
    if cmd.upper()=="USER":c.state["u"]=arg;return "+OK"
    if cmd.upper()=="PASS":c.ev("auth","PASS","-ERR Auth failed",user=c.state.get("u",""),pw=arg);return "-ERR Auth failed"
    return None if cmd.upper()=="QUIT" else "-ERR unknown"
def _h_imap(c,l):
    p=l.split(" ",3);tag=p[0];cmd=p[1].upper() if len(p)>1 else ""
    if cmd=="LOGIN":c.ev("auth","LOGIN","NO",user=p[2] if len(p)>2 else "",pw=p[3] if len(p)>3 else "");return tag+" NO AUTH failed."
    if cmd=="LOGOUT":return None
    return tag+" BAD Error"
def _h_redis(c,l):
    cmd=l.split(" ")[0].upper().strip("*$0123456789\r\n")
    return "+PONG" if cmd=="PING" else "-NOAUTH Authentication required."
def _h_generic(c,l):return ""

def _http_sess(c,cfg,decoy_info=None):
    buf=b"";c.sock.settimeout(cfg["timeout"])
    while b"\r\n\r\n" not in buf and len(buf)<65536:
        d=c.sock.recv(4096)
        if not d:break
        buf+=d
    head,_,body=buf.partition(b"\r\n\r\n")
    lines=head.decode("latin-1").split("\r\n");rl=lines[0].split(" ") if lines else ["","/",""]
    hdr={}
    for l in lines[1:]:
        if ":" in l:
            k,v=l.split(":",1);hdr[k.strip().lower()]=v.strip()
    try:cl=int(hdr.get("content-length","0") or 0)
    except:cl=0
    while len(body)<min(cl,65536):
        d=c.sock.recv(4096)
        if not d:break
        body+=d
    path=rl[1] if len(rl)>1 else "/";body_s=body.decode("latin-1")
    ua=hdr.get("user-agent","")
    user=pw=None
    m=re.search(r"(?:user(?:name)?|log)=([^&]*)&.*?(?:pass(?:word)?|pwd)=([^&]*)",body_s,re.I)
    if m:user,pw=m.groups()
    if c.decoy and decoy_info:
        # Use LOCKED banner, ignore current config
        code=200
        page="<html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>"
        banner=decoy_info.get("banner","Apache/2.4.54 (Ubuntu)")
    else:
        code=401 if re.search(r"admin|login|manager",path) else 200
        page="<h1>401 Unauthorized</h1>" if code==401 else "<html><body><h1>It works!</h1></body></html>"
        banner=cfg["banner"]
    r="HTTP/1.1 %d OK\r\nServer: %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"%(code,banner,len(page),page)
    c.send(r)
    if user is not None:c.ev("auth",body_s,"HTTP %d"%code,user=user,pw=pw,ua=ua)
    c.ev("request","%s %s"%(rl[0],path),"HTTP %d"%code,
         extra={"method":rl[0],"path":_clean(path,300),"ua":ua},ua=ua)

def _tcp_session(name,cfg,sock,addr,decoy=False,decoy_info=None):
    # Jitter first — confuse timing fingerprinting
    shield_jitter()
    # Tarpit if scanner
    if decoy and SHIELD["tarpit"]:shield_tarpit()
    c=Ctx(sock,addr,name,cfg["port"],decoy=decoy,decoy_info=decoy_info)
    sock.settimeout(cfg["timeout"])
    try:
        banner=c.banner if c.banner else cfg["banner"]
        c.ev("connect","",banner)
        if name=="HTTP":return _http_sess(c,cfg,decoy_info if decoy else None)
        H={"FTP":_h_ftp,"SMTP":_h_smtp,"TELNET":_h_telnet,"POP3":_h_pop,"IMAP":_h_imap,"REDIS":_h_redis}.get(name,_h_generic)
        host=c.hostname if c.hostname else cfg["hostname"]
        banners={
            "FTP":banner+"\r\n","SMTP":banner+"\r\n",
            "TELNET":"\r\n%s\r\n\r\n%s login: "%(banner,host),
            "POP3":banner+"\r\n","IMAP":banner+"\r\n","SSH":banner+"\r\n"
        }
        if name in banners:c.send(banners[name])
        raw=name in("SSH","MYSQL","POSTGRES","SMB","LDAP","HTTPS")
        for _ in range(200):
            d=sock.recv(4096)
            if not d:break
            if raw or not d.isascii():
                c.ev("input",d.decode("latin-1") if d.isascii() else "hex:"+d.hex()[:600],"(raw)",extra={"bytes":len(d)})
                if raw:break
                continue
            for l in d.decode("latin-1").replace("\r","\n").split("\n"):
                if not l.strip():continue
                r=H(c,l.strip());c.ev("input",l,r if r is not None else "(close)")
                if r is None:return
                if r:c.send(r+"\r\n" if not r.endswith(" ") else r)
    except:pass
    finally:
        try:sock.close()
        except:pass

class _Listener(threading.Thread):
    def __init__(s,name,cfg):
        super().__init__(daemon=True)
        s.name_,s.cfg,s.stop_,s.active,s.sock=name,cfg,threading.Event(),0,None
    def run(s):
        udp=s.cfg["transport"]=="udp"
        try:
            s.sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
            s.sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            s.sock.bind((CFG["listen_address"],s.cfg["port"]));s.sock.settimeout(1)
            if not udp:s.sock.listen(128)
            ERR.pop(s.name_,None)
        except Exception as e:ERR[s.name_]=str(e);return
        while not s.stop_.is_set():
            try:
                if udp:
                    d,a=s.sock.recvfrom(8192)
                    shield_record(a[0],s.cfg["port"])
                    c=Ctx(s.sock,a,s.name_,s.cfg["port"])
                    c.ev("connect","","")
                    c.ev("input",d.decode("latin-1") if d.isascii() else "hex:"+d.hex()[:800],"(udp)")
                else:
                    cs,a=s.sock.accept()
                    ip=a[0]
                    # SHIELD: record hit + get ban status
                    ban=shield_record(ip,s.cfg["port"])
                    if ban=="NEW_BAN":
                        emit(ip,a[1],s.cfg["port"],s.name_,"connect","","SHIELD: scanner auto-banned",shielded=True)
                    # Check if decoy should be served
                    decoy=shield_should_serve_decoy(ip) and SHIELD["decoy_scan_response"]
                    decoy_info=shield_get_decoy_for(s.cfg["port"]) if decoy else None
                    if s.active>=s.cfg["max_conn"]:cs.close();continue
                    threading.Thread(target=s._handle_conn,args=(cs,a,decoy,decoy_info),daemon=True).start()
            except socket.timeout:continue
            except Exception:
                if not s.stop_.is_set():time.sleep(0.2)
        try:s.sock.close()
        except:pass
    def _handle_conn(s,cs,a,decoy,decoy_info):
        s.active+=1
        try:_tcp_session(s.name_,s.cfg,cs,a,decoy,decoy_info)
        finally:s.active-=1
    def stop(s):s.stop_.set()

LISTENERS={}
def restart_listeners():
    for l in LISTENERS.values():l.stop()
    for l in LISTENERS.values():
        try:l.join(2)
        except:pass
    LISTENERS.clear();ERR.clear()
    for n,c in CFG["services"].items():
        if c["enabled"]:
            l=_Listener(n,c);LISTENERS[n]=l;l.start()
    time.sleep(0.3)

def _validate(nc):
    used={}
    for n,c in nc["services"].items():
        p=int(c["port"])
        if not 1<=p<=65535:raise ValueError("%s: bad port"%n)
        c["port"]=p;c["enabled"]=bool(c["enabled"]);c["transport"]="udp" if c["transport"]=="udp" else "tcp"
        for k in("sensitivity","max_conn","timeout"):c[k]=max(1,int(c[k]))
        c["banner"]=_clean(c["banner"],200);c["hostname"]=_clean(c["hostname"],60)
        if c["enabled"]:
            key=(c["transport"],p)
            if key in used:raise ValueError("Conflict: %s/%s"%(n,used[key]))
            used[key]=n
    if "alert" in nc:
        wh=_clean(nc["alert"].get("webhook",""),500)
        if wh and not wh.startswith(("http://","https://")):raise ValueError("webhook must be http(s) URL")
        nc["alert"]["webhook"]=wh
        for k in("threshold","brute","conn_rate"):
            if k in nc["alert"]:nc["alert"][k]=max(1,int(nc["alert"][k]))
    if "web_lockout" in nc:
        for k in("attempts","window","ban"):
            if k in nc["web_lockout"]:nc["web_lockout"][k]=max(1,int(nc["web_lockout"][k]))
    return nc

def _esc(a):
    d=dict(a);d["ports"]=sorted(a["ports"]);d["geo"]=GEO.get(a["ip"]);d["private"]=not is_public(a["ip"])
    d["shield_status"]=shield_status(a["ip"])
    return d

def _filt(q):
    now=time.time();rng=float(q.get("range",["0"])[0] or 0);s=q.get("q",[""])[0].lower()
    out=[]
    for e in list(EVENTS):
        if rng and now-e["ts"]>rng:continue
        if q.get("proto",[""])[0] and e["proto"]!=q["proto"][0]:continue
        if q.get("sev",[""])[0] and e["sev"]!=q["sev"][0]:continue
        if q.get("ip",[""])[0] and q["ip"][0] not in e["src"]:continue
        if q.get("alerts",[""])[0]=="1" and e["sevn"]<CFG["alert"]["threshold"]:continue
        if q.get("shielded",[""])[0]=="1" and not e.get("shielded"):continue
        if s and s not in json.dumps(e).lower():continue
        out.append(e)
    return out

def get_local_ips():
    ips=[]
    try:
        for i in socket.getaddrinfo(socket.gethostname(),None):
            ip=i[4][0]
            if ip and not ip.startswith("127.") and ":" not in ip:ips.append(ip)
    except:pass
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect(("8.8.8.8",80))
        ips.append(s.getsockname()[0]);s.close()
    except:pass
    return list(set(ips))

def arp_scan():
    devices=[]
    try:
        if sys.platform.startswith("win"):
            try:
                out=subprocess.check_output(["arp","-a"],timeout=6,stderr=subprocess.DEVNULL).decode('cp1252','ignore')
                for line in out.splitlines():
                    m=re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)",line)
                    if m:
                        ip,mac,typ=m.groups()
                        if ip.startswith(('224.','239.','255.')) or ip.endswith('.255'):continue
                        devices.append(dict(ip=ip,mac=mac.replace('-',':').upper(),kind=typ))
            except:pass
        elif sys.platform=="darwin":
            try:
                out=subprocess.check_output(["arp","-an"],timeout=6).decode()
                for line in out.splitlines():
                    m=re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)",line)
                    if m:devices.append(dict(ip=m.group(1),mac=m.group(2).upper(),kind="dynamic"))
            except:pass
        else:
            try:
                with open("/proc/net/arp") as f:
                    for line in f.readlines()[1:]:
                        p=line.split()
                        if len(p)>=4 and p[3]!="00:00:00:00:00:00":
                            devices.append(dict(ip=p[0],mac=p[3].upper(),kind="dynamic"))
            except:pass
        my_ips=get_local_ips()
        for d in devices:
            try:d['hostname']=socket.gethostbyaddr(d['ip'])[0]
            except:d['hostname']=''
            d['vendor']=':'.join(d['mac'].split(':')[:3]) if d['mac'] else ''
        devices=[d for d in devices if d['ip'] not in my_ips]
    except Exception as e:return [],str(e)
    return devices,None

# ═══════════════════════════════════════════════════════════════════
#  PAGES
# ═══════════════════════════════════════════════════════════════════
def _page_login(msg="",ok=False):
    mc=""
    if msg:
        col="background:rgba(0,255,120,.08);border-left:3px solid #00ff78;color:#5fffa6" if ok else "background:rgba(255,40,80,.1);border-left:3px solid #ff2850;color:#ff5577"
        mc='<div style="margin-bottom:20px;padding:14px 18px;font-size:12px;'+col+';border-radius:4px">'+msg.replace("<","&lt;").replace(">","&gt;")+'</div>'
    return """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SentinelX Login</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
*{margin:0;padding:0;box-sizing:border-box}html,body{height:100%;background:#000208;font-family:'Share Tech Mono',monospace;overflow:hidden}
body{display:flex;align-items:center;justify-content:center;position:relative}canvas#bg{position:fixed;inset:0;z-index:0}
.wrap{position:relative;z-index:10;width:400px}.brand{text-align:center;margin-bottom:28px}
.hex{width:56px;height:56px;margin:0 auto 14px;background:linear-gradient(135deg,#00d4ff33,#00ff8822);
border:1px solid #00d4ff77;clip-path:polygon(50% 0,100% 25%,100% 75%,50% 100%,0 75%,0 25%);
display:flex;align-items:center;justify-content:center;box-shadow:0 0 30px #00d4ff44}
.hex span{color:#00d4ff;font-size:20px;font-family:'Rajdhani',sans-serif;font-weight:700}
.brand-name{font-family:'Rajdhani',sans-serif;font-size:32px;font-weight:700;letter-spacing:12px;
background:linear-gradient(90deg,#00d4ff,#00ff88);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.brand-tag{font-size:10px;letter-spacing:5px;color:#3a6070;margin-top:6px}
.card{background:linear-gradient(160deg,rgba(7,14,29,.95),rgba(4,11,23,.98));border:1px solid rgba(0,212,255,.15);
border-radius:8px;padding:34px;box-shadow:0 30px 80px rgba(0,0,0,.7),0 0 60px rgba(0,212,255,.08);position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:5%;right:5%;height:1px;background:linear-gradient(90deg,transparent,#00d4ff,transparent)}
.status-row{display:flex;align-items:center;gap:8px;margin-bottom:22px;font-size:10px;color:#2a5060;letter-spacing:2px}
.s-dot{width:7px;height:7px;border-radius:50%;background:#00ff88;box-shadow:0 0 8px #00ff88;animation:blink 2s infinite}
@keyframes blink{50%{opacity:.3}}
.field{position:relative;margin-bottom:20px}
.field input{width:100%;background:rgba(1,4,9,.9);border:1px solid #0b1e38;border-radius:4px;
padding:15px 16px 15px 46px;color:#c0dcea;font-family:inherit;font-size:13px;outline:none;transition:.25s}
.field input:focus{border-color:#00d4ff;box-shadow:0 0 0 3px rgba(0,212,255,.1)}
.field input:focus~label,.field input:not(:placeholder-shown)~label{top:-10px;left:12px;font-size:9px;letter-spacing:3px;color:#00d4ff;background:#070e1d;padding:0 8px}
.field label{position:absolute;left:46px;top:15px;font-size:12px;color:#2a5060;pointer-events:none;transition:.2s}
.field input::placeholder{color:transparent}.field-icon{position:absolute;left:16px;top:50%;transform:translateY(-50%);color:#00d4ff66;font-size:15px}
.btn-login{width:100%;padding:16px;margin-top:6px;cursor:pointer;font-family:inherit;font-size:14px;letter-spacing:6px;
border:1px solid rgba(0,212,255,.4);border-radius:4px;background:linear-gradient(135deg,rgba(0,212,255,.1),rgba(0,255,136,.08));
color:#00d4ff;transition:.3s}
.btn-login:hover{background:linear-gradient(135deg,rgba(0,212,255,.25),rgba(0,255,136,.18));border-color:#00d4ff;box-shadow:0 0 40px rgba(0,212,255,.3);color:#fff;letter-spacing:8px}
.alt{text-align:center;margin-top:22px;font-size:11px;color:#2a5060}.alt a{color:#00ff88;text-decoration:none;letter-spacing:2px}
</style></head><body><canvas id="bg"></canvas><div class="wrap">
<div class="brand"><div class="hex"><span>SX</span></div>
<div class="brand-name">SENTINEL&#8209;X</div><div class="brand-tag">DECEPTION COMMAND</div></div>
<div class="card"><div class="status-row"><span class="s-dot"></span>ONLINE &nbsp;&#183;&nbsp; AUTH REQUIRED</div>"""+mc+"""
<form method="post" action="/login">
<div class="field"><span class="field-icon">&#9679;</span><input type="text" name="u" placeholder="x" autocomplete="username" required><label>Username</label></div>
<div class="field"><span class="field-icon">&#9670;</span><input type="password" name="p" placeholder="x" autocomplete="current-password" required><label>Password</label></div>
<button class="btn-login">AUTHENTICATE</button></form>
<div class="alt">No account? <a href="/signup">Create one &rarr;</a></div>
</div></div>
<script>
const c=document.getElementById('bg'),x=c.getContext('2d');let W,H,p=[];
function init(){W=c.width=innerWidth;H=c.height=innerHeight;p=Array.from({length:80},()=>({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.5,vy:(Math.random()-.5)*.5,r:Math.random()*1.5+.3}))}
init();addEventListener('resize',init);
function f(){x.fillStyle='rgba(0,2,8,.08)';x.fillRect(0,0,W,H);
p.forEach(q=>{q.x+=q.vx;q.y+=q.vy;if(q.x<0||q.x>W)q.vx*=-1;if(q.y<0||q.y>H)q.vy*=-1;
x.beginPath();x.arc(q.x,q.y,q.r,0,7);x.fillStyle='rgba(0,212,255,.5)';x.fill()});
p.forEach((a,i)=>p.slice(i+1).forEach(b=>{const d=Math.hypot(a.x-b.x,a.y-b.y);
if(d<140){x.beginPath();x.moveTo(a.x,a.y);x.lineTo(b.x,b.y);x.strokeStyle='rgba(0,212,255,'+(1-d/140)*.1+')';x.stroke()}}));requestAnimationFrame(f)}f();
</script></body></html>"""

def _page_signup(msg="",ok=False):
    mc=""
    if msg:
        col="background:rgba(0,255,120,.08);border-left:3px solid #00ff78;color:#5fffa6" if ok else "background:rgba(255,40,80,.1);border-left:3px solid #ff2850;color:#ff5577"
        mc='<div style="margin-bottom:20px;padding:14px 18px;font-size:12px;'+col+';border-radius:4px">'+msg.replace("<","&lt;").replace(">","&gt;")+'</div>'
    return """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SentinelX Signup</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
*{margin:0;padding:0;box-sizing:border-box}html,body{height:100%;background:#000208;font-family:'Share Tech Mono',monospace;overflow:hidden}
body{display:flex;align-items:center;justify-content:center;position:relative}canvas#bg{position:fixed;inset:0;z-index:0}
.wrap{position:relative;z-index:10;width:440px}.brand{text-align:center;margin-bottom:26px}
.brand-name{font-family:'Rajdhani',sans-serif;font-size:28px;font-weight:700;letter-spacing:10px;
background:linear-gradient(90deg,#00ff88,#00d4ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.brand-tag{font-size:9px;letter-spacing:5px;color:#3a6070;margin-top:6px}
.card{background:linear-gradient(160deg,rgba(7,14,29,.95),rgba(4,11,23,.98));border:1px solid rgba(0,255,136,.15);
border-radius:8px;padding:32px;box-shadow:0 30px 80px rgba(0,0,0,.7),0 0 60px rgba(0,255,136,.06)}
.card-title{font-size:10px;letter-spacing:5px;color:#00ff8899;margin-bottom:22px;text-align:center}
.field{position:relative;margin-bottom:18px}
.field input{width:100%;background:rgba(1,4,9,.9);border:1px solid #0b1e38;border-radius:4px;
padding:14px 16px 14px 46px;color:#c0dcea;font-family:inherit;font-size:13px;outline:none;transition:.25s}
.field input:focus{border-color:#00ff88;box-shadow:0 0 0 3px rgba(0,255,136,.1)}
.field input:focus~label,.field input:not(:placeholder-shown)~label{top:-10px;left:12px;font-size:9px;letter-spacing:3px;color:#00ff88;background:#070e1d;padding:0 8px}
.field label{position:absolute;left:46px;top:14px;font-size:12px;color:#2a5060;pointer-events:none;transition:.2s}
.field input::placeholder{color:transparent}.field-icon{position:absolute;left:16px;top:50%;transform:translateY(-50%);color:#00ff8866;font-size:15px}
.hint{font-size:10px;color:#1e3a40;margin-top:5px;padding-left:4px}
.btn-signup{width:100%;padding:16px;margin-top:8px;cursor:pointer;font-family:inherit;font-size:14px;letter-spacing:6px;
border:1px solid rgba(0,255,136,.4);border-radius:4px;background:linear-gradient(135deg,rgba(0,255,136,.1),rgba(0,212,255,.08));
color:#00ff88;transition:.3s}
.btn-signup:hover{background:linear-gradient(135deg,rgba(0,255,136,.25),rgba(0,212,255,.18));border-color:#00ff88;box-shadow:0 0 40px rgba(0,255,136,.3);color:#fff}
.alt{text-align:center;margin-top:18px;font-size:11px;color:#2a5060}.alt a{color:#00d4ff;text-decoration:none;letter-spacing:2px}
</style></head><body><canvas id="bg"></canvas><div class="wrap">
<div class="brand"><div class="brand-name">SENTINEL&#8209;X</div><div class="brand-tag">OPERATOR REGISTRATION</div></div>
<div class="card"><div class="card-title">&#9650; NEW OPERATOR ACCOUNT</div>"""+mc+"""
<form method="post" action="/signup">
<div class="field"><span class="field-icon">&#9679;</span><input type="text" name="u" placeholder="x" required minlength="3" maxlength="32"><label>Username</label><div class="hint">3-32 chars</div></div>
<div class="field"><span class="field-icon">&#9670;</span><input type="password" name="p" placeholder="x" required minlength="10"><label>Password</label><div class="hint">Min 10 chars</div></div>
<div class="field"><span class="field-icon">&#10003;</span><input type="password" name="p2" placeholder="x" required><label>Confirm</label></div>
<button class="btn-signup">CREATE ACCOUNT</button></form>
<div class="alt"><a href="/">&larr; Back to login</a></div>
</div></div>
<script>
const c=document.getElementById('bg'),x=c.getContext('2d');let W,H,p=[];
function init(){W=c.width=innerWidth;H=c.height=innerHeight;p=Array.from({length:80},()=>({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.5,vy:(Math.random()-.5)*.5,r:Math.random()*1.5+.3}))}
init();addEventListener('resize',init);
function f(){x.fillStyle='rgba(0,2,8,.08)';x.fillRect(0,0,W,H);
p.forEach(q=>{q.x+=q.vx;q.y+=q.vy;if(q.x<0||q.x>W)q.vx*=-1;if(q.y<0||q.y>H)q.vy*=-1;
x.beginPath();x.arc(q.x,q.y,q.r,0,7);x.fillStyle='rgba(0,255,136,.4)';x.fill()});
p.forEach((a,i)=>p.slice(i+1).forEach(b=>{const d=Math.hypot(a.x-b.x,a.y-b.y);
if(d<140){x.beginPath();x.moveTo(a.x,a.y);x.lineTo(b.x,b.y);x.strokeStyle='rgba(0,255,136,'+(1-d/140)*.08+')';x.stroke()}}));requestAnimationFrame(f)}f();
</script></body></html>"""

# ═══════════════════════════════════════════════════════════════════
#  MAIN DASHBOARD
# ═══════════════════════════════════════════════════════════════════
PAGE_MAIN=r"""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SentinelX Command</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#000208;--panel:rgba(6,13,28,.75);--b1:#0a1a30;--b2:#0d2040;
--cyan:#00d4ff;--green:#00ff88;--red:#ff2255;--amber:#ffaa00;--tx:#4a7090;--br:#8ab4cc;--wh:#e0f2ff}
html{background:var(--bg);color:var(--br);font:12px 'Share Tech Mono',monospace}body{min-height:100vh;overflow-x:hidden}
#hdr{display:flex;align-items:center;justify-content:space-between;height:56px;padding:0 20px;
position:sticky;top:0;z-index:100;background:rgba(4,11,24,.94);backdrop-filter:blur(20px);
border-bottom:1px solid var(--b1);box-shadow:0 4px 30px rgba(0,0,0,.7)}
.logo{display:flex;align-items:center;gap:12px}
.logo-hex{width:32px;height:32px;clip-path:polygon(50% 0,100% 25%,100% 75%,50% 100%,0 75%,0 25%);
background:linear-gradient(135deg,rgba(0,212,255,.2),rgba(0,255,136,.15));border:1px solid rgba(0,212,255,.4);
display:flex;align-items:center;justify-content:center;font-family:'Rajdhani',sans-serif;font-size:12px;
color:var(--cyan);font-weight:700;box-shadow:0 0 20px rgba(0,212,255,.3)}
.logo-text{font-family:'Rajdhani',sans-serif;font-size:20px;font-weight:700;letter-spacing:8px;
background:linear-gradient(90deg,var(--cyan),var(--green));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo-sub{font-size:8px;letter-spacing:5px;color:var(--tx);margin-top:1px}
nav{display:flex;gap:3px}
.nb{background:transparent;border:1px solid transparent;color:var(--tx);padding:7px 14px;
font:11px 'Share Tech Mono',monospace;letter-spacing:2px;cursor:pointer;transition:.2s;border-radius:3px}
.nb:hover,.nb.on{color:var(--cyan);border-color:var(--b2);background:rgba(0,212,255,.06)}
.nb.on{border-color:var(--cyan);box-shadow:0 0 15px rgba(0,212,255,.2);color:#fff}
.nb-shield{color:var(--green)!important;border-color:rgba(0,255,136,.3)!important;animation:shieldGlow 2s infinite}
@keyframes shieldGlow{50%{box-shadow:0 0 25px rgba(0,255,136,.5);text-shadow:0 0 10px #00ff88}}
.nb-out{color:var(--red)!important}
#sys-time{font-size:11px;color:var(--cyan);opacity:.8;letter-spacing:1.5px}
.warn-bar{padding:5px 20px;background:rgba(255,170,0,.04);border-bottom:1px solid rgba(255,170,0,.08);
font-size:10px;color:rgba(255,170,0,.6);letter-spacing:.5px}
.view{display:none;padding:14px;position:relative;z-index:1}.view.on{display:block;animation:vi .3s}
@keyframes vi{from{opacity:0;transform:translateY(6px)}}
.g{display:grid;gap:12px;margin-bottom:12px}.g4{grid-template-columns:repeat(4,1fr)}.g31{grid-template-columns:3fr 1fr}
.g2{grid-template-columns:1fr 1fr}.g3{grid-template-columns:repeat(3,1fr)}
@media(max-width:1100px){.g4,.g31,.g2,.g3{grid-template-columns:1fr}}
.p{background:var(--panel);border:1px solid var(--b1);border-radius:6px;padding:14px;position:relative;
overflow:hidden;backdrop-filter:blur(14px);box-shadow:0 8px 32px rgba(0,0,0,.4)}
.p::before{content:'';position:absolute;top:0;left:20%;right:20%;height:1px;background:linear-gradient(90deg,transparent,rgba(0,212,255,.4),transparent)}
.ph{font-size:10px;letter-spacing:4px;color:var(--cyan);margin-bottom:12px;display:flex;align-items:center;gap:10px}
.ph::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,rgba(0,212,255,.3),transparent)}
.sc{text-align:center;padding:16px 8px}
.sc-val{font-family:'Rajdhani',sans-serif;font-size:38px;font-weight:700;display:block;line-height:1;margin-bottom:6px;
background:linear-gradient(135deg,var(--cyan),var(--green));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sc-val.warn{background:linear-gradient(135deg,var(--amber),#ff6600);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sc-val.danger{background:linear-gradient(135deg,var(--red),var(--amber));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sc-label{font-size:9px;letter-spacing:3px;color:var(--tx);text-transform:uppercase}
.sc-sub{font-size:10px;color:var(--tx);margin-top:4px;opacity:.7}
#globeC{width:100%;display:block;border-radius:4px;cursor:grab;background:#000}
#globeC:active{cursor:grabbing}#radarC{width:100%;display:block}
.g-tip{position:absolute;background:rgba(2,6,20,.97);border:1px solid var(--cyan);padding:10px 14px;
font-size:11px;color:var(--br);pointer-events:none;display:none;z-index:20;border-radius:4px;
box-shadow:0 0 30px rgba(0,212,255,.4);max-width:280px;line-height:1.6;backdrop-filter:blur(10px)}
.g-tip b{color:var(--wh)}
.tel{height:240px;overflow-y:auto;padding-right:4px}
.trow{padding:8px 10px;border-left:3px solid;margin-bottom:5px;font-size:11px;cursor:pointer;transition:.15s;
background:rgba(0,0,0,.2);border-radius:0 3px 3px 0;animation:ri .3s}
.trow.shielded{background:rgba(0,255,136,.08);border-left-color:#00ff88}
@keyframes ri{from{opacity:0;transform:translateX(-10px)}}
.trow:hover{background:rgba(0,212,255,.06);transform:translateX(3px)}
.trow.INFO{border-color:#1a3d55;color:var(--tx)}.trow.LOW{border-color:var(--green);color:#5fffa6}
.trow.MEDIUM{border-color:var(--amber);color:#ffcc66}.trow.HIGH{border-color:#ff6600;color:#ff8844}
.trow.CRITICAL{border-color:var(--red);color:var(--red);font-weight:bold;animation:pulseRed 1.5s infinite}
@keyframes pulseRed{50%{box-shadow:0 0 25px rgba(255,34,85,.3)}}
.sg{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px}
.sc2{border:1px solid var(--b1);padding:10px 12px;cursor:pointer;transition:.2s;border-radius:4px;font-size:10px;background:rgba(0,0,0,.15)}
.sc2:hover{background:rgba(0,212,255,.05);border-color:rgba(0,212,255,.4);transform:translateY(-2px)}
.sc2.listening{border-color:rgba(0,255,136,.3);color:var(--green)}
.sc2.failure{border-color:rgba(255,34,85,.3);color:var(--red)}
.sc2.disabled{border-color:var(--b1);color:var(--tx);opacity:.5}
.sc2-name{font-size:11px;font-family:'Rajdhani',sans-serif;font-weight:600;letter-spacing:2px;margin-bottom:4px;display:flex;align-items:center;gap:6px}
.sc2-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.listening .sc2-dot{background:var(--green);box-shadow:0 0 8px var(--green);animation:blink 2s infinite}
.failure .sc2-dot{background:var(--red);box-shadow:0 0 8px var(--red)}.disabled .sc2-dot{background:var(--tx)}
table{width:100%;border-collapse:collapse;font-size:11px}
th{padding:7px 9px;font-size:9px;letter-spacing:2px;color:var(--cyan);border-bottom:1px solid var(--b2);text-align:left;background:rgba(0,212,255,.03)}
td{padding:6px 9px;border-bottom:1px solid #050d1a;vertical-align:top}tr:hover td{background:rgba(0,212,255,.03)}
.ki-v{font-family:'Rajdhani',sans-serif;font-size:19px;font-weight:700;letter-spacing:3px;margin-bottom:8px}
.ki-s{margin-bottom:10px;padding:10px 12px;background:rgba(0,0,0,.3);border-left:2px solid var(--b2);font-size:11px;line-height:1.8}
.ki-s strong{font-size:9px;letter-spacing:3px;color:var(--cyan);display:block;margin-bottom:5px}
.ki-tag{display:inline-block;padding:2px 9px;border:1px solid;border-radius:3px;font-size:10px;margin:2px}
#pop{position:fixed;top:20px;right:20px;z-index:999;width:320px}
.pu{background:linear-gradient(160deg,rgba(20,4,10,.97),rgba(10,2,6,.98));border:1px solid var(--red);
border-radius:5px;padding:14px 16px;margin-bottom:10px;backdrop-filter:blur(20px);
box-shadow:0 0 40px rgba(255,34,85,.4);animation:pu-i .4s}
@keyframes pu-i{from{transform:translateX(110%) scale(.9);opacity:0}}
.pu-t{color:var(--red);font-size:12px;letter-spacing:4px;margin-bottom:7px}
.pu-b{font-size:11px;color:var(--tx);line-height:1.7}
#modal{display:none;position:fixed;inset:0;background:rgba(0,2,8,.94);z-index:200;overflow-y:auto;padding:24px;backdrop-filter:blur(8px)}
#modal.on{display:block;animation:mi .4s}@keyframes mi{from{opacity:0;transform:scale(.94)}}
#mbox{max-width:920px;margin:auto;background:linear-gradient(160deg,rgba(7,16,31,.99),rgba(4,11,23,.99));
border:1px solid var(--b2);border-radius:6px;padding:24px;position:relative;box-shadow:0 0 80px rgba(0,212,255,.2),0 30px 100px rgba(0,0,0,.8)}
.m-close{position:absolute;top:14px;right:14px;background:transparent;border:1px solid var(--b1);color:var(--tx);
padding:5px 12px;cursor:pointer;font:10px 'Share Tech Mono',monospace;letter-spacing:2px;border-radius:3px;transition:.2s}
.m-close:hover{color:var(--red);border-color:var(--red)}
.af{position:relative;padding-left:24px}
.af::before{content:'';position:absolute;left:7px;top:0;bottom:0;width:1px;background:linear-gradient(180deg,var(--b2),transparent)}
.af-ev{position:relative;margin-bottom:10px;animation:ri .3s}
.af-ev::before{content:'';position:absolute;left:-22px;top:9px;width:9px;height:9px;border-radius:50%;border:1px solid var(--b2);background:var(--bg)}
.af-ev.LOW::before{border-color:var(--green);background:rgba(0,255,136,.3)}.af-ev.MEDIUM::before{border-color:var(--amber);background:rgba(255,170,0,.3)}
.af-ev.HIGH::before{border-color:#ff6600;background:rgba(255,102,0,.3)}.af-ev.CRITICAL::before{border-color:var(--red);background:rgba(255,34,85,.4)}
.af-hdr{padding:8px 12px;border:1px solid var(--b1);border-radius:3px;cursor:pointer;font-size:11px;background:rgba(0,0,0,.25)}
.af-hdr:hover{background:rgba(0,212,255,.06);border-color:rgba(0,212,255,.3)}
.af-body{display:none;padding:10px;background:rgba(0,0,0,.35);border-left:2px solid var(--b2);margin-top:4px;
font-size:10px;line-height:1.8;white-space:pre-wrap;word-break:break-all;color:var(--tx)}
.ff{margin-bottom:11px}.ff label{display:block;font-size:9px;letter-spacing:2px;color:var(--cyan);margin-bottom:5px}
.ff input,.ff select{width:100%;background:rgba(1,4,9,.9);border:1px solid var(--b1);color:var(--br);
font:11px 'Share Tech Mono',monospace;padding:9px 11px;outline:none;border-radius:3px}
.ff input:focus{border-color:var(--cyan);box-shadow:0 0 0 2px rgba(0,212,255,.15)}
.fr{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.btn{background:rgba(0,212,255,.08);border:1px solid rgba(0,212,255,.3);color:var(--cyan);
font:10px 'Share Tech Mono',monospace;letter-spacing:2px;padding:9px 16px;cursor:pointer;border-radius:3px;transition:.2s}
.btn:hover{background:rgba(0,212,255,.2);box-shadow:0 0 20px rgba(0,212,255,.25)}
.btn-g{background:rgba(0,255,136,.08);border-color:rgba(0,255,136,.3);color:var(--green)}
.btn-g:hover{background:rgba(0,255,136,.2)}
.btn-a{background:rgba(255,170,0,.08);border-color:rgba(255,170,0,.3);color:var(--amber)}
.btn-r{background:rgba(255,34,85,.08);border-color:rgba(255,34,85,.3);color:var(--red)}
pre{white-space:pre-wrap;word-break:break-all;background:rgba(0,0,0,.4);padding:10px;border:1px solid var(--b1);
font-size:10px;border-radius:3px;line-height:1.6;color:#7fb8d4}
.bar{height:3px;background:linear-gradient(90deg,var(--cyan),var(--green));margin-top:3px;transition:.4s;border-radius:2px}
input[type=checkbox]{accent-color:var(--cyan);transform:scale(1.2);margin-right:4px}
.shield-on{background:linear-gradient(135deg,rgba(0,255,136,.15),rgba(0,212,255,.1))!important;
border-color:rgba(0,255,136,.5)!important;box-shadow:0 0 30px rgba(0,255,136,.2)!important}
.legend{position:absolute;bottom:15px;left:15px;font-size:10px;color:var(--tx);display:flex;gap:14px;
background:rgba(0,0,0,.6);padding:6px 12px;border-radius:20px;backdrop-filter:blur(10px);border:1px solid var(--b1);z-index:5}
.dot-legend{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:4px;vertical-align:middle}
#you-label{position:absolute;top:45px;left:15px;background:rgba(0,0,0,.6);border:1px solid rgba(0,212,255,.4);
padding:6px 12px;border-radius:20px;font-size:10px;color:var(--cyan);backdrop-filter:blur(10px);z-index:5;max-width:400px}
.shield-banner{padding:8px 16px;background:linear-gradient(90deg,rgba(0,255,136,.15),rgba(0,212,255,.1));
border:1px solid rgba(0,255,136,.4);border-radius:4px;color:#00ff88;font-size:11px;letter-spacing:2px;
display:flex;align-items:center;gap:10px;margin-bottom:14px;box-shadow:0 0 20px rgba(0,255,136,.15)}
.shield-banner::before{content:'🛡️';font-size:18px}
</style></head><body>

<header id="hdr">
<div class="logo"><div class="logo-hex">SX</div>
<div><div class="logo-text">SENTINEL&#8209;X</div><div class="logo-sub">DECEPTION COMMAND</div></div></div>
<nav>
<button class="nb on" data-v="dash">DASHBOARD</button>
<button class="nb" data-v="logs">LOGS</button>
<button class="nb" data-v="ports">PORTS</button>
<button class="nb" data-v="cfg">CONFIG</button>
<button class="nb nb-shield" data-v="shield">🛡️ SHIELD</button>
<button class="nb" onclick="location='/api/download?fmt=jsonl'">EXPORT</button>
<button class="nb nb-out" onclick="location='/logout'">LOGOUT</button>
</nav>
<div id="sys-time"></div>
</header>
<div class="warn-bar">Deployed in isolated environment &mdash; input captured, never executed</div>
<div id="pop"></div>

<div id="dash" class="view on">
<div id="shield-banner-top"></div>
<div class="g g4">
<div class="p sc"><span class="sc-val" id="v-conn">0</span><div class="sc-label">Connections</div></div>
<div class="p sc"><span class="sc-val" id="v-evt">0</span><div class="sc-label">Events</div><div class="sc-sub"><span id="v-epm">0</span>/min</div></div>
<div class="p sc"><span class="sc-val warn" id="v-alr">0</span><div class="sc-label">Alerts</div><div class="sc-sub"><span id="v-crit">0</span> critical</div></div>
<div class="p sc"><span class="sc-val danger" id="v-att">0</span><div class="sc-label">Attackers</div><div class="sc-sub"><span id="v-sess">0</span> sessions</div></div>
</div>
<div class="g g31">
<div class="p" style="position:relative">
<div class="ph">3D EARTH &mdash; LIVE ATTACK MAP</div>
<canvas id="globeC" height="500"></canvas>
<div class="g-tip" id="g-tip"></div>
<div id="you-label">&#9679; Detecting your location...</div>
<div class="legend">
<span><span class="dot-legend" style="background:#00d4ff;box-shadow:0 0 8px #00d4ff"></span>YOU</span>
<span><span class="dot-legend" style="background:#ff2255;box-shadow:0 0 8px #ff2255"></span>ATTACKER</span>
<span><span class="dot-legend" style="background:#00ff88;box-shadow:0 0 8px #00ff88"></span>SHIELDED</span>
</div>
</div>
<div class="p">
<div class="ph">LIVE TELEMETRY</div>
<div class="tel" id="tel"></div>
<div class="ph" style="margin-top:14px">TARGETS</div>
<div id="tops" style="font-size:10px"></div>
</div>
</div>
<div class="g g31">
<div class="p"><div class="ph">THREAT RADAR</div><canvas id="radarC" height="380"></canvas></div>
<div class="p"><div class="ph">KI ANALYST</div>
<div id="ki-box" style="font-size:11px;color:var(--tx);line-height:1.8">Awaiting HIGH/CRITICAL&hellip;</div></div>
</div>
<div class="p"><div class="ph">SERVICE LISTENERS</div><div class="sg" id="svc-grid"></div></div>
</div>

<div id="logs" class="view"><div class="p">
<div class="ph">LOG VIEWER</div>
<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;margin-bottom:14px">
<div class="ff" style="margin:0"><label>SEARCH</label><input id="lf-q" style="width:150px"></div>
<div class="ff" style="margin:0"><label>SEV</label><select id="lf-s" style="width:100px"><option value="">All</option><option>INFO</option><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select></div>
<div class="ff" style="margin:0"><label>IP</label><input id="lf-ip" style="width:130px"></div>
<label style="font-size:10px;color:var(--tx)"><input type="checkbox" id="lf-shield">Shielded only</label>
<button class="btn" onclick="loadLogs()">FILTER</button>
<button class="btn btn-a" onclick="location='/api/download?fmt=jsonl'">DOWNLOAD</button></div>
<div style="overflow-x:auto"><table><thead><tr><th>TIME</th><th>SEV</th><th>SHIELD</th><th>PROTO</th><th>SOURCE</th><th>PORT</th><th>KIND</th><th>DATA</th><th>REASON</th></tr></thead>
<tbody id="log-body"></tbody></table></div></div></div>

<div id="ports" class="view"><div class="p">
<div class="ph">PORT &amp; SERVICE MANAGEMENT</div>
<div style="overflow-x:auto"><table><thead><tr><th>NAME</th><th>ON</th><th>PORT</th><th>BANNER</th><th>HOST</th><th>STATUS</th><th>CONN</th><th>EVT</th><th>ALR</th></tr></thead>
<tbody id="port-body"></tbody></table></div>
<div style="margin-top:14px;display:flex;gap:10px;align-items:center">
<button class="btn btn-g" onclick="savePorts()">APPLY &amp; RESTART</button><span id="port-msg" style="font-size:10px"></span></div>
</div></div>

<div id="cfg" class="view"><div class="p" style="max-width:700px">
<div class="ph">SYSTEM CONFIGURATION</div><div id="cfg-body"></div>
<div style="margin-top:14px"><button class="btn btn-g" onclick="saveCfg()">SAVE</button> <span id="cfg-msg" style="font-size:10px"></span></div>
</div></div>

<div id="shield" class="view">
<div class="shield-banner" id="shield-status-banner">SHIELD LOADING...</div>

<div class="g g2">
<div class="p">
<div class="ph">🛡️ ANTI-DETECTION SHIELD</div>
<div style="font-size:11px;line-height:1.9;margin-bottom:14px;color:var(--tx)">
Isse enable karne ke baad:<br>
• Scanners ko <b style="color:#00ff88">LOCKED fingerprint</b> dikhega — chahe aap config change karo<br>
• Automated scanners detect honge aur <b style="color:#ff2255">5 min ban</b> honge<br>
• Random timing jitter se fingerprinting confuse hogi<br>
• Aggressive scanners ko <b style="color:var(--amber)">tarpit</b> treatment milega<br>
</div>

<div style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap">
<button class="btn btn-g" id="btn-lock" onclick="shieldLock()">🔒 LOCK CURRENT FINGERPRINT</button>
<button class="btn btn-r" id="btn-unlock" onclick="shieldUnlock()">🔓 UNLOCK</button>
</div>

<div class="ff"><label><input type="checkbox" id="shield-jitter" onchange="toggleShieldOpt('jitter')"> Timing Jitter (random delays)</label></div>
<div class="ff"><label><input type="checkbox" id="shield-tarpit" onchange="toggleShieldOpt('tarpit')"> Tarpit scanners (slow them down)</label></div>
<div class="ff"><label><input type="checkbox" id="shield-decoy" onchange="toggleShieldOpt('decoy_scan_response')"> Serve decoy banner to scanners</label></div>
</div>

<div class="p">
<div class="ph">📸 LOCKED FINGERPRINT</div>
<div id="locked-fp" style="font-size:11px;line-height:1.8;max-height:400px;overflow-y:auto">
Not locked yet. Click "LOCK CURRENT FINGERPRINT" to freeze your external signature.
</div>
</div>
</div>

<div class="p">
<div class="ph">🚨 DETECTED SCANNERS</div>
<div style="overflow-x:auto"><table><thead><tr><th>IP</th><th>PORTS HIT</th><th>HITS/60s</th><th>STATUS</th><th>BANNED UNTIL</th><th>REASON</th></tr></thead>
<tbody id="scanner-body"><tr><td colspan="6" style="text-align:center;opacity:.5;padding:20px">No scanners yet</td></tr></tbody></table></div>
<button class="btn btn-a" onclick="clearScanners()" style="margin-top:10px">CLEAR SCANNER LIST</button>
</div>
</div>

<div id="modal" onclick="if(event.target===this)closeModal()"><div id="mbox">
<button class="m-close" onclick="closeModal()">CLOSE &#10005;</button><div id="mc"></div></div></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
<script>
const $=id=>document.getElementById(id);
const E=v=>{const d=document.createElement('div');d.textContent=v==null?'':String(v);return d.innerHTML};
const J=async u=>{try{const r=await fetch(u);return await r.json()}catch(e){return null}};
const SC={INFO:'#1a3d55',LOW:'#00ff88',MEDIUM:'#ffaa00',HIGH:'#ff6600',CRITICAL:'#ff2255'};
const SEVS=['INFO','LOW','MEDIUM','HIGH','CRITICAL'];
const cl=(v,a,b)=>Math.max(a,Math.min(b,v));
let ST=null,CFG2=null,SHIELD=null,PULSES=[],LAST=null,AUD=null;
let LOCAL_DEVICES=[],RPTS_LOCAL=[],RPTS=[],MY_LOC={lat:null,lon:null,city:'',regionName:'',country:'',isp:'',ip:'',confidence:'',sources:[],proxy:false,hosting:false};

setInterval(()=>{$('sys-time').textContent=new Date().toISOString().replace('T',' ').slice(0,19)+' UTC'},500);

document.querySelectorAll('.nb[data-v]').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('.nb').forEach(x=>x.classList.remove('on'));b.classList.add('on');
  ['dash','logs','ports','cfg','shield'].forEach(v=>$(v).classList.toggle('on',v===b.dataset.v));
  if(b.dataset.v==='logs')loadLogs();
  if(b.dataset.v==='ports')loadPortsUI();
  if(b.dataset.v==='cfg')loadCfgUI();
  if(b.dataset.v==='shield')loadShieldUI();
});

function cnt(el,to){
  const from=+(el.dataset.v||0);el.dataset.v=to;if(from===to)return;
  const t0=performance.now();
  (function f(t){const k=cl((t-t0)/500,0,1),e=1-Math.pow(1-k,3);
    el.textContent=Math.round(from+(to-from)*e);
    if(k<1)requestAnimationFrame(f);})(t0);
}

// ════════ MY LOCATION ════════
async function detectMyLocation(){
  const d=await J('/api/mylocation');
  if(d&&d.lat){
    MY_LOC.lat=d.lat;MY_LOC.lon=d.lon;MY_LOC.city=d.city||'';
    MY_LOC.regionName=d.regionName||'';MY_LOC.country=d.country||'';
    MY_LOC.isp=d.isp||'';MY_LOC.src='IP';MY_LOC.ip=d.ip||d.query||'';
    MY_LOC.confidence=d.confidence||'';MY_LOC.sources=d.sources||[];
    MY_LOC.agreement_km=d.agreement_km;MY_LOC.proxy=!!d.proxy;MY_LOC.hosting=!!d.hosting;
    updateMyLocation();
  }
}
function updateMyLocation(){
  if(window.youMarker&&window.earthGroup)window.earthGroup.remove(window.youMarker);
  if(MY_LOC.lat!=null&&window.earthGroup){
    const pos=latLonToVec3(MY_LOC.lat,MY_LOC.lon,5.06);
    window.youMarker=new THREE.Mesh(new THREE.SphereGeometry(0.1,16,16),new THREE.MeshBasicMaterial({color:0x00d4ff}));
    window.youMarker.position.copy(pos);
    const halo=new THREE.Mesh(new THREE.SphereGeometry(0.22,16,16),
      new THREE.MeshBasicMaterial({color:0x00d4ff,transparent:true,opacity:0.35,side:THREE.BackSide}));
    window.youMarker.add(halo);
    window.youMarker.userData={isYou:true,halo:halo};
    window.earthGroup.add(window.youMarker);
  }
  const lbl=$('you-label');
  if(lbl&&MY_LOC.lat!=null){
    lbl.innerHTML='&#9679; YOU: <b>'+E([MY_LOC.city,MY_LOC.regionName,MY_LOC.country].filter(Boolean).join(', ')||'Unknown')+'</b>'+
      (MY_LOC.confidence?' <span style="opacity:.6;font-size:9px">['+E(MY_LOC.confidence)+']</span>':'');
  }
}
detectMyLocation();

// ════════ POLL ════════
async function poll(){
  try{
    ST=await J('/api/state');if(!ST)return;
    const s=ST.stats;
    cnt($('v-conn'),s.conns||0);cnt($('v-evt'),s.events||0);
    cnt($('v-alr'),s.alerts||0);cnt($('v-crit'),s.critical||0);
    cnt($('v-att'),ST.active);cnt($('v-sess'),ST.sessions);
    $('v-epm').textContent=ST.epm;
    $('svc-grid').innerHTML=Object.entries(ST.services).map(([n,c])=>
      '<div class="sc2 '+c.status+'" onclick="openSvc(\''+E(n)+'\')">'+
      '<div class="sc2-name"><span class="sc2-dot"></span>'+E(n)+'</div>'+
      '<div style="opacity:.6">'+c.transport+'/:'+c.port+'</div>'+
      '<div style="opacity:.5;margin-top:3px">'+c.conns+'c '+c.events+'e '+c.alerts+'a</div></div>').join('');
    const mp=ST.ports[0]?ST.ports[0][1]:1;
    $('tops').innerHTML='<div style="font-size:9px;letter-spacing:2px;color:var(--cyan);margin-bottom:6px">PORTS</div>'+
      ST.ports.map(([p,n])=>'<div style="display:flex;justify-content:space-between;padding:3px 0;font-size:10px">:'+p+'<span style="color:var(--cyan)">'+n+'</span></div><div class="bar" style="width:'+(n/mp*100).toFixed(0)+'%"></div>').join('');
    updateAttackers3D();
    // Shield banner
    const sh=await J('/api/shield');
    if(sh){
      SHIELD=sh;
      const b=$('shield-banner-top');
      if(sh.enabled){
        b.innerHTML='<div class="shield-banner">SHIELD ACTIVE &mdash; External fingerprint LOCKED at '+new Date(sh.locked_at*1000).toISOString().slice(0,19)+' UTC &mdash; '+Object.keys(sh.locked_signature||{}).length+' ports frozen</div>';
      } else {
        b.innerHTML='';
      }
    }
  }catch(e){console.warn('poll',e)}
}
setInterval(poll,3000);

// ════════ SHIELD UI ════════
async function loadShieldUI(){
  const sh=await J('/api/shield');SHIELD=sh;if(!sh)return;
  const banner=$('shield-status-banner');
  if(sh.enabled){
    banner.innerHTML='🛡️ SHIELD ACTIVE — '+Object.keys(sh.locked_signature||{}).length+' ports locked at '+new Date(sh.locked_at*1000).toISOString().replace('T',' ').slice(0,19)+' UTC';
    banner.style.background='linear-gradient(90deg,rgba(0,255,136,.15),rgba(0,212,255,.1))';
  } else {
    banner.innerHTML='⚠️ SHIELD DISABLED — Your real config is exposed to scanners';
    banner.style.background='linear-gradient(90deg,rgba(255,170,0,.15),rgba(255,102,0,.1))';
    banner.style.color='#ffaa00';
  }
  $('shield-jitter').checked=!!sh.jitter;
  $('shield-tarpit').checked=!!sh.tarpit;
  $('shield-decoy').checked=!!sh.decoy_scan_response;
  // Locked fingerprint
  const fp=$('locked-fp');
  if(sh.locked_signature&&Object.keys(sh.locked_signature).length){
    fp.innerHTML=Object.entries(sh.locked_signature).map(([port,info])=>
      '<div style="padding:8px 10px;border:1px solid var(--b1);border-radius:3px;margin-bottom:6px;background:rgba(0,255,136,.04)">'+
      '<div style="display:flex;justify-content:space-between">'+
      '<b style="color:#00ff88">:'+E(port)+'</b>'+
      '<span style="color:var(--cyan)">'+E(info.service||'?')+'/'+E(info.transport||'tcp')+'</span></div>'+
      '<div style="font-size:10px;opacity:.7;margin-top:4px">'+E(info.banner||'')+'</div>'+
      '<div style="font-size:9px;opacity:.5;margin-top:2px">host: '+E(info.hostname||'—')+'</div>'+
      '</div>').join('');
  } else {
    fp.innerHTML='<div style="opacity:.5">Not locked yet. Click LOCK to freeze your external signature.</div>';
  }
  // Scanners
  loadScanners();
}
async function loadScanners(){
  const r=await J('/api/shield/scanners');
  if(!r||!r.scanners)return;
  const tb=$('scanner-body');
  const list=Object.entries(r.scanners);
  if(!list.length){
    tb.innerHTML='<tr><td colspan="6" style="text-align:center;opacity:.5;padding:20px">No scanners detected</td></tr>';
    return;
  }
  tb.innerHTML=list.map(([ip,s])=>{
    const banned=s.banned_until>Date.now()/1000;
    return '<tr style="cursor:pointer" onclick="openAtt(\''+E(ip)+'\')">'+
      '<td style="color:'+(banned?'var(--red)':'var(--amber)')+'">'+E(ip)+'</td>'+
      '<td>'+s.ports+'</td><td>'+s.hits+'</td>'+
      '<td style="color:'+(banned?'var(--red)':'var(--green)')+'">'+(banned?'BANNED':'Active')+'</td>'+
      '<td>'+(banned?new Date(s.banned_until*1000).toISOString().slice(11,19):'—')+'</td>'+
      '<td style="opacity:.6;font-size:10px">'+E(s.reason||'—')+'</td></tr>';
  }).join('');
}
async function shieldLock(){
  if(!confirm('Lock current ports & banners as permanent external fingerprint?\n\nAfter this, all your config changes will NOT be visible to external scanners. Only real attackers/visitors will see new configs.'))return;
  const r=await fetch('/api/shield/lock',{method:'POST'});
  const j=await r.json();
  if(j.ok){alert('SHIELD ACTIVATED — '+j.count+' ports locked');loadShieldUI();poll()}
  else alert('Error: '+(j.error||'failed'));
}
async function shieldUnlock(){
  if(!confirm('Disable shield? Scanners will see your real config again.'))return;
  await fetch('/api/shield/unlock',{method:'POST'});
  loadShieldUI();poll();
}
async function toggleShieldOpt(key){
  const val=$('shield-'+key.replace('_scan_response','')).checked;
  await fetch('/api/shield/config',{method:'POST',body:JSON.stringify({[key]:val})});
  loadShieldUI();
}
async function clearScanners(){
  if(!confirm('Clear scanner tracking list?'))return;
  await fetch('/api/shield/clear',{method:'POST'});
  loadScanners();
}

// ════════ SSE ════════
let _sse=null,_sseBackoff=0;
function onEv(e){
  try{
    PULSES.push({ip:e.src,t:performance.now(),c:SC[e.sev]});
    const ts=(e.iso||'').slice(11,19);
    const w=document.createElement('div');w.className='trow '+e.sev+(e.shielded?' shielded':'');
    w.innerHTML='<div style="display:flex;justify-content:space-between;gap:6px;margin-bottom:3px">'+
      '<span style="color:'+SC[e.sev]+';font-weight:bold">'+E(e.sev)+'</span>'+
      (e.shielded?'<span style="color:#00ff88;font-size:9px">🛡️ SHIELD</span>':'')+
      '<span style="opacity:.5;font-size:9px">'+ts+'</span></div>'+
      '<div style="font-size:10px">'+E(e.proto)+':'+e.dport+' &middot; '+E(e.kind)+'</div>'+
      '<div style="font-size:10px;color:var(--cyan);margin-top:2px">'+E(e.src)+'</div>'+
      '<div style="font-size:9px;opacity:.6;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+E((e.data||'').slice(0,60))+'</div>';
    w.dataset.ts=e.ts;w.onclick=()=>openAtt(e.src);
    const tel=$('tel');tel.prepend(w);while(tel.children.length>100)tel.lastChild.remove();
    if(e.sevn>=3){LAST=e;try{beep()}catch(_){};showPop(e);runKI(e)}
  }catch(err){}
}
function connectSSE(){
  try{if(_sse)_sse.close()}catch(e){}
  try{
    _sse=new EventSource('/api/stream');
    _sse.onopen=()=>{_sseBackoff=0};
    _sse.onmessage=m=>{try{onEv(JSON.parse(m.data))}catch(e){}};
    _sse.onerror=()=>{try{_sse.close()}catch(e){}_sseBackoff=Math.min(_sseBackoff+1,6);setTimeout(connectSSE,1000*_sseBackoff)};
  }catch(e){setTimeout(connectSSE,3000)}
}
connectSSE();
setInterval(async()=>{
  const evs=await J('/api/events?n=15');if(!evs)return;
  const seen=new Set();document.querySelectorAll('.trow').forEach(r=>seen.add(String(r.dataset.ts)));
  evs.forEach(e=>{if(!seen.has(String(e.ts)))onEv(e)});
},5000);
J('/api/events?n=40').then(evs=>{if(evs)evs.forEach(onEv)});

function beep(){
  try{AUD=AUD||new (window.AudioContext||window.webkitAudioContext)();
    const o=AUD.createOscillator(),g=AUD.createGain();
    o.type='sawtooth';o.frequency.value=700;g.gain.value=.04;
    o.connect(g);g.connect(AUD.destination);o.start();
    o.frequency.exponentialRampToValueAtTime(1200,AUD.currentTime+.15);
    g.gain.exponentialRampToValueAtTime(.001,AUD.currentTime+.4);
    o.stop(AUD.currentTime+.4);
  }catch(e){}
}
function showPop(e){
  const d=document.createElement('div');d.className='pu';
  d.innerHTML='<div class="pu-t">'+(e.shielded?'🛡️ SHIELDED ':'')+E(e.sev)+'</div>'+
    '<div class="pu-b">SRC <b style="color:var(--wh)">'+E(e.src)+'</b><br>'+
    E(e.proto)+' :'+e.dport+' &mdash; '+E(e.kind)+'<br>'+
    '<span style="color:var(--red)">'+E(e.reason)+'</span></div>';
  $('pop').prepend(d);
  setTimeout(()=>{d.style.transition='.5s';d.style.opacity='0';d.style.transform='translateX(115%)';setTimeout(()=>d.remove(),500)},8000);
}
async function runKI(e){
  if(!e||!e.id)return;
  $('ki-box').innerHTML='<span style="opacity:.4">Analysing&hellip;</span>';
  try{
    const k=await J('/api/analyze?id='+encodeURIComponent(e.id));
    if(!k||k.error){$('ki-box').innerHTML='<span style="color:var(--red)">'+E((k&&k.error)||'Failed')+'</span>';return}
    $('ki-box').innerHTML=kiHTML(k);
  }catch(err){$('ki-box').innerHTML='<span style="color:var(--red)">'+E(err.message)+'</span>'}
}
function kiHTML(k){
  if(!k||k.error)return E(k?k.error:'error');
  const vc=k.verdict.startsWith('LIKELY')?'var(--red)':k.verdict==='SUSPICIOUS'?'var(--amber)':'var(--green)';
  return '<div class="ki-v" style="color:'+vc+'">'+E(k.verdict)+'</div>'+
    '<div style="font-size:10px;color:var(--tx);margin-bottom:10px">Confidence: <b style="color:var(--br)">'+k.confidence+'%</b></div>'+
    (k.shield?'<div style="color:#00ff88;font-size:10px;margin-bottom:8px">🛡️ Shield was active during this attack</div>':'')+
    '<div class="ki-s"><strong>INDICATORS</strong>'+(k.indicators||[]).map(i=>'<span class="ki-tag" style="border-color:var(--amber);color:var(--amber)">'+E(i)+'</span>').join('')+'</div>'+
    '<div class="ki-s"><strong>SUMMARY</strong>'+E(k.what)+'</div>'+
    '<div class="ki-s"><strong>ACTIONS</strong><ul style="padding-left:18px;margin-top:5px">'+(k.actions||[]).map(a=>'<li style="margin-bottom:3px">'+E(a)+'</li>').join('')+'</ul></div>';
}

// ════════ 3D EARTH ════════
const GC=$('globeC');
let scene,camera,renderer,earthGroup,earth,clouds,markersGroup,arcsGroup;
let GDRAG=false,GLAST={x:0,y:0};
function latLonToVec3(lat,lon,r){
  const phi=(90-lat)*Math.PI/180,theta=(lon+180)*Math.PI/180;
  return new THREE.Vector3(-r*Math.sin(phi)*Math.cos(theta),r*Math.cos(phi),r*Math.sin(phi)*Math.sin(theta));
}
function initThree(){
  scene=new THREE.Scene();
  const w=GC.parentElement.clientWidth-30,h=500;
  GC.width=w;GC.height=h;
  camera=new THREE.PerspectiveCamera(45,w/h,0.1,1000);camera.position.z=14;
  renderer=new THREE.WebGLRenderer({canvas:GC,antialias:true,alpha:true});
  renderer.setPixelRatio(Math.min(devicePixelRatio,2));renderer.setSize(w,h);
  const starGeo=new THREE.BufferGeometry();const N=3000,pos=new Float32Array(N*3);
  for(let i=0;i<N*3;i+=3){
    const r=40+Math.random()*60,theta=Math.random()*Math.PI*2,phi=Math.acos(2*Math.random()-1);
    pos[i]=r*Math.sin(phi)*Math.cos(theta);pos[i+1]=r*Math.cos(phi);pos[i+2]=r*Math.sin(phi)*Math.sin(theta);
  }
  starGeo.setAttribute('position',new THREE.BufferAttribute(pos,3));
  scene.add(new THREE.Points(starGeo,new THREE.PointsMaterial({color:0xffffff,size:0.15,transparent:true,opacity:0.8})));
  earthGroup=new THREE.Group();scene.add(earthGroup);
  const loader=new THREE.TextureLoader();loader.setCrossOrigin('anonymous');
  const eTex=loader.load('https://unpkg.com/three-globe/example/img/earth-blue-marble.jpg');
  const bTex=loader.load('https://unpkg.com/three-globe/example/img/earth-topology.png');
  const cTex=loader.load('https://unpkg.com/three-globe/example/img/earth-clouds.png');
  earth=new THREE.Mesh(new THREE.SphereGeometry(5,64,64),
    new THREE.MeshPhongMaterial({map:eTex,bumpMap:bTex,bumpScale:0.1,shininess:5,specular:new THREE.Color('grey')}));
  earthGroup.add(earth);
  clouds=new THREE.Mesh(new THREE.SphereGeometry(5.02,64,64),
    new THREE.MeshLambertMaterial({map:cTex,transparent:true,opacity:0.35,depthWrite:false}));
  earthGroup.add(clouds);
  earthGroup.add(new THREE.Mesh(new THREE.SphereGeometry(5.5,64,64),
    new THREE.MeshBasicMaterial({color:0x3399ff,transparent:true,opacity:0.1,side:THREE.BackSide})));
  scene.add(new THREE.AmbientLight(0xffffff,0.5));
  const sun=new THREE.DirectionalLight(0xffffff,1.2);sun.position.set(8,3,8);scene.add(sun);
  const rim=new THREE.DirectionalLight(0x4488ff,0.5);rim.position.set(-8,-3,-8);scene.add(rim);
  markersGroup=new THREE.Group();earthGroup.add(markersGroup);
  arcsGroup=new THREE.Group();earthGroup.add(arcsGroup);
  animate();window.earthGroup=earthGroup;updateMyLocation();
  addEventListener('resize',()=>{
    const w=GC.parentElement.clientWidth-30;
    GC.width=w;renderer.setSize(w,500);camera.aspect=w/500;camera.updateProjectionMatrix();
  });
}
function animate(){
  requestAnimationFrame(animate);
  try{
    if(!GDRAG){earthGroup.rotation.y+=0.0015;clouds.rotation.y+=0.0008}
    const t=performance.now()/400;
    markersGroup.children.forEach(m=>{if(m.userData&&m.userData.halo){const s=1+Math.sin(t)*0.3;m.userData.halo.scale.set(s,s,s)}});
    if(window.youMarker&&window.youMarker.userData.halo){const s=1+Math.sin(t*0.8)*0.4;window.youMarker.userData.halo.scale.set(s,s,s)}
    renderer.render(scene,camera);
  }catch(e){}
}
GC.addEventListener('mousedown',e=>{GDRAG=true;GLAST={x:e.clientX,y:e.clientY};GC.style.cursor='grabbing'});
window.addEventListener('mousemove',e=>{
  if(!GDRAG)return;
  const dx=e.clientX-GLAST.x,dy=e.clientY-GLAST.y;
  earthGroup.rotation.y+=dx*0.005;
  earthGroup.rotation.x=cl(earthGroup.rotation.x+dy*0.003,-0.6,0.6);
  GLAST={x:e.clientX,y:e.clientY};
});
window.addEventListener('mouseup',()=>{GDRAG=false;GC.style.cursor='grab'});
GC.addEventListener('wheel',e=>{e.preventDefault();camera.position.z=cl(camera.position.z+e.deltaY*0.008,7,25)});

function getHit(e){
  const rect=GC.getBoundingClientRect();
  const mouse=new THREE.Vector2(((e.clientX-rect.left)/rect.width)*2-1,-((e.clientY-rect.top)/rect.height)*2+1);
  const ray=new THREE.Raycaster();ray.setFromCamera(mouse,camera);
  const hits=ray.intersectObjects(markersGroup.children,true);
  if(hits.length){
    let obj=hits[0].object;while(obj&&!obj.userData.ip)obj=obj.parent;
    if(obj&&obj.userData.ip)return {type:'attacker',data:obj.userData};
  }
  if(window.youMarker){
    const h2=ray.intersectObject(window.youMarker,false);
    if(h2.length)return {type:'you'};
  }
  return null;
}
GC.addEventListener('mousemove',e=>{
  const hit=getHit(e);const tip=$('g-tip');const rect=GC.getBoundingClientRect();
  if(hit&&hit.type==='attacker'){
    const d=hit.data;
    tip.style.display='block';tip.style.left=(e.clientX-rect.left+15)+'px';tip.style.top=(e.clientY-rect.top)+'px';
    tip.innerHTML='<b style="color:'+(d.shielded?'#00ff88':(SC[SEVS[d.maxsev]]||'#fff'))+'">'+E(d.ip)+'</b>'+(d.shielded?' 🛡️':'')+'<br>'+
      (d.city?E(d.city)+', ':'')+(d.region?E(d.region)+', ':'')+(d.country?E(d.country):'')+
      '<br><span style="opacity:.7">'+E(d.isp||'Unknown ISP')+'</span>';
    GC.style.cursor='pointer';
  }else if(hit&&hit.type==='you'){
    tip.style.display='block';tip.style.left=(e.clientX-rect.left+15)+'px';tip.style.top=(e.clientY-rect.top)+'px';
    tip.innerHTML='<b style="color:#00d4ff">YOU</b><br>'+E([MY_LOC.city,MY_LOC.regionName,MY_LOC.country].filter(Boolean).join(', '));
    GC.style.cursor='pointer';
  }else{tip.style.display='none';if(!GDRAG)GC.style.cursor='grab'}
});
GC.addEventListener('click',e=>{
  const hit=getHit(e);
  if(hit&&hit.type==='attacker')openAtt(hit.data.ip);
  else if(hit&&hit.type==='you')showYouInfo();
});

function updateAttackers3D(){
  if(!markersGroup||!ST)return;
  const existing={};markersGroup.children.forEach(m=>{if(m.userData.ip)existing[m.userData.ip]=m});
  const newIPs=new Set();
  (ST.attackers||[]).forEach(a=>{
    if(!a.geo||a.geo.lat==null)return;
    newIPs.add(a.ip);let marker=existing[a.ip];
    if(!marker){
      const col=a.shielded?'#00ff88':(SC[SEVS[a.maxsev]]||'#ff2255');
      const g=new THREE.Group();
      g.add(new THREE.Mesh(new THREE.SphereGeometry(0.1,16,16),new THREE.MeshBasicMaterial({color:col})));
      const halo=new THREE.Mesh(new THREE.SphereGeometry(0.2,16,16),
        new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:0.4,side:THREE.BackSide}));
      g.add(halo);
      g.position.copy(latLonToVec3(a.geo.lat,a.geo.lon,5.05));
      g.userData={ip:a.ip,city:a.geo.city,region:a.geo.regionName,country:a.geo.country,
                  isp:a.geo.isp,mac:a.mac,ua:a.ua,maxsev:a.maxsev,halo:halo,shielded:a.shielded};
      markersGroup.add(g);marker=g;
      if(MY_LOC.lat!=null){
        const start=latLonToVec3(a.geo.lat,a.geo.lon,5.02);
        const end=latLonToVec3(MY_LOC.lat,MY_LOC.lon,5.02);
        const mid=start.clone().add(end).normalize().multiplyScalar(7.5);
        const curve=new THREE.QuadraticBezierCurve3(start,mid,end);
        const arcGeo=new THREE.BufferGeometry().setFromPoints(curve.getPoints(60));
        const arcMat=new THREE.LineBasicMaterial({color:col,transparent:true,opacity:0.55});
        const arc=new THREE.Line(arcGeo,arcMat);arc.userData={ip:a.ip};
        arcsGroup.add(arc);
      }
    }else{
      marker.userData.maxsev=a.maxsev;marker.userData.shielded=a.shielded;
    }
  });
  markersGroup.children.slice().forEach(m=>{if(m.userData.ip&&!newIPs.has(m.userData.ip))markersGroup.remove(m)});
  arcsGroup.children.slice().forEach(m=>{if(m.userData.ip&&!newIPs.has(m.userData.ip))arcsGroup.remove(m)});
}

function showYouInfo(){
  const confColor=MY_LOC.confidence==='HIGH'?'var(--green)':MY_LOC.confidence==='MEDIUM'?'var(--amber)':'var(--red)';
  $('mc').innerHTML='<h2 style="color:#00d4ff;font-family:Rajdhani,sans-serif;letter-spacing:4px;margin-bottom:16px">&#9679; YOUR LOCATION</h2>'+
    '<div class="ki-s"><strong>GEOGRAPHY</strong><b style="color:#00d4ff;font-size:14px">'+E([MY_LOC.city,MY_LOC.regionName,MY_LOC.country].filter(Boolean).join(', '))+'</b><br>'+
    'Lat: '+E(MY_LOC.lat)+'&deg; &middot; Lon: '+E(MY_LOC.lon)+'&deg;</div>'+
    '<div class="ki-s"><strong>NETWORK</strong>IP: '+E(MY_LOC.ip||'—')+'<br>ISP: '+E(MY_LOC.isp||'—')+'</div>'+
    '<div class="ki-s"><strong>GEOIP CROSS-CHECK</strong>Sources: '+(MY_LOC.sources||[]).map(x=>'<span class="ki-tag" style="border-color:var(--cyan);color:var(--cyan)">'+E(x)+'</span>').join('')+'<br>'+
    'Confidence: <b style="color:'+confColor+'">'+E(MY_LOC.confidence||'—')+'</b>'+(MY_LOC.agreement_km!=null?' (sources agree within '+MY_LOC.agreement_km+' km)':'')+'</div>'+
    (MY_LOC.proxy||MY_LOC.hosting?'<div class="ki-s" style="border-left-color:var(--amber)"><strong style="color:var(--amber)">⚠ WARNING</strong>Your own connection looks like it is going through a '+(MY_LOC.proxy?'VPN/proxy':'')+(MY_LOC.proxy&&MY_LOC.hosting?' / ':'')+(MY_LOC.hosting?'datacenter/hosting IP':'')+' — shown location is the exit node, not your real one.</div>':'');
  $('modal').classList.add('on');$('modal').style.display='block';
}

async function openAtt(ip){
  const d=await J('/api/attacker?ip='+encodeURIComponent(ip));
  if(!d||!d.a)return;
  const a=d.a,g=a.geo||{};
  const locStr=[g.city,g.regionName,g.country].filter(Boolean).join(', ')||'Unknown';
  const confColor=g.confidence==='HIGH'?'var(--green)':g.confidence==='MEDIUM'?'var(--amber)':'var(--red)';
  let h='<h2 style="color:var(--cyan);font-family:Rajdhani,sans-serif;letter-spacing:4px;margin-bottom:16px;font-size:22px">TARGET DOSSIER &mdash; '+E(ip)+'</h2>';
  if(a.shielded)h+='<div style="background:rgba(0,255,136,.1);border:1px solid rgba(0,255,136,.4);padding:10px 14px;border-radius:4px;margin-bottom:14px;color:#00ff88;font-size:11px">🛡️ SHIELD ACTIVATED — This attacker hit the locked fingerprint. Decoy response was served.</div>';
  if(g.proxy||g.hosting)h+='<div style="background:rgba(255,170,0,.1);border:1px solid rgba(255,170,0,.4);padding:10px 14px;border-radius:4px;margin-bottom:14px;color:var(--amber);font-size:11px">⚠️ '+(g.proxy?'VPN/PROXY':'')+(g.proxy&&g.hosting?' + ':'')+(g.hosting?'DATACENTER/HOSTING IP':'')+' detected — the location below is the exit node / server location, not the real attacker IP.</div>';
  h+='<div class="g g2" style="gap:12px;margin-bottom:14px">'+
    '<div class="ki-s"><strong>LOCATION</strong><b style="color:var(--cyan);font-size:14px">'+E(locStr)+'</b><br>'+
      '<span style="opacity:.7">'+E(g.isp||'Unknown ISP')+'</span><br><span style="opacity:.5;font-size:10px">'+E(g.asn||g.as||'')+'</span></div>'+
    '<div class="ki-s"><strong>GEOIP CROSS-CHECK</strong>'+(g.sources||[]).map(x=>'<span class="ki-tag" style="border-color:var(--cyan);color:var(--cyan)">'+E(x)+'</span>').join('')+
      '<br>Confidence: <b style="color:'+confColor+'">'+E(g.confidence||'—')+'</b>'+(g.agreement_km!=null?' <span style="opacity:.6">(&Delta;'+g.agreement_km+'km)</span>':'')+'</div>'+
    '<div class="ki-s"><strong>NETWORK</strong>MAC: <b style="color:'+(a.mac?'var(--green)':'var(--tx)')+'">'+E(a.mac||'N/A')+'</b><br>DNS: '+E(a.dns||'—')+'<br>Private: '+E(a.private?'YES':'no')+'</div>'+
    '<div class="ki-s"><strong>DEVICE</strong>'+(a.ua?'<div style="font-size:10px;word-break:break-word">'+E(a.ua)+'</div>':'<span style="opacity:.5">No UA captured</span>')+'</div>'+
    '<div class="ki-s"><strong>ACTIVITY</strong><b>'+a.conns+'</b> conns &middot; <b>'+a.events+'</b> events &middot; <b style="color:var(--amber)">'+a.alerts+'</b> alerts<br>'+
      'Peak: <span style="color:'+SC[SEVS[a.maxsev]]+'">'+SEVS[a.maxsev]+'</span><br>Ports: '+a.ports.join(', ')+'</div>'+
    '<div class="ki-s"><strong>SOURCE TRUST</strong>'+
      ((a.tcp_hits||0)>0?'<span style="color:var(--green)">✓ '+a.tcp_hits+' TCP (handshake-verified IP)</span><br>':'')+
      ((a.udp_hits||0)>0?'<span style="color:var(--amber)">⚠ '+a.udp_hits+' UDP (source IP spoofable)</span>':'')+
      (!(a.tcp_hits||0)&&!(a.udp_hits||0)?'<span style="opacity:.5">No data</span>':'')+'</div>'+
    '</div>'+
    '<div style="font-family:Rajdhani,sans-serif;font-size:12px;letter-spacing:3px;color:var(--cyan);margin-bottom:10px">TIMELINE</div><div class="af">';
  (d.events||[]).slice(-30).forEach(e=>{
    h+='<div class="af-ev '+e.sev+'"><div class="af-hdr" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display===\'block\'?\'none\':\'block\'">'+
      '<span style="color:'+SC[e.sev]+';font-weight:bold">['+E(e.sev)+']</span> '+
      (e.shielded?'<span style="color:#00ff88">🛡️</span> ':'')+
      '<span style="opacity:.5">'+E(e.iso.slice(11,19))+'</span> '+
      '<b style="color:var(--cyan)">'+E(e.proto)+':'+e.dport+'</b> '+E(e.kind)+
      ' &mdash; <span style="opacity:.7">'+E((e.data||'').slice(0,55))+'</span></div>'+
      '<div class="af-body">'+E(JSON.stringify(e,null,2))+'</div></div>';
  });
  h+='</div>';
  $('mc').innerHTML=h;$('modal').classList.add('on');$('modal').style.display='block';
}
function closeModal(){$('modal').classList.remove('on');$('modal').style.display='none'}

async function openSvc(n){
  const evs=await J('/api/events?proto='+encodeURIComponent(n)+'&n=20');
  if(!ST)return;const c=ST.services[n];
  $('mc').innerHTML='<h2 style="color:var(--cyan);font-family:Rajdhani,sans-serif;letter-spacing:4px;margin-bottom:14px">'+E(n)+'</h2>'+
  '<div class="ki-s"><strong>CONFIG</strong>'+c.transport+'/'+c.port+'<br>banner: '+E(c.banner)+'<br>Status: '+c.status+'</div>'+
  (evs&&evs.length?evs.map(e=>'<div class="af-ev '+e.sev+'"><div class="af-hdr">['+E(e.sev)+'] '+E(e.src)+' '+E(e.kind)+'</div></div>').join(''):'<div style="opacity:.5">No events</div>');
  $('modal').classList.add('on');$('modal').style.display='block';
}

// ════════ RADAR ════════
const RC=$('radarC'),RX=RC.getContext('2d');let RANGLE=0;
function hipHash(s){let h=5381;for(let i=0;i<s.length;i++)h=((h<<5)+h+s.charCodeAt(i))|0;return Math.abs(h)}
function drawRadar(){
  try{
    const W=RC.width=RC.parentElement.clientWidth-30,H=380;
    const cx=W/2,cy=H/2,R=Math.min(cx,cy)-20;
    RX.clearRect(0,0,W,H);
    RX.strokeStyle='rgba(0,212,255,.08)';
    for(let i=1;i<=4;i++){RX.beginPath();RX.arc(cx,cy,R*i/4,0,Math.PI*2);RX.stroke()}
    RX.beginPath();RX.moveTo(cx-R,cy);RX.lineTo(cx+R,cy);RX.moveTo(cx,cy-R);RX.lineTo(cx,cy+R);
    RX.strokeStyle='rgba(0,212,255,.05)';RX.stroke();
    RANGLE+=0.014;
    if(RX.createConicGradient){
      const sg=RX.createConicGradient(RANGLE,cx,cy);
      sg.addColorStop(0,'rgba(0,255,136,.18)');sg.addColorStop(.1,'rgba(0,255,136,.06)');sg.addColorStop(.11,'transparent');
      RX.fillStyle=sg;RX.beginPath();RX.arc(cx,cy,R,0,Math.PI*2);RX.fill();
    }
    RX.beginPath();RX.moveTo(cx,cy);RX.lineTo(cx+R*Math.cos(RANGLE),cy+R*Math.sin(RANGLE));
    RX.strokeStyle='rgba(0,255,136,.6)';RX.lineWidth=1.5;RX.stroke();
    RX.beginPath();RX.arc(cx,cy,3,0,Math.PI*2);RX.fillStyle='#00d4ff';RX.shadowBlur=12;RX.shadowColor='#00d4ff';RX.fill();RX.shadowBlur=0;
    RPTS=[];const now=performance.now();
    if(ST&&ST.attackers){
      ST.attackers.forEach(a=>{
        const h=hipHash(a.ip),th=(h%6283)/1000,rf=.28+.65*(h%97)/97;
        const r=R*rf,x=cx+r*Math.cos(th),y=cy+r*Math.sin(th);
        const col=a.shielded?'#00ff88':(SC[SEVS[a.maxsev]]||'#ff2255');
        const pu=PULSES.find(p=>p.ip===a.ip&&now-p.t<2500);
        if(pu){const age=(now-pu.t)/2500;RX.beginPath();RX.arc(x,y,8+60*age,0,Math.PI*2);
          RX.strokeStyle=col+Math.round((1-age)*100).toString(16).padStart(2,'0');RX.lineWidth=1.5;RX.stroke()}
        const sz=cl(3+a.maxsev*.9,2.5,10);
        RX.beginPath();RX.arc(x,y,sz,0,Math.PI*2);
        RX.shadowBlur=a.maxsev>=2?16:6;RX.shadowColor=col;RX.fillStyle=col;RX.fill();RX.shadowBlur=0;
        RPTS.push({x,y,ip:a.ip});
      });
    }
    RPTS_LOCAL=[];
    LOCAL_DEVICES.forEach(d=>{
      const h=hipHash(d.ip),th=(h%6283)/1000,rf=.15+.35*(h%97)/97;
      const r=R*rf,x=cx+r*Math.cos(th),y=cy+r*Math.sin(th);
      RX.fillStyle='rgba(0,255,136,.2)';RX.strokeStyle='rgba(0,255,136,.7)';RX.lineWidth=1.2;
      RX.fillRect(x-5,y-5,10,10);RX.strokeRect(x-5,y-5,10,10);
      RX.font='8px Share Tech Mono';RX.fillStyle='rgba(0,255,136,.85)';RX.fillText(d.ip,x+8,y-6);
      RPTS_LOCAL.push({x,y,dev:d});
    });
    PULSES=PULSES.filter(p=>now-p.t<2500);
  }catch(e){}
}
RC.onclick=ev=>{
  const b=RC.getBoundingClientRect(),x=ev.clientX-b.left,y=ev.clientY-b.top;
  const ld=RPTS_LOCAL.find(p=>Math.hypot(p.x-x,p.y-y)<14);
  if(ld){openDevice(ld.dev);return}
  const p=RPTS.find(p=>Math.hypot(p.x-x,p.y-y)<12);if(p)openAtt(p.ip);
};
function openDevice(d){
  $('mc').innerHTML='<h2 style="color:var(--green);font-family:Rajdhani,sans-serif;letter-spacing:4px;margin-bottom:16px">&#9632; LOCAL DEVICE</h2>'+
    '<div class="ki-s"><strong>INFO</strong>IP: <b>'+E(d.ip)+'</b><br>MAC: '+E(d.mac||'—')+'<br>Hostname: '+E(d.hostname||'—')+'<br>Vendor: '+E(d.vendor||'—')+'</div>';
  $('modal').classList.add('on');$('modal').style.display='block';
}

// ════════ LOGS ════════
async function loadLogs(){
  const q=new URLSearchParams({q:$('lf-q').value,sev:$('lf-s').value,ip:$('lf-ip').value,
    shielded:$('lf-shield').checked?1:'',n:500});
  const evs=await J('/api/events?'+q);if(!evs)return;
  $('log-body').innerHTML=evs.slice().reverse().map(e=>
    '<tr style="cursor:pointer" onclick="openAtt(\''+E(e.src)+'\')">'+
    '<td>'+E(e.iso)+'</td><td style="color:'+SC[e.sev]+'">'+E(e.sev)+'</td>'+
    '<td>'+(e.shielded?'🛡️':'—')+'</td>'+
    '<td style="color:var(--cyan)">'+E(e.proto)+'</td><td>'+E(e.src)+'</td><td>'+e.dport+'</td><td>'+E(e.kind)+'</td>'+
    '<td style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+E((e.data||'').slice(0,90))+'</td>'+
    '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;opacity:.6">'+E(e.reason)+'</td></tr>').join('');
}

// ════════ PORTS ════════
async function loadPortsUI(){
  const cf=await J('/api/config');if(!cf)return;CFG2=cf;
  $('port-body').innerHTML=Object.entries(cf.services).map(([n,c])=>{
    const st=ST&&ST.services[n]?ST.services[n]:{status:'?',conns:0,events:0,alerts:0};
    const inp=(cls,v,w)=>'<input class="'+cls+'" value="'+E(v)+'" style="width:'+w+'px;background:rgba(1,4,9,.9);border:1px solid var(--b1);color:var(--br);font:10px \'Share Tech Mono\',monospace;padding:4px 6px;border-radius:2px">';
    return '<tr data-n="'+E(n)+'">'+
      '<td style="color:var(--cyan)">'+E(n)+'</td>'+
      '<td><input type="checkbox" class="c-en"'+(c.enabled?' checked':'')+'></td>'+
      '<td>'+inp('c-pt',c.port,60)+'</td>'+
      '<td>'+inp('c-bn',c.banner,250)+'</td>'+
      '<td>'+inp('c-hn',c.hostname,90)+'</td>'+
      '<td style="color:'+(st.status==='listening'?'var(--green)':'var(--red)')+'">'+st.status+'</td>'+
      '<td>'+(st.conns||0)+'</td><td>'+(st.events||0)+'</td><td style="color:var(--amber)">'+(st.alerts||0)+'</td></tr>';
  }).join('');
}
async function savePorts(){
  const b={services:{}};
  document.querySelectorAll('#port-body tr[data-n]').forEach(r=>{
    b.services[r.dataset.n]={enabled:r.querySelector('.c-en').checked,
      port:r.querySelector('.c-pt').value,banner:r.querySelector('.c-bn').value,
      hostname:r.querySelector('.c-hn').value};
  });
  const r=await fetch('/api/config',{method:'POST',body:JSON.stringify(b)});
  const j=await r.json();
  const msg=$('port-msg');
  msg.textContent=j.ok?'Applied'+(SHIELD&&SHIELD.enabled?' (Shield still active — external view unchanged)':''):'Error: '+j.error;
  msg.style.color=j.ok?'var(--green)':'var(--red)';
  await poll();loadPortsUI();
}

// ════════ CONFIG ════════
async function loadCfgUI(){
  const cf=CFG2||await J('/api/config');if(!cf)return;
  const wl=cf.web_lockout||{attempts:6,window:300,ban:900};
  $('cfg-body').innerHTML=
    '<div class="fr"><div class="ff"><label>Listen Address</label><input id="k-la" value="'+E(cf.listen_address)+'"></div>'+
    '<div class="ff"><label>Session Timeout (s)</label><input id="k-st" value="'+cf.web_session_timeout+'"></div></div>'+
    '<div class="fr"><div class="ff"><label>Alert Threshold</label><input id="k-at" value="'+cf.alert.threshold+'"></div>'+
    '<div class="ff"><label>Brute-Force Threshold</label><input id="k-bf" value="'+cf.alert.brute+'"></div></div>'+
    '<div class="ff"><label><input type="checkbox" id="k-ge"'+(cf.geo.enabled?' checked':'')+'> Enable Geolocation</label></div>'+
    '<div class="ff"><label>Alert Webhook URL (Discord/Slack — fires on HIGH/CRITICAL)</label><input id="k-wh" placeholder="https://discord.com/api/webhooks/..." value="'+E(cf.alert.webhook||'')+'"></div>'+
    '<div style="font-size:9px;letter-spacing:3px;color:var(--cyan);margin:18px 0 8px">ADMIN PANEL LOGIN PROTECTION</div>'+
    '<div class="fr"><div class="ff"><label>Lockout After (attempts)</label><input id="k-wla" value="'+wl.attempts+'"></div>'+
    '<div class="ff"><label>Lockout Duration (s)</label><input id="k-wlb" value="'+wl.ban+'"></div></div>';
}
async function saveCfg(){
  const b={listen_address:$('k-la').value,web_session_timeout:+$('k-st').value,
    alert:{threshold:+$('k-at').value,brute:+$('k-bf').value,webhook:$('k-wh').value.trim()},
    geo:{enabled:$('k-ge').checked},
    web_lockout:{attempts:+$('k-wla').value,ban:+$('k-wlb').value}};
  const r=await fetch('/api/config',{method:'POST',body:JSON.stringify(b)});
  const j=await r.json();
  const msg=$('cfg-msg');msg.textContent=j.ok?'Saved':'Error: '+j.error;
  msg.style.color=j.ok?'var(--green)':'var(--red)';
}

try{initThree()}catch(e){console.error('Three.js failed:',e);
  GC.parentElement.innerHTML='<div style="padding:60px;text-align:center;color:#ff2255">3D Earth requires internet. Check connection.</div>';}
(function loopRadar(){try{drawRadar()}catch(e){}requestAnimationFrame(loopRadar)})();
poll();
</script></body></html>"""

# ═══════════════════════════════════════════════════════════════════
#  WEB HANDLER
# ═══════════════════════════════════════════════════════════════════
class _Web(BaseHTTPRequestHandler):
    server_version="SentinelX/2"
    def log_message(s,*a):pass
    def _user(s):
        m=re.search(r"sx=([\w-]+)",s.headers.get("Cookie",""))
        t=SESS.get(m.group(1)) if m else None
        if t and t>time.time():SESS[m.group(1)]=time.time()+CFG["web_session_timeout"];return True
        return False
    def _out(s,code,body,ct="text/html;charset=utf-8",extra=()):
        try:
            b=body if isinstance(body,bytes) else body.encode()
            s.send_response(code);s.send_header("Content-Type",ct);s.send_header("Content-Length",str(len(b)))
            s.send_header("X-Frame-Options","DENY");s.send_header("Cache-Control","no-store")
            s.send_header("X-Content-Type-Options","nosniff")
            s.send_header("Referrer-Policy","no-referrer")
            s.send_header("Permissions-Policy","geolocation=(),camera=(),microphone=(),interest-cohort=()")
            s.send_header("Content-Security-Policy",
                "default-src 'self';"
                "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://unpkg.com;"
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;"
                "font-src https://fonts.gstatic.com;"
                "img-src 'self' data: blob: https:;"
                "connect-src 'self';"
                "object-src 'none';base-uri 'none';frame-ancestors 'none'")
            for h in extra:s.send_header(*h)
            s.end_headers();s.wfile.write(b)
        except:pass
    def _js(s,o,code=200):s._out(code,json.dumps(o),"application/json")
    def _form(s):
        n=int(s.headers.get("Content-Length",0));return s.rfile.read(min(n,1<<20))
    def do_GET(s):
        try:
            u=urlparse(s.path);q=parse_qs(u.query)
            if not auth_exists():return s._out(200,_page_signup("No accounts exist. Create first operator."))
            if u.path=="/logout":
                m=re.search(r"sx=([\w-]+)",s.headers.get("Cookie",""))
                if m:SESS.pop(m.group(1),None)
                return s._out(302,"",extra=[("Location","/"),("Set-Cookie","sx=;Max-Age=0;Path=/")])
            if u.path=="/signup" and not s._user():return s._out(200,_page_signup())
            if not s._user():return s._out(200,_page_login())
            if u.path=="/":return s._out(200,PAGE_MAIN)
            if u.path=="/api/state":
                with LOCK:
                    now=time.time();epm=sum(1 for t in TIMES if now-t<60)
                    svcs={n:dict(c,status="disabled" if not c["enabled"] else "failure" if n in ERR else "listening",
                        error=ERR.get(n,""),**{k:SVCSTAT[n][k] for k in("conns","events","alerts")})
                        for n,c in CFG["services"].items()}
                    atts=sorted(ATT.values(),key=lambda a:-a["last"])[:150]
                    return s._js(dict(stats=dict(STATS),epm=epm,
                        active=sum(1 for a in ATT.values() if now-a["last"]<300),
                        sessions=sum(l.active for l in LISTENERS.values()),
                        services=svcs,attackers=[_esc(a) for a in atts],
                        ports=PORTS.most_common(6),mylocation=MY_LOC))
            if u.path=="/api/shield":return s._js(SHIELD)
            if u.path=="/api/shield/scanners":
                with SCAN_LOCK:
                    out={}
                    for ip,st in SHIELD["scanners"].items():
                        now=time.time()
                        hits=len([h for h in st.get("hits",[]) if now-h<60])
                        ports=len([p for p,t in st.get("ports",{}).items() if now-t<60])
                        if hits or ports:
                            out[ip]=dict(hits=hits,ports=ports,
                                banned_until=st.get("banned_until",0),reason=st.get("reason",""))
                    return s._js({"scanners":out})
            if u.path=="/api/events":return s._js(_filt(q)[-int(q.get("n",["300"])[0]):])
            if u.path=="/api/attacker":
                ip=q.get("ip",[""])[0]
                with LOCK:return s._js(dict(a=_esc(ATT[ip]) if ip in ATT else None,
                    events=[e for e in EVENTS if e["src"]==ip][-200:]))
            if u.path=="/api/analyze":
                with LOCK:ev=next((e for e in EVENTS if e["id"]==q.get("id",[""])[0]),None)
                return s._js(analyze(ev) if ev else{"error":"not found"})
            if u.path=="/api/config":return s._js(CFG)
            if u.path=="/api/mylocation":
                try:
                    with urllib.request.urlopen("https://api.ipify.org?format=json",timeout=6) as r:myip=json.load(r).get("ip","")
                except:myip=""
                g=geo_lookup(myip) if myip else None
                if g:
                    MY_LOC.update(g);MY_LOC["ip"]=myip;MY_LOC["src"]="multi"
                    return s._js(g)
                return s._js({"error":"geo failed"})
            if u.path=="/api/localdevices":
                devices,err=arp_scan()
                return s._js(dict(devices=devices,error=err))
            if u.path=="/api/download":
                fmt=q.get("fmt",["jsonl"])[0];evs=_filt(q)
                if fmt=="json":b,ct=json.dumps(evs,indent=2),"application/json"
                elif fmt=="csv":
                    import csv,io;o=io.StringIO();w=csv.writer(o)
                    cols=["iso","sev","proto","src","dport","kind","ua","data","reason","shielded"]
                    w.writerow(cols)
                    for e in evs:w.writerow([str(e.get(c) or "") for c in cols])
                    b,ct=o.getvalue(),"text/csv"
                else:b,ct="\n".join(json.dumps(e) for e in evs),"application/x-ndjson"
                return s._out(200,b,ct,[("Content-Disposition","attachment;filename=sentinelx_logs."+fmt)])
            if u.path=="/api/stream":
                qq=queue.Queue(200);SUBS.append(qq)
                s.send_response(200);s.send_header("Content-Type","text/event-stream")
                s.send_header("Cache-Control","no-cache");s.send_header("X-Accel-Buffering","no");s.end_headers()
                try:
                    while True:
                        try:e=qq.get(timeout=15);s.wfile.write(("data:%s\n\n"%json.dumps(e)).encode())
                        except queue.Empty:s.wfile.write(b":ping\n\n")
                        s.wfile.flush()
                except:pass
                finally:
                    try:SUBS.remove(qq)
                    except:pass
                return
            s._out(404,"not found","text/plain")
        except:
            traceback.print_exc()
            try:s._out(500,"error","text/plain")
            except:pass

    def do_POST(s):
        try:
            u=urlparse(s.path)
            f=({k:v[0] for k,v in parse_qs(s._form().decode("utf-8","replace")).items()}
               if u.path not in("/api/config","/api/shield/config") else None)
            if u.path in("/signup","/setup"):
                un,pw_,us=f.get("u","").strip(),f.get("p",""),_users()
                err=("Username 3-32 chars" if not re.fullmatch(r"[\w.\-]{3,32}",un) else
                     "Password min 10 chars" if len(pw_)<10 else
                     "Passwords mismatch" if pw_!=f.get("p2","") else
                     "Username taken" if un in us else "")
                if err:return s._out(200,_page_signup(err))
                add_user(un,pw_)
                return s._out(200,_page_login("Created. Please log in.",ok=True))
            if not auth_exists():return s._out(302,"",extra=[("Location","/")])
            if u.path=="/login":
                cip=s.client_address[0];now=time.time();lo=CFG["web_lockout"]
                if WEB_BAN.get(cip,0)>now:
                    wait=int(WEB_BAN[cip]-now)
                    return s._out(429,_page_login("Too many failed attempts. Try again in %ds."%wait))
                time.sleep(0.4)
                if check_auth(f.get("u",""),f.get("p","")):
                    WEB_FAIL.pop(cip,None);WEB_BAN.pop(cip,None)
                    t=secrets.token_urlsafe(24)
                    SESS[t]=time.time()+CFG["web_session_timeout"];SESSU[t]=f["u"]
                    emit(cip,0,CFG["web_port"],"WEBADMIN","connect","","login ok")
                    return s._out(302,"",extra=[("Location","/"),("Set-Cookie","sx=%s;HttpOnly;SameSite=Strict;Path=/"%t)])
                d=WEB_FAIL[cip];d.append(now)
                while d and now-d[0]>lo["window"]:d.popleft()
                if len(d)>=lo["attempts"]:
                    WEB_BAN[cip]=now+lo["ban"]
                    emit(cip,0,CFG["web_port"],"WEBADMIN","auth","brute lockout","banned")
                    return s._out(429,_page_login("Too many failed attempts. Locked out for %ds."%lo["ban"]))
                return s._out(200,_page_login("Invalid credentials (%d/%d attempts left)"%(lo["attempts"]-len(d),lo["attempts"])))
            if not s._user():return s._out(401,"auth required","text/plain")
            if u.path=="/api/shield/lock":
                try:
                    sig=shield_lock_current()
                    return s._js({"ok":True,"count":len(sig)})
                except Exception as e:return s._js({"ok":False,"error":str(e)},400)
            if u.path=="/api/shield/unlock":
                shield_unlock();return s._js({"ok":True})
            if u.path=="/api/shield/clear":
                with SCAN_LOCK:SHIELD["scanners"]={}
                shield_save();return s._js({"ok":True})
            if u.path=="/api/shield/config":
                try:
                    body=json.loads(s._form())
                    for k in("jitter","tarpit","decoy_scan_response"):
                        if k in body:SHIELD[k]=bool(body[k])
                    shield_save();return s._js({"ok":True})
                except Exception as e:return s._js({"ok":False,"error":str(e)},400)
            if u.path=="/api/config":
                try:
                    new=json.loads(s._form());nc=json.loads(json.dumps(CFG));_merge(nc,new);_validate(nc)
                    CFG.clear();CFG.update(nc);save_cfg();restart_listeners()
                    return s._js({"ok":True,"errors":ERR,"shield_active":SHIELD["enabled"]})
                except Exception as e:return s._js({"ok":False,"error":str(e)},400)
            s._out(404,"not found","text/plain")
        except:
            traceback.print_exc()
            try:s._out(500,"error","text/plain")
            except:pass

# ═══════════════════════════════════════════════════════════════════
#  ENTRY
# ═══════════════════════════════════════════════════════════════════
def main():
    print("="*66)
    print("   SENTINEL-X ULTIMATE + SHIELD")
    print("="*66)
    shield_load()
    geoip_init()
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json",timeout=8) as r:myip=json.load(r).get("ip","")
    except Exception as e:myip="";print("  [!] Public IP detect failed:",e)
    g=geo_lookup(myip) if myip else None
    if g:
        MY_LOC.update(g);MY_LOC["ip"]=myip;MY_LOC["src"]="multi"
        print("  Location: %s, %s, %s  (confidence: %s, sources: %s)"%(
            g.get("city"),g.get("regionName"),g.get("country"),g.get("confidence"),",".join(g.get("sources",[]))))
        print("  Public IP: %s"%myip)
    else:
        print("  [!] Location detect failed (no geo source responded)")
    try:
        with open(EV_F) as f:
            for l in f.readlines()[-2000:]:
                try:EVENTS.append(json.loads(l))
                except:pass
    except:pass
    restart_listeners()
    print("  SHIELD: %s"%("ACTIVE" if SHIELD["enabled"] else "Disabled (configurable in dashboard)"))
    host="127.0.0.1";port=CFG["web_port"]
    srv=None
    for p in [port,8081,8082,8888,9090,7070]:
        try:srv=ThreadingHTTPServer((host,p),_Web);port=p;break
        except OSError:pass
    if srv is None:print("  [!] No free port.");input("Press Enter...");return
    srv.daemon_threads=True
    print("  GUI  >  http://%s:%d"%(host,port))
    print("  Data >  %s"%DATA)
    print("  Ctrl+C to stop")
    print("="*66)
    for n,e in ERR.items():print("  [!] %s: %s"%(n,e))
    try:srv.serve_forever()
    except KeyboardInterrupt:print("\n  Shutting down...")
    finally:
        for l in LISTENERS.values():l.stop()

if __name__=="__main__":
    try:main()
    except KeyboardInterrupt:print("\n[!] Interrupted.")
    except Exception:
        print("\n"+"!"*66);traceback.print_exc();print("!"*66)
    finally:
        try:
            if sys.stdin.isatty():input("\nPress Enter to close...")
        except:pass
