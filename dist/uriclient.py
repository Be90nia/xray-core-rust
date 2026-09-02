"""URI -> xray client JSON config. 用法: python uriclient.py <uri> <local_socks_port> [out_path]"""
import base64, json, sys, urllib.parse as up

def parse_ss(uri):
    # ss://base64(method:password)@host:port?...  (method may be embedded in b64 prefix)
    body = uri[5:].split('#',1)[0]
    if '?' in body: body = body.split('?',1)[0]
    if '@' in body:
        head, hp = body.rsplit('@',1)
        host, port = hp.split(':')
        try:
            decoded = base64.urlsafe_b64decode(head + '=' * (-len(head)%4)).decode()
            method, password = decoded.split(':',1)
        except Exception:
            # head is plain "method:password"
            method, password = head.split(':',1)
    else:
        # entire body b64
        decoded = base64.urlsafe_b64decode(body + '=' * (-len(body)%4)).decode()
        m, rest = decoded.split(':',1)
        hp = rest.split('@',1)
        method = m; host, port = hp[1].split(':') if len(hp)>1 else (None,None)
        password = hp[0]
    return method, password, host, int(port)

def cfg(uri, socks_port=11080):
    u = uri.strip()
    p = up.urlparse(u)
    tag = "proxy"; q = dict(up.parse_qsl(p.query, keep_blank_values=True))
    if u.startswith("vmess://"):
        raw = base64.b64decode(u[8:] + '='*4).decode()
        j = json.loads(raw)
        out = {"protocol":"vmess","tag":tag,"settings":{"vnext":[{"address":j["add"],"port":int(j["port"]),"users":[{"id":j["id"],"alterId":int(j.get("aid","0")),"security":j.get("scy","auto")}]}]}}
        net = j.get("net","tcp"); host = j.get("host",""); path = j.get("path",""); tls = j.get("tls","")
        ss = {"network": net}
        if net in ("ws","httpupgrade","xhttp","grpc","splithttp"):
            ws = {"path": path}
            if host: ws["host"] = host
            if j.get("type","none") and j["type"]!="none": ws["headerType"] = j["type"]
            ss[net+"Settings"] = ws
        if tls == "tls":
            ss["security"]="tls"; ss["tlsSettings"]={"serverName": j.get("sni","") or host or j["add"], "fingerprint": j.get("fp","chrome"), "alpn": ([j["alpn"]] if j.get("alpn") else [])}
        out["streamSettings"] = ss
        return out
    if u.startswith("vless://"):
        user = p.username; host = p.hostname; port = p.port
        enc = q.get("encryption","none"); flow = q.get("flow"); net = q.get("type","tcp")
        sec = q.get("security","none"); sni = q.get("sni",""); fp = q.get("fp","chrome"); pbk = q.get("pbk",""); sid = q.get("sid","")
        out = {"protocol":"vless","tag":tag,"settings":{"vnext":[{"address":host,"port":port,"users":[{"id":user,"encryption":enc,"flow":flow,"level":0}]}]}}
        ss = {"network":net}
        if net in ("ws","httpupgrade","xhttp","grpc","splithttp"):
            ws = {"path":q.get("path","")}
            if q.get("host"): ws["host"]=q["host"]
            ss[net+"Settings"]=ws
        # xhttp mode
        if net == "xhttp" and q.get("mode"):
            ss["xhttpSettings"]["mode"] = q["mode"]
        if sec == "tls":
            ss["security"]="tls"; ss["tlsSettings"]={"serverName":sni or host,"fingerprint":fp,"alpn":([q["alpn"]] if q.get("alpn") else [])}
        elif sec == "reality":
            ss["security"]="reality"; ss["realitySettings"]={"serverName":sni,"fingerprint":fp,"publicKey":pbk,"shortId":sid,"spiderX":""}
        out["streamSettings"]=ss
        return out
    if u.startswith("trojan://"):
        pw = p.username; host = p.hostname; port = p.port
        net = q.get("type","tcp"); sec = q.get("security",""); sni=q.get("sni",""); fp=q.get("fp","chrome"); pbk=q.get("pbk",""); sid=q.get("sid","")
        out = {"protocol":"trojan","tag":tag,"settings":{"servers":[{"address":host,"port":port,"password":pw}]}}
        ss={"network":net}
        if net in ("ws","httpupgrade","xhttp","grpc","splithttp"):
            ws={"path":q.get("path","")}
            if q.get("host"): ws["host"]=q["host"]
            ss[net+"Settings"]=ws
        if net=="xhttp" and q.get("mode"): ss["xhttpSettings"]["mode"]=q["mode"]
        if sec=="tls":
            ss["security"]="tls"; ss["tlsSettings"]={"serverName":sni or host,"fingerprint":fp,"alpn":([q["alpn"]] if q.get("alpn") else [])}
        elif sec=="reality":
            ss["security"]="reality"; ss["realitySettings"]={"serverName":sni,"fingerprint":fp,"publicKey":pbk,"shortId":sid,"spiderX":""}
        out["streamSettings"]=ss
        return out
    if u.startswith("ss://"):
        method,pw,host,port = parse_ss(u)
        out = {"protocol":"shadowsocks","tag":tag,"settings":{"servers":[{"address":host,"port":port,"method":method,"password":pw}]}}
        net=q.get("type","")
        plugin = q.get("plugin","")
        if "v2ray-plugin" in plugin or net=="ws":
            ss={"network":"ws","wsSettings":{"path":q.get("path","/")}}
            if q.get("host"): ss["wsSettings"]["host"]=q["host"]
            # plugin tls flag
            tls_in = ("tls" in plugin)
            if tls_in:
                ss["security"]="tls"; ss["tlsSettings"]={"serverName":q.get("host") or host, "fingerprint":"chrome"}
            out["streamSettings"]=ss
        return out
    if u.startswith("tuic://"):
        # tuic://uuid:password@host:port?sni=&alpn=h3&congestion_control=cubic  (userinfo %3A = ':')
        userinfo = up.unquote(p.netloc.rsplit("@",1)[0])
        uid, pw = userinfo.split(":",1)
        host = p.hostname; port = p.port
        sv = {"address":host,"port":port,"uuid":uid,"password":pw,
              "server_name":q.get("sni") or host,
              "alpn":[a for a in q.get("alpn","").split(",") if a],
              "congestion_control":q.get("congestion_control","bbr"),
              "reduce_rtt":q.get("reduce_rtt","false").lower()=="true",
              "udp_relay_mode":q.get("udp_relay_mode","native"),
              "heartbeat":int(q.get("heartbeat","3")),
              "insecure":q.get("insecure",q.get("allow_insecure","false")).lower()=="true"}
        if q.get("certificate"): sv["certificate"] = q["certificate"]
        return {"protocol":"tuic","tag":tag,"settings":{"servers":[sv]}}
    if u.startswith("anytls://"):
        # anytls://<password>@host:port?security=tls&sni=&type=tcp&headerType=none
        # userinfo 只有 password，urlparse 会把它放在 p.password
        pw = p.password or p.username
        host = p.hostname; port = p.port
        sv = {
            "server": host,
            "server_port": port,
            "sni": q.get("sni") or host,
            "insecure": q.get("insecure", q.get("allow_insecure", "false")).lower() == "true",
            "password": pw,
        }
        return {"protocol":"anytls","tag":tag,"settings":sv}
    if u.startswith("hysteria2://"):
        # hysteria2://password@host:port?sni=&alpn=h3&congestion_control=cubic
        pw = up.unquote(p.password or p.username or "")
        host = p.hostname; port = p.port or 443
        sv = {"address": host, "port": port,
              "auth": pw,
              "serverName": q.get("sni") or q.get("serverName") or host,
              "alpn": [a for a in q.get("alpn", "").split(",") if a],
              "congestion_control": q.get("congestion_control", "bbr")}
        if q.get("insecure", q.get("allow_insecure", "false")).lower() == "true":
            sv["insecure"] = True
        return {"protocol": "hysteria", "tag": tag, "settings": {"servers": [sv]}}
    if u.startswith("naive+https://"):
        # naive+https://user:pass@host:port?security=tls&type=tcp&headerType=none
        user = up.unquote(p.username or "")
        pw = up.unquote(p.password or "")
        host = p.hostname; port = p.port or 443
        return {"protocol":"naive","tag":tag,"settings":{
            "server": host,
            "port": port,
            "sni": q.get("sni") or host,
            "username": user,
            "password": pw,
        }}
    raise ValueError(f"unsupported scheme: {u[:20]}")

def main():
    uri = sys.argv[1]; sp = int(sys.argv[2])
    ob = cfg(uri, sp)
    cfgobj = {
        "log":{"loglevel":"warning"},
        "inbounds":[{"tag":"socks-in","listen":"127.0.0.1","port":sp,"protocol":"socks","settings":{"udp":True},"sniffing":{"enabled":True,"destOverride":["http","tls","quic"]}}],
        "outbounds":[ob, {"tag":"direct","protocol":"freedom","settings":{}}]
    }
    out = sys.argv[3] if len(sys.argv)>3 else "dist/gencfg.json"
    open(out,"w",encoding="utf-8").write(json.dumps(cfgobj, indent=2, ensure_ascii=False))
    print(out)

if __name__=="__main__": main()
