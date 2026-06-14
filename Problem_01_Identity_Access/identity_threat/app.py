"""
app.py  —  Identity Threat Intelligence SOC Dashboard (v5 — Premium)
Premium Enterprise Security UI | Flask + Plotly | Groq-powered explanations
"""
import os, json, math
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
import pandas as pd
import numpy as np
import plotly
import plotly.graph_objects as go

app = Flask(__name__)

BASE = os.path.join(os.path.dirname(__file__), "..", "sample_data")

def _csv(name):
    p = os.path.join(BASE, name)
    return pd.read_csv(p) if os.path.exists(p) else pd.DataFrame()

def load_data():
    users  = _csv("flagged_users.csv")
    events = _csv("flagged_events.csv")
    all_u  = _csv("identity_users_labels.csv")
    all_e  = _csv("identity_events_labels.csv")
    expl   = {}
    ep = os.path.join(BASE, "explanations.json")
    if os.path.exists(ep):
        with open(ep) as f:
            d = json.load(f)
        for u in d.get("user_explanations", []):
            expl[u.get("user_id")] = u
    return users, events, all_u, all_e, expl

C = dict(bg="#020812",s1="#0a0f1e",s2="#0f1629",border="#1a2340",
         crit="#ef4444",high="#f59e0b",med="#eab308",safe="#22c55e",
         accent="#3b82f6",purple="#8b5cf6",text="#f1f5f9",muted="#64748b",dim="#334155")

def sev_color(s):
    return {"CRITICAL":C["crit"],"HIGH":C["high"],"MEDIUM":C["med"],"LOW":C["safe"]}.get(str(s).upper(),C["muted"])

def fig_json(fig):
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

DARK = dict(paper_bgcolor="#020812",plot_bgcolor="#0a0f1e",
            font=dict(color="#f1f5f9",family="Inter"),
            xaxis=dict(gridcolor="#1a2340",showgrid=True),
            yaxis=dict(gridcolor="#1a2340",showgrid=True),
            margin=dict(l=40,r=20,t=45,b=40))

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
::selection{background:#ef444433;color:#ef4444}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:#020812}
::-webkit-scrollbar-thumb{background:#ef4444;border-radius:2px}
:root{--bg:#020812;--s1:#0a0f1e;--s2:#0f1629;--border:#1a2340;--crit:#ef4444;--high:#f59e0b;--med:#eab308;--safe:#22c55e;--accent:#3b82f6;--purple:#8b5cf6;--text:#f1f5f9;--muted:#64748b;--dim:#334155}
body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;min-height:100vh;line-height:1.5}
a{color:var(--accent);text-decoration:none;transition:color .2s}
a:hover{color:#60a5fa}
.mono{font-family:'JetBrains Mono',monospace}

nav{background:rgba(2,8,18,.85);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border-bottom:1px solid var(--border);box-shadow:0 1px 0 #ef444422;padding:0 2rem;display:flex;align-items:center;height:56px;position:sticky;top:0;z-index:100}
nav .brand{font-family:'JetBrains Mono',monospace;font-size:.82rem;font-weight:700;color:var(--crit);letter-spacing:.12em;display:flex;align-items:center;gap:.5rem;margin-right:2rem;white-space:nowrap}
nav .pdot{width:8px;height:8px;border-radius:50%;background:var(--crit);animation:pulse-red 2s infinite}
nav .nl{display:flex;gap:0;flex:1;justify-content:center}
nav .nl a{color:var(--muted);font-size:.78rem;font-weight:500;padding:.5rem 1.1rem;position:relative;transition:color .2s}
nav .nl a::after{content:'';position:absolute;bottom:0;left:50%;width:0;height:2px;background:var(--crit);transition:width .3s,left .3s}
nav .nl a:hover::after,nav .nl a.active::after{width:60%;left:20%}
nav .nl a:hover,nav .nl a.active{color:var(--text);text-decoration:none}
nav .nr{display:flex;align-items:center;gap:1rem;margin-left:auto}
nav .lb{display:flex;align-items:center;gap:.4rem;font-size:.68rem;color:var(--safe);font-family:'JetBrains Mono',monospace;font-weight:600;letter-spacing:.06em}
nav .lb .gd{width:6px;height:6px;border-radius:50%;background:var(--safe);animation:pulse-green 1.5s infinite}
nav .ck{font-family:'JetBrains Mono',monospace;font-size:.68rem;color:var(--dim);letter-spacing:.04em}

.container{max-width:1440px;margin:0 auto;padding:2rem 2.5rem}
.card{background:var(--s1);border:1px solid var(--border);border-radius:8px;padding:20px;transition:border-color .2s}
.card:hover{border-color:#263354}

.metric-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2rem}
@media(max-width:900px){.metric-grid{grid-template-columns:repeat(2,1fr)}}
.mc{background:linear-gradient(135deg,var(--s1),var(--s2));border:1px solid var(--border);border-radius:8px;padding:1.5rem;text-align:center;height:120px;display:flex;flex-direction:column;justify-content:center;transition:all .3s;position:relative;overflow:hidden}
.mc::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;border-radius:8px 8px 0 0}
.mc:hover{transform:translateY(-3px);box-shadow:0 8px 30px rgba(0,0,0,.4)}
.mc .v{font-size:3rem;font-weight:700;font-family:'JetBrains Mono',monospace;animation:count-up .6s ease-out}
.mc .l{font-size:.65rem;color:#475569;text-transform:uppercase;letter-spacing:.12em;margin-top:.25rem}

.badge-crit{background:#ef444418;color:var(--crit);border:1px solid #ef444440;padding:2px 8px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:600}
.badge-high{background:#f59e0b18;color:var(--high);border:1px solid #f59e0b40;padding:2px 8px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:600}
.badge-med{background:#eab30818;color:var(--med);border:1px solid #eab30840;padding:2px 8px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:600}
.badge-safe{background:#22c55e18;color:var(--safe);border:1px solid #22c55e40;padding:2px 8px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:600}
.badge-purple{background:#8b5cf618;color:var(--purple);border:1px solid #8b5cf640;padding:2px 8px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:600}

.rc{width:44px;height:44px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-family:'JetBrains Mono',monospace;font-weight:700;font-size:13px}
.rc-crit{background:#ef444420;color:var(--crit);border:2px solid var(--crit);animation:pulse-red 2s infinite}
.rc-high{background:#f59e0b20;color:var(--high);border:2px solid var(--high)}
.rc-med{background:#eab30820;color:var(--med);border:2px solid var(--med)}
.rc-safe{background:#22c55e20;color:var(--safe);border:2px solid var(--safe)}

.dp{padding:2px 8px;border-radius:9999px;font-size:10px;font-weight:600;display:inline-block;font-family:'JetBrains Mono',monospace}
.dp-finance{background:#22c55e18;color:#22c55e;border:1px solid #22c55e30}
.dp-hr{background:#8b5cf618;color:#8b5cf6;border:1px solid #8b5cf630}
.dp-it{background:#3b82f618;color:#3b82f6;border:1px solid #3b82f630}
.dp-engineering{background:#06b6d418;color:#06b6d4;border:1px solid #06b6d430}
.dp-sales{background:#f9731618;color:#f97316;border:1px solid #f9731630}
.dp-cto_office,.dp-executive,.dp-security{background:#ef444418;color:#ef4444;border:1px solid #ef444430}
.dp-default{background:var(--s2);border:1px solid var(--border);color:var(--muted)}

.pp{padding:2px 8px;border-radius:9999px;font-size:10px;font-weight:600;display:inline-block;font-family:'JetBrains Mono',monospace}
.pp-superadmin{background:#ef444418;color:#ef4444;border:1px solid #ef444440}
.pp-admin{background:#f59e0b18;color:#f59e0b;border:1px solid #f59e0b40}
.pp-power-user,.pp-editor{background:#3b82f618;color:#3b82f6;border:1px solid #3b82f640}
.pp-viewer,.pp-user,.pp-service-account{background:rgba(100,116,139,.12);color:var(--muted);border:1px solid rgba(100,116,139,.25)}

table{width:100%;border-collapse:collapse;font-size:.85rem}
th{background:var(--bg);color:var(--muted);text-transform:uppercase;font-size:.62rem;letter-spacing:.1em;padding:.75rem 1rem;text-align:left;border-bottom:1px solid var(--border)}
td{padding:.75rem 1rem;border-bottom:1px solid rgba(26,35,64,.4);vertical-align:middle;transition:background .15s}
tr{transition:all .2s}
tr:hover td{background:var(--s2)}
tr.row-crit td:first-child{border-left:3px solid var(--crit)}
tr.row-high td:first-child{border-left:3px solid var(--high)}
tr.row-med td:first-child{border-left:3px solid var(--med)}
tr.row-safe td:first-child{border-left:3px solid var(--safe)}
tr:hover .vb{opacity:1}
.vb{opacity:0;transition:opacity .2s}

.ac{display:flex;align-items:center;gap:1rem;padding:1rem;border-radius:8px;border:1px solid var(--border);border-left:4px solid;margin-bottom:.5rem;background:linear-gradient(90deg,#ef444406,var(--s1));transition:all .25s;cursor:pointer;text-decoration:none;color:inherit}
.ac:hover{transform:translateX(4px);box-shadow:0 0 20px rgba(239,68,68,.08);text-decoration:none;color:inherit}
.ac .sg{font-family:'JetBrains Mono',monospace;font-size:1.4rem;font-weight:700;text-shadow:0 0 20px rgba(239,68,68,.3)}

.blast-box{background:linear-gradient(135deg,#1a0808,var(--s1));border:1px solid #ef444444;border-radius:8px;padding:1.5rem}
.blast-box h3{color:var(--crit);font-size:.75rem;letter-spacing:.12em;text-transform:uppercase;margin-bottom:1.25rem}
.big-num{font-family:'JetBrains Mono',monospace;font-size:2rem;font-weight:700;color:var(--crit)}
.sp{display:inline-block;background:#ef444410;border:1px solid #ef444430;color:var(--crit);padding:3px 10px;border-radius:9999px;font-size:11px;margin:2px;font-family:'JetBrains Mono',monospace;font-weight:600;animation:pulse-red 3s infinite}

.fc{border:1px solid var(--border);border-radius:6px;padding:1rem;margin-bottom:.75rem;transition:border-color .2s}
.fc:hover{border-color:#263354}
.fc.sev-HIGH{border-left:3px solid var(--high)}
.fc.sev-CRITICAL{border-left:3px solid var(--crit)}
.fc.sev-MEDIUM{border-left:3px solid var(--med)}
.rb{background:var(--s2);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:4px;padding:8px 12px;margin-top:8px;font-size:12px;color:var(--accent)}

.cb{background:#ef444410;border:1px solid #ef444425;color:var(--crit);padding:3px 10px;border-radius:9999px;font-size:11px;font-weight:600;display:inline-block;margin:2px;font-family:'JetBrains Mono',monospace}

.btn{padding:8px 18px;border-radius:6px;font-weight:600;font-size:12px;border:none;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:6px}
.btn:hover{transform:translateY(-1px);box-shadow:0 4px 15px rgba(0,0,0,.3)}
.btn-r{background:var(--crit);color:white}.btn-r:hover{background:#dc2626}
.btn-g{background:var(--safe);color:white}.btn-g:hover{background:#16a34a}
.btn-a{background:var(--high);color:white}.btn-a:hover{background:#d97706}
.btn-o{background:transparent;border:1px solid var(--border);color:var(--text)}.btn-o:hover{border-color:var(--accent);color:var(--accent)}

.cl{list-style:none;counter-reset:steps}
.cl li{counter-increment:steps;padding:8px 0;display:flex;gap:10px;align-items:flex-start;font-size:13px;border-bottom:1px solid rgba(26,35,64,.3)}
.cl li::before{content:counter(steps);background:var(--accent);color:white;width:20px;height:20px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;flex-shrink:0;margin-top:2px}

.sim-node{background:var(--s1);border:1px solid var(--border);border-radius:6px;padding:10px 18px;margin:4px 0;display:flex;align-items:center;gap:10px;font-family:'JetBrains Mono',monospace;font-size:13px;animation:slide-in-left .5s ease}
.chain-arrow{color:var(--crit);text-align:center;font-size:1.2rem;margin:2px 0}

.le{border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:6px;animation:slide-in-left .4s ease;background:var(--s1);transition:all .3s}
.le.ce{border-color:#ef444440;box-shadow:0 0 20px rgba(239,68,68,.08)}
.scanline{position:fixed;top:0;left:0;right:0;bottom:0;pointer-events:none;z-index:99;background:repeating-linear-gradient(0deg,transparent,transparent 2px,#00ff0005 2px,#00ff0005 4px)}
.sb{position:fixed;bottom:0;left:0;right:0;height:36px;background:rgba(2,8,18,.95);border-top:1px solid var(--border);display:flex;align-items:center;padding:0 2rem;gap:2rem;z-index:100;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--dim)}
.sb .gd{width:6px;height:6px;border-radius:50%;background:var(--safe);animation:pulse-green 1.5s infinite;display:inline-block}

.ub{background:var(--s1);border:1px solid var(--border);border-radius:8px;padding:2rem;margin-bottom:1.5rem;position:relative;overflow:hidden}
.ub::before{content:'';position:absolute;top:0;left:0;right:0;bottom:0;background-image:linear-gradient(#1a234011 1px,transparent 1px),linear-gradient(90deg,#1a234011 1px,transparent 1px);background-size:30px 30px;opacity:.6}
.ub>*{position:relative;z-index:1}
.rc-lg{width:80px;height:80px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-family:'JetBrains Mono',monospace;font-size:1.8rem;font-weight:700;border:2px solid}
.rc-lg.rc-crit{border-color:var(--crit);color:var(--crit);box-shadow:0 0 30px rgba(239,68,68,.3);animation:pulse-red 2s infinite}
.rc-lg.rc-high{border-color:var(--high);color:var(--high);box-shadow:0 0 20px rgba(245,158,11,.2)}
.rc-lg.rc-med{border-color:var(--med);color:var(--med)}
.rc-lg.rc-safe{border-color:var(--safe);color:var(--safe)}

.ms{background:var(--s2);border:1px solid var(--border);border-radius:6px;padding:14px;text-align:center;position:relative}
.ms::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--crit);border-radius:6px 6px 0 0}
.ms .mi{font-size:1.2rem;margin-bottom:4px}
.ms .mv{font-family:'JetBrains Mono',monospace;font-size:1.5rem;font-weight:700;color:var(--crit)}
.ms .ml{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-top:2px}

.pg{display:flex;gap:0;border:1px solid var(--border);border-radius:6px;overflow:hidden}
.pg a{padding:6px 14px;font-size:11px;font-weight:600;color:var(--muted);text-decoration:none;transition:all .2s;text-transform:uppercase;letter-spacing:.04em}
.pg a:hover{color:var(--text);background:var(--s2);text-decoration:none}
.pg a.ap{color:var(--text);background:var(--s2)}
.pg a.ac-crit{background:#ef444418;color:var(--crit)}
.pg a.ac-high{background:#f59e0b18;color:var(--high)}
.pg a.ac-med{background:#eab30818;color:var(--med)}
.pg a.ac-safe{background:#22c55e18;color:var(--safe)}

@keyframes pulse-red{0%,100%{box-shadow:0 0 0 0 #ef444466}50%{box-shadow:0 0 12px 4px #ef444422}}
@keyframes pulse-green{0%,100%{opacity:1}50%{opacity:.4}}
@keyframes slide-in-left{from{transform:translateX(-20px);opacity:0}to{transform:translateX(0);opacity:1}}
@keyframes count-up{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
@keyframes flash-red{0%{background:rgba(239,68,68,.15)}100%{background:transparent}}
"""

HEAD = f"""<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IDENTITY THREAT INTELLIGENCE</title>
<meta name="description" content="SOC Identity Sprawl & Privilege Abuse Detection Dashboard">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<script src="https://cdn.plot.ly/plotly-2.26.0.min.js"></script>
<style>{CSS}</style>
</head>"""

def _dept_cls(d):
    d2 = str(d).lower().replace(" ","_")
    if d2 in ("finance",): return "dp-finance"
    if d2 in ("hr","human_resources"): return "dp-hr"
    if d2 in ("it","information_technology"): return "dp-it"
    if d2 in ("engineering","development"): return "dp-engineering"
    if d2 in ("sales","marketing"): return "dp-sales"
    if d2 in ("cto_office","executive","security"): return "dp-cto_office"
    return "dp-default"

def _priv_cls(p):
    p2 = str(p).lower().replace("-","_").replace(" ","_")
    return f"pp-{p2}" if p2 in ("superadmin","admin","power_user","editor","viewer","user","service_account") else "pp-viewer"

def _priv_icon(p):
    p2 = str(p).lower()
    if "superadmin" in p2: return "&#128081; "
    if "admin" in p2: return "&#128273; "
    return ""

def _page(body, title="IDENTITY THREAT INTELLIGENCE", active="home"):
    nls = [("home","Command Center","/"),("users","Users","/users"),("events","Events","/events"),("graph","Graph","/graph"),("live","Live Feed","/live")]
    links = "".join(f'<a href="{u}" {"class=\"active\"" if active==k else ""}>{l}</a>' for k,l,u in nls)
    hd = HEAD.replace("IDENTITY THREAT INTELLIGENCE</title>", f"{title}</title>")
    return f"""<!DOCTYPE html><html lang='en'>{hd}<body>
<nav><span class="brand"><span class="pdot"></span>IDENTITY THREAT INTEL</span>
<div class="nl">{links}</div>
<div class="nr"><span class="lb"><span class="gd"></span>LIVE</span><span class="ck" id="ck"></span></div>
</nav><div class="container">{body}</div>
<script>!function u(){{var d=new Date();document.getElementById('ck').textContent=d.toISOString().slice(0,19).replace('T',' ')+' UTC';setTimeout(u,1000)}}();</script>
</body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
@app.route("/api/live-feed")
def live_feed():
    _, events, _, _, _ = load_data()
    if events.empty: return jsonify([])
    cols = [c for c in ["timestamp","user_id","username","action","resource","resource_sensitivity","risk_score","severity","destination"] if c in events.columns]
    return jsonify(events.sort_values("risk_score",ascending=False).head(20)[cols].fillna("").to_dict("records"))


# ══════════════════════════════════════════════════════════════════════════════
# HOMEPAGE
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    users, events, all_u, all_e, expl = load_data()
    total_u = len(all_u) if not all_u.empty else len(users)
    anom_u = len(users)
    crit_cnt = int((users["severity"]=="CRITICAL").sum()) if not users.empty and "severity" in users.columns else 0
    sys_risk = int(users["num_systems"].sum()) if not users.empty and "num_systems" in users.columns else 0

    # Dept chart
    df = go.Figure()
    if not users.empty and "department" in users.columns and "risk_score" in users.columns:
        da = users.groupby("department")["risk_score"].mean().sort_values(ascending=False).head(10)
        df.add_trace(go.Bar(x=da.index.tolist(),y=da.values.tolist(),
            marker_color=[C["crit"] if v>=80 else C["high"] if v>=60 else C["med"] for v in da.values]))
    df.update_layout(**DARK,title="DEPARTMENT RISK SCORES",height=340)
    dj = fig_json(df)

    # Timeline
    ef = go.Figure()
    if not events.empty and "timestamp" in events.columns:
        ev = events.copy(); ev["timestamp"]=pd.to_datetime(ev["timestamp"],errors="coerce"); ev=ev.dropna(subset=["timestamp"])
        if not ev.empty:
            ev["date"]=ev["timestamp"].dt.date; dl=ev.groupby("date").size().reset_index(name="count").sort_values("date")
            ef.add_trace(go.Scatter(x=[str(d) for d in dl["date"]],y=dl["count"].tolist(),mode="lines+markers",
                line=dict(color=C["crit"],width=2),marker=dict(color=C["crit"],size=5),fill="tozeroy",fillcolor="rgba(239,68,68,0.06)"))
    ef.update_layout(**DARK,title="ANOMALOUS EVENTS TIMELINE",height=340)
    ej = fig_json(ef)

    # Heatmap
    hj = ""
    if not events.empty and "timestamp" in events.columns:
        eh = events.copy(); eh["timestamp"]=pd.to_datetime(eh["timestamp"],errors="coerce"); eh=eh.dropna(subset=["timestamp"])
        now=pd.Timestamp.now(); eh=eh[eh["timestamp"]>=now-pd.Timedelta(days=90)].copy()
        if not eh.empty:
            eh["date"]=eh["timestamp"].dt.date; dc=eh.groupby("date").size().reset_index(name="count")
            ad=pd.date_range((now-pd.Timedelta(days=90)).normalize(),now.normalize(),freq="D")
            hm=pd.DataFrame({"date":ad.date}).merge(dc,on="date",how="left").fillna(0); hm["count"]=hm["count"].astype(int)
            hm["dow"]=pd.to_datetime(hm["date"]).dt.dayofweek; hm["week"]=((pd.to_datetime(hm["date"])-pd.to_datetime(hm["date"].iloc[0])).dt.days//7)
            dl2=["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]; mw=hm["week"].max()+1
            z=[[0]*mw for _ in range(7)]; tx=[[""]*mw for _ in range(7)]
            for _,r in hm.iterrows(): z[int(r["dow"])][int(r["week"])]=int(r["count"]); tx[int(r["dow"])][int(r["week"])]=f"{r['date']}: {int(r['count'])} events"
            hf=go.Figure(data=go.Heatmap(z=z,y=dl2,text=tx,hoverinfo="text",colorscale=[[0,"#0a0f1e"],[0.5,"#f59e0b"],[1,"#ef4444"]],showscale=True,colorbar=dict(title="Events",tickfont=dict(color="#f1f5f9"))))
            hf.update_layout(paper_bgcolor="#020812",plot_bgcolor="#0a0f1e",font=dict(color="#f1f5f9",family="Inter"),title="THREAT ACTIVITY HEATMAP \u2014 LAST 90 DAYS",height=220,margin=dict(l=60,r=20,t=40,b=20),yaxis=dict(autorange="reversed"),xaxis=dict(showticklabels=False,title="Weeks"))
            hj = fig_json(hf)

    # Active threats
    ath = ""
    if not users.empty:
        for _,u in users.head(6).iterrows():
            sc=str(u.get("severity","LOW")).upper(); bc={"CRITICAL":"crit","HIGH":"high","MEDIUM":"med"}.get(sc,"safe"); rs2=float(u.get("risk_score",0))
            ath += f'<a href="/user/{u.get("user_id","")}" class="ac" style="border-left-color:var(--{bc})"><div style="flex:1;min-width:0"><div class="mono" style="font-size:13px;font-weight:600">{u.get("user_id","")} &mdash; {u.get("username","")}</div><div style="font-size:11px;color:var(--muted);margin-top:3px">{u.get("department","")} | {u.get("privilege_level","")} | {int(u.get("days_inactive",0))}d inactive</div></div><div class="sg" style="color:var(--{bc})">{rs2:.0f}</div><span class="btn btn-o vb" style="font-size:10px;padding:4px 10px">INVESTIGATE &rarr;</span></a>'

    # Live feed preview
    lfp = ""
    if not events.empty:
        cols = [c for c in ["timestamp","username","action","resource","risk_score","severity"] if c in events.columns]
        feed = events.sort_values("risk_score",ascending=False).head(5)[cols].fillna("").to_dict("records")
        for ev in feed:
            bc2 = {"CRITICAL":"crit","HIGH":"high","MEDIUM":"med"}.get(str(ev.get("severity","")).upper(),"safe")
            lfp += f'<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid rgba(26,35,64,.4)"><span style="width:6px;height:6px;border-radius:50%;background:var(--{bc2});flex-shrink:0"></span><span class="mono" style="font-size:11px;color:var(--muted);width:120px;flex-shrink:0">{str(ev.get("timestamp",""))[:16]}</span><span style="font-size:12px;flex:1">{ev.get("username","")} &rarr; {ev.get("resource","")}</span><span class="badge-{bc2}">{int(float(ev.get("risk_score",0)))}</span></div>'

    hmb = f'<div class="card" style="margin-bottom:2rem;padding:0 16px 16px"><div id="hc"></div></div>' if hj else ""
    hms = f"var hm={hj};Plotly.newPlot('hc',hm.data,hm.layout,{{responsive:true,displayModeBar:false}});" if hj else ""

    body = f"""
<div style="margin-bottom:2rem"><h1 style="font-size:1.6rem;font-weight:700;letter-spacing:.03em">COMMAND CENTER</h1><p style="color:var(--muted);font-size:13px">Real-time privilege abuse &amp; identity sprawl detection</p></div>
<div class="metric-grid">
  <div class="mc" style="--c:var(--accent)"><div style="position:absolute;top:0;left:0;right:0;height:3px;background:var(--accent);border-radius:8px 8px 0 0"></div><div class="v" style="color:var(--accent)" data-count="{total_u}">0</div><div class="l">Total Identities</div></div>
  <div class="mc"><div style="position:absolute;top:0;left:0;right:0;height:3px;background:var(--high);border-radius:8px 8px 0 0"></div><div class="v" style="color:var(--high)" data-count="{anom_u}">0</div><div class="l">Anomalous Accounts</div></div>
  <div class="mc"><div style="position:absolute;top:0;left:0;right:0;height:3px;background:var(--crit);border-radius:8px 8px 0 0"></div><div class="v" style="color:var(--crit)" data-count="{crit_cnt}">0</div><div class="l">Critical Alerts</div></div>
  <div class="mc"><div style="position:absolute;top:0;left:0;right:0;height:3px;background:var(--purple);border-radius:8px 8px 0 0"></div><div class="v" style="color:var(--purple)" data-count="{sys_risk}">0</div><div class="l">Systems Exposed</div></div>
</div>
<div style="display:grid;grid-template-columns:3fr 2fr;gap:1rem;margin-bottom:2rem"><div class="card" style="padding:0 16px 16px"><div id="ec"></div></div><div class="card" style="padding:0 16px 16px"><div id="dc"></div></div></div>
{hmb}
<div style="margin-bottom:2rem"><h2 style="font-size:13px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:1rem;display:flex;align-items:center;gap:10px">&#9889; ACTIVE THREATS <span class="badge-crit" style="animation:pulse-red 2s infinite">{crit_cnt}</span></h2>{ath}</div>
<div class="card" style="margin-bottom:2rem"><h2 style="font-size:13px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:1rem;display:flex;align-items:center;gap:10px;justify-content:space-between">&#128225; LIVE THREAT FEED <a href="/live" style="font-size:11px;color:var(--accent)">VIEW ALL &rarr;</a></h2><div id="lfp">{lfp}</div></div>
<script>
var dj={dj};var ej={ej};Plotly.newPlot('dc',dj.data,dj.layout,{{responsive:true,displayModeBar:false}});Plotly.newPlot('ec',ej.data,ej.layout,{{responsive:true,displayModeBar:false}});{hms}
document.querySelectorAll('.mc .v[data-count]').forEach(el=>{{const t=parseInt(el.dataset.count);let c=0;const s=Math.max(1,Math.floor(t/40));const i=setInterval(()=>{{c+=s;if(c>=t){{c=t;clearInterval(i)}}el.textContent=c.toLocaleString()}},25)}});
async function rf(){{try{{const r=await fetch('/api/live-feed');const d=await r.json();const sm={{CRITICAL:'crit',HIGH:'high',MEDIUM:'med',LOW:'safe'}};document.getElementById('lfp').innerHTML=d.slice(0,5).map(e=>`<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid rgba(26,35,64,.4)"><span style="width:6px;height:6px;border-radius:50%;background:var(--${{sm[e.severity]||'muted'}});flex-shrink:0"></span><span class="mono" style="font-size:11px;color:var(--muted);width:120px;flex-shrink:0">${{(e.timestamp||'').slice(0,16)}}</span><span style="font-size:12px;flex:1">${{e.username||''}} &rarr; ${{e.resource||''}}</span><span class="badge-${{sm[e.severity]||'safe'}}">${{Math.round(e.risk_score||0)}}</span></div>`).join('')}}catch(e){{}}}}
setInterval(rf,10000);
</script>"""
    return _page(body, "Command Center", "home")


# ══════════════════════════════════════════════════════════════════════════════
# USERS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/users")
def users_page():
    users, _, _, _, _ = load_data()
    sev_f = request.args.get("sev",""); dept_f = request.args.get("dept",""); priv_f = request.args.get("priv",""); q = request.args.get("q","")
    df = users.copy() if not users.empty else pd.DataFrame()
    if not df.empty:
        if sev_f and "severity" in df.columns: df = df[df["severity"].str.upper()==sev_f.upper()]
        if dept_f and "department" in df.columns: df = df[df["department"]==dept_f]
        if priv_f and "privilege_level" in df.columns: df = df[df["privilege_level"].str.lower()==priv_f.lower()]
        if q and "username" in df.columns: df = df[df["username"].str.lower().str.contains(q.lower(),na=False)|df["user_id"].str.lower().str.contains(q.lower(),na=False)]

    n_crit = int((users["severity"]=="CRITICAL").sum()) if not users.empty and "severity" in users.columns else 0
    n_orph = int(users["is_orphaned"].sum()) if not users.empty and "is_orphaned" in users.columns else 0

    # Severity pills
    sp = f'<a href="/users?dept={dept_f}&priv={priv_f}&q={q}" class="{"ap" if not sev_f else ""}">All</a>'
    for s,cls in [("CRITICAL","ac-crit"),("HIGH","ac-high"),("MEDIUM","ac-med"),("LOW","ac-safe")]:
        sp += f'<a href="/users?sev={s}&dept={dept_f}&priv={priv_f}&q={q}" class="{cls if sev_f.upper()==s else ""}">{s}</a>'

    # Dept pills
    depts = sorted(users["department"].dropna().unique().tolist()) if not users.empty and "department" in users.columns else []
    dph = f'<a href="/users?sev={sev_f}&priv={priv_f}&q={q}" class="{"ap" if not dept_f else ""}">All Depts</a>'
    for d in depts[:8]:
        dph += f'<a href="/users?sev={sev_f}&dept={d}&priv={priv_f}&q={q}" class="{"ap" if dept_f==d else ""}">{d}</a>'

    rows = ""
    if not df.empty:
        for _,r in df.iterrows():
            sc=str(r.get("severity","LOW")).upper(); bc={"CRITICAL":"badge-crit","HIGH":"badge-high","MEDIUM":"badge-med"}.get(sc,"badge-safe")
            di=int(r.get("days_inactive",0)); dic="var(--crit)" if di>60 else "var(--high)" if di>30 else "var(--safe)"
            die = " &#9888;&#65039;" if di>60 else ""
            ns=int(r.get("num_systems",0)); nsc="var(--crit)" if ns>5 else "var(--text)"
            dept=str(r.get("department",""))
            pv=str(r.get("privilege_level","viewer"))
            rcl = {"CRITICAL":"rc-crit","HIGH":"rc-high","MEDIUM":"rc-med"}.get(sc,"rc-safe")
            rows += (
                f'<tr class="row-{sc.lower()}" onclick="location.href=\'/user/{r.get("user_id","")}\'" style="cursor:pointer">'
                f'<td><span class="mono" style="color:var(--accent);font-weight:600;font-size:13px">{r.get("user_id","")}</span><br>'
                f'<span style="font-size:11px;color:var(--muted)">{r.get("username","")}</span></td>'
                f'<td><span class="dp {_dept_cls(dept)}">{dept}</span></td>'
                f'<td><span class="pp {_priv_cls(pv)}">{_priv_icon(pv)}{pv}</span></td>'
                f'<td class="mono" style="color:{dic};font-weight:600;font-size:13px">{di}{die}</td>'
                f'<td><span class="mono" style="color:{nsc};font-weight:600">{ns}</span></td>'
                f'<td><div class="rc {rcl}">{float(r.get("risk_score",0)):.0f}</div></td>'
                f'<td><span style="display:flex;align-items:center;gap:5px"><span style="width:6px;height:6px;border-radius:50%;background:{sev_color(sc)};animation:pulse-red 2s infinite;display:inline-block"></span>'
                f'<span style="color:{sev_color(sc)};font-weight:600;font-size:12px">{sc}</span></span></td>'
                f'<td><a href="/user/{r.get("user_id","")}" class="btn btn-o vb" style="font-size:10px;padding:3px 8px">VIEW &rarr;</a></td></tr>'
            )

    body = f"""
<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:1.5rem;flex-wrap:wrap;gap:1rem">
  <div><h1 style="font-size:1.4rem;font-weight:700;letter-spacing:.03em">IDENTITY RISK REGISTRY</h1>
  <p style="color:var(--muted);font-size:12px;margin-top:4px">Flagged accounts requiring investigation</p>
  <p style="font-size:11px;color:var(--dim);margin-top:6px"><span style="color:var(--text);font-weight:600">{len(df)}</span> users flagged &middot; <span style="color:var(--crit);font-weight:600">{n_crit}</span> critical &middot; <span style="color:var(--high);font-weight:600">{n_orph}</span> orphaned</p></div>
  <form method="get" style="display:flex;flex-direction:column;gap:6px;align-items:flex-end">
    <div style="display:flex;gap:6px;align-items:center"><div class="pg">{sp}</div>
    <input type="text" name="q" value="{q}" placeholder="Search username or ID..." style="background:var(--s1);border:1px solid var(--border);color:var(--text);padding:6px 12px;border-radius:6px;font-size:12px;font-family:'JetBrains Mono',monospace;width:200px;outline:none;transition:border-color .2s" onfocus="this.style.borderColor='var(--crit)';this.style.boxShadow='0 0 8px rgba(239,68,68,.15)'" onblur="this.style.borderColor='';this.style.boxShadow=''">
    <button type="submit" class="btn btn-o" style="font-size:10px;padding:5px 12px">GO</button></div>
    <div class="pg" style="font-size:10px">{dph}</div>
    <input type="hidden" name="sev" value="{sev_f}"><input type="hidden" name="priv" value="{priv_f}">
  </form>
</div>
<div class="card" style="padding:0;overflow:hidden;overflow-x:auto"><table><thead><tr>
<th>User</th><th>Department</th><th>Privilege</th><th>Inactive</th><th>Systems</th><th>Risk</th><th>Severity</th><th></th>
</tr></thead><tbody>{rows}</tbody></table></div>"""
    return _page(body, "Users", "users")


# ══════════════════════════════════════════════════════════════════════════════
# EVENTS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/events")
def events_page():
    _, events, _, _, _ = load_data()
    sev_f=request.args.get("sev",""); action_f=request.args.get("action",""); sens_f=request.args.get("sens","")
    df = events.copy() if not events.empty else pd.DataFrame()
    if not df.empty:
        if sev_f and "severity" in df.columns: df=df[df["severity"].str.upper()==sev_f.upper()]
        if action_f and "action" in df.columns: df=df[df["action"]==action_f]
        if sens_f and "resource_sensitivity" in df.columns: df=df[df["resource_sensitivity"]==sens_f]

    acts=sorted(events["action"].dropna().unique().tolist()) if not events.empty and "action" in events.columns else []
    sevs=sorted(events["severity"].dropna().unique().tolist()) if not events.empty and "severity" in events.columns else []
    senss=sorted(events["resource_sensitivity"].dropna().unique().tolist()) if not events.empty and "resource_sensitivity" in events.columns else []

    rows=""
    if not df.empty:
        for _,r in df.head(200).iterrows():
            sc=str(r.get("severity","LOW")).upper(); bc={"CRITICAL":"badge-crit","HIGH":"badge-high","MEDIUM":"badge-med"}.get(sc,"badge-safe")
            rows += f'<tr class="row-{sc.lower()}"><td class="mono" style="font-size:11px;color:var(--dim)">{str(r.get("timestamp",""))[:16]}</td><td><a href="/user/{r.get("user_id","")}" class="mono" style="font-size:12px">{r.get("username","")}</a></td><td style="font-size:12px">{r.get("action","")}</td><td style="font-size:12px">{r.get("resource","")}</td><td><span class="dp dp-default" style="font-size:9px">{r.get("resource_sensitivity","")}</span></td><td class="mono" style="font-size:12px">{int(r.get("rowcount",0)):,}</td><td style="font-size:11px;color:var(--dim)">{r.get("destination","")}</td><td><span class="{bc}">{float(r.get("risk_score",0)):.0f}</span></td></tr>'

    so="".join(f'<option value="{s}" {"selected" if s==sev_f else ""}>{s}</option>' for s in sevs)
    ao="".join(f'<option value="{a}" {"selected" if a==action_f else ""}>{a}</option>' for a in acts)
    ss="".join(f'<option value="{s}" {"selected" if s==sens_f else ""}>{s}</option>' for s in senss)
    sel='background:var(--s1);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:6px;font-size:12px'

    body = f"""
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem;flex-wrap:wrap;gap:1rem">
  <div><h1 style="font-size:1.4rem;font-weight:700;letter-spacing:.03em">EVENT LOG</h1><p style="color:var(--muted);font-size:12px">{min(200,len(df))} of {len(df)} flagged events</p></div>
  <form method="get" style="display:flex;gap:6px"><select name="sev" style="{sel}" onchange="this.form.submit()"><option value="">All Severity</option>{so}</select><select name="action" style="{sel}" onchange="this.form.submit()"><option value="">All Actions</option>{ao}</select><select name="sens" style="{sel}" onchange="this.form.submit()"><option value="">All Sensitivity</option>{ss}</select></form>
</div>
<div class="card" style="padding:0;overflow:hidden;overflow-x:auto"><table><thead><tr><th>Timestamp</th><th>User</th><th>Action</th><th>Resource</th><th>Sensitivity</th><th>Records</th><th>Destination</th><th>Risk</th></tr></thead><tbody>{rows}</tbody></table></div>"""
    return _page(body, "Events", "events")


# ══════════════════════════════════════════════════════════════════════════════
# USER DETAIL
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/user/<user_id>")
def user_detail(user_id):
    users, _, _, all_e, expl = load_data()
    row = None
    if not users.empty and "user_id" in users.columns:
        m = users[users["user_id"]==user_id]
        if not m.empty: row = m.iloc[0]
    if row is None:
        return _page(f"<div class='card'><h2>User {user_id} not found</h2></div>",active="users")

    sc=str(row.get("severity","LOW")).upper(); rs=float(row.get("risk_score",0))
    rcl={"CRITICAL":"rc-crit","HIGH":"rc-high","MEDIUM":"rc-med"}.get(sc,"rc-safe")

    # Load ALL events
    ue = pd.DataFrame()
    if not all_e.empty and "user_id" in all_e.columns:
        ue = all_e[all_e["user_id"]==user_id].copy()
        if not ue.empty:
            ue["timestamp"]=pd.to_datetime(ue["timestamp"],errors="coerce"); ue=ue.dropna(subset=["timestamp"]).sort_values("timestamp")

    te=len(ue); ah=0; be2=0; ra=0
    if not ue.empty:
        hrs = ue.get("hour_of_day", ue["timestamp"].dt.hour)
        ah=int(((hrs<8)|(hrs>19)).sum())
        if "rowcount" in ue.columns: be2=int((ue["rowcount"]>10000).sum())
        if "resource_sensitivity" in ue.columns: ra=int((ue["resource_sensitivity"]=="restricted").sum())

    # Timeline
    tf=go.Figure(); tmsg=""
    if not ue.empty and "risk_score" in ue.columns:
        sm2={"restricted":"#ef4444","confidential":"#f59e0b","high":"#ef4444","internal":"#3b82f6","medium":"#3b82f6","low":"#22c55e","public":"#22c55e"}
        cols2=[sm2.get(str(s).lower(),"#64748b") for s in ue.get("resource_sensitivity",pd.Series(["low"]*len(ue)))]
        ht=[f"<b>{str(t)[:19]}</b><br>Action: {a}<br>Resource: {r2}<br>Rows: {int(rc2):,}<br>Sensitivity: {s}" for t,a,r2,rc2,s in zip(ue["timestamp"],ue.get("action",""),ue.get("resource",""),ue.get("rowcount",pd.Series([0]*len(ue))),ue.get("resource_sensitivity",""))]
        tf.add_trace(go.Scatter(x=ue["timestamp"].astype(str).tolist(),y=ue["risk_score"].tolist(),mode="markers+lines",marker=dict(color=cols2,size=10,line=dict(width=1,color="rgba(255,255,255,.2)")),line=dict(color="rgba(59,130,246,.4)",width=1),hovertext=ht,hoverinfo="text"))
    elif not ue.empty:
        tf.add_trace(go.Scatter(x=ue["timestamp"].astype(str).tolist(),y=ue.get("rowcount",pd.Series([0]*len(ue))).tolist(),mode="markers+lines",marker=dict(color=C["accent"],size=10),line=dict(color=C["accent"])))
    else: tmsg="No events recorded for this user"
    tf.update_layout(paper_bgcolor="#020812",plot_bgcolor="#0a0f1e",font=dict(color="#f1f5f9",family="Inter"),xaxis=dict(gridcolor="#1a2340",showgrid=True,title="Time"),yaxis=dict(gridcolor="#1a2340",showgrid=True,title="Risk Score"),margin=dict(l=40,r=20,t=45,b=40),title="USER EVENT TIMELINE" if not tmsg else tmsg,height=300)
    tj=fig_json(tf)

    exp=expl.get(user_id,{}); br=exp.get("blast_radius",{})
    sl=[s.strip() for s in str(row.get("systems_access","")).split("|") if s.strip() and s.strip()!="nan"]
    bs=br.get("systems_at_risk",sl); bre=br.get("estimated_records_exposed",0)
    bg2=br.get("gdpr_fine_exposure","EUR 20M or 4% revenue"); bi=br.get("business_impact","Potential data exfiltration risk.")
    sph="".join(f'<span class="sp">{s}</span>' for s in (bs if isinstance(bs,list) else str(bs).split("|")) if s.strip() and s.strip()!="nan")

    fh=""
    for fn in exp.get("findings",[]):
        fc=fn.get("severity","MEDIUM")
        fh+=f'<div class="fc sev-{fc}"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px"><span class="mono" style="font-size:12px;font-weight:600;text-transform:uppercase;color:var(--crit)">{fn.get("finding","")}</span><span class="badge-{"crit" if fc=="CRITICAL" else "high" if fc=="HIGH" else "med"}">{fc}</span></div><p style="font-size:13px;margin-bottom:6px">{fn.get("details","")}</p><div class="rb">&rarr; {fn.get("recommendation","")}</div></div>'
    if not fh: fh='<div style="color:var(--dim);font-size:13px;padding:12px">Run explainer.py to generate LLM-powered findings.</div>'

    ch="".join(f'<span class="cb">{c}</span>' for c in exp.get("compliance_violations",[]))
    aah="".join(f"<li>{a}</li>" for a in exp.get("suggested_actions",[]))
    esc=exp.get("next_escalation","")
    pv=str(row.get("privilege_level","viewer"))

    body = f"""
<div class="ub"><div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1.5rem">
<div><p class="mono" style="font-size:11px;color:var(--dim);letter-spacing:.1em;margin-bottom:4px">{user_id}</p>
<h1 style="font-size:2.2rem;font-weight:700;margin-bottom:8px">{row.get("username","")}</h1>
<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px"><span class="dp {_dept_cls(row.get('department',''))}">{row.get("department","")}</span><span class="pp {_priv_cls(pv)}">{_priv_icon(pv)}{pv}</span><span class="dp dp-default">Hired: {str(row.get("hire_date",""))[:10]}</span><span class="dp dp-default">{row.get("job_title","")}</span></div>
<div style="display:flex;gap:6px"><button class="btn btn-r" onclick="alert('Access revocation request sent to IT team')">&#128274; REVOKE ACCESS</button><button class="btn btn-g" onclick="alert('User marked safe - removed from watchlist')">&#9989; MARK SAFE</button><button class="btn btn-a" onclick="alert('Escalated to Security Manager')">&#9888;&#65039; ESCALATE</button></div>
</div><div class="rc-lg {rcl}">{rs:.0f}</div></div></div>

<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:1.5rem">
<div class="ms"><div class="mi">&#128202;</div><div class="mv">{te}</div><div class="ml">Total Events</div></div>
<div class="ms"><div class="mi">&#127769;</div><div class="mv">{ah}</div><div class="ml">After Hours</div></div>
<div class="ms"><div class="mi">&#128230;</div><div class="mv">{be2}</div><div class="ml">Bulk Exports</div></div>
<div class="ms"><div class="mi">&#128274;</div><div class="mv">{ra}</div><div class="ml">Restricted Access</div></div>
</div>

<div style="display:grid;grid-template-columns:2fr 3fr;gap:1rem;margin-bottom:1.5rem">
<div>
<div class="card" style="margin-bottom:12px"><h3 style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:10px">ACCOUNT DETAILS</h3>
<table style="width:100%"><tr><td style="color:var(--muted);font-size:12px;padding:5px 0;border-bottom:1px solid rgba(26,35,64,.3)">Privilege</td><td class="mono" style="font-size:12px;padding:5px 0;border-bottom:1px solid rgba(26,35,64,.3)">{pv}</td></tr>
<tr><td style="color:var(--muted);font-size:12px;padding:5px 0;border-bottom:1px solid rgba(26,35,64,.3)">Status</td><td style="font-size:12px;padding:5px 0;color:{'var(--safe)' if row.get('is_active') else 'var(--crit)'};font-weight:600;border-bottom:1px solid rgba(26,35,64,.3)">{'ACTIVE' if row.get('is_active') else 'INACTIVE'}</td></tr>
<tr><td style="color:var(--muted);font-size:12px;padding:5px 0;border-bottom:1px solid rgba(26,35,64,.3)">Days Inactive</td><td class="mono" style="font-size:12px;padding:5px 0;color:var(--high);font-weight:600;border-bottom:1px solid rgba(26,35,64,.3)">{int(row.get("days_inactive",0))}</td></tr>
<tr><td style="color:var(--muted);font-size:12px;padding:5px 0;border-bottom:1px solid rgba(26,35,64,.3)">Systems</td><td class="mono" style="font-size:12px;padding:5px 0;border-bottom:1px solid rgba(26,35,64,.3)">{int(row.get("num_systems",0))}</td></tr>
<tr><td style="color:var(--muted);font-size:12px;padding:5px 0">Severity</td><td style="color:{sev_color(sc)};font-weight:700;font-size:12px;padding:5px 0">{sc}</td></tr></table></div>
<div class="card" style="margin-bottom:12px"><h3 style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:10px">COMPLIANCE VIOLATIONS</h3>{ch if ch else '<span style="color:var(--dim);font-size:12px">None detected</span>'}</div>
<div class="card"><h3 style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:10px">SUGGESTED ACTIONS</h3>
<ol class="cl">{aah if aah else '<li style="color:var(--dim)">Run explainer.py</li>'}</ol>
{'<p style="font-size:11px;color:var(--crit);margin-top:10px;padding:8px;background:rgba(239,68,68,.05);border-radius:4px">&#9200; '+esc+'</p>' if esc else ""}</div>
</div>
<div>
<div class="card" style="margin-bottom:12px;padding:0 16px 16px"><div id="tc"></div></div>
<div class="card"><h3 style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:10px">&#128270; LLM FINDINGS</h3>{fh}</div>
</div></div>

<div class="blast-box" style="margin-bottom:1.5rem"><h3>&#128165; BLAST RADIUS SIMULATION &mdash; <a href="/simulate/{user_id}" style="color:var(--crit);font-size:12px">Run Full Simulation &rarr;</a></h3>
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:16px;text-align:center">
<div><div class="big-num">{len(sl)}</div><p style="font-size:9px;color:var(--muted);text-transform:uppercase;margin-top:4px">Systems at Risk</p></div>
<div><div class="big-num">{int(bre):,}</div><p style="font-size:9px;color:var(--muted);text-transform:uppercase;margin-top:4px">Records Exposed</p></div>
<div><div class="big-num" style="font-size:1.3rem">{bg2}</div><p style="font-size:9px;color:var(--muted);text-transform:uppercase;margin-top:4px">GDPR Exposure</p></div>
<div><div class="big-num" style="color:var(--high)">~6mo</div><p style="font-size:9px;color:var(--muted);text-transform:uppercase;margin-top:4px">Detection w/o Tool</p></div>
</div><div style="margin-bottom:10px">{sph}</div>
<div style="background:rgba(239,68,68,.05);border:1px solid rgba(239,68,68,.12);border-radius:4px;padding:10px;font-size:13px">{bi}</div></div>
<script>var tl={tj};Plotly.newPlot('tc',tl.data,tl.layout,{{responsive:true,displayModeBar:false}});</script>"""
    return _page(body, f"{user_id}", "users")


# ══════════════════════════════════════════════════════════════════════════════
# SIMULATE
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/simulate/<user_id>")
def simulate(user_id):
    users, _, _, _, expl = load_data()
    row = None
    if not users.empty and "user_id" in users.columns:
        m = users[users["user_id"]==user_id]
        if not m.empty: row = m.iloc[0]
    if row is None: return _page(f"<p>User {user_id} not found</p>",active="users")

    sys=[s for s in str(row.get("systems_access","")).split("|") if s.strip() and s.strip()!="nan"]
    exp=expl.get(user_id,{}); br=exp.get("blast_radius",{})
    rec=br.get("estimated_records_exposed",len(sys)*250000); gdpr=br.get("gdpr_fine_exposure","EUR 20M or 4%"); imp=br.get("business_impact","Unauthorized access across multiple systems.")

    sn="".join(f'<div class="sim-node" style="animation-delay:{i*0.15}s"><span style="color:var(--crit)">&#9888;</span><div><div style="font-weight:600">{s}</div><div style="font-size:11px;color:var(--muted)">Full access compromised</div></div></div><div class="chain-arrow">&darr;</div>' for i,s in enumerate(sys))

    body = f"""
<div style="max-width:700px;margin:0 auto">
<div style="text-align:center;margin-bottom:2rem"><p style="color:var(--crit);font-size:11px;letter-spacing:.15em;text-transform:uppercase;margin-bottom:8px">&#9888; BREACH SIMULATION</p>
<h1 style="font-size:1.75rem">IF {row.get("username","").upper()} IS COMPROMISED...</h1><p style="color:var(--muted);font-size:13px">Attacker kill chain for {user_id}</p></div>
<div class="blast-box" style="margin-bottom:2rem"><div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;text-align:center">
<div><div class="big-num">{len(sys)}</div><p style="font-size:9px;color:var(--muted);text-transform:uppercase">Systems</p></div>
<div><div class="big-num" style="font-size:1.5rem">{int(rec):,}</div><p style="font-size:9px;color:var(--muted);text-transform:uppercase">Records</p></div>
<div><div class="big-num" style="font-size:1rem">{gdpr}</div><p style="font-size:9px;color:var(--muted);text-transform:uppercase">GDPR</p></div></div></div>
<div class="card" style="margin-bottom:1.5rem"><h3 style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:1rem">ATTACK CASCADE</h3>
<div class="sim-node" style="border-color:var(--crit);background:rgba(239,68,68,.05)"><span style="color:var(--crit)">&#128275;</span><div><div style="font-weight:700;color:var(--crit)">INITIAL ACCESS &mdash; {user_id}</div><div style="font-size:11px;color:var(--muted)">{row.get("privilege_level","")} | {int(row.get("days_inactive",0))}d inactive</div></div></div><div class="chain-arrow">&darr;</div>
{sn}
<div class="sim-node" style="border-color:var(--crit);background:rgba(239,68,68,.08)"><span>&#9760;</span><div><div style="font-weight:700;color:var(--crit)">EXFILTRATION COMPLETE</div><div style="font-size:11px;color:var(--muted)">{int(rec):,} records</div></div></div></div>
<div class="card" style="margin-bottom:1.5rem"><h3 style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px">BUSINESS IMPACT</h3><p style="font-size:14px">{imp}</p></div>
<div style="text-align:center;display:flex;gap:10px;justify-content:center"><a href="/user/{user_id}" class="btn btn-r">View Full Profile</a><a href="/users" class="btn btn-o">Back to Users</a></div></div>"""
    return _page(body, f"Simulate &mdash; {user_id}", "users")


# ══════════════════════════════════════════════════════════════════════════════
# GRAPH
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/graph")
def graph_page():
    users, _, _, _, _ = load_data()
    if users.empty: return _page('<div class="card"><h2>No data</h2><p>Run detector.py first.</p></div>',active="graph")
    try:
        import networkx as nx
    except ImportError: return _page('<div class="card"><h2>pip install networkx</h2></div>',active="graph")

    G=nx.Graph(); ss2=set(); flagged=0
    for _,r in users.iterrows():
        uid=r.get("user_id",""); sa=[s.strip() for s in str(r.get("systems_access","")).split("|") if s.strip() and s.strip()!="nan"]
        G.add_node(uid,node_type="user",risk_score=float(r.get("risk_score",0)),severity=str(r.get("severity","LOW")),username=str(r.get("username","")),days_inactive=int(r.get("days_inactive",0)))
        if str(r.get("severity","")).upper() in ("CRITICAL","HIGH"): flagged+=1
        for s in sa: ss2.add(s); G.add_node(s,node_type="system"); G.add_edge(uid,s)

    pos=nx.spring_layout(G,k=2.5,iterations=60,seed=42)
    sstats={}
    for s in ss2:
        nb=list(G.neighbors(s)); sstats[s]=(len(nb),sum(1 for n in nb if G.nodes[n].get("severity","") in ("CRITICAL","HIGH")))

    ex2,ey2=[],[]
    for u,v in G.edges():
        x0,y0=pos[u];x1,y1=pos[v];ex2.extend([x0,x1,None]);ey2.extend([y0,y1,None])
    et=go.Scatter(x=ex2,y=ey2,mode='lines',line=dict(width=0.4,color='rgba(26,35,64,0.5)'),hoverinfo='none')

    ux,uy,ut2,us2,uc2=[],[],[],[],[]
    for n in G.nodes():
        if G.nodes[n].get("node_type")!="user": continue
        x,y=pos[n];ux.append(x);uy.append(y)
        rs2=G.nodes[n].get("risk_score",0);sv=G.nodes[n].get("severity","LOW")
        ut2.append(f"<b>{n}</b><br>{G.nodes[n].get('username','')}<br>Risk: {rs2:.0f} | {sv}<br>Inactive: {G.nodes[n].get('days_inactive',0)}d")
        us2.append(max(8,min(30,rs2/3)));uc2.append(sev_color(sv))
    ut3=go.Scatter(x=ux,y=uy,mode='markers',name='Users',marker=dict(size=us2,color=uc2,line=dict(width=1,color='rgba(255,255,255,.12)')),text=ut2,hoverinfo='text')

    sx2,sy2,st2,sn2=[],[],[],[]
    for n in G.nodes():
        if G.nodes[n].get("node_type")!="system": continue
        x,y=pos[n];sx2.append(x);sy2.append(y);sn2.append(n)
        t,f=sstats.get(n,(0,0));st2.append(f"<b>{n}</b><br>{t} users<br>{f} flagged")
    st3=go.Scatter(x=sx2,y=sy2,mode='markers+text',name='Systems',marker=dict(size=16,color='#334155',symbol='square',line=dict(width=1.5,color='#64748b')),text=sn2,textposition="top center",textfont=dict(size=8,color="#f1f5f9",family="JetBrains Mono"),hovertext=st2,hoverinfo='text')

    fig=go.Figure(data=[et,ut3,st3])
    fig.update_layout(paper_bgcolor="#020812",plot_bgcolor="#020812",font=dict(color="#f1f5f9",family="Inter"),showlegend=True,height=600,xaxis=dict(showgrid=False,zeroline=False,showticklabels=False),yaxis=dict(showgrid=False,zeroline=False,showticklabels=False),margin=dict(l=20,r=20,t=20,b=20),legend=dict(x=0,y=1,bgcolor="rgba(10,15,30,.8)"))
    gj2=fig_json(fig)

    body = f"""
<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:1.5rem;flex-wrap:wrap;gap:1rem">
<div><h1 style="font-size:1.4rem;font-weight:700;letter-spacing:.03em">PRIVILEGE SPRAWL MAP</h1>
<p style="color:var(--muted);font-size:12px">Identity access relationships across all systems</p>
<p style="font-size:11px;color:var(--dim);margin-top:6px"><span style="color:var(--text);font-weight:600">{len(users)}</span> users &middot; <span style="color:var(--text);font-weight:600">{len(ss2)}</span> systems &middot; <span style="color:var(--crit);font-weight:600">{flagged}</span> flagged connections</p></div>
</div>
<div class="card" style="padding:0;overflow:hidden"><div id="gc" style="width:100%;height:600px"></div></div>
<div style="display:flex;gap:20px;margin-top:10px;justify-content:center">
<div style="display:flex;align-items:center;gap:6px"><span style="width:10px;height:10px;border-radius:50%;background:var(--safe);display:inline-block"></span><span style="font-size:11px;color:var(--muted)">Normal User</span></div>
<div style="display:flex;align-items:center;gap:6px"><span style="width:10px;height:10px;border-radius:50%;background:var(--crit);display:inline-block"></span><span style="font-size:11px;color:var(--muted)">Flagged User</span></div>
<div style="display:flex;align-items:center;gap:6px"><span style="width:10px;height:10px;border-radius:2px;background:#334155;display:inline-block"></span><span style="font-size:11px;color:var(--muted)">System Node</span></div>
</div>
<script>var gd={gj2};Plotly.newPlot('gc',gd.data,gd.layout,{{responsive:true,displayModeBar:true}});</script>"""
    return _page(body, "Privilege Graph", "graph")


# ══════════════════════════════════════════════════════════════════════════════
# LIVE FEED
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/live")
def live_page():
    body = """
<div class="scanline"></div>
<div style="display:flex;align-items:center;gap:12px;margin-bottom:2rem">
<span style="width:10px;height:10px;border-radius:50%;background:var(--safe);animation:pulse-green 1.2s infinite;display:inline-block"></span>
<div><h1 style="font-family:'JetBrains Mono',monospace;font-size:1.3rem;letter-spacing:.05em;color:var(--safe)">[ LIVE THREAT MONITOR ]<span style="animation:blink 1s infinite;color:var(--safe)">_</span></h1>
<p style="color:var(--dim);font-size:11px;font-family:'JetBrains Mono',monospace">Real-time anomalous event stream</p></div>
<div style="margin-left:auto;display:flex;align-items:center;gap:14px">
<label style="font-size:11px;color:var(--muted);display:flex;align-items:center;gap:5px;cursor:pointer;font-family:'JetBrains Mono',monospace"><input type="checkbox" id="st" checked style="accent-color:var(--crit)">SOUND</label>
<span id="ec2" class="badge-crit" style="font-size:14px">0</span></div></div>
<div id="lf" style="font-family:'JetBrains Mono',monospace;margin-bottom:48px"></div>
<div class="sb"><span style="display:flex;align-items:center;gap:6px"><span class="gd"></span><span style="color:var(--safe)">MONITORING ACTIVE</span></span><span id="lu">Last updated: now</span><span id="ep">Events processed: 0</span></div>
<script>
const aC=new(window.AudioContext||window.webkitAudioContext)();
function beep(){if(!document.getElementById('st').checked)return;const o=aC.createOscillator(),g=aC.createGain();o.connect(g);g.connect(aC.destination);o.type='sine';o.frequency.value=880;g.gain.setValueAtTime(0.3,aC.currentTime);g.gain.exponentialRampToValueAtTime(0.001,aC.currentTime+0.3);o.start(aC.currentTime);o.stop(aC.currentTime+0.3)}
const sm={CRITICAL:'crit',HIGH:'high',MEDIUM:'med',LOW:'safe'};let lut=Date.now();let total=0;
async function fl(){
try{const r=await fetch('/api/live-feed');const d=await r.json();total+=d.length;
document.getElementById('ec2').textContent=d.length;document.getElementById('ep').textContent='Events processed: '+total;
let hc=false;const h=d.map((e,i)=>{const sc=sm[e.severity]||'safe';if(e.severity==='CRITICAL')hc=true;
return `<div class="le ${e.severity==='CRITICAL'?'ce':''}" style="animation-delay:${i*0.04}s"><div style="display:flex;justify-content:space-between;align-items:center;gap:12px"><div style="flex:1;min-width:0"><div style="display:flex;align-items:center;gap:10px;margin-bottom:5px"><span style="width:6px;height:6px;border-radius:50%;background:var(--${sc});animation:pulse-red 2s infinite;display:inline-block"></span><span style="font-size:11px;color:#22c55e">${(e.timestamp||'').slice(0,19)}</span><span class="badge-${sc}" style="font-size:10px">${e.severity||'LOW'}</span></div><div style="font-size:13px"><span style="color:#06b6d4">${e.username||'?'}</span> <span style="color:var(--dim)">&rarr;</span> <span style="color:var(--accent)">${e.resource||''}</span></div><div style="font-size:11px;color:var(--dim);margin-top:3px">${e.action||''} &middot; ${e.destination||'local'} &middot; ${e.resource_sensitivity||'?'}</div></div><div class="badge-${sc}" style="font-size:16px;padding:4px 12px">${Math.round(e.risk_score||0)}</div></div></div>`}).join('');
document.getElementById('lf').innerHTML=h;lut=Date.now();
if(hc){beep();document.body.style.animation='flash-red .2s';setTimeout(()=>document.body.style.animation='',200)}
}catch(e){}}
fl();setInterval(fl,5000);
setInterval(()=>{const s=Math.round((Date.now()-lut)/1000);document.getElementById('lu').textContent='Last updated: '+s+'s ago'},1000);
</script>"""
    return _page(body, "Live Feed", "live")


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
