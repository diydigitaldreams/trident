import { useState, useEffect, useRef, useCallback } from "react";

const uid = () => crypto.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2,9)}`;
const digest = async (t) => {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(t));
  return Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,"0")).join("");
};
const now = () => new Date().toISOString();
const hms = (i) => { try { return new Date(i).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"}); } catch { return "—"; } };
const hmFull = (i) => { try { return new Date(i).toLocaleString([],{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"}); } catch { return "—"; } };

const TACTICS = [
  {id:"TA0043",name:"Reconnaissance",short:"recon"},
  {id:"TA0042",name:"Resource Development",short:"resource_dev"},
  {id:"TA0001",name:"Initial Access",short:"initial_access"},
  {id:"TA0002",name:"Execution",short:"execution"},
  {id:"TA0003",name:"Persistence",short:"persistence"},
  {id:"TA0004",name:"Privilege Escalation",short:"priv_esc"},
  {id:"TA0005",name:"Defense Evasion",short:"def_evasion"},
  {id:"TA0006",name:"Credential Access",short:"cred_access"},
  {id:"TA0007",name:"Discovery",short:"discovery"},
  {id:"TA0008",name:"Lateral Movement",short:"lateral"},
  {id:"TA0009",name:"Collection",short:"collection"},
  {id:"TA0011",name:"Command and Control",short:"c2"},
  {id:"TA0010",name:"Exfiltration",short:"exfil"},
  {id:"TA0040",name:"Impact",short:"impact"},
];
const tacticName = (s) => TACTICS.find(t => t.short===s||t.id===s)?.name || s;
const tacticId   = (s) => TACTICS.find(t => t.short===s||t.id===s)?.id   || "";

const GATE_MODES = {
  observer:   {name:"OBSERVER",   color:"#ef4444", desc:"Read-only — no execution allowed",   icon:"📡"},
  supervised: {name:"SUPERVISED", color:"#f59e0b", desc:"Auto-recon, gate exploit + lateral", icon:"👁"},
  controlled: {name:"CONTROLLED", color:"#f97316", desc:"Every action requires sign-off",     icon:"🔒"},
  autonomous: {name:"AUTONOMOUS", color:"#22c55e", desc:"No gates — lab & CTF use only",      icon:"⚡"},
};

const STEALTH_PRESETS = {
  blitz:      {val:0,   color:"#ef4444"},
  methodical: {val:35,  color:"#f59e0b"},
  whisper:    {val:70,  color:"#22c55e"},
  ghost:      {val:100, color:"#8b5cf6"},
};

const stealthParams = (val) => {
  const v = Math.max(0,Math.min(100,val));
  return {delay:Math.round(v*80),concurrent:Math.max(1,Math.round(50-v*0.48)),jitter:Math.round(v*30),toolRotation:v>40,dnsStyle:v>60?"doh":"standard",tlsRotation:v>50};
};

const EMPTY_OP = {
  operation:{name:"",id:"",start:"",end:"",classification:"",roe_url:"",client_poc:"",abort_contact:""},
  perimeter:{cidrs:[],hosts:[],domains:[]},
  no_touch:{hosts:[],cidrs:[],restricted_periods:[]},
  constraints:{blocked_tactics:["impact","exfil"],gated_tactics:["initial_access","execution","priv_esc","lateral","cred_access"]},
};

const TOOL_SLOTS = [
  {slot:"port-scan",name:"rustscan",ver:"2.3",desc:"Fast port discovery",tactics:["recon"],footprint:"medium",on:true,core:true},
  {slot:"port-scan",name:"naabu",ver:"2.3",desc:"SYN/CONNECT scanner",tactics:["recon"],footprint:"low",on:true,core:true},
  {slot:"web-fuzz",name:"feroxbuster",ver:"2.10",desc:"Recursive content discovery",tactics:["discovery"],footprint:"medium",on:true,core:true},
  {slot:"web-fuzz",name:"gobuster",ver:"3.6",desc:"Directory/DNS brute-forcing",tactics:["discovery"],footprint:"medium",on:true,core:true},
  {slot:"dns-enum",name:"dnsx",ver:"1.2",desc:"Multi-purpose DNS toolkit",tactics:["recon"],footprint:"low",on:true,core:true},
  {slot:"subdomain",name:"subfinder",ver:"2.6",desc:"Passive subdomain enumeration",tactics:["recon"],footprint:"low",on:true,core:true},
  {slot:"vuln-scan",name:"nuclei",ver:"3.3",desc:"Template-driven vuln detection",tactics:["discovery"],footprint:"medium",on:true,core:true},
  {slot:"exploit",name:"sliver",ver:"1.5",desc:"Adversary emulation framework",tactics:["execution","c2"],footprint:"high",on:true,core:true},
  {slot:"ad-recon",name:"certipy",ver:"4.8",desc:"AD certificate abuse toolkit",tactics:["cred_access"],footprint:"low",on:true,core:true},
  {slot:"ad-recon",name:"crackmapexec",ver:"5.4",desc:"Swiss army knife for AD",tactics:["lateral"],footprint:"medium",on:true,core:true},
  {slot:"tunnel",name:"ligolo-ng",ver:"0.6",desc:"Tunneling/pivoting",tactics:["lateral"],footprint:"low",on:true,core:true},
  {slot:"http",name:"httpx",ver:"1.6",desc:"HTTP toolkit",tactics:["recon"],footprint:"low",on:true,core:true},
];

const SC = {critical:"#ef4444",high:"#f97316",medium:"#f59e0b",low:"#22c55e",info:"#3b82f6"};
const TC = {action:"#22c55e",plan:"#3b82f6",approval:"#f59e0b",violation:"#ef4444",finding:"#f97316",import:"#8b5cf6",export:"#06b6d4"};
const F  = "'JetBrains Mono','Fira Code',monospace";

// ── PerimeterGuard inline ────────────────────────────────────────────
function escapeRx(s) { return s.replace(/[.*+?^${}()|[\]\\]/g,"\\$&"); }
function normTarget(t) { return t.replace(/^https?:\/\//,"").split("/")[0].split(":")[0]; }
function matchCIDR(host,cidr) {
  const p=cidr.split("/"); if(p.length!==2) return host===cidr;
  const mask=parseInt(p[1],10); if(isNaN(mask)||mask<0||mask>32) return false;
  const co=p[0].split(".").map(Number), ho=host.split(".").map(Number);
  if(co.length!==4||ho.length!==4) return false;
  const ci=((co[0]<<24)|(co[1]<<16)|(co[2]<<8)|co[3])>>>0;
  const hi=((ho[0]<<24)|(ho[1]<<16)|(ho[2]<<8)|ho[3])>>>0;
  const mi=mask===0?0:((~0<<(32-mask))>>>0);
  return (ci&mi)===(hi&mi);
}
function matchHost(h,p) { if(!p.includes("*")) return h===p; return new RegExp("^"+p.split("*").map(escapeRx).join(".*")+"$").test(h); }
function matchDomain(h,d) { if(d.startsWith("*.")) return h.endsWith("."+d.slice(2))||h===d.slice(2); return h===d; }

class PerimeterGuard {
  constructor(op) { this.op=op; }
  authorize(target) {
    if(!this.op||!target) return {cleared:false,reason:"No operation or target"};
    const n=new Date();
    if(this.op.operation.start&&n<new Date(this.op.operation.start)) return {cleared:false,reason:"Operation not yet active"};
    if(this.op.operation.end&&n>new Date(this.op.operation.end)) return {cleared:false,reason:"Operation window closed"};
    const h=normTarget(target);
    if(this.op.no_touch.hosts.some(x=>matchHost(h,x))) return {cleared:false,reason:`${h} is no-touch`};
    if(this.op.no_touch.cidrs.some(c=>matchCIDR(h,c))) return {cleared:false,reason:`${h} in no-touch CIDR`};
    const inP=this.op.perimeter.hosts.some(x=>matchHost(h,x))||this.op.perimeter.domains.some(d=>matchDomain(h,d))||this.op.perimeter.cidrs.some(c=>matchCIDR(h,c));
    return inP ? {cleared:true,reason:""} : {cleared:false,reason:`${h} outside perimeter`};
  }
  classify(tactic) {
    if(this.op.constraints.blocked_tactics.includes(tactic)) return {allowed:false,reason:`'${tacticName(tactic)}' is blocked`};
    return {allowed:true,reason:""};
  }
  gateCheck(tactic,mode) {
    if(mode==="observer") return "block";
    if(mode==="autonomous") return "pass";
    if(mode==="controlled") return "gate";
    return this.op.constraints.gated_tactics.includes(tactic)?"gate":"pass";
  }
}

// ── Claude API ───────────────────────────────────────────────────────
async function callClaude(apiKey,system,userMsg,maxTokens=1000) {
  const r=await fetch("https://api.anthropic.com/v1/messages",{method:"POST",headers:{"Content-Type":"application/json","x-api-key":apiKey,"anthropic-version":"2023-06-01"},body:JSON.stringify({model:"claude-sonnet-4-20250514",max_tokens:maxTokens,system,messages:[{role:"user",content:userMsg}]})});
  const d=await r.json();
  return d.content?.filter(b=>b.type==="text").map(b=>b.text).join("\n")||"";
}
async function callClaudeJSON(apiKey,system,userMsg) {
  const raw=await callClaude(apiKey,system+" Respond only with valid JSON. No markdown.",userMsg);
  try { return JSON.parse(raw.replace(/```json|```/g,"").trim()); } catch { return null; }
}

// ── Design primitives ────────────────────────────────────────────────
const CSS = `*{box-sizing:border-box;margin:0;padding:0}body{background:#0a0a0f;color:#e2e8f0;font-family:${F}}::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:#1e1e2e;border-radius:2px}input,textarea,select{background:#0a0a0f;color:#e2e8f0;border:1px solid #1e1e2e;border-radius:4px;font-family:${F};font-size:11px;padding:7px 10px;outline:none;width:100%}input:focus,textarea:focus,select:focus{border-color:#00c896}`;

const Badge = ({s,sm}) => {
  const cols = {critical:"#ef4444",high:"#f97316",medium:"#f59e0b",low:"#22c55e",info:"#3b82f6"};
  const c = cols[s]||"#64748b";
  return (
    <span style={{fontSize:sm?8:9,fontFamily:F,fontWeight:700,letterSpacing:1,padding:sm?"2px 5px":"3px 8px",borderRadius:3,color:c,border:`1px solid ${c}`,textTransform:"uppercase",whiteSpace:"nowrap"}}>
      {s?.replace(/_/g," ")}
    </span>
  );
};

const Btn = ({children,onClick,c,dis,sm,ol}) => (
  <button onClick={onClick} disabled={dis} style={{background:ol?"transparent":(c||"#00c896"),color:ol?(c||"#00c896"):"#000",border:ol?`1px solid ${c||"#00c896"}`:"none",borderRadius:4,padding:sm?"4px 10px":"8px 16px",fontFamily:F,fontSize:sm?9:11,fontWeight:700,cursor:dis?"not-allowed":"pointer",letterSpacing:1,opacity:dis?0.5:1,whiteSpace:"nowrap"}}>
    {children}
  </button>
);

const Card = ({children,bc,sx}) => (
  <div style={{background:"#12121a",border:`1px solid ${bc||"#1e1e2e"}`,borderRadius:6,padding:16,marginBottom:12,...sx}}>
    {children}
  </div>
);

const Sec = ({t,children,action}) => (
  <div style={{marginBottom:16}}>
    <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:8}}>
      <span style={{fontSize:9,fontWeight:700,letterSpacing:2,color:"#64748b",fontFamily:F,textTransform:"uppercase"}}>{t}</span>
      {action}
    </div>
    {children}
  </div>
);

const Empty = ({t}) => (
  <div style={{fontSize:11,color:"#64748b",fontFamily:F,fontStyle:"italic",padding:"12px 0",textAlign:"center"}}>{t}</div>
);

const Row = ({label,value,vc}) => (
  <div style={{display:"flex",justifyContent:"space-between",padding:"5px 0",borderBottom:"1px solid #252535"}}>
    <span style={{fontSize:10,color:"#64748b",fontFamily:F}}>{label}</span>
    <span style={{fontSize:11,fontWeight:700,color:vc||"#e2e8f0",fontFamily:F}}>{value}</span>
  </div>
);

// ── Dashboard ────────────────────────────────────────────────────────
function VDash({op,approvals,findings,violations,actions,evidence,timeline}) {
  const pc = approvals.filter(a=>a.status==="pending").length;
  return (
    <div>
      <div style={{marginBottom:16}}>
        <div style={{fontSize:18,fontWeight:700,fontFamily:F,color:"#00c896",letterSpacing:2}}>◈ TRIDENT</div>
        <div style={{fontSize:11,color:"#64748b",fontFamily:F}}>{op.operation.name||"No operation loaded"}</div>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:10,marginBottom:16}}>
        {[["PHASES",actions.length,"#00c896"],["FINDINGS",findings.length,findings.length>0?"#f59e0b":"#64748b"],["EVIDENCE",evidence.length,"#00c896"],["VIOLATIONS",violations.length,violations.length>0?"#ef4444":"#64748b"],["GATES",pc,pc>0?"#f59e0b":"#64748b"]].map(([l,v,c]) => (
          <div key={l} style={{background:"#12121a",border:"1px solid #1e1e2e",borderRadius:6,padding:12,textAlign:"center"}}>
            <div style={{fontSize:22,fontWeight:700,color:c,fontFamily:F}}>{v}</div>
            <div style={{fontSize:8,color:"#64748b",fontFamily:F,letterSpacing:1}}>{l}</div>
          </div>
        ))}
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
        <Card>
          <Sec t="RECENT ACTIVITY">
            {timeline.slice(-6).reverse().map(e => (
              <div key={e.id} style={{display:"flex",gap:8,alignItems:"center",padding:"4px 0",borderBottom:"1px solid #252535"}}>
                <div style={{width:6,height:6,borderRadius:"50%",background:TC[e.type]||"#64748b",flexShrink:0}}/>
                <span style={{fontSize:9,color:"#64748b",fontFamily:F,minWidth:48}}>{hms(e.ts)}</span>
                <span style={{fontSize:10,color:"#e2e8f0",fontFamily:F,flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{e.text}</span>
              </div>
            ))}
            {timeline.length===0 && <Empty t="No activity yet"/>}
          </Sec>
        </Card>
        <Card>
          <Sec t="FINDINGS BY SEVERITY">
            {["critical","high","medium","low","info"].map(sv => {
              const c = findings.filter(f=>f.severity===sv).length;
              if (!c) return null;
              return (
                <div key={sv} style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
                  <div style={{width:56,fontSize:9,fontFamily:F,color:SC[sv],fontWeight:700,textTransform:"uppercase"}}>{sv}</div>
                  <div style={{flex:1,height:5,background:"#0a0a0f",borderRadius:3,overflow:"hidden"}}>
                    <div style={{height:"100%",width:`${Math.min(c/Math.max(findings.length,1)*100,100)}%`,background:SC[sv],borderRadius:3}}/>
                  </div>
                  <span style={{fontSize:10,fontFamily:F,minWidth:16,textAlign:"right"}}>{c}</span>
                </div>
              );
            })}
            {findings.length===0 && <Empty t="No findings"/>}
          </Sec>
        </Card>
        <Card>
          <Sec t="VIOLATIONS">
            {violations.slice(-5).reverse().map(v => (
              <div key={v.id} style={{padding:"5px 0",borderBottom:"1px solid #252535"}}>
                <div style={{fontSize:11,color:"#ef4444",fontFamily:F}}>⛔ {v.target}</div>
                <div style={{fontSize:9,color:"#64748b",fontFamily:F}}>{v.reason} · {hms(v.ts)}</div>
              </div>
            ))}
            {violations.length===0 && <Empty t="Clean — no violations"/>}
          </Sec>
        </Card>
        <Card>
          <Sec t="EVIDENCE CHAIN">
            {evidence.slice(-5).reverse().map(e => (
              <div key={e.id} style={{display:"flex",gap:6,alignItems:"center",padding:"4px 0",borderBottom:"1px solid #252535"}}>
                <span style={{fontSize:9,color:"#64748b",fontFamily:F,minWidth:52}}>{hms(e.ts)}</span>
                <span style={{fontSize:10,fontFamily:F,flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{e.tool} → {e.target}</span>
                <span style={{fontSize:8,color:"#64748b",fontFamily:F}}>#{e.seq}</span>
              </div>
            ))}
            {evidence.length===0 && <Empty t="No evidence records"/>}
          </Sec>
        </Card>
      </div>
    </div>
  );
}

// ── Perimeter ────────────────────────────────────────────────────────
function VScope({op,setOp}) {
  const [tab,sTab] = useState("perimeter");
  const getVal = (path) => path.split(".").reduce((o,k)=>o?.[k],op)||[];
  const add = (path,val) => {
    if(!val?.trim()) return;
    const x=JSON.parse(JSON.stringify(op));
    const keys=path.split("."); let o=x;
    for(let i=0;i<keys.length-1;i++) o=o[keys[i]];
    if(!o[keys.at(-1)].includes(val.trim())) o[keys.at(-1)].push(val.trim());
    setOp(x);
  };
  const rm = (path,idx) => {
    const x=JSON.parse(JSON.stringify(op));
    const keys=path.split("."); let o=x;
    for(let i=0;i<keys.length-1;i++) o=o[keys[i]];
    o[keys.at(-1)].splice(idx,1); setOp(x);
  };
  const setField = (path,val) => {
    const x=JSON.parse(JSON.stringify(op));
    const keys=path.split("."); let o=x;
    for(let i=0;i<keys.length-1;i++) o=o[keys[i]];
    o[keys.at(-1)]=val; setOp(x);
  };

  return (
    <div>
      <div style={{display:"flex",gap:4,marginBottom:16}}>
        {["perimeter","no-touch","constraints","meta"].map(t => (
          <button key={t} onClick={()=>sTab(t)} style={{padding:"6px 14px",borderRadius:4,background:tab===t?"#00c896":"transparent",color:tab===t?"#000":"#64748b",border:`1px solid ${tab===t?"#00c896":"#1e1e2e"}`,fontFamily:F,fontSize:9,fontWeight:700,cursor:"pointer",textTransform:"uppercase"}}>
            {t}
          </button>
        ))}
      </div>

      {tab==="perimeter" && (
        <Card>
          {[["HOSTS","perimeter.hosts","api.example.com"],["CIDRS","perimeter.cidrs","10.0.0.0/16"],["DOMAINS","perimeter.domains","*.corp.local"]].map(([title,path,ph]) => (
            <Sec key={path} t={title}>
              <div style={{display:"flex",gap:6,marginBottom:8}}>
                <input placeholder={ph} onKeyDown={e=>{if(e.key==="Enter"){add(path,e.target.value);e.target.value="";}}}/>
                <Btn sm>ADD</Btn>
              </div>
              {getVal(path).map((h,i) => (
                <div key={i} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"4px 0",borderBottom:"1px solid #252535"}}>
                  <span style={{fontSize:11,fontFamily:F,color:"#00c896"}}>{h}</span>
                  <Btn sm ol c="#ef4444" onClick={()=>rm(path,i)}>×</Btn>
                </div>
              ))}
            </Sec>
          ))}
        </Card>
      )}

      {tab==="no-touch" && (
        <Card>
          {[["NO-TOUCH HOSTS","no_touch.hosts","prod.example.com"],["NO-TOUCH CIDRS","no_touch.cidrs","10.0.1.0/24"]].map(([title,path,ph]) => (
            <Sec key={path} t={title}>
              <div style={{display:"flex",gap:6,marginBottom:8}}>
                <input placeholder={ph} onKeyDown={e=>{if(e.key==="Enter"){add(path,e.target.value);e.target.value="";}}}/>
                <Btn sm>ADD</Btn>
              </div>
              {getVal(path).map((h,i) => (
                <div key={i} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"4px 0",borderBottom:"1px solid #252535"}}>
                  <span style={{fontSize:11,fontFamily:F,color:"#ef4444"}}>{h}</span>
                  <Btn sm ol c="#ef4444" onClick={()=>rm(path,i)}>×</Btn>
                </div>
              ))}
            </Sec>
          ))}
        </Card>
      )}

      {tab==="constraints" && (
        <Card>
          <Sec t="BLOCKED TACTICS">
            {TACTICS.map(t => {
              const on = op.constraints.blocked_tactics.includes(t.short);
              return (
                <button key={t.short} onClick={()=>{const x=JSON.parse(JSON.stringify(op));if(on)x.constraints.blocked_tactics=x.constraints.blocked_tactics.filter(s=>s!==t.short);else x.constraints.blocked_tactics.push(t.short);setOp(x);}} style={{margin:"0 4px 4px 0",padding:"4px 10px",borderRadius:3,background:on?"#ef4444":"transparent",color:on?"#fff":"#64748b",border:`1px solid ${on?"#ef4444":"#1e1e2e"}`,fontFamily:F,fontSize:9,cursor:"pointer"}}>
                  {t.name}
                </button>
              );
            })}
          </Sec>
          <Sec t="GATED TACTICS">
            {TACTICS.map(t => {
              const on = op.constraints.gated_tactics.includes(t.short);
              return (
                <button key={t.short} onClick={()=>{const x=JSON.parse(JSON.stringify(op));if(on)x.constraints.gated_tactics=x.constraints.gated_tactics.filter(s=>s!==t.short);else x.constraints.gated_tactics.push(t.short);setOp(x);}} style={{margin:"0 4px 4px 0",padding:"4px 10px",borderRadius:3,background:on?"#f59e0b":"transparent",color:on?"#000":"#64748b",border:`1px solid ${on?"#f59e0b":"#1e1e2e"}`,fontFamily:F,fontSize:9,cursor:"pointer"}}>
                  {t.name}
                </button>
              );
            })}
          </Sec>
        </Card>
      )}

      {tab==="meta" && (
        <Card>
          <Sec t="OPERATION METADATA">
            {[["Operation Name","operation.name"],["Operation ID","operation.id"],["Classification","operation.classification"],["ROE URL","operation.roe_url"],["Client POC","operation.client_poc"],["Abort Contact","operation.abort_contact"]].map(([l,p]) => (
              <div key={p} style={{marginBottom:8}}>
                <div style={{fontSize:9,color:"#64748b",fontFamily:F,marginBottom:4}}>{l.toUpperCase()}</div>
                <input value={p.split(".").reduce((o,k)=>o?.[k],op)||""} onChange={e=>setField(p,e.target.value)} placeholder={l}/>
              </div>
            ))}
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginTop:8}}>
              <div>
                <div style={{fontSize:9,color:"#64748b",fontFamily:F,marginBottom:4}}>START</div>
                <input type="datetime-local" value={op.operation.start} onChange={e=>setField("operation.start",e.target.value)}/>
              </div>
              <div>
                <div style={{fontSize:9,color:"#64748b",fontFamily:F,marginBottom:4}}>END</div>
                <input type="datetime-local" value={op.operation.end} onChange={e=>setField("operation.end",e.target.value)}/>
              </div>
            </div>
          </Sec>
        </Card>
      )}
    </div>
  );
}

// ── Network Map ──────────────────────────────────────────────────────
function VMap({op,actions,violations}) {
  const tested   = new Set(actions.map(a=>normTarget(a.target||"")));
  const violated = new Set(violations.map(v=>normTarget(v.target||"")));
  const targets  = [...op.perimeter.hosts,...op.perimeter.domains,...op.perimeter.cidrs];
  const cx=300,cy=200,r=140;
  return (
    <Card sx={{textAlign:"center"}}>
      <Sec t="PERIMETER NETWORK MAP"/>
      <svg width="600" height="400" style={{maxWidth:"100%"}}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#1e1e2e" strokeWidth="1" strokeDasharray="4,4"/>
        <circle cx={cx} cy={cy} r={8} fill="#00c896"/>
        <text x={cx} y={cy+20} textAnchor="middle" fill="#00c896" fontSize="9" fontFamily={F}>TRIDENT</text>
        {targets.map((t,i) => {
          const angle=(i/Math.max(targets.length,1))*2*Math.PI-Math.PI/2;
          const tx=cx+r*Math.cos(angle), ty=cy+r*Math.sin(angle);
          const col=violated.has(t)?"#ef4444":tested.has(t)?"#22c55e":"#64748b";
          return (
            <g key={t}>
              <line x1={cx} y1={cy} x2={tx} y2={ty} stroke="#1e1e2e" strokeWidth="1"/>
              <circle cx={tx} cy={ty} r={5} fill={col}/>
              <text x={tx} y={ty-10} textAnchor="middle" fill={col} fontSize="8" fontFamily={F}>{t.length>16?t.slice(0,14)+"…":t}</text>
            </g>
          );
        })}
        {targets.length===0 && <text x={cx} y={cy+50} textAnchor="middle" fill="#64748b" fontSize="11" fontFamily={F}>Define perimeter targets first</text>}
      </svg>
    </Card>
  );
}

// ── Workbench ────────────────────────────────────────────────────────
function VWorkbench({op,mode,setActions,setViolations,setEvidence,addTL,actions,evidence}) {
  const [target,sTarget]     = useState("");
  const [tactic,sTactic]     = useState("recon");
  const [tool,sTool]         = useState("rustscan");
  const [output,sOutput]     = useState("");
  const [phase,sPhase]       = useState("");
  const [chat,sChat]         = useState([]);
  const [inp,sInp]           = useState("");
  const [busy,sBusy]         = useState(false);
  const [apiKey,sApiKey]     = useState("");
  const [plan,sPlan]         = useState(null);
  const ref = useRef(null);
  useEffect(()=>{ ref.current?.scrollIntoView({behavior:"smooth"}); },[chat]);
  const guard = new PerimeterGuard(op);

  const logPhase = async () => {
    if(!target.trim()||!phase.trim()) return;
    if(mode==="observer") { addTL("violation","Observer mode — blocked"); return; }
    const auth=guard.authorize(target), cls=guard.classify(tactic), gate=guard.gateCheck(tactic,mode);
    if(!auth.cleared) { setViolations(p=>[...p,{id:uid(),ts:now(),target,reason:auth.reason}]); addTL("violation",`Violation: ${auth.reason}`); return; }
    if(!cls.allowed)  { setViolations(p=>[...p,{id:uid(),ts:now(),target,reason:cls.reason}]);  addTL("violation",`Blocked: ${cls.reason}`); return; }
    if(gate==="gate") { addTL("approval",`Gate required: ${phase}`); return; }
    const seq=evidence.length+1, prevHash=evidence.length>0?evidence[evidence.length-1].hash:"GENESIS";
    const rec={id:uid(),seq,ts:now(),operator:"practitioner",phase,target,tactic,tool,output,prevHash};
    const hash=await digest(JSON.stringify(rec));
    setEvidence(p=>[...p,{...rec,hash}]);
    setActions(p=>[...p,{id:uid(),ts:now(),phase,target,tactic,tool}]);
    addTL("action",`Logged: ${phase} → ${target}`);
    sPhase(""); sTarget(""); sOutput("");
  };

  const genPlan = async () => {
    if(!apiKey) return; sBusy(true);
    const r=await callClaudeJSON(apiKey,"Generate a phased assessment plan as JSON array: [{name,tactic,tool,description,risk_level}]. risk_level: low|medium|high.",`Perimeter: ${JSON.stringify(op.perimeter)}`);
    if(r) sPlan(Array.isArray(r)?r:[]); sBusy(false);
  };

  const send = async () => {
    if(!inp.trim()||!apiKey) return;
    const msg=inp.trim(); sInp(""); sChat(p=>[...p,{r:"user",t:msg}]); sBusy(true);
    const t=await callClaude(apiKey,"You are TRIDENT's assessment advisor. Help with MITRE ATT&CK mappings, risk analysis, and methodology. Never provide attack code.",`Op: ${op.operation.name||"unnamed"}\n\n${msg}`);
    sChat(p=>[...p,{r:"ai",t}]); sBusy(false);
  };

  return (
    <div style={{display:"flex",flexDirection:"column",gap:12}}>
      <Card>
        <Sec t="LOG PHASE"/>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:8}}>
          <div>
            <div style={{fontSize:9,color:"#64748b",fontFamily:F,marginBottom:4}}>PHASE NAME</div>
            <input value={phase} onChange={e=>sPhase(e.target.value)} placeholder="Port scan — external"/>
          </div>
          <div>
            <div style={{fontSize:9,color:"#64748b",fontFamily:F,marginBottom:4}}>TARGET</div>
            <input value={target} onChange={e=>sTarget(e.target.value)} placeholder="host or IP"/>
          </div>
          <div>
            <div style={{fontSize:9,color:"#64748b",fontFamily:F,marginBottom:4}}>TACTIC</div>
            <select value={tactic} onChange={e=>sTactic(e.target.value)}>
              {TACTICS.map(t=><option key={t.short} value={t.short}>{t.name} — {t.id}</option>)}
            </select>
          </div>
          <div>
            <div style={{fontSize:9,color:"#64748b",fontFamily:F,marginBottom:4}}>TOOL</div>
            <input value={tool} onChange={e=>sTool(e.target.value)} placeholder="tool name"/>
          </div>
        </div>
        <textarea value={output} onChange={e=>sOutput(e.target.value)} placeholder="Paste tool output..." rows={3} style={{marginBottom:8,resize:"vertical"}}/>
        <div style={{display:"flex",gap:8,alignItems:"center"}}>
          <Btn onClick={logPhase} dis={mode==="observer"||!phase.trim()||!target.trim()}>LOG TO EVIDENCE CHAIN</Btn>
          {mode==="observer" && <span style={{fontSize:10,color:"#ef4444",fontFamily:F}}>📡 Observer — disabled</span>}
        </div>
      </Card>

      <Card>
        <Sec t="AI PLAN GENERATOR" action={
          <div style={{display:"flex",gap:6}}>
            <input value={apiKey} onChange={e=>sApiKey(e.target.value)} placeholder="API key" type="password" style={{width:160}}/>
            <Btn sm onClick={genPlan} dis={busy||!apiKey}>{busy?"…":"GENERATE"}</Btn>
          </div>
        }/>
        {plan && (
          <div style={{maxHeight:180,overflowY:"auto"}}>
            {plan.map((p,i) => (
              <div key={i} style={{display:"flex",alignItems:"center",gap:8,padding:"6px 8px",marginBottom:3,background:"#0a0a0f",border:"1px solid #1e1e2e",borderRadius:4,borderLeft:`3px solid ${SC[p.risk_level]||"#1e1e2e"}`}}>
                <span style={{fontSize:10,color:"#64748b",fontFamily:F,minWidth:16}}>{i+1}</span>
                <div style={{flex:1}}>
                  <div style={{fontSize:11,fontFamily:F}}>{p.name}</div>
                  <div style={{fontSize:9,color:"#64748b",fontFamily:F}}>{tacticName(p.tactic)} · {p.description}</div>
                </div>
                <Badge s={p.risk_level} sm/>
                <Btn sm ol onClick={()=>{sPhase(p.name);sTactic(p.tactic);sTool(p.tool||"");}} dis={mode==="observer"}>USE</Btn>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card>
        <Sec t="ASSESSMENT ADVISOR"/>
        <div style={{maxHeight:200,overflowY:"auto",marginBottom:8,display:"flex",flexDirection:"column",gap:5}}>
          {chat.length===0 && <Empty t="Ask about MITRE, risk analysis, findings..."/>}
          {chat.map((m,i) => (
            <div key={i} style={{padding:"6px 10px",borderRadius:4,maxWidth:"88%",fontSize:11,fontFamily:F,lineHeight:1.5,whiteSpace:"pre-wrap",alignSelf:m.r==="user"?"flex-end":"flex-start",background:m.r==="user"?"rgba(0,200,150,.12)":"#0a0a0f",border:`1px solid ${m.r==="user"?"rgba(0,200,150,.25)":"#1e1e2e"}`}}>
              {m.t}
            </div>
          ))}
          <div ref={ref}/>
        </div>
        <div style={{display:"flex",gap:8}}>
          <input value={inp} onChange={e=>sInp(e.target.value)} onKeyDown={e=>e.key==="Enter"&&send()} placeholder="Ask about methodology, MITRE..."/>
          <Btn onClick={send} dis={busy||!apiKey}>SEND</Btn>
        </div>
      </Card>
    </div>
  );
}

// ── Gate ─────────────────────────────────────────────────────────────
function VGate({approvals,setApprovals,addTL}) {
  const decide = (id,status) => {
    setApprovals(p=>p.map(a=>a.id===id?{...a,status,decided_at:now()}:a));
    addTL("approval",`Gate ${status}: ${approvals.find(a=>a.id===id)?.phase||id}`);
  };
  const pending = approvals.filter(a=>a.status==="pending");
  const decided = approvals.filter(a=>a.status!=="pending");
  return (
    <div>
      <Card>
        <Sec t={`PENDING (${pending.length})`}>
          {pending.map(a => (
            <div key={a.id} style={{padding:12,marginBottom:8,background:"#0a0a0f",border:"1px solid #f59e0b",borderRadius:6}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}>
                <span style={{fontSize:12,fontWeight:700,fontFamily:F}}>{a.phase}</span>
              </div>
              <Row label="Target"    value={a.target}/>
              <Row label="Tactic"    value={tacticName(a.tactic)}/>
              <Row label="Requested" value={hmFull(a.ts)}/>
              <div style={{display:"flex",gap:8,marginTop:10}}>
                <Btn onClick={()=>decide(a.id,"approved")} c="#00c896">APPROVE</Btn>
                <Btn onClick={()=>decide(a.id,"rejected")} c="#ef4444" ol>REJECT</Btn>
              </div>
            </div>
          ))}
          {pending.length===0 && <Empty t="No pending approvals"/>}
        </Sec>
      </Card>
      {decided.length>0 && (
        <Card>
          <Sec t="DECIDED">
            {decided.slice(-10).reverse().map(a => (
              <div key={a.id} style={{display:"flex",gap:8,alignItems:"center",padding:"5px 0",borderBottom:"1px solid #252535"}}>
                <span style={{fontSize:9,fontFamily:F,color:a.status==="approved"?"#00c896":"#ef4444",fontWeight:700,minWidth:56}}>{a.status.toUpperCase()}</span>
                <span style={{fontSize:10,fontFamily:F,flex:1}}>{a.phase}</span>
                <span style={{fontSize:9,color:"#64748b",fontFamily:F}}>{hmFull(a.ts)}</span>
              </div>
            ))}
          </Sec>
        </Card>
      )}
    </div>
  );
}

// ── Findings ─────────────────────────────────────────────────────────
function VFind({findings,setFindings,addTL}) {
  const [apiKey,sApiKey] = useState("");
  const [busy,sBusy]     = useState(false);
  const [form,sForm]     = useState({title:"",severity:"high",host:"",cwe:"",description:"",remediation:""});

  const add = () => {
    if(!form.title.trim()) return;
    setFindings(p=>[...p,{...form,id:uid(),ts:now(),status:"open"}]);
    addTL("finding",`Finding: ${form.title}`);
    sForm({title:"",severity:"high",host:"",cwe:"",description:"",remediation:""});
  };

  const aiDoc = async (f) => {
    if(!apiKey) return; sBusy(true);
    const r=await callClaudeJSON(apiKey,"Document this vulnerability as JSON: {description,technical_details,business_impact,remediation,mitre_tactic,mitre_id}.",`Title: ${f.title}\nHost: ${f.host}\nSeverity: ${f.severity}`);
    if(r) setFindings(p=>p.map(x=>x.id===f.id?{...x,...r}:x));
    sBusy(false);
  };

  return (
    <div>
      <Card>
        <Sec t="ADD FINDING"/>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:8}}>
          <div>
            <div style={{fontSize:9,color:"#64748b",fontFamily:F,marginBottom:4}}>TITLE</div>
            <input value={form.title} onChange={e=>sForm(p=>({...p,title:e.target.value}))} placeholder="SQL Injection — Login Form"/>
          </div>
          <div>
            <div style={{fontSize:9,color:"#64748b",fontFamily:F,marginBottom:4}}>HOST</div>
            <input value={form.host} onChange={e=>sForm(p=>({...p,host:e.target.value}))} placeholder="api.example.com"/>
          </div>
          <div>
            <div style={{fontSize:9,color:"#64748b",fontFamily:F,marginBottom:4}}>SEVERITY</div>
            <select value={form.severity} onChange={e=>sForm(p=>({...p,severity:e.target.value}))}>
              {["critical","high","medium","low","info"].map(s=><option key={s} value={s}>{s.toUpperCase()}</option>)}
            </select>
          </div>
          <div>
            <div style={{fontSize:9,color:"#64748b",fontFamily:F,marginBottom:4}}>CWE</div>
            <input value={form.cwe} onChange={e=>sForm(p=>({...p,cwe:e.target.value}))} placeholder="CWE-89"/>
          </div>
        </div>
        <textarea value={form.description} onChange={e=>sForm(p=>({...p,description:e.target.value}))} placeholder="Description..." rows={2} style={{marginBottom:8,resize:"vertical"}}/>
        <textarea value={form.remediation} onChange={e=>sForm(p=>({...p,remediation:e.target.value}))} placeholder="Remediation..." rows={2} style={{marginBottom:8,resize:"vertical"}}/>
        <div style={{display:"flex",gap:8,alignItems:"center"}}>
          <Btn onClick={add} dis={!form.title.trim()}>ADD FINDING</Btn>
          <input value={apiKey} onChange={e=>sApiKey(e.target.value)} placeholder="API key for AI doc" type="password" style={{flex:1}}/>
        </div>
      </Card>
      {["critical","high","medium","low","info"].map(sv => {
        const group = findings.filter(f=>f.severity===sv);
        if(!group.length) return null;
        return (
          <div key={sv}>
            <div style={{fontSize:9,fontWeight:700,color:SC[sv],fontFamily:F,letterSpacing:2,marginBottom:6,textTransform:"uppercase"}}>── {sv} ({group.length})</div>
            {group.map(f => (
              <Card key={f.id} bc={SC[sv]+"44"}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}>
                  <div>
                    <div style={{fontSize:13,fontWeight:700,fontFamily:F}}>{f.title}</div>
                    <div style={{fontSize:10,color:"#64748b",fontFamily:F}}>{f.host} · {f.cwe||"CWE unknown"}</div>
                  </div>
                  <div style={{display:"flex",gap:6}}>
                    <Badge s={f.severity}/>
                    <Btn sm ol c="#00c896" onClick={()=>aiDoc(f)} dis={busy||!apiKey}>AI DOC</Btn>
                    <Btn sm ol c="#ef4444" onClick={()=>setFindings(p=>p.filter(x=>x.id!==f.id))}>×</Btn>
                  </div>
                </div>
                {f.description && <div style={{fontSize:11,fontFamily:F,lineHeight:1.5,marginBottom:6}}>{f.description}</div>}
                {f.remediation && <div style={{fontSize:10,fontFamily:F,color:"#00c896",padding:"6px 8px",background:"rgba(0,200,150,.06)",borderRadius:4}}>Remediation: {f.remediation}</div>}
              </Card>
            ))}
          </div>
        );
      })}
      {findings.length===0 && <Empty t="No findings documented"/>}
    </div>
  );
}

// ── Evidence ─────────────────────────────────────────────────────────
function VEvid({evidence}) {
  const [expanded,sExp] = useState(null);
  const [verified,sVer] = useState(null);
  const verify = async () => {
    if(evidence.length===0) { sVer({ok:true,msg:"No records"}); return; }
    const sorted=[...evidence].sort((a,b)=>a.seq-b.seq);
    for(let i=1;i<sorted.length;i++) {
      if(sorted[i].prevHash!==sorted[i-1].hash) { sVer({ok:false,msg:`Chain broken at #${sorted[i].seq}`}); return; }
    }
    sVer({ok:true,msg:`Chain verified — ${evidence.length} records intact`});
  };
  return (
    <div>
      <Card>
        <Sec t="MERKLE EVIDENCE CHAIN" action={<Btn sm onClick={verify}>VERIFY</Btn>}/>
        {verified && (
          <div style={{padding:"8px 12px",borderRadius:4,marginBottom:12,fontSize:11,fontFamily:F,background:verified.ok?"rgba(0,200,150,.08)":"rgba(239,68,68,.08)",border:`1px solid ${verified.ok?"#00c896":"#ef4444"}`,color:verified.ok?"#00c896":"#ef4444"}}>
            {verified.ok?"✓":"✗"} {verified.msg}
          </div>
        )}
        {evidence.length===0 && <Empty t="No evidence records — log phases in Workbench"/>}
        {[...evidence].sort((a,b)=>b.seq-a.seq).map(e => (
          <div key={e.id} style={{marginBottom:8,background:"#0a0a0f",border:"1px solid #1e1e2e",borderRadius:4}}>
            <div onClick={()=>sExp(expanded===e.id?null:e.id)} style={{display:"flex",gap:8,alignItems:"center",padding:"8px 10px",cursor:"pointer"}}>
              <span style={{fontSize:10,fontWeight:700,color:"#64748b",fontFamily:F,minWidth:24}}>#{e.seq}</span>
              <span style={{fontSize:10,fontFamily:F,flex:1}}>{e.phase}</span>
              <span style={{fontSize:9,color:"#00c896",fontFamily:F}}>{e.target}</span>
              <span style={{fontSize:8,color:"#64748b",fontFamily:F}}>{hms(e.ts)}</span>
              <Badge s={e.tactic} sm/>
            </div>
            {expanded===e.id && (
              <div style={{padding:"8px 12px",borderTop:"1px solid #1e1e2e"}}>
                <Row label="Hash" value={e.hash?.slice(0,16)+"…"} vc="#00c896"/>
                <Row label="Prev" value={e.prevHash==="GENESIS"?"GENESIS":e.prevHash?.slice(0,16)+"…"} vc="#64748b"/>
                <Row label="Tool" value={e.tool}/>
              </div>
            )}
          </div>
        ))}
      </Card>
    </div>
  );
}

// ── Tools ─────────────────────────────────────────────────────────────
function VTools({tools,setTools}) {
  const slots = [...new Set(tools.map(t=>t.slot))];
  return (
    <div>
      {slots.map(slot => (
        <Card key={slot}>
          <Sec t={slot.toUpperCase()}>
            {tools.filter(t=>t.slot===slot).map(t => (
              <div key={t.name} style={{display:"flex",gap:8,alignItems:"center",padding:"6px 0",borderBottom:"1px solid #252535"}}>
                <button onClick={()=>setTools(p=>p.map(x=>x.name===t.name?{...x,on:!x.on}:x))} style={{width:32,height:16,borderRadius:8,background:t.on?"#00c896":"#1e1e2e",border:"none",cursor:"pointer",position:"relative",flexShrink:0}}>
                  <div style={{width:12,height:12,borderRadius:"50%",background:"#fff",position:"absolute",top:2,left:t.on?18:2,transition:"left .15s"}}/>
                </button>
                <div style={{flex:1}}>
                  <span style={{fontSize:11,fontWeight:700,fontFamily:F}}>{t.name}</span>
                  <span style={{fontSize:9,color:"#64748b",fontFamily:F}}> v{t.ver} · {t.desc}</span>
                </div>
                <span style={{fontSize:8,fontFamily:F,fontWeight:700,color:t.footprint==="high"?"#ef4444":t.footprint==="medium"?"#f59e0b":"#00c896"}}>{t.footprint?.toUpperCase()}</span>
              </div>
            ))}
          </Sec>
        </Card>
      ))}
    </div>
  );
}

// ── CVSS ─────────────────────────────────────────────────────────────
function VCvss() {
  const M = {
    AV:{n:"Attack Vector",      v:{N:{n:"Network",v:0.85},A:{n:"Adjacent",v:0.62},L:{n:"Local",v:0.55},P:{n:"Physical",v:0.20}}},
    AC:{n:"Attack Complexity",  v:{L:{n:"Low",v:0.77},H:{n:"High",v:0.44}}},
    PR:{n:"Privileges Required",v:{N:{n:"None",v:0.85},L:{n:"Low",v:0.62},H:{n:"High",v:0.27}}},
    UI:{n:"User Interaction",   v:{N:{n:"None",v:0.85},R:{n:"Required",v:0.62}}},
    S: {n:"Scope",              v:{U:{n:"Unchanged"},C:{n:"Changed"}}},
    C: {n:"Confidentiality",    v:{N:{n:"None",v:0},L:{n:"Low",v:0.22},H:{n:"High",v:0.56}}},
    I: {n:"Integrity",          v:{N:{n:"None",v:0},L:{n:"Low",v:0.22},H:{n:"High",v:0.56}}},
    A: {n:"Availability",       v:{N:{n:"None",v:0},L:{n:"Low",v:0.22},H:{n:"High",v:0.56}}},
  };
  const [sel,sSel] = useState({AV:"N",AC:"L",PR:"N",UI:"N",S:"U",C:"N",I:"N",A:"N"});
  const calc = () => {
    const av=M.AV.v[sel.AV].v, ac=M.AC.v[sel.AC].v;
    let pr=M.PR.v[sel.PR].v;
    if(sel.S==="C"&&sel.PR==="L") pr=0.68;
    if(sel.S==="C"&&sel.PR==="H") pr=0.50;
    const ui=M.UI.v[sel.UI].v, c=M.C.v[sel.C].v, i=M.I.v[sel.I].v, a=M.A.v[sel.A].v;
    const iss=1-((1-c)*(1-i)*(1-a));
    const impact=sel.S==="U"?6.42*iss:7.52*(iss-0.029)-3.25*Math.pow(iss-0.02,15);
    const exploit=8.22*av*ac*pr*ui;
    if(impact<=0) return 0;
    return Math.ceil(Math.min(sel.S==="U"?impact+exploit:1.08*(impact+exploit),10)*10)/10;
  };
  const score=calc(), sev=score===0?"None":score<4?"Low":score<7?"Medium":score<9?"High":"Critical";
  const col=score===0?"#64748b":(SC[sev.toLowerCase()]||"#64748b");
  return (
    <Card>
      <div style={{textAlign:"center",marginBottom:20}}>
        <div style={{fontSize:56,fontWeight:700,fontFamily:F,color:col}}>{score.toFixed(1)}</div>
        <div style={{fontSize:14,fontWeight:700,fontFamily:F,color:col,letterSpacing:2}}>{sev.toUpperCase()}</div>
        <div style={{fontSize:8,color:"#64748b",fontFamily:F,marginTop:4}}>CVSS v3.1</div>
      </div>
      {Object.entries(M).map(([k,m]) => (
        <Sec key={k} t={m.n}>
          <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
            {Object.entries(m.v).map(([vk,vv]) => (
              <button key={vk} onClick={()=>sSel(p=>({...p,[k]:vk}))} style={{padding:"5px 12px",borderRadius:4,background:sel[k]===vk?col:"transparent",color:sel[k]===vk?"#000":"#64748b",border:`1px solid ${sel[k]===vk?col:"#1e1e2e"}`,fontFamily:F,fontSize:10,cursor:"pointer",fontWeight:sel[k]===vk?700:400}}>
                {vv.n}
              </button>
            ))}
          </div>
        </Sec>
      ))}
    </Card>
  );
}

// ── Report ────────────────────────────────────────────────────────────
function VReport({op,findings,evidence}) {
  const [apiKey,sApiKey]   = useState("");
  const [report,sReport]   = useState("");
  const [busy,sBusy]       = useState(false);
  const [name,sName]       = useState("");
  const [certs,sCerts]     = useState("");
  const [attested,sAttest] = useState(false);
  const gen = async () => {
    if(!apiKey) return; sBusy(true);
    const t=await callClaude(apiKey,"Write a professional penetration test report (PTES methodology). Be factual. No offensive techniques.",`Op: ${JSON.stringify(op.operation)}\nFindings: ${JSON.stringify(findings.map(f=>({title:f.title,severity:f.severity,host:f.host})))}\nEvidence: ${evidence.length} records`,3000);
    sReport(t); sBusy(false);
  };
  return (
    <div>
      <Card>
        <Sec t="GENERATE REPORT"/>
        <div style={{display:"flex",gap:8,marginBottom:12}}>
          <input value={apiKey} onChange={e=>sApiKey(e.target.value)} placeholder="API key" type="password" style={{flex:1}}/>
          <Btn onClick={gen} dis={busy||!apiKey}>{busy?"GENERATING…":"GENERATE"}</Btn>
        </div>
        {report ? <pre style={{fontSize:11,fontFamily:F,lineHeight:1.6,whiteSpace:"pre-wrap",maxHeight:400,overflowY:"auto"}}>{report}</pre> : <Empty t="Generate report to see output"/>}
      </Card>
      <Card bc={attested?"#00c896":"#1e1e2e"}>
        <Sec t="PRACTITIONER ATTESTATION"/>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:12}}>
          <div>
            <div style={{fontSize:9,color:"#64748b",fontFamily:F,marginBottom:4}}>NAME</div>
            <input value={name} onChange={e=>sName(e.target.value)} placeholder="Full name"/>
          </div>
          <div>
            <div style={{fontSize:9,color:"#64748b",fontFamily:F,marginBottom:4}}>CERTIFICATIONS</div>
            <input value={certs} onChange={e=>sCerts(e.target.value)} placeholder="OSCP, CEH"/>
          </div>
        </div>
        <label style={{display:"flex",gap:8,alignItems:"center",cursor:"pointer",marginBottom:12,fontSize:11,fontFamily:F}}>
          <input type="checkbox" checked={attested} onChange={e=>sAttest(e.target.checked)} style={{width:"auto"}}/>
          I confirm this assessment was performed within authorized scope.
        </label>
        {attested&&name && <div style={{padding:12,background:"rgba(0,200,150,.06)",border:"1px solid #00c896",borderRadius:4,fontSize:11,fontFamily:F,color:"#00c896"}}>✓ Attested by {name} {certs?`(${certs})`:""}— {new Date().toLocaleDateString()}</div>}
      </Card>
    </div>
  );
}

// ── Knowledge ─────────────────────────────────────────────────────────
function VKB({knowledge,setKnowledge}) {
  const [apiKey,sApiKey] = useState("");
  const [busy,sBusy]     = useState(false);
  const [text,sText]     = useState("");
  const QC = {pinned:"#f59e0b",good:"#00c896",unreviewed:"#64748b"};
  const add = () => {
    if(!text.trim()) return;
    setKnowledge(p=>[...p,{id:uid(),ts:now(),content:text,quality:"unreviewed",source:"manual"}]);
    sText("");
  };
  const aiPop = async () => {
    if(!apiKey) return; sBusy(true);
    const r=await callClaudeJSON(apiKey,"Generate 3 security knowledge entries about remediation and documentation. Return JSON array: [{content}].","Security knowledge entries.");
    if(Array.isArray(r)) setKnowledge(p=>[...p,...r.map(x=>({id:uid(),ts:now(),content:x.content,quality:"unreviewed",source:"ai"}))]);
    sBusy(false);
  };
  return (
    <div>
      <Card>
        <Sec t="ADD KNOWLEDGE"/>
        <textarea value={text} onChange={e=>sText(e.target.value)} placeholder="Document a pattern, remediation, or note..." rows={3} style={{marginBottom:8,resize:"vertical"}}/>
        <div style={{display:"flex",gap:8}}>
          <Btn onClick={add} dis={!text.trim()}>ADD</Btn>
          <input value={apiKey} onChange={e=>sApiKey(e.target.value)} placeholder="API key" type="password" style={{flex:1}}/>
          <Btn sm onClick={aiPop} dis={busy||!apiKey}>{busy?"…":"AI POPULATE"}</Btn>
        </div>
      </Card>
      {["pinned","good","unreviewed"].map(q => {
        const group=knowledge.filter(k=>k.quality===q);
        if(!group.length) return null;
        return (
          <div key={q}>
            <div style={{fontSize:9,fontWeight:700,color:QC[q],fontFamily:F,letterSpacing:2,marginBottom:6,textTransform:"uppercase"}}>── {q} ({group.length})</div>
            {group.map(k => (
              <Card key={k.id}>
                <div style={{display:"flex",justifyContent:"space-between",gap:8}}>
                  <div style={{fontSize:11,fontFamily:F,flex:1,lineHeight:1.5}}>{k.content}</div>
                  <div style={{display:"flex",gap:4,flexShrink:0}}>
                    <Btn sm ol c="#f59e0b" onClick={()=>setKnowledge(p=>p.map(x=>x.id===k.id?{...x,quality:"pinned"}:x))}>📌</Btn>
                    <Btn sm ol c="#00c896" onClick={()=>setKnowledge(p=>p.map(x=>x.id===k.id?{...x,quality:"good"}:x))}>✓</Btn>
                    <Btn sm ol c="#ef4444" onClick={()=>setKnowledge(p=>p.filter(x=>x.id!==k.id))}>×</Btn>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        );
      })}
      {knowledge.length===0 && <Empty t="No knowledge entries"/>}
    </div>
  );
}

// ── Integrations ──────────────────────────────────────────────────────
function VInteg({findings,evidence,op,setFindings,addTL}) {
  const [apiKey,sApiKey] = useState("");
  const [busy,sBusy]     = useState(false);
  const exportJSON = () => {
    const blob=new Blob([JSON.stringify({op,findings,evidence,exported_at:now()},null,2)],{type:"application/json"});
    const a=document.createElement("a"); a.href=URL.createObjectURL(blob); a.download=`trident-export-${Date.now()}.json`; a.click();
    addTL("export","Exported JSON");
  };
  const simNessus = async () => {
    if(!apiKey) return; sBusy(true);
    const r=await callClaudeJSON(apiKey,"Simulate a Nessus scan. Return JSON array: [{title,severity,host,cwe,description,remediation}]. severity: critical|high|medium|low|info.",`Perimeter: ${JSON.stringify(op.perimeter)}`);
    if(Array.isArray(r)) { setFindings(p=>[...p,...r.map(f=>({...f,id:uid(),ts:now(),status:"open",source:"nessus"}))]); addTL("import",`Imported ${r.length} findings`); }
    sBusy(false);
  };
  return (
    <div>
      <Card><Sec t="EXPORT"/><div style={{display:"flex",gap:8}}><Btn onClick={exportJSON}>EXPORT JSON</Btn></div></Card>
      <Card>
        <Sec t="IMPORT (SIMULATED)"/>
        <div style={{display:"flex",gap:8}}>
          <input value={apiKey} onChange={e=>sApiKey(e.target.value)} placeholder="API key" type="password" style={{flex:1}}/>
          <Btn onClick={simNessus} dis={busy||!apiKey}>{busy?"…":"SIMULATE NESSUS"}</Btn>
        </div>
      </Card>
    </div>
  );
}

// ── Timeline ──────────────────────────────────────────────────────────
function VTL({timeline}) {
  return (
    <Card>
      <Sec t="ACTIVITY TIMELINE"/>
      {timeline.length===0 && <Empty t="No activity yet"/>}
      <div style={{position:"relative"}}>
        <div style={{position:"absolute",left:7,top:0,bottom:0,width:1,background:"#1e1e2e"}}/>
        {[...timeline].reverse().map(e => (
          <div key={e.id} style={{display:"flex",gap:12,marginBottom:10,paddingLeft:24,position:"relative"}}>
            <div style={{position:"absolute",left:4,top:5,width:8,height:8,borderRadius:"50%",background:TC[e.type]||"#64748b"}}/>
            <div>
              <div style={{fontSize:11,fontFamily:F}}>{e.text}</div>
              <div style={{fontSize:8,color:"#64748b",fontFamily:F}}>{hmFull(e.ts)} · {e.type?.toUpperCase()}</div>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

// ── Settings ──────────────────────────────────────────────────────────
function VSet({stealthVal,setStealthVal,mode,setMode}) {
  const sp = stealthParams(stealthVal);
  const pe = Object.entries(STEALTH_PRESETS).find(([,p])=>Math.abs(stealthVal-p.val)<10);
  const pn = pe?.[0]||`${stealthVal}%`, pc = pe?.[1]?.color||"#64748b";
  return (
    <div>
      <Card bc="#f59e0b44">
        <Sec t="⚠ API DATA WARNING"/>
        <div style={{fontSize:11,fontFamily:F,color:"#f59e0b",lineHeight:1.6}}>When using AI features, operation data is sent to Anthropic. Do not use with classified or sensitive data.</div>
      </Card>
      <Card>
        <Sec t={`STEALTH — ${pn.toUpperCase()}`}/>
        <input type="range" min={0} max={100} value={stealthVal} onChange={e=>setStealthVal(+e.target.value)} style={{width:"100%",marginBottom:12,accentColor:pc}}/>
        <div style={{display:"flex",gap:6,marginBottom:12}}>
          {Object.entries(STEALTH_PRESETS).map(([k,p]) => (
            <button key={k} onClick={()=>setStealthVal(p.val)} style={{flex:1,padding:"6px 0",borderRadius:4,background:pn===k?p.color:"transparent",color:pn===k?"#000":"#64748b",border:`1px solid ${pn===k?p.color:"#1e1e2e"}`,fontFamily:F,fontSize:9,cursor:"pointer",fontWeight:700}}>
              {k.toUpperCase()}
            </button>
          ))}
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:8}}>
          {[["Delay",`${sp.delay}ms`],["Concurrent",sp.concurrent],["Jitter",`${sp.jitter}%`],["Tool Rotation",sp.toolRotation?"on":"off"],["DNS",sp.dnsStyle],["TLS Rotation",sp.tlsRotation?"on":"off"]].map(([l,v]) => (
            <div key={l} style={{padding:"8px 10px",background:"#0a0a0f",borderRadius:4,border:"1px solid #1e1e2e"}}>
              <div style={{fontSize:8,color:"#64748b",fontFamily:F}}>{l.toUpperCase()}</div>
              <div style={{fontSize:12,fontWeight:700,fontFamily:F,marginTop:2}}>{v}</div>
            </div>
          ))}
        </div>
      </Card>
      <Card>
        <Sec t="GATE MODE"/>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
          {Object.entries(GATE_MODES).map(([k,m]) => (
            <button key={k} onClick={()=>setMode(k)} style={{padding:12,borderRadius:6,cursor:"pointer",textAlign:"left",border:`2px solid ${mode===k?m.color:"#1e1e2e"}`,background:mode===k?`${m.color}18`:"#12121a"}}>
              <div style={{fontSize:11,fontWeight:700,color:m.color,fontFamily:F}}>{m.icon} {m.name}</div>
              <div style={{fontSize:9,color:"#64748b",fontFamily:F,marginTop:4}}>{m.desc}</div>
            </button>
          ))}
        </div>
      </Card>
    </div>
  );
}

// ── App Root ──────────────────────────────────────────────────────────
export default function App() {
  const [view,sView]           = useState("dashboard");
  const [op,sOp]               = useState(JSON.parse(JSON.stringify(EMPTY_OP)));
  const [approvals,sAppr]      = useState([]);
  const [findings,sFind]       = useState([]);
  const [violations,sViol]     = useState([]);
  const [actions,sAct]         = useState([]);
  const [evidence,sEvid]       = useState([]);
  const [tools,sTools]         = useState([...TOOL_SLOTS]);
  const [knowledge,sKB]        = useState([]);
  const [timeline,sTL]         = useState([]);
  const [stealthVal,sStealthVal] = useState(35);
  const [mode,sMode]           = useState("supervised");

  useEffect(() => {
    (async () => {
      try {
        const r = await window.storage.get("trident-v5");
        if (r) {
          const d = JSON.parse(r.value);
          if(d.op)         sOp(d.op);
          if(d.findings)   sFind(d.findings);
          if(d.evidence)   sEvid(d.evidence);
          if(d.actions)    sAct(d.actions);
          if(d.approvals)  sAppr(d.approvals);
          if(d.violations) sViol(d.violations);
          if(d.knowledge)  sKB(d.knowledge);
          if(d.timeline)   sTL(d.timeline);
          if(d.tools)      sTools(d.tools);
          if(d.stealthVal!=null) sStealthVal(d.stealthVal);
          if(d.mode)       sMode(d.mode);
        }
      } catch {}
    })();
  }, []);

  useEffect(() => {
    const t = setTimeout(() => {
      (async () => {
        try { await window.storage.set("trident-v5",JSON.stringify({op,findings,evidence,actions,approvals,violations,knowledge,timeline,tools,stealthVal,mode})); }
        catch {}
      })();
    }, 1000);
    return () => clearTimeout(t);
  }, [op,findings,evidence,actions,approvals,violations,knowledge,timeline,tools,stealthVal,mode]);

  const addTL = useCallback((type,text) => { sTL(p=>[...p,{id:uid(),type,text,ts:now()}]); }, []);

  const reset = () => {
    if(!confirm("Reset all operation data?")) return;
    sOp(JSON.parse(JSON.stringify(EMPTY_OP)));
    sAppr([]); sFind([]); sViol([]); sAct([]); sEvid([]);
    sKB([]); sTL([]); sTools([...TOOL_SLOTS]); sStealthVal(35); sMode("supervised");
    window.storage.delete("trident-v5").catch(()=>{});
  };

  const pc = approvals.filter(a=>a.status==="pending").length;
  const pn = Object.entries(STEALTH_PRESETS).find(([,p])=>Math.abs(stealthVal-p.val)<10)?.[0]||`${stealthVal}%`;

  const nav = [
    {id:"dashboard",  ic:"◈", l:"DASHBOARD"},
    {id:"scope",      ic:"◎", l:"PERIMETER"},
    {id:"map",        ic:"🗺", l:"NET MAP"},
    {id:"workbench",  ic:"⚡", l:"WORKBENCH"},
    {id:"gate",       ic:"⏳", l:"GATE",         n:pc},
    {id:"findings",   ic:"🔍", l:"FINDINGS",     n:findings.length},
    {id:"evidence",   ic:"🔗", l:"EVIDENCE",     n:evidence.length},
    {id:"tools",      ic:"🔧", l:"TOOLS"},
    {id:"cvss",       ic:"📊", l:"CVSS"},
    {id:"report",     ic:"📄", l:"REPORT"},
    {id:"knowledge",  ic:"🧠", l:"KNOWLEDGE"},
    {id:"integrations",ic:"🔌",l:"INTEGRATIONS"},
    {id:"timeline",   ic:"📋", l:"TIMELINE",     n:timeline.length},
    {id:"settings",   ic:"⚙", l:"SETTINGS"},
  ];

  return (
    <>
      <style>{CSS}</style>
      <div style={{display:"flex",height:"100vh",overflow:"hidden",fontFamily:F}}>
        <div style={{width:160,background:"#12121a",borderRight:"1px solid #1e1e2e",display:"flex",flexDirection:"column",flexShrink:0}}>
          <div style={{padding:"14px 12px",borderBottom:"1px solid #1e1e2e"}}>
            <div style={{fontSize:14,fontWeight:700,color:"#00c896",fontFamily:F,letterSpacing:2}}>◈ TRIDENT</div>
            <div style={{fontSize:8,color:"#64748b",fontFamily:F,marginTop:2}}>{op.operation.name||"No operation"}</div>
          </div>
          <div style={{flex:1,overflowY:"auto",padding:"6px 0"}}>
            {nav.map(n => (
              <button key={n.id} onClick={()=>sView(n.id)} style={{width:"100%",display:"flex",alignItems:"center",gap:7,padding:"7px 12px",background:"transparent",border:"none",borderLeft:view===n.id?"2px solid #00c896":"2px solid transparent",color:view===n.id?"#e2e8f0":"#64748b",fontFamily:F,fontSize:10,cursor:"pointer",textAlign:"left"}}>
                <span style={{fontSize:11,width:14,textAlign:"center"}}>{n.ic}</span>
                <span style={{flex:1}}>{n.l}</span>
                {(n.n||0)>0 && <span style={{background:n.id==="gate"&&pc>0?"#ef4444":"#252535",color:n.id==="gate"&&pc>0?"#fff":"#64748b",fontSize:7,padding:"1px 4px",borderRadius:6,fontWeight:700}}>{n.n}</span>}
              </button>
            ))}
          </div>
          <div style={{padding:"8px 12px",borderTop:"1px solid #1e1e2e"}}>
            <div style={{display:"flex",alignItems:"center",gap:5,fontSize:8,fontFamily:F,color:"#64748b",marginBottom:4}}>
              <div style={{width:5,height:5,borderRadius:"50%",background:GATE_MODES[mode].color}}/>
              {GATE_MODES[mode].name}
            </div>
            <div style={{fontSize:8,fontFamily:F,color:"#64748b",marginBottom:6}}>Stealth: {pn.toUpperCase()}</div>
            <button onClick={reset} style={{width:"100%",padding:"4px 0",background:"transparent",border:"1px solid #1e1e2e",borderRadius:3,color:"#64748b",fontFamily:F,fontSize:8,cursor:"pointer"}}>RESET</button>
          </div>
        </div>
        <div style={{flex:1,padding:"20px 24px",overflowY:"auto"}}>
          {view==="dashboard"    && <VDash op={op} approvals={approvals} findings={findings} violations={violations} actions={actions} evidence={evidence} timeline={timeline}/>}
          {view==="scope"        && <VScope op={op} setOp={sOp}/>}
          {view==="map"          && <VMap op={op} actions={actions} violations={violations}/>}
          {view==="workbench"    && <VWorkbench op={op} mode={mode} setActions={sAct} setViolations={sViol} setEvidence={sEvid} addTL={addTL} actions={actions} evidence={evidence}/>}
          {view==="gate"         && <VGate approvals={approvals} setApprovals={sAppr} addTL={addTL}/>}
          {view==="findings"     && <VFind findings={findings} setFindings={sFind} addTL={addTL}/>}
          {view==="evidence"     && <VEvid evidence={evidence}/>}
          {view==="tools"        && <VTools tools={tools} setTools={sTools}/>}
          {view==="cvss"         && <VCvss/>}
          {view==="report"       && <VReport op={op} findings={findings} evidence={evidence}/>}
          {view==="knowledge"    && <VKB knowledge={knowledge} setKnowledge={sKB}/>}
          {view==="integrations" && <VInteg findings={findings} evidence={evidence} op={op} setFindings={sFind} addTL={addTL}/>}
          {view==="timeline"     && <VTL timeline={timeline}/>}
          {view==="settings"     && <VSet stealthVal={stealthVal} setStealthVal={sStealthVal} mode={mode} setMode={sMode}/>}
        </div>
      </div>
    </>
  );
}
