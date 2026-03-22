import { useState, useEffect, useRef, useCallback } from "react";

// ═══════════════════════════════════════════════════════════════════════
// TRIDENT COMMAND CENTER v5
// Red team assessment documentation platform
// AI role: assessment advisor + documentation (never offensive)
// 14 views · Merkle Evidence Chain · PerimeterGuard · Persistent Storage
// ═══════════════════════════════════════════════════════════════════════
// NOTE: PerimeterGuard is kept inline for artifact compatibility.
// Canonical package: github.com/diydigitaldreams/perimeterguard
// Production: import { PerimeterGuard } from "perimeterguard"
// ═══════════════════════════════════════════════════════════════════════

const uid = () => crypto.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2,9)}`;
const digest = async (t) => {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(t));
  return Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,"0")).join("");
};
const now = () => new Date().toISOString();
const MODEL_ID = "claude-sonnet-4-20250514";
const isValidCIDR = (s) => { const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/); return m && [1,2,3,4].every(i => +m[i] >= 0 && +m[i] <= 255) && +m[5] >= 0 && +m[5] <= 32; };
const isValidHost = (s) => /^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/.test(s) || /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
const isValidDomain = (s) => /^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/.test(s);
const isValidApiKey = (k) => typeof k === "string" && (k.startsWith("sk-ant-") || k.startsWith("sk-"));
const isValidCWE = (s) => !s || /^CWE-\d+$/i.test(s);
const sanitizeForPrompt = (s, max = 500) => String(s).slice(0, max).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, "");
const hms = (i) => { try { return new Date(i).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"}); } catch{return"—";}};
const hmFull = (i) => { try { return new Date(i).toLocaleString([],{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"}); } catch{return"—";}};

// MITRE ATT&CK Enterprise Tactics — https://attack.mitre.org
const TACTICS = [
  {id:"TA0043",name:"Reconnaissance",    short:"recon"},
  {id:"TA0042",name:"Resource Development",short:"resource_dev"},
  {id:"TA0001",name:"Initial Access",    short:"initial_access"},
  {id:"TA0002",name:"Execution",         short:"execution"},
  {id:"TA0003",name:"Persistence",       short:"persistence"},
  {id:"TA0004",name:"Privilege Escalation",short:"priv_esc"},
  {id:"TA0005",name:"Defense Evasion",   short:"def_evasion"},
  {id:"TA0006",name:"Credential Access", short:"cred_access"},
  {id:"TA0007",name:"Discovery",         short:"discovery"},
  {id:"TA0008",name:"Lateral Movement",  short:"lateral"},
  {id:"TA0009",name:"Collection",        short:"collection"},
  {id:"TA0011",name:"Command and Control",short:"c2"},
  {id:"TA0010",name:"Exfiltration",      short:"exfil"},
  {id:"TA0040",name:"Impact",            short:"impact"},
];
const tacticName = (s) => TACTICS.find(t=>t.short===s||t.id===s)?.name || s;
const tacticId   = (s) => TACTICS.find(t=>t.short===s||t.id===s)?.id   || "";

const GATE_MODES = {
  observer:   {name:"OBSERVER",  color:"#ef4444",desc:"Read-only — no execution allowed",   icon:"📡"},
  supervised: {name:"SUPERVISED",color:"#f59e0b",desc:"Auto-recon, gate exploit + lateral",  icon:"👁"},
  controlled: {name:"CONTROLLED",color:"#f97316",desc:"Every action requires sign-off",      icon:"🔒"},
  autonomous: {name:"AUTONOMOUS",color:"#22c55e",desc:"No gates — lab & CTF use only",       icon:"⚡"},
};

const STEALTH_PRESETS = {
  blitz:      {val:0,  color:"#ef4444",desc:"Zero delay, max parallel"},
  methodical: {val:35, color:"#f59e0b",desc:"Moderate pacing, some evasion"},
  whisper:    {val:70, color:"#22c55e",desc:"Slow pacing, fingerprint rotation"},
  ghost:      {val:100,color:"#8b5cf6",desc:"Maximum evasion, minimum footprint"},
};
const stealthParams = (val) => {
  const v = Math.max(0,Math.min(100,val));
  return {delay:Math.round(v*80),concurrent:Math.max(1,Math.round(50-v*0.48)),jitter:Math.round(v*30),toolRotation:v>40,dnsStyle:v>60?"doh":"standard",tlsRotation:v>50};
};

const EMPTY_OP = {
  operation:{name:"",id:"",start:"",end:"",classification:"",roe_url:"",client_poc:"",abort_contact:""},
  perimeter:{cidrs:[],hosts:[],domains:[],ports:{tcp:[],udp:[]}},
  no_touch:{hosts:[],cidrs:[],restricted_periods:[]},
  constraints:{max_parallel:5,blocked_tactics:["impact","exfil"],gated_tactics:["initial_access","execution","priv_esc","lateral","cred_access"]},
};

const TOOL_SLOTS = [
  {slot:"port-scan", name:"rustscan",    ver:"2.3", desc:"Fast port discovery with adaptive timing",          tactics:["recon","discovery"],               footprint:"medium",on:true,core:true},
  {slot:"port-scan", name:"naabu",       ver:"2.3", desc:"SYN/CONNECT scanner by ProjectDiscovery",          tactics:["recon"],                            footprint:"low",   on:true,core:true},
  {slot:"web-fuzz",  name:"feroxbuster", ver:"2.10",desc:"Recursive content discovery with smart filtering", tactics:["discovery"],                        footprint:"medium",on:true,core:true},
  {slot:"web-fuzz",  name:"gobuster",    ver:"3.6", desc:"Directory/DNS/vhost brute-forcing",                tactics:["discovery"],                        footprint:"medium",on:true,core:true},
  {slot:"dns-enum",  name:"dnsx",        ver:"1.2", desc:"Multi-purpose DNS toolkit with wildcard filtering", tactics:["recon"],                            footprint:"low",   on:true,core:true},
  {slot:"subdomain", name:"subfinder",   ver:"2.6", desc:"Passive subdomain enumeration from 40+ sources",   tactics:["recon"],                            footprint:"low",   on:true,core:true},
  {slot:"vuln-scan", name:"nuclei",      ver:"3.3", desc:"Template-driven vulnerability detection",          tactics:["discovery","initial_access"],       footprint:"medium",on:true,core:true},
  {slot:"exploit",   name:"sliver",      ver:"1.5", desc:"Adversary emulation framework",                    tactics:["execution","lateral","c2"],         footprint:"high",  on:true,core:true},
  {slot:"ad-recon",  name:"certipy",     ver:"4.8", desc:"Active Directory certificate abuse toolkit",       tactics:["cred_access","priv_esc"],           footprint:"low",   on:true,core:true},
  {slot:"ad-recon",  name:"crackmapexec",ver:"5.4", desc:"Swiss army knife for AD/network pentesting",       tactics:["lateral","cred_access","discovery"],footprint:"medium",on:true,core:true},
  {slot:"tunnel",    name:"ligolo-ng",   ver:"0.6", desc:"Tunneling/pivoting with TUN interface",            tactics:["lateral","c2"],                     footprint:"low",   on:true,core:true},
  {slot:"http",      name:"httpx",       ver:"1.6", desc:"HTTP toolkit with tech detection",                 tactics:["recon","discovery"],                footprint:"low",   on:true,core:true},
];

const SC = {critical:"#ef4444",high:"#f97316",medium:"#f59e0b",low:"#22c55e",info:"#3b82f6"};
const RC = {critical:"#ef4444",high:"#f97316",medium:"#f59e0b",low:"#22c55e"};
const TC = {action:"#22c55e",plan:"#3b82f6",approval:"#f59e0b",violation:"#ef4444",finding:"#f97316",import:"#8b5cf6",export:"#06b6d4",knowledge:"#a78bfa"};

const storage = {
  get: async (k) => { try { return await window.storage?.get(k); } catch { try { const v = localStorage.getItem(k); return v ? { value: v } : null; } catch { return null; } } },
  set: async (k, v) => { try { await window.storage?.set(k, v); } catch { try { localStorage.setItem(k, v); } catch {} } },
  delete: async (k) => { try { await window.storage?.delete(k); } catch { try { localStorage.removeItem(k); } catch {} } }
};

// ─── PERIMETERGUARD (inline — canonical: github.com/diydigitaldreams/perimeterguard) ──
function escapeRegex(s){return s.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");}
function normalizeTarget(t){return t.replace(/^https?:\/\//,"").split("/")[0].split(":")[0];}
// NOTE: IPv4 only. IPv6 CIDR support is out of scope for single-file artifact.
function matchCIDR(host,cidr){
  const parts=cidr.split("/");if(parts.length!==2)return host===cidr;
  const mask=parseInt(parts[1],10);if(isNaN(mask)||mask<0||mask>32)return false;
  const co=parts[0].split(".").map(Number),ho=host.split(".").map(Number);
  if(co.length!==4||ho.length!==4)return false;
  if(co.some(o=>isNaN(o)||o<0||o>255)||ho.some(o=>isNaN(o)||o<0||o>255))return false;
  const ci=((co[0]<<24)|(co[1]<<16)|(co[2]<<8)|co[3])>>>0;
  const hi=((ho[0]<<24)|(ho[1]<<16)|(ho[2]<<8)|ho[3])>>>0;
  const mi=mask===0?0:((~0<<(32-mask))>>>0);
  return(ci&mi)===(hi&mi);
}
function matchHost(h,p){if(!p.includes("*"))return h===p;return new RegExp("^"+p.split("*").map(escapeRegex).join("[^.]*")+"$").test(h);}
function matchDomain(h,d){if(d.startsWith("*."))return h.endsWith("."+d.slice(2))||h===d.slice(2);return h===d;}
class PerimeterGuard{
  constructor(op){this.op=op;}
  authorize(target){
    if(!this.op||!target)return{cleared:false,reason:"No operation or target"};
    const n=new Date();
    if(this.op.operation.start&&n<new Date(this.op.operation.start))return{cleared:false,reason:"Operation not yet active"};
    if(this.op.operation.end&&n>new Date(this.op.operation.end))return{cleared:false,reason:"Operation window closed"};
    for(const p of this.op.no_touch.restricted_periods||[])
      if(n>new Date(p.start)&&n<new Date(p.end))return{cleared:false,reason:`Restricted period: ${p.note||"active"}`};
    const h=normalizeTarget(target);
    if(this.op.no_touch.hosts.some(x=>matchHost(h,x)))return{cleared:false,reason:`${h} is no-touch`};
    if(this.op.no_touch.cidrs.some(c=>matchCIDR(h,c)))return{cleared:false,reason:`${h} in no-touch CIDR`};
    const inP=this.op.perimeter.hosts.some(x=>matchHost(h,x))||this.op.perimeter.domains.some(d=>matchDomain(h,d))||this.op.perimeter.cidrs.some(c=>matchCIDR(h,c));
    return inP?{cleared:true,reason:""}:{cleared:false,reason:`${h} outside perimeter`};
  }
  classify(tactic){
    if(this.op.constraints.blocked_tactics.includes(tactic))return{allowed:false,reason:`Tactic '${tacticName(tactic)}' is blocked`};
    return{allowed:true,reason:""};
  }
  gateCheck(tactic,mode){
    if(mode==="observer")return"block";if(mode==="autonomous")return"pass";if(mode==="controlled")return"gate";
    return this.op.constraints.gated_tactics.includes(tactic)?"gate":"pass";
  }
  dryRun(target,tactic,mode){
    const auth=this.authorize(target),cls=this.classify(tactic),gate=this.gateCheck(tactic,mode);
    return{target,tactic,mode,auth,classify:cls,gate,cleared:auth.cleared&&cls.allowed&&gate==="pass"};
  }
}

// ─── CLAUDE API ───────────────────────────────────────────────────────
async function callClaude(apiKey,system,userMsg,maxTokens=1000){
  if(!isValidApiKey(apiKey))throw new Error("Invalid API key format — expected sk-ant-* or sk-*");
  const r=await fetch("https://api.anthropic.com/v1/messages",{method:"POST",headers:{"Content-Type":"application/json","x-api-key":apiKey,"anthropic-version":"2023-06-01"},body:JSON.stringify({model:MODEL_ID,max_tokens:maxTokens,system,messages:[{role:"user",content:userMsg}]})});
  if(!r.ok){const err=await r.json().catch(()=>({}));throw new Error(err.error?.message||`API error: ${r.status}`);}
  const d=await r.json();
  return d.content?.filter(b=>b.type==="text").map(b=>b.text).join("\n")||"";
}
async function callClaudeJSON(apiKey,system,userMsg){
  try{const raw=await callClaude(apiKey,system+" Respond only with valid JSON. No markdown, no backticks.",userMsg);
  try{return JSON.parse(raw.replace(/```json|```/g,"").trim());}catch{return null;}}catch(e){console.error("callClaudeJSON:",e.message);return null;}
}

// ─── DESIGN SYSTEM ────────────────────────────────────────────────────
const F="'JetBrains Mono','Fira Code','Courier New',monospace";
const CSS=`*{box-sizing:border-box;margin:0;padding:0}:root{--bg:#0a0a0f;--sf:#12121a;--b:#1e1e2e;--bs:#252535;--fg:#e2e8f0;--d:#64748b;--a:#00c896;--r:#ef4444;--w:#f59e0b;--f:${F}}body{background:var(--bg);color:var(--fg);font-family:var(--f)}::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:var(--b);border-radius:2px}input,textarea,select{background:var(--bg);color:var(--fg);border:1px solid var(--b);border-radius:4px;font-family:var(--f);font-size:11px;padding:7px 10px;outline:none;width:100%}input:focus,textarea:focus,select:focus{border-color:var(--a)}`;

const Badge=({s,sm})=>{const c=SC[s]||RC[s]||"var(--d)";return<span style={{fontSize:sm?8:9,fontFamily:F,fontWeight:700,letterSpacing:1,padding:sm?"2px 5px":"3px 8px",borderRadius:3,color:c,border:`1px solid ${c}`,textTransform:"uppercase",whiteSpace:"nowrap"}}>{s?.replace(/_/g," ")}</span>;};
const Btn=({children,onClick,c,dis,sm,ol})=><button onClick={onClick} disabled={dis} style={{background:ol?"transparent":(c||"var(--a)"),color:ol?(c||"var(--a)"):"#000",border:ol?`1px solid ${c||"var(--a)"}`:"none",borderRadius:4,padding:sm?"4px 10px":"8px 16px",fontFamily:F,fontSize:sm?9:11,fontWeight:700,cursor:dis?"not-allowed":"pointer",letterSpacing:1,opacity:dis?0.5:1,whiteSpace:"nowrap"}}>{children}</button>;
const Card=({children,bc,sx})=><div style={{background:"var(--sf)",border:`1px solid ${bc||"var(--b)"}`,borderRadius:6,padding:16,marginBottom:12,...sx}}>{children}</div>;
const Sec=({t,children,action})=><div style={{marginBottom:16}}><div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:8}}><span style={{fontSize:9,fontWeight:700,letterSpacing:2,color:"var(--d)",fontFamily:F,textTransform:"uppercase"}}>{t}</span>{action}</div>{children}</div>;
const Empty=({t})=><div style={{fontSize:11,color:"var(--d)",fontFamily:F,fontStyle:"italic",padding:"12px 0",textAlign:"center"}}>{t}</div>;
const Row=({label,value,vc})=><div style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"5px 0",borderBottom:"1px solid var(--bs)"}}><span style={{fontSize:10,color:"var(--d)",fontFamily:F}}>{label}</span><span style={{fontSize:11,fontWeight:700,color:vc||"var(--fg)",fontFamily:F}}>{value}</span></div>;

// ─── VIEWS ────────────────────────────────────────────────────────────
function VDash({op,approvals,findings,violations,actions,evidence,timeline}){
  const pc=approvals.filter(a=>a.status==="pending").length;
  return<div>
    <div style={{marginBottom:16}}><div style={{fontSize:18,fontWeight:700,fontFamily:F,color:"var(--a)",letterSpacing:2}}>◈ TRIDENT</div><div style={{fontSize:11,color:"var(--d)",fontFamily:F}}>{op.operation.name||"No operation loaded"}</div></div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:10,marginBottom:16}}>
      {[["PHASES",actions.length,"var(--a)"],["FINDINGS",findings.length,findings.length>0?"var(--w)":"var(--d)"],["EVIDENCE",evidence.length,"var(--a)"],["VIOLATIONS",violations.length,violations.length>0?"var(--r)":"var(--d)"],["PENDING GATES",pc,pc>0?"var(--w)":"var(--d)"]].map(([l,v,c])=><div key={l} style={{background:"var(--sf)",border:"1px solid var(--b)",borderRadius:6,padding:12,textAlign:"center"}}><div style={{fontSize:22,fontWeight:700,color:c,fontFamily:F,lineHeight:1}}>{v}</div><div style={{fontSize:8,color:"var(--d)",fontFamily:F,letterSpacing:1,marginTop:2}}>{l}</div></div>)}
    </div>
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
      <Card><Sec t="RECENT ACTIVITY">{timeline.slice(-6).reverse().map(e=><div key={e.id} style={{display:"flex",gap:8,alignItems:"center",padding:"4px 0",borderBottom:"1px solid var(--bs)"}}><div style={{width:6,height:6,borderRadius:"50%",background:TC[e.type]||"var(--d)",flexShrink:0}}/><span style={{fontSize:9,color:"var(--d)",fontFamily:F,minWidth:48}}>{hms(e.ts)}</span><span style={{fontSize:10,color:"var(--fg)",fontFamily:F,flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{e.text}</span></div>)}{timeline.length===0&&<Empty t="No activity yet"/>}</Sec></Card>
      <Card><Sec t="FINDINGS BY SEVERITY">{["critical","high","medium","low","info"].map(sv=>{const c=findings.filter(f=>f.severity===sv).length;return c>0?<div key={sv} style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}><div style={{width:56,fontSize:9,fontFamily:F,color:SC[sv],fontWeight:700,textTransform:"uppercase"}}>{sv}</div><div style={{flex:1,height:5,background:"var(--bg)",borderRadius:3,overflow:"hidden"}}><div style={{height:"100%",width:`${Math.min(c/Math.max(findings.length,1)*100,100)}%`,background:SC[sv],borderRadius:3}}/></div><span style={{fontSize:10,fontFamily:F,color:"var(--fg)",minWidth:16,textAlign:"right"}}>{c}</span></div>:null;})}{findings.length===0&&<Empty t="No findings"/>}</Sec></Card>
      <Card><Sec t="PERIMETER VIOLATIONS">{violations.slice(-5).reverse().map(v=><div key={v.id} style={{padding:"5px 0",borderBottom:"1px solid var(--bs)"}}><div style={{fontSize:11,color:"var(--r)",fontFamily:F}}>⛔ {v.target}</div><div style={{fontSize:9,color:"var(--d)",fontFamily:F}}>{v.reason} · {hms(v.ts)}</div></div>)}{violations.length===0&&<Empty t="Clean — no violations"/>}</Sec></Card>
      <Card><Sec t="EVIDENCE CHAIN">{evidence.slice(-5).reverse().map(e=><div key={e.id} style={{display:"flex",gap:6,alignItems:"center",padding:"4px 0",borderBottom:"1px solid var(--bs)"}}><span style={{fontSize:9,color:"var(--d)",fontFamily:F,minWidth:52}}>{hms(e.ts)}</span><span style={{fontSize:10,color:"var(--fg)",fontFamily:F,flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{e.tool} → {e.target}</span><span style={{fontSize:8,color:"var(--d)",fontFamily:F}}>#{e.seq}</span></div>)}{evidence.length===0&&<Empty t="No evidence records"/>}</Sec></Card>
    </div>
  </div>;
}

function VScope({op,setOp}){
  const[tab,sTab]=useState("perimeter");
  const add=(path,val)=>{if(!val?.trim())return;const v=val.trim();if(path.endsWith(".cidrs")&&!isValidCIDR(v))return;if(path.endsWith(".hosts")&&!isValidHost(v))return;if(path.endsWith(".domains")&&!isValidDomain(v))return;const x=structuredClone(op);const keys=path.split(".");let o=x;for(let i=0;i<keys.length-1;i++)o=o[keys[i]];if(!o[keys.at(-1)].includes(v))o[keys.at(-1)].push(v);setOp(x);};
  const rm=(path,idx)=>{const x=structuredClone(op);const keys=path.split(".");let o=x;for(let i=0;i<keys.length-1;i++)o=o[keys[i]];o[keys.at(-1)].splice(idx,1);setOp(x);};
  const setField=(path,val)=>{const x=structuredClone(op);const keys=path.split(".");let o=x;for(let i=0;i<keys.length-1;i++)o=o[keys[i]];o[keys.at(-1)]=val;setOp(x);};
  return<div>
    <div style={{display:"flex",gap:4,marginBottom:16}}>{["perimeter","no-touch","constraints","meta"].map(t=><button key={t} onClick={()=>sTab(t)} style={{padding:"6px 14px",borderRadius:4,background:tab===t?"var(--a)":"transparent",color:tab===t?"#000":"var(--d)",border:`1px solid ${tab===t?"var(--a)":"var(--b)"}`,fontFamily:F,fontSize:9,fontWeight:700,cursor:"pointer",letterSpacing:1,textTransform:"uppercase"}}>{t}</button>)}</div>
    {tab==="perimeter"&&<Card>
      {[["PERIMETER HOSTS","perimeter.hosts","api.example.com"],["PERIMETER CIDRS","perimeter.cidrs","10.0.0.0/16"],["PERIMETER DOMAINS","perimeter.domains","*.corp.local"]].map(([title,path,ph])=><Sec key={path} t={title}>
        <div style={{display:"flex",gap:6,marginBottom:8}}><input placeholder={ph} onKeyDown={e=>{if(e.key==="Enter"){add(path,e.target.value);e.target.value="";}}}/><Btn sm onClick={()=>{}}>ADD</Btn></div>
        {(path.split(".").reduce((o,k)=>o?.[k],op)||[]).map((h,i)=><div key={h} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"4px 0",borderBottom:"1px solid var(--bs)"}}><span style={{fontSize:11,fontFamily:F,color:"var(--a)"}}>{h}</span><Btn sm ol c="var(--r)" onClick={()=>rm(path,i)}>×</Btn></div>)}
      </Sec>)}
    </Card>}
    {tab==="no-touch"&&<Card>
      {[["NO-TOUCH HOSTS","no_touch.hosts","prod.example.com"],["NO-TOUCH CIDRS","no_touch.cidrs","10.0.1.0/24"]].map(([title,path,ph])=><Sec key={path} t={title}>
        <div style={{display:"flex",gap:6,marginBottom:8}}><input placeholder={ph} onKeyDown={e=>{if(e.key==="Enter"){add(path,e.target.value);e.target.value="";}}}/><Btn sm onClick={()=>{}}>ADD</Btn></div>
        {(path.split(".").reduce((o,k)=>o?.[k],op)||[]).map((h,i)=><div key={h} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"4px 0",borderBottom:"1px solid var(--bs)"}}><span style={{fontSize:11,fontFamily:F,color:"var(--r)"}}>{h}</span><Btn sm ol c="var(--r)" onClick={()=>rm(path,i)}>×</Btn></div>)}
      </Sec>)}
    </Card>}
    {tab==="constraints"&&<Card>
      <Sec t="BLOCKED TACTICS (always denied)">{TACTICS.map(t=>{const blocked=op.constraints.blocked_tactics.includes(t.short);return<button key={t.short} onClick={()=>{const x=structuredClone(op);if(blocked)x.constraints.blocked_tactics=x.constraints.blocked_tactics.filter(s=>s!==t.short);else x.constraints.blocked_tactics.push(t.short);setOp(x);}} style={{margin:"0 4px 4px 0",padding:"4px 10px",borderRadius:3,background:blocked?"var(--r)":"transparent",color:blocked?"#fff":"var(--d)",border:`1px solid ${blocked?"var(--r)":"var(--b)"}`,fontFamily:F,fontSize:9,cursor:"pointer"}}>{t.name} <span style={{opacity:0.6}}>{t.id}</span></button>;})}
      </Sec>
      <Sec t="GATED TACTICS (approval required in supervised)">{TACTICS.map(t=>{const gated=op.constraints.gated_tactics.includes(t.short);return<button key={t.short} onClick={()=>{const x=structuredClone(op);if(gated)x.constraints.gated_tactics=x.constraints.gated_tactics.filter(s=>s!==t.short);else x.constraints.gated_tactics.push(t.short);setOp(x);}} style={{margin:"0 4px 4px 0",padding:"4px 10px",borderRadius:3,background:gated?"var(--w)":"transparent",color:gated?"#000":"var(--d)",border:`1px solid ${gated?"var(--w)":"var(--b)"}`,fontFamily:F,fontSize:9,cursor:"pointer"}}>{t.name} <span style={{opacity:0.6}}>{t.id}</span></button>;})}
      </Sec>
    </Card>}
    {tab==="meta"&&<Card><Sec t="OPERATION METADATA">
      {[["Operation Name","operation.name"],["Operation ID","operation.id"],["Classification","operation.classification"],["ROE URL","operation.roe_url"],["Client POC","operation.client_poc"],["Abort Contact","operation.abort_contact"]].map(([l,p])=><div key={p} style={{marginBottom:8}}><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>{l.toUpperCase()}</div><input value={p.split(".").reduce((o,k)=>o?.[k],op)||""} onChange={e=>setField(p,e.target.value)} placeholder={l}/></div>)}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginTop:8}}>
        <div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>START</div><input type="datetime-local" value={op.operation.start} onChange={e=>setField("operation.start",e.target.value)}/></div>
        <div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>END</div><input type="datetime-local" value={op.operation.end} onChange={e=>setField("operation.end",e.target.value)}/></div>
      </div>
    </Sec></Card>}
  </div>;
}

function VMap({op,actions,violations}){
  const tested=new Set(actions.map(a=>normalizeTarget(a.target||"")));
  const violated=new Set(violations.map(v=>normalizeTarget(v.target||"")));
  const targets=[...op.perimeter.hosts,...op.perimeter.domains,...op.perimeter.cidrs];
  const cx=300,cy=200,r=140;
  return<Card sx={{textAlign:"center"}}>
    <Sec t="PERIMETER NETWORK MAP"/>
    <svg width="600" height="400" style={{maxWidth:"100%"}}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--b)" strokeWidth="1" strokeDasharray="4,4"/>
      <circle cx={cx} cy={cy} r={8} fill="var(--a)"/>
      <text x={cx} y={cy+20} textAnchor="middle" fill="var(--a)" fontSize="9" fontFamily={F}>TRIDENT</text>
      {targets.map((t,i)=>{const angle=(i/Math.max(targets.length,1))*2*Math.PI-Math.PI/2,tx=cx+r*Math.cos(angle),ty=cy+r*Math.sin(angle),col=violated.has(t)?"#ef4444":tested.has(t)?"#22c55e":"var(--d)";return<g key={t}><line x1={cx} y1={cy} x2={tx} y2={ty} stroke={violated.has(t)?"#ef444433":"var(--b)"} strokeWidth="1" strokeDasharray={violated.has(t)?"4,4":""}/><circle cx={tx} cy={ty} r={5} fill={col}/><text x={tx} y={ty-10} textAnchor="middle" fill={col} fontSize="8" fontFamily={F}>{t.length>18?t.slice(0,16)+"…":t}</text></g>;})}
      {targets.length===0&&<text x={cx} y={cy+50} textAnchor="middle" fill="var(--d)" fontSize="11" fontFamily={F}>Define perimeter in PERIMETER view</text>}
    </svg>
    <div style={{display:"flex",gap:16,justifyContent:"center",fontSize:9,fontFamily:F,color:"var(--d)"}}><span><span style={{color:"var(--d)"}}>● </span>Untested</span><span><span style={{color:"#22c55e"}}>● </span>Tested</span><span><span style={{color:"#ef4444"}}>● </span>Violation</span></div>
  </Card>;
}

function VWorkbench({op,mode,setActions,setViolations,setEvidence,addTL,actions,evidence,apiKey,sApiKey,setApprovals}){
  const[target,sTarget]=useState("");const[tactic,sTactic]=useState("recon");const[tool,sTool]=useState("rustscan");
  const[output,sOutput]=useState("");const[phaseName,sPhaseName]=useState("");const[chat,sChat]=useState([]);
  const[inp,sInp]=useState("");const[busy,sBusy]=useState(false);const[plan,sPlan]=useState(null);
  const ref=useRef(null);useEffect(()=>{ref.current?.scrollIntoView({behavior:"smooth"});},[chat]);
  const guard=new PerimeterGuard(op);
  const execPhase=async()=>{
    if(!target.trim()||!phaseName.trim())return;
    if(mode==="observer"){addTL("violation","Observer mode — execution blocked");return;}
    const auth=guard.authorize(target),cls=guard.classify(tactic),gate=guard.gateCheck(tactic,mode);
    if(!auth.cleared){setViolations(p=>[...p,{id:uid(),ts:now(),target,reason:auth.reason}]);addTL("violation",`Violation: ${auth.reason}`);return;}
    if(!cls.allowed){setViolations(p=>[...p,{id:uid(),ts:now(),target,reason:cls.reason}]);addTL("violation",`Tactic blocked: ${cls.reason}`);return;}
    if(gate==="gate"){setApprovals(p=>[...p,{id:uid(),status:"pending",phase:phaseName,target,tactic,ts:now()}]);addTL("approval",`Gate required: ${phaseName}`);return;}
    const seq=evidence.length+1,prevHash=evidence.length>0?evidence[evidence.length-1].hash:"GENESIS";
    const record={id:uid(),seq,ts:now(),operator:"practitioner",phase:phaseName,target,tactic,tool,output,perimeterCheck:auth,prevHash};
    const hash=await digest(JSON.stringify(record));
    setEvidence(p=>[...p,{...record,hash,integrityPayload:JSON.stringify(record)}]);
    setActions(p=>[...p,{id:uid(),ts:now(),phase:phaseName,target,tactic,tool}]);
    addTL("action",`Phase logged: ${phaseName} → ${target}`);
    sPhaseName("");sTarget("");sOutput("");
  };
  const genPlan=async()=>{
    if(!apiKey)return;sBusy(true);
    const result=await callClaudeJSON(apiKey,"You are an assessment methodology advisor. Generate a phased assessment plan as JSON array: [{name,tactic,tool,description,risk_level}]. risk_level: low|medium|high. tactic: MITRE short names. Documentation and methodology only — no offensive techniques.",`Perimeter: ${sanitizeForPrompt(JSON.stringify(op.perimeter),1000)}\nConstraints: ${sanitizeForPrompt(JSON.stringify(op.constraints),500)}`);
    if(result){sPlan(Array.isArray(result)?result:[]);}sBusy(false);
  };
  const send=async()=>{
    if(!inp.trim()||!apiKey)return;const msg=inp.trim();sInp("");sChat(p=>[...p,{r:"user",t:msg}]);sBusy(true);
    const text=await callClaude(apiKey,"You are TRIDENT's assessment advisor — a documentation specialist. Help with MITRE ATT&CK mappings, risk analysis, finding documentation, and methodology. Never provide attack code or offensive techniques.",`Operation: ${sanitizeForPrompt(op.operation.name||"unnamed")}\n\n${sanitizeForPrompt(msg,1000)}`);
    sChat(p=>[...p,{r:"ai",t:text}]);sBusy(false);
  };
  return<div style={{display:"flex",flexDirection:"column",gap:12}}>
    <Card><Sec t="LOG PHASE TO EVIDENCE CHAIN"/>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:8}}>
        <div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>PHASE NAME</div><input value={phaseName} onChange={e=>sPhaseName(e.target.value)} placeholder="Port scan — external"/></div>
        <div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>TARGET</div><input value={target} onChange={e=>sTarget(e.target.value)} placeholder="host, domain, or IP"/></div>
        <div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>TACTIC</div><select value={tactic} onChange={e=>sTactic(e.target.value)}>{TACTICS.map(t=><option key={t.short} value={t.short}>{t.name} — {t.id}</option>)}</select></div>
        <div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>TOOL</div><input value={tool} onChange={e=>sTool(e.target.value)} placeholder="tool name"/></div>
      </div>
      <div style={{marginBottom:8}}><textarea value={output} onChange={e=>sOutput(e.target.value)} placeholder="Paste tool output here..." rows={3} style={{resize:"vertical"}}/></div>
      <div style={{display:"flex",gap:8,alignItems:"center"}}>
        <Btn onClick={execPhase} dis={mode==="observer"||!phaseName.trim()||!target.trim()}>LOG TO EVIDENCE CHAIN</Btn>
        {mode==="observer"&&<span style={{fontSize:10,color:"var(--r)",fontFamily:F}}>📡 Observer mode — execution disabled</span>}
      </div>
    </Card>
    <Card><Sec t="AI PLAN GENERATOR" action={<div style={{display:"flex",gap:6}}><input value={apiKey} onChange={e=>sApiKey(e.target.value)} placeholder="API key" type="password" style={{width:160}}/><Btn sm onClick={genPlan} dis={busy||!apiKey}>{busy?"…":"GENERATE"}</Btn></div>}/>
      {plan&&<div style={{maxHeight:180,overflowY:"auto",marginBottom:8}}>{plan.map((p,i)=><div key={i} style={{display:"flex",alignItems:"center",gap:8,padding:"6px 8px",marginBottom:3,background:"var(--bg)",border:"1px solid var(--b)",borderRadius:4,borderLeft:`3px solid ${RC[p.risk_level]||"var(--b)"}`}}><span style={{fontSize:10,fontWeight:700,color:"var(--d)",fontFamily:F,minWidth:16}}>{i+1}</span><div style={{flex:1}}><div style={{fontSize:11,fontWeight:600,fontFamily:F}}>{p.name}</div><div style={{fontSize:9,color:"var(--d)",fontFamily:F}}>{tacticName(p.tactic)} · {p.description}</div></div><Badge s={p.risk_level} sm/><Btn sm ol onClick={()=>{sPhaseName(p.name);sTactic(p.tactic);sTool(p.tool||"");}} dis={mode==="observer"}>USE</Btn></div>)}</div>}
    </Card>
    <Card><Sec t="ASSESSMENT ADVISOR"/>
      <div style={{maxHeight:200,overflowY:"auto",marginBottom:8,display:"flex",flexDirection:"column",gap:5}}>{chat.length===0&&<Empty t="Ask about MITRE mappings, risk analysis, finding documentation..."/>}{chat.map((m,i)=><div key={i} style={{padding:"6px 10px",borderRadius:4,maxWidth:"88%",fontSize:11,fontFamily:F,lineHeight:1.5,whiteSpace:"pre-wrap",alignSelf:m.r==="user"?"flex-end":"flex-start",background:m.r==="user"?"rgba(0,200,150,.12)":"var(--bg)",border:`1px solid ${m.r==="user"?"rgba(0,200,150,.25)":"var(--b)"}`}}>{m.t}</div>)}<div ref={ref}/></div>
      <div style={{display:"flex",gap:8}}><input value={inp} onChange={e=>sInp(e.target.value)} onKeyDown={e=>e.key==="Enter"&&send()} placeholder="Ask about methodology, MITRE, findings..."/><Btn onClick={send} dis={busy||!apiKey}>SEND</Btn></div>
    </Card>
  </div>;
}

function VGate({approvals,setApprovals,addTL}){
  const decide=(id,status)=>{setApprovals(p=>p.map(a=>a.id===id?{...a,status,decided_at:now()}:a));addTL("approval",`Gate ${status}: ${approvals.find(a=>a.id===id)?.phase||id}`);};
  const pending=approvals.filter(a=>a.status==="pending");
  const decided=approvals.filter(a=>a.status!=="pending");
  return<div>
    <Card><Sec t={`PENDING (${pending.length})`}>
      {pending.map(a=><div key={a.id} style={{padding:12,marginBottom:8,background:"var(--bg)",border:"1px solid var(--w)",borderRadius:6}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}><span style={{fontSize:12,fontWeight:700,fontFamily:F}}>{a.phase}</span><Badge s="pending" sm/></div>
        <Row label="Target" value={a.target}/><Row label="Tactic" value={`${tacticName(a.tactic)} (${tacticId(a.tactic)})`}/><Row label="Requested" value={hmFull(a.ts)}/>
        <div style={{display:"flex",gap:8,marginTop:10}}><Btn onClick={()=>decide(a.id,"approved")} c="var(--a)">APPROVE</Btn><Btn onClick={()=>decide(a.id,"rejected")} c="var(--r)" ol>REJECT</Btn></div>
      </div>)}
      {pending.length===0&&<Empty t="No pending approvals"/>}
    </Sec></Card>
    {decided.length>0&&<Card><Sec t="DECIDED">{decided.slice(-10).reverse().map(a=><div key={a.id} style={{display:"flex",gap:8,alignItems:"center",padding:"5px 0",borderBottom:"1px solid var(--bs)"}}><span style={{fontSize:9,fontFamily:F,color:a.status==="approved"?"var(--a)":"var(--r)",fontWeight:700,textTransform:"uppercase",minWidth:56}}>{a.status}</span><span style={{fontSize:10,fontFamily:F,flex:1}}>{a.phase}</span><span style={{fontSize:9,color:"var(--d)",fontFamily:F}}>{hmFull(a.ts)}</span></div>)}</Sec></Card>}
  </div>;
}

function VFind({findings,setFindings,op,addTL,apiKey,sApiKey}){
  const[busy,sBusy]=useState(false);
  const[form,sForm]=useState({title:"",severity:"high",host:"",cwe:"",description:"",remediation:""});
  const add=()=>{if(!form.title.trim())return;if(form.cwe&&!isValidCWE(form.cwe))return;setFindings(p=>[...p,{...form,id:uid(),ts:now(),status:"open"}]);addTL("finding",`Finding: ${form.title}`);sForm({title:"",severity:"high",host:"",cwe:"",description:"",remediation:""});};
  const aiDoc=async(f)=>{if(!apiKey)return;sBusy(true);const result=await callClaudeJSON(apiKey,"Security documentation specialist. Document this vulnerability as JSON: {description,technical_details,business_impact,remediation,references,mitre_tactic,mitre_id,cvss_vector}. Professional, accurate, no exploit code.",`Title: ${sanitizeForPrompt(f.title)}\nHost: ${sanitizeForPrompt(f.host)}\nSeverity: ${sanitizeForPrompt(f.severity)}`);if(result)setFindings(p=>p.map(x=>x.id===f.id?{...x,...result}:x));sBusy(false);};
  const del=(id)=>setFindings(p=>p.filter(f=>f.id!==id));
  return<div>
    <Card><Sec t="ADD FINDING"/>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:8}}>
        <div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>TITLE</div><input value={form.title} onChange={e=>sForm(p=>({...p,title:e.target.value}))} placeholder="SQL Injection — Login Form"/></div>
        <div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>HOST</div><input value={form.host} onChange={e=>sForm(p=>({...p,host:e.target.value}))} placeholder="api.example.com"/></div>
        <div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>SEVERITY</div><select value={form.severity} onChange={e=>sForm(p=>({...p,severity:e.target.value}))}>{["critical","high","medium","low","info"].map(s=><option key={s} value={s}>{s.toUpperCase()}</option>)}</select></div>
        <div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>CWE</div><input value={form.cwe} onChange={e=>sForm(p=>({...p,cwe:e.target.value}))} placeholder="CWE-89"/></div>
      </div>
      <textarea value={form.description} onChange={e=>sForm(p=>({...p,description:e.target.value}))} placeholder="Description..." rows={2} style={{marginBottom:8,resize:"vertical"}}/>
      <textarea value={form.remediation} onChange={e=>sForm(p=>({...p,remediation:e.target.value}))} placeholder="Remediation..." rows={2} style={{marginBottom:8,resize:"vertical"}}/>
      <div style={{display:"flex",gap:8,alignItems:"center"}}><Btn onClick={add} dis={!form.title.trim()}>ADD FINDING</Btn><input value={apiKey} onChange={e=>sApiKey(e.target.value)} placeholder="API key for AI doc" type="password" style={{flex:1}}/></div>
    </Card>
    {["critical","high","medium","low","info"].map(sv=>{const group=findings.filter(f=>f.severity===sv);if(!group.length)return null;return<div key={sv}><div style={{fontSize:9,fontWeight:700,color:SC[sv],fontFamily:F,letterSpacing:2,marginBottom:6,textTransform:"uppercase"}}>── {sv} ({group.length})</div>{group.map(f=><Card key={f.id} bc={SC[sv]+"44"}><div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:6}}><div><div style={{fontSize:13,fontWeight:700,fontFamily:F}}>{f.title}</div><div style={{fontSize:10,color:"var(--d)",fontFamily:F}}>{f.host} · {f.cwe||"CWE unknown"}</div></div><div style={{display:"flex",gap:6}}><Badge s={f.severity}/><Btn sm ol c="var(--a)" onClick={()=>aiDoc(f)} dis={busy||!apiKey}>AI DOC</Btn><Btn sm ol c="var(--r)" onClick={()=>del(f.id)}>×</Btn></div></div>{f.description&&<div style={{fontSize:11,fontFamily:F,lineHeight:1.5,marginBottom:6}}>{f.description}</div>}{f.remediation&&<div style={{fontSize:10,fontFamily:F,color:"var(--a)",padding:"6px 8px",background:"rgba(0,200,150,.06)",borderRadius:4,border:"1px solid rgba(0,200,150,.15)"}}>Remediation: {f.remediation}</div>}{f.mitre_tactic&&<div style={{fontSize:9,color:"var(--d)",fontFamily:F,marginTop:6}}>ATT&CK: {f.mitre_tactic} · {f.mitre_id}</div>}</Card>)}</div>;})}
    {findings.length===0&&<Empty t="No findings documented"/>}
  </div>;
}

function VEvid({evidence}){
  const[expanded,sExp]=useState(null);const[verified,sVer]=useState(null);
  const verify=async()=>{
    if(evidence.length===0){sVer({ok:true,msg:"No records to verify"});return;}
    const sorted=[...evidence].sort((a,b)=>a.seq-b.seq);
    for(let i=0;i<sorted.length;i++){
      const recomputed=await digest(sorted[i].integrityPayload);
      if(recomputed!==sorted[i].hash){sVer({ok:false,msg:`Hash mismatch at record #${sorted[i].seq}`});return;}
      if(i>0&&sorted[i].prevHash!==sorted[i-1].hash){sVer({ok:false,msg:`Chain broken at record #${sorted[i].seq}`});return;}
    }
    sVer({ok:true,msg:`Chain verified — ${evidence.length} records intact`});
  };
  return<div><Card><Sec t="MERKLE EVIDENCE CHAIN" action={<Btn sm onClick={verify}>VERIFY CHAIN</Btn>}/>
    {verified&&<div style={{padding:"8px 12px",borderRadius:4,background:verified.ok?"rgba(0,200,150,.08)":"rgba(239,68,68,.08)",border:`1px solid ${verified.ok?"var(--a)":"var(--r)"}`,marginBottom:12,fontSize:11,fontFamily:F,color:verified.ok?"var(--a)":"var(--r)"}}>{verified.ok?"✓":"✗"} {verified.msg}</div>}
    {evidence.length===0&&<Empty t="No evidence records — log phases in Workbench"/>}
    {[...evidence].sort((a,b)=>b.seq-a.seq).map(e=><div key={e.id} style={{marginBottom:8,background:"var(--bg)",border:"1px solid var(--b)",borderRadius:4}}>
      <div onClick={()=>sExp(expanded===e.id?null:e.id)} style={{display:"flex",gap:8,alignItems:"center",padding:"8px 10px",cursor:"pointer"}}><span style={{fontSize:10,fontWeight:700,color:"var(--d)",fontFamily:F,minWidth:24}}>#{e.seq}</span><span style={{fontSize:10,fontFamily:F,flex:1}}>{e.phase}</span><span style={{fontSize:9,color:"var(--a)",fontFamily:F}}>{e.target}</span><span style={{fontSize:8,color:"var(--d)",fontFamily:F}}>{hms(e.ts)}</span><Badge s={e.tactic} sm/></div>
      {expanded===e.id&&<div style={{padding:"8px 12px",borderTop:"1px solid var(--b)"}}><Row label="Hash" value={e.hash?.slice(0,16)+"…"} vc="var(--a)"/><Row label="Prev Hash" value={e.prevHash==="GENESIS"?"GENESIS":e.prevHash?.slice(0,16)+"…"} vc="var(--d)"/><Row label="Tool" value={e.tool}/><Row label="Operator" value={e.operator}/>{e.output&&<div style={{marginTop:8}}><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>OUTPUT</div><pre style={{fontSize:9,fontFamily:F,color:"var(--fg)",background:"var(--sf)",padding:8,borderRadius:4,overflowX:"auto",whiteSpace:"pre-wrap",maxHeight:100,overflowY:"auto"}}>{e.output}</pre></div>}</div>}
    </div>)}
  </Card></div>;
}

function VTools({tools,setTools}){
  const[form,sForm]=useState({name:"",slot:"",desc:"",footprint:"low",tactics:""});
  const addCustom=()=>{if(!form.name.trim())return;const tacticList=form.tactics.split(",").map(t=>t.trim()).filter(Boolean);if(tacticList.length>0&&!tacticList.every(t=>TACTICS.some(T=>T.short===t)))return;setTools(p=>[...p,{...form,tactics:tacticList,ver:"custom",on:true,core:false}]);sForm({name:"",slot:"",desc:"",footprint:"low",tactics:""});};
  const toggle=(name)=>setTools(p=>p.map(t=>t.name===name?{...t,on:!t.on}:t));
  const slots=[...new Set(tools.map(t=>t.slot))];
  return<div>
    {slots.map(slot=><Card key={slot}><Sec t={slot.toUpperCase()}>
      {tools.filter(t=>t.slot===slot).map(t=><div key={t.name} style={{display:"flex",gap:8,alignItems:"center",padding:"6px 0",borderBottom:"1px solid var(--bs)"}}>
        <button onClick={()=>toggle(t.name)} style={{width:32,height:16,borderRadius:8,background:t.on?"var(--a)":"var(--b)",border:"none",cursor:"pointer",position:"relative",flexShrink:0}}><div style={{width:12,height:12,borderRadius:"50%",background:"#fff",position:"absolute",top:2,left:t.on?18:2,transition:"left .15s"}}/></button>
        <div style={{flex:1}}><span style={{fontSize:11,fontWeight:700,fontFamily:F}}>{t.name}</span><span style={{fontSize:9,color:"var(--d)",fontFamily:F}}> v{t.ver}</span><div style={{fontSize:9,color:"var(--d)",fontFamily:F}}>{t.desc}</div></div>
        <span style={{fontSize:8,color:t.footprint==="high"?"var(--r)":t.footprint==="medium"?"var(--w)":"var(--a)",fontFamily:F,fontWeight:700}}>{t.footprint?.toUpperCase()}</span>
        {!t.core&&<Btn sm ol c="var(--r)" onClick={()=>setTools(p=>p.filter(x=>x.name!==t.name))}>×</Btn>}
      </div>)}
    </Sec></Card>)}
    <Card><Sec t="REGISTER CUSTOM TOOL"/>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:8}}>
        <div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>NAME</div><input value={form.name} onChange={e=>sForm(p=>({...p,name:e.target.value}))} placeholder="mytool"/></div>
        <div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>SLOT</div><input value={form.slot} onChange={e=>sForm(p=>({...p,slot:e.target.value}))} placeholder="web-fuzz"/></div>
        <div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>FOOTPRINT</div><select value={form.footprint} onChange={e=>sForm(p=>({...p,footprint:e.target.value}))}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option></select></div>
        <div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>TACTICS</div><input value={form.tactics} onChange={e=>sForm(p=>({...p,tactics:e.target.value}))} placeholder="recon,discovery"/></div>
      </div>
      <input value={form.desc} onChange={e=>sForm(p=>({...p,desc:e.target.value}))} placeholder="Description" style={{marginBottom:8}}/>
      <Btn onClick={addCustom} dis={!form.name.trim()}>REGISTER</Btn>
    </Card>
  </div>;
}

function VCvss(){
  const METRICS={AV:{n:"Attack Vector",vals:{N:{n:"Network",v:0.85},A:{n:"Adjacent",v:0.62},L:{n:"Local",v:0.55},P:{n:"Physical",v:0.20}}},AC:{n:"Attack Complexity",vals:{L:{n:"Low",v:0.77},H:{n:"High",v:0.44}}},PR:{n:"Privileges Required",vals:{N:{n:"None",v:0.85},L:{n:"Low",v:0.62},H:{n:"High",v:0.27}}},UI:{n:"User Interaction",vals:{N:{n:"None",v:0.85},R:{n:"Required",v:0.62}}},S:{n:"Scope",vals:{U:{n:"Unchanged"},C:{n:"Changed"}}},C:{n:"Confidentiality",vals:{N:{n:"None",v:0},L:{n:"Low",v:0.22},H:{n:"High",v:0.56}}},I:{n:"Integrity",vals:{N:{n:"None",v:0},L:{n:"Low",v:0.22},H:{n:"High",v:0.56}}},A:{n:"Availability",vals:{N:{n:"None",v:0},L:{n:"Low",v:0.22},H:{n:"High",v:0.56}}}};
  const[sel,sSel]=useState({AV:"N",AC:"L",PR:"N",UI:"N",S:"U",C:"N",I:"N",A:"N"});
  const calc=()=>{
    const{AV,AC,PR,UI,S,C,I,A}=sel;
    const av=METRICS.AV.vals[AV].v,ac=METRICS.AC.vals[AC].v;
    let pr=METRICS.PR.vals[PR].v;if(S==="C"&&PR==="L")pr=0.68;if(S==="C"&&PR==="H")pr=0.50;
    const ui=METRICS.UI.vals[UI].v,c=METRICS.C.vals[C].v,i=METRICS.I.vals[I].v,a=METRICS.A.vals[A].v;
    const iss=1-((1-c)*(1-i)*(1-a));
    const impact=S==="U"?6.42*iss:7.52*(iss-0.029)-3.25*Math.pow(iss-0.02,15);
    const exploit=8.22*av*ac*pr*ui;
    if(impact<=0)return 0;
    const raw=S==="U"?Math.min(impact+exploit,10):Math.min(1.08*(impact+exploit),10);
    return Math.ceil(raw*10)/10;
  };
  const score=calc();
  const severity=score===0?"None":score<4?"Low":score<7?"Medium":score<9?"High":"Critical";
  const col=score===0?"var(--d)":SC[severity.toLowerCase()]||"var(--d)";
  const vector=`CVSS:3.1/AV:${sel.AV}/AC:${sel.AC}/PR:${sel.PR}/UI:${sel.UI}/S:${sel.S}/C:${sel.C}/I:${sel.I}/A:${sel.A}`;
  return<Card>
    <div style={{textAlign:"center",marginBottom:20}}><div style={{fontSize:56,fontWeight:700,fontFamily:F,color:col,lineHeight:1}}>{score.toFixed(1)}</div><div style={{fontSize:14,fontWeight:700,fontFamily:F,color:col,letterSpacing:2}}>{severity.toUpperCase()}</div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,marginTop:6,wordBreak:"break-all"}}>{vector}</div><div style={{fontSize:8,color:"var(--d)",fontFamily:F,marginTop:4}}>CVSS v3.1 — FIRST.org</div></div>
    {Object.entries(METRICS).map(([k,m])=><Sec key={k} t={m.n}><div style={{display:"flex",flexWrap:"wrap",gap:6}}>{Object.entries(m.vals).map(([vk,vv])=><button key={vk} onClick={()=>sSel(p=>({...p,[k]:vk}))} style={{padding:"5px 12px",borderRadius:4,background:sel[k]===vk?col:"transparent",color:sel[k]===vk?"#000":"var(--d)",border:`1px solid ${sel[k]===vk?col:"var(--b)"}`,fontFamily:F,fontSize:10,cursor:"pointer",fontWeight:sel[k]===vk?700:400}}>{vv.n}</button>)}</div></Sec>)}
  </Card>;
}

function VReport({op,findings,evidence,apiKey,sApiKey}){
  const[report,sReport]=useState("");const[busy,sBusy]=useState(false);
  const[practitioner,sPractitioner]=useState("");const[certs,sCerts]=useState("");const[attested,sAttested]=useState(false);
  const gen=async()=>{if(!apiKey)return;sBusy(true);try{const text=await callClaude(apiKey,"You are a security assessment documentation specialist. Write a professional penetration test report following PTES methodology: 1. Executive Summary, 2. Scope and Rules of Engagement, 3. Methodology, 4. Findings by severity, 5. Recommendations, 6. Conclusion. Be factual and professional. No offensive techniques or exploit code.",`Operation: ${sanitizeForPrompt(JSON.stringify(op.operation),500)}\nFindings: ${sanitizeForPrompt(JSON.stringify(findings.map(f=>({title:f.title,severity:f.severity,host:f.host,cwe:f.cwe}))),2000)}\nEvidence records: ${evidence.length}`,3000);sReport(text);}catch(e){sReport(`Error: ${e.message}`);}sBusy(false);};
  return<div>
    <Card><Sec t="GENERATE REPORT"/><div style={{display:"flex",gap:8,marginBottom:12}}><input value={apiKey} onChange={e=>sApiKey(e.target.value)} placeholder="API key" type="password" style={{flex:1}}/><Btn onClick={gen} dis={busy||!apiKey}>{busy?"GENERATING…":"GENERATE"}</Btn></div>{report?<pre style={{fontSize:11,fontFamily:F,lineHeight:1.6,whiteSpace:"pre-wrap",maxHeight:400,overflowY:"auto"}}>{report}</pre>:<Empty t="Generate report to see output"/>}</Card>
    <Card bc={attested?"var(--a)":"var(--b)"}><Sec t="PRACTITIONER ATTESTATION"/>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:12}}>
        <div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>NAME</div><input value={practitioner} onChange={e=>sPractitioner(e.target.value)} placeholder="Full name"/></div>
        <div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:4}}>CERTIFICATIONS</div><input value={certs} onChange={e=>sCerts(e.target.value)} placeholder="OSCP, CEH"/></div>
      </div>
      <label style={{display:"flex",gap:8,alignItems:"center",cursor:"pointer",marginBottom:12,fontSize:11,fontFamily:F}}><input type="checkbox" checked={attested} onChange={e=>sAttested(e.target.checked)} style={{width:"auto"}}/>I confirm this assessment was performed within the authorized scope defined in the Rules of Engagement.</label>
      {attested&&practitioner&&<div style={{padding:12,background:"rgba(0,200,150,.06)",border:"1px solid var(--a)",borderRadius:4,fontSize:11,fontFamily:F,color:"var(--a)"}}>✓ Attested by {practitioner} {certs?`(${certs}) `:""}— {new Date().toLocaleDateString()}</div>}
    </Card>
  </div>;
}

function VKB({knowledge,setKnowledge,apiKey,sApiKey}){
  const[busy,sBusy]=useState(false);const[text,sText]=useState("");
  const add=()=>{if(!text.trim())return;setKnowledge(p=>[...p,{id:uid(),ts:now(),content:text,quality:"unreviewed",source:"manual"}]);sText("");};
  const aiPop=async()=>{if(!apiKey)return;sBusy(true);const result=await callClaudeJSON(apiKey,"Security knowledge curator. Generate 3 useful knowledge entries about defensive analysis, remediation patterns, and security documentation best practices. Return JSON array: [{content}].","Generate security knowledge entries for an assessment team.");if(Array.isArray(result))setKnowledge(p=>[...p,...result.map(r=>({id:uid(),ts:now(),content:r.content,quality:"unreviewed",source:"ai"}))]);sBusy(false);};
  const setQ=(id,q)=>setKnowledge(p=>p.map(k=>k.id===id?{...k,quality:q}:k));
  const del=(id)=>setKnowledge(p=>p.filter(k=>k.id!==id));
  const QC={pinned:"#f59e0b",good:"var(--a)",unreviewed:"var(--d)"};
  return<div>
    <Card><Sec t="ADD KNOWLEDGE"/><textarea value={text} onChange={e=>sText(e.target.value)} placeholder="Document a finding pattern, remediation approach, or technique note..." rows={3} style={{marginBottom:8,resize:"vertical"}}/><div style={{display:"flex",gap:8,alignItems:"center"}}><Btn onClick={add} dis={!text.trim()}>ADD</Btn><input value={apiKey} onChange={e=>sApiKey(e.target.value)} placeholder="API key for AI" type="password" style={{flex:1}}/><Btn sm onClick={aiPop} dis={busy||!apiKey}>{busy?"…":"AI POPULATE"}</Btn></div></Card>
    {["pinned","good","unreviewed"].map(q=>{const group=knowledge.filter(k=>k.quality===q);if(!group.length)return null;return<div key={q}><div style={{fontSize:9,fontWeight:700,color:QC[q],fontFamily:F,letterSpacing:2,marginBottom:6,textTransform:"uppercase"}}>── {q} ({group.length})</div>{group.map(k=><Card key={k.id}><div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:8}}><div style={{fontSize:11,fontFamily:F,flex:1,lineHeight:1.5}}>{k.content}</div><div style={{display:"flex",gap:4,flexShrink:0}}><Btn sm ol c="var(--w)" onClick={()=>setQ(k.id,"pinned")}>📌</Btn><Btn sm ol c="var(--a)" onClick={()=>setQ(k.id,"good")}>✓</Btn><Btn sm ol c="var(--r)" onClick={()=>del(k.id)}>×</Btn></div></div><div style={{fontSize:8,color:"var(--d)",fontFamily:F,marginTop:6}}>{k.source.toUpperCase()} · {hmFull(k.ts)}</div></Card>)}</div>;})}
    {knowledge.length===0&&<Empty t="No knowledge entries"/>}
  </div>;
}

function VInteg({findings,evidence,op,setFindings,addTL,apiKey,sApiKey}){
  const[busy,sBusy]=useState(false);
  const exportJSON=()=>{const data={op,findings,evidence,exported_at:now(),version:"trident-v5"};const blob=new Blob([JSON.stringify(data,null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=`trident-export-${Date.now()}.json`;a.click();addTL("export","Exported engagement JSON");};
  const importNessus=async()=>{if(!apiKey)return;sBusy(true);const result=await callClaudeJSON(apiKey,"Security tool integration specialist. Simulate a Nessus scan for the provided perimeter. Generate 3-5 realistic vulnerability findings. Return JSON array: [{title,severity,host,cwe,description,remediation}]. severity: critical|high|medium|low|info. Hosts must be from provided perimeter.",`Perimeter: ${sanitizeForPrompt(JSON.stringify(op.perimeter),1000)}`);if(Array.isArray(result)){const imported=result.map(f=>({...f,id:uid(),ts:now(),status:"open",source:"nessus-import"}));setFindings(p=>[...p,...imported]);addTL("import",`Imported ${imported.length} Nessus findings`);}sBusy(false);};
  return<div>
    <Card><Sec t="EXPORT"/><div style={{display:"flex",gap:8}}><Btn onClick={exportJSON}>EXPORT JSON</Btn><Btn ol dis>EXPORT SARIF</Btn><Btn ol dis>EXPORT JIRA</Btn></div></Card>
    <Card><Sec t="IMPORT (SIMULATED)"/><div style={{marginBottom:8,fontSize:10,color:"var(--d)",fontFamily:F}}>Simulated import via AI for testing. Real file parsing in v6.</div><div style={{display:"flex",gap:8,alignItems:"center"}}><input value={apiKey} onChange={e=>sApiKey(e.target.value)} placeholder="API key" type="password" style={{flex:1}}/><Btn onClick={importNessus} dis={busy||!apiKey}>{busy?"…":"SIMULATE NESSUS"}</Btn></div></Card>
    <Card><Sec t="SUPPORTED FORMATS"/><div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}><div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:6}}>IMPORT</div>{["Nessus (.nessus)","Qualys (.xml)","Burp Suite (.xml)","Nuclei (JSON)","ZAP (.xml)"].map(f=><div key={f} style={{fontSize:10,fontFamily:F,padding:"3px 0"}}>{f}</div>)}</div><div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,letterSpacing:1,marginBottom:6}}>EXPORT</div>{["JSON (full engagement)","SARIF","Jira","DefectDojo","Slack webhook"].map(f=><div key={f} style={{fontSize:10,fontFamily:F,padding:"3px 0"}}>{f}</div>)}</div></div></Card>
  </div>;
}

function VTL({timeline}){
  return<Card><Sec t="ACTIVITY TIMELINE"/>
    {timeline.length===0&&<Empty t="No activity yet"/>}
    <div style={{position:"relative"}}><div style={{position:"absolute",left:7,top:0,bottom:0,width:1,background:"var(--b)"}}/>
      {[...timeline].reverse().map(e=><div key={e.id} style={{display:"flex",gap:12,alignItems:"flex-start",marginBottom:10,paddingLeft:24,position:"relative"}}><div style={{position:"absolute",left:4,top:5,width:8,height:8,borderRadius:"50%",background:TC[e.type]||"var(--d)",flexShrink:0}}/><div style={{flex:1}}><div style={{fontSize:11,fontFamily:F}}>{e.text}</div><div style={{fontSize:8,color:"var(--d)",fontFamily:F,marginTop:2}}>{hmFull(e.ts)} · {e.type?.toUpperCase()}</div></div></div>)}
    </div>
  </Card>;
}

function VSet({stealthVal,setStealthVal,mode,setMode}){
  const sp=stealthParams(stealthVal);
  const presetEntry=Object.entries(STEALTH_PRESETS).find(([,p])=>Math.abs(stealthVal-p.val)<10);
  const presetName=presetEntry?.[0]||`${stealthVal}%`;const presetColor=presetEntry?.[1]?.color||"var(--d)";
  return<div>
    <Card bc="#f59e0b44"><Sec t="⚠ API DATA WARNING"/><div style={{fontSize:11,fontFamily:F,color:"var(--w)",lineHeight:1.6}}>When using AI features, operation data is transmitted to the Claude API (Anthropic). Do not use with classified, sensitive, or non-public engagement data. Review your organization's data handling policy before use.</div></Card>
    <Card><Sec t={`STEALTH PROFILE — ${presetName.toUpperCase()}`}/>
      <input type="range" min={0} max={100} value={stealthVal} onChange={e=>setStealthVal(+e.target.value)} style={{width:"100%",marginBottom:12,accentColor:presetColor}}/>
      <div style={{display:"flex",gap:6,marginBottom:12}}>{Object.entries(STEALTH_PRESETS).map(([k,p])=><button key={k} onClick={()=>setStealthVal(p.val)} style={{flex:1,padding:"6px 0",borderRadius:4,background:presetName===k?p.color:"transparent",color:presetName===k?"#000":"var(--d)",border:`1px solid ${presetName===k?p.color:"var(--b)"}`,fontFamily:F,fontSize:9,cursor:"pointer",fontWeight:700,letterSpacing:1}}>{k.toUpperCase()}</button>)}</div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:8}}>{[["Delay",`${sp.delay}ms`],["Concurrent",sp.concurrent],["Jitter",`${sp.jitter}%`],["Tool Rotation",sp.toolRotation?"on":"off"],["DNS Style",sp.dnsStyle],["TLS Rotation",sp.tlsRotation?"on":"off"]].map(([l,v])=><div key={l} style={{padding:"8px 10px",background:"var(--bg)",borderRadius:4,border:"1px solid var(--b)"}}><div style={{fontSize:8,color:"var(--d)",fontFamily:F,letterSpacing:1}}>{l.toUpperCase()}</div><div style={{fontSize:12,fontWeight:700,fontFamily:F,marginTop:2}}>{v}</div></div>)}</div>
    </Card>
    <Card><Sec t="GATE MODE"/><div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>{Object.entries(GATE_MODES).map(([k,m])=><button key={k} onClick={()=>setMode(k)} style={{padding:12,borderRadius:6,cursor:"pointer",textAlign:"left",border:`2px solid ${mode===k?m.color:"var(--b)"}`,background:mode===k?`${m.color}18`:"var(--sf)"}}><div style={{fontSize:11,fontWeight:700,color:m.color,fontFamily:F,letterSpacing:1}}>{m.icon} {m.name}</div><div style={{fontSize:9,color:"var(--d)",fontFamily:F,marginTop:4}}>{m.desc}</div></button>)}</div></Card>
  </div>;
}

// ─── APP ROOT ─────────────────────────────────────────────────────────
export default function App(){
  const[view,sView]=useState("dashboard");
  const[op,sOp]=useState(structuredClone(EMPTY_OP));
  const[approvals,sAppr]=useState([]);const[findings,sFind]=useState([]);const[violations,sViol]=useState([]);
  const[actions,sAct]=useState([]);const[evidence,sEvid]=useState([]);const[tools,sTools]=useState([...TOOL_SLOTS]);
  const[knowledge,sKB]=useState([]);const[timeline,sTL]=useState([]);
  const[stealthVal,sStealthVal]=useState(35);const[mode,sMode]=useState("supervised");const[apiKey,sApiKey]=useState("");

  useEffect(()=>{(async()=>{try{const r=await storage.get("trident-v5");if(r){const d=JSON.parse(r.value);if(d.op)sOp(d.op);if(d.findings)sFind(d.findings);if(d.evidence)sEvid(d.evidence);if(d.actions)sAct(d.actions);if(d.approvals)sAppr(d.approvals);if(d.violations)sViol(d.violations);if(d.knowledge)sKB(d.knowledge);if(d.timeline)sTL(d.timeline);if(d.tools)sTools(d.tools);if(d.stealthVal!=null)sStealthVal(d.stealthVal);if(d.mode)sMode(d.mode);}}catch{}})();},[]);
  useEffect(()=>{const t=setTimeout(()=>{(async()=>{try{await storage.set("trident-v5",JSON.stringify({op,findings,evidence,actions,approvals,violations,knowledge,timeline,tools,stealthVal,mode}));}catch{}})();},1000);return()=>clearTimeout(t);},[op,findings,evidence,actions,approvals,violations,knowledge,timeline,tools,stealthVal,mode]);

  const addTL=useCallback((type,text)=>{sTL(p=>[...p,{id:uid(),type,text,ts:now()}]);},[]);
  const reset=()=>{if(!confirm("Reset all operation data?"))return;sOp(structuredClone(EMPTY_OP));sAppr([]);sFind([]);sViol([]);sAct([]);sEvid([]);sKB([]);sTL([]);sTools([...TOOL_SLOTS]);sStealthVal(35);sMode("supervised");sApiKey("");storage.delete("trident-v5").catch(()=>{});};

  const pc=approvals.filter(a=>a.status==="pending").length;
  const presetName=Object.entries(STEALTH_PRESETS).find(([,p])=>Math.abs(stealthVal-p.val)<10)?.[0]||`${stealthVal}%`;
  const nav=[{id:"dashboard",ic:"◈",l:"DASHBOARD"},{id:"scope",ic:"◎",l:"PERIMETER"},{id:"map",ic:"🗺",l:"NET MAP"},{id:"workbench",ic:"⚡",l:"WORKBENCH"},{id:"gate",ic:"⏳",l:"GATE",n:pc},{id:"findings",ic:"🔍",l:"FINDINGS",n:findings.length},{id:"evidence",ic:"🔗",l:"EVIDENCE",n:evidence.length},{id:"tools",ic:"🔧",l:"TOOLS"},{id:"cvss",ic:"📊",l:"CVSS"},{id:"report",ic:"📄",l:"REPORT"},{id:"knowledge",ic:"🧠",l:"KNOWLEDGE"},{id:"integrations",ic:"🔌",l:"INTEGRATIONS"},{id:"timeline",ic:"📋",l:"TIMELINE",n:timeline.length},{id:"settings",ic:"⚙",l:"SETTINGS"}];

  return<>
    <style>{CSS}</style>
    <div style={{display:"flex",height:"100vh",overflow:"hidden",fontFamily:F}}>
      <div style={{width:160,background:"var(--sf)",borderRight:"1px solid var(--b)",display:"flex",flexDirection:"column",flexShrink:0}}>
        <div style={{padding:"14px 12px",borderBottom:"1px solid var(--b)"}}><div style={{fontSize:14,fontWeight:700,color:"var(--a)",fontFamily:F,letterSpacing:2}}>◈ TRIDENT</div><div style={{fontSize:8,color:"var(--d)",fontFamily:F,marginTop:2}}>{op.operation.name||"No operation"}</div></div>
        <div style={{flex:1,overflowY:"auto",padding:"6px 0"}}>{nav.map(n=><button key={n.id} onClick={()=>sView(n.id)} style={{width:"100%",display:"flex",alignItems:"center",gap:7,padding:"7px 12px",background:"transparent",border:"none",borderLeft:view===n.id?"2px solid var(--a)":"2px solid transparent",color:view===n.id?"var(--fg)":"var(--d)",fontFamily:F,fontSize:10,cursor:"pointer",letterSpacing:.5,textAlign:"left"}}><span style={{fontSize:11,width:14,textAlign:"center"}}>{n.ic}</span><span style={{flex:1}}>{n.l}</span>{(n.n||0)>0&&<span style={{background:n.id==="gate"&&pc>0?"var(--r)":"var(--bs)",color:n.id==="gate"&&pc>0?"#fff":"var(--d)",fontSize:7,padding:"1px 4px",borderRadius:6,fontWeight:700,minWidth:14,textAlign:"center"}}>{n.n}</span>}</button>)}</div>
        <div style={{padding:"8px 12px",borderTop:"1px solid var(--b)"}}><div style={{display:"flex",alignItems:"center",gap:5,fontSize:8,fontFamily:F,color:"var(--d)",marginBottom:4}}><div style={{width:5,height:5,borderRadius:"50%",background:GATE_MODES[mode].color}}/>{GATE_MODES[mode].name}</div><div style={{fontSize:8,fontFamily:F,color:"var(--d)",marginBottom:6}}>Stealth: {presetName.toUpperCase()}</div><button onClick={reset} style={{width:"100%",padding:"4px 0",background:"transparent",border:"1px solid var(--b)",borderRadius:3,color:"var(--d)",fontFamily:F,fontSize:8,cursor:"pointer",letterSpacing:1}}>RESET</button></div>
      </div>
      <div style={{flex:1,padding:"20px 24px",overflowY:"auto"}}>
        {view==="dashboard"    &&<VDash op={op} approvals={approvals} findings={findings} violations={violations} actions={actions} evidence={evidence} timeline={timeline}/>}
        {view==="scope"        &&<VScope op={op} setOp={sOp}/>}
        {view==="map"          &&<VMap op={op} actions={actions} violations={violations}/>}
        {view==="workbench"    &&<VWorkbench op={op} mode={mode} setActions={sAct} setViolations={sViol} setEvidence={sEvid} addTL={addTL} actions={actions} evidence={evidence} apiKey={apiKey} sApiKey={sApiKey} setApprovals={sAppr}/>}
        {view==="gate"         &&<VGate approvals={approvals} setApprovals={sAppr} addTL={addTL}/>}
        {view==="findings"     &&<VFind findings={findings} setFindings={sFind} op={op} addTL={addTL} apiKey={apiKey} sApiKey={sApiKey}/>}
        {view==="evidence"     &&<VEvid evidence={evidence}/>}
        {view==="tools"        &&<VTools tools={tools} setTools={sTools}/>}
        {view==="cvss"         &&<VCvss/>}
        {view==="report"       &&<VReport op={op} findings={findings} evidence={evidence} apiKey={apiKey} sApiKey={sApiKey}/>}
        {view==="knowledge"    &&<VKB knowledge={knowledge} setKnowledge={sKB} apiKey={apiKey} sApiKey={sApiKey}/>}
        {view==="integrations" &&<VInteg findings={findings} evidence={evidence} op={op} setFindings={sFind} addTL={addTL} apiKey={apiKey} sApiKey={sApiKey}/>}
        {view==="timeline"     &&<VTL timeline={timeline}/>}
        {view==="settings"     &&<VSet stealthVal={stealthVal} setStealthVal={sStealthVal} mode={mode} setMode={sMode}/>}
      </div>
    </div>
  </>;
}
