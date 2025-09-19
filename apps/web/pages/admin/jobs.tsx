import { useState } from 'react';
const sources = ['NVD','OSV','GHSA','CISA_KEV','RSS'];
export default function Jobs(){
  const [busy, setBusy] = useState<string|null>(null);
  const run = async (k:string) => {
    setBusy(k);
    await fetch(`/api/admin/run?kind=${k}`, { method: 'POST' });
    setBusy(null);
  };
  return (
    <div style={{padding:24}}>
      <h1 style={{fontSize:24}}>Jobs</h1>
      {sources.map(k => (
        <button key={k} onClick={()=>run(k)} disabled={busy===k}
          style={{marginRight:8, padding:'8px 12px', background:'#0049B7', color:'#fff', borderRadius:10, opacity: busy===k?0.6:1}}>
          {busy===k? 'Running…' : `Refresh ${k} now`}
        </button>
      ))}
    </div>
  );
}