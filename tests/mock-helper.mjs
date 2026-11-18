// Local UI acceptance fixture. Generates deterministic samples; sends no network probes.
import http from 'node:http';
import {readFileSync} from 'node:fs';
const names=Array.from({length:156},(_,i)=>`Fixture ${String(i+1).padStart(3,'0')}`);
let job=null;
http.createServer(async(req,res)=>{
 const path=new URL(req.url,'http://localhost').pathname;
 if(path==='/'){res.setHeader('Content-Type','text/html');res.end(readFileSync('.internal/dist/index.html'));return;}
 let body='';for await(const part of req)body+=part;
 res.setHeader('Content-Type','application/json');
 let data={};
 if(path==='/api/nodes')data={nodes:names.map(name=>({name,type:'Fixture'})),groups:{}};
 if(path==='/api/snapshot')data={clash:{},connections:[]};
 if(path.endsWith('/start')){
  const options=JSON.parse(body);
  if(options.consent!==true){res.statusCode=400;res.end(JSON.stringify({error:'Consent required'}));return;}
  job={id:'fixture-'+Date.now(),options,state:'running',started_at:new Date().toISOString(),rows:options.nodes.map(name=>({name}))};
 }
 if(path.endsWith('/stop')&&job){job.state='cancelled';job.finished_at=new Date().toISOString();}
 if(job&&job.state==='running'){
  const count=Math.min(60,Math.floor((Date.now()-Date.parse(job.started_at))/1000));
  job.rows=job.rows.map((row,i)=>({...row,recent:Array.from({length:count},(_,j)=>({at:new Date(Date.parse(job.started_at)+j*1000).toISOString(),[job.options.mode]:{state:(j+i)%4===0?'fail':'ok',ms:30+i}}))}));
 }
 if(path.startsWith('/api/monitor'))data={monitor:job,history:[]};
 if(path.startsWith('/api/stability'))data={job:job&&{...job,rows:job.rows.map(r=>({...r,samples:r.recent}))}};
 res.end(JSON.stringify(data));
}).listen(4175,'127.0.0.1',()=>console.log('Fixture preview: http://127.0.0.1:4175/#token=fixture'));
