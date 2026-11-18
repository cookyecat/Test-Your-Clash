import test from 'node:test';
import assert from 'node:assert/strict';
import {probeStats, normalizeSamples} from '../src/model.js';
test('loss excludes collection errors and gaps; latest failure clears latency',()=>{
 const s=probeStats({samples:[{state:'ok',ms:30},{state:'error'},{state:'skipped'},{state:'fail'}]});
 assert.equal(s.loss,50);assert.equal(s.tested,2);assert.equal(s.lastMs,null);assert.equal(s.streak,1);
 assert.equal(s.mean,30);assert.equal(s.error,1);assert.equal(s.skipped,1);
});
test('cumulative totals differ from recent window; helper latest state works without raw history',()=>{
 const s=probeStats({summary:{ok:90,failed:10,errors:2,skipped:3,current_failure_streak:4,last_state:'fail',last_ms:null,avg_ms:42},samples:[{state:'fail'},{state:'fail'}]});
 assert.equal(s.loss,10);assert.equal(s.recentLoss,100);assert.equal(s.streak,4);assert.equal(s.lastState,'fail');assert.equal(s.mean,42);
});
test('last 20 observations retain errors without misreporting them as packet loss',()=>{
 const s=probeStats({samples:[{state:'fail'},...Array.from({length:20},()=>({state:'error'}))]});
 assert.equal(s.loss,100);assert.equal(s.recentLoss,null);assert.equal(s.recentTested,0);
});
test('nested ICMP, legacy flat data and absent metric normalize honestly',()=>{
 const rows=normalizeSamples([{at:'2026-01-01T00:00:00Z',icmp:{state:'ok',ms:2}},{at:10,state:'fail'},{at:20,https:{state:'ok',ms:4}}],'icmp');
 assert.deepEqual(rows.map(s=>s.state),['fail','skipped','ok']);
 assert.equal(rows[2].ms,2);
});
