import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Execute the actual click handler against the helper's required request contract.
const source = readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');
const handler = source.slice(source.indexOf('async function start()'), source.indexOf('\nfunction schedule()'));
for (const tab of ['continuous', 'quick']) {
  test(`${tab}: explicit Start sends consent and selected nodes to the helper`, async () => {
    const calls = [];
    const fields = {target:'cloudflare', interval:'15', timeout:'5000', workers:'4', duration:'1800'};
    const context = vm.createContext({
      busy:false, active:()=>false, conn:{kind:'helper'}, selected:new Set(['node A','node B']),
      tab, $:id=>({value:fields[id]}), t:zh=>zh,
      api:async (path, request)=>{
        assert.equal(request.body.consent, true, 'helper rejects requests without explicit consent');
        calls.push({path, ...request});
      },
      pollHelper:async quick=>calls.push({quick}), render:()=>{},
      toast:message=>assert.fail(message), releaseLock:null,
    });
    await vm.runInContext(handler+'; start()', context);
    assert.equal(calls[0].path, tab==='quick'?'/api/stability/start':'/api/monitor/start');
    assert.equal(calls[0].method, 'POST');
    assert.deepEqual(Array.from(calls[0].body.nodes), ['node A','node B']);
    assert.equal(calls[1].quick, tab==='quick');
    assert.equal(context.busy, false);
  });
}
