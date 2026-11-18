import {test} from 'node:test';
import assert from 'node:assert/strict';
import {summarize,classify,leaves,nextDue,csv} from '../src/model.js';
test('errors and gaps never inflate failure denominator',()=>{const s=summarize([{state:'ok',ms:20},{state:'fail'},{state:'error'},{state:'skipped'},{state:'ok',ms:80}]);assert.equal(s.tested,3);assert.equal(s.p50,20);assert.equal(s.p95,80);assert.ok(Math.abs(s.rate-200/3)<1e-10)});
test('failure streak breaks across missing evidence',()=>assert.equal(summarize([{state:'fail'},{state:'skipped'},{state:'fail'},{state:'fail'}]).max,2));
test('only recognized delay failures are node failures',()=>{for(const code of [400,401,403,404,429,500])assert.equal(classify(code,{message:'error'}).state,'error');assert.equal(classify(503,{message:'test failed'}).state,'fail');assert.equal(classify(504,{message:'timeout'}).state,'fail');assert.equal(classify(200,{}).state,'error');assert.equal(classify(200,{delay:42}).ms,42)});
test('nested groups deduplicate and tolerate cycles',()=>assert.deepEqual(leaves({A:{all:['B','n','DIRECT']},B:{all:['A','n']},n:{type:'Shadowsocks'},DIRECT:{type:'Direct'}},'A'),['n']));
test('scheduler skips missed slots instead of replaying',()=>assert.equal(nextDue(0,49000,15000),60000));
test('CSV guards formulas and quote escaping',()=>assert.ok(csv([['=cmd','a"b']]).includes('"\'=cmd","a""b"')));
