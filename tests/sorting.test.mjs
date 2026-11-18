import test from 'node:test';
import assert from 'node:assert/strict';
import {compareNodes} from '../src/model.js';
const rows={A:{loss:20,lastState:'ok'},B:{loss:5,lastState:'fail'},C:{loss:null},D:{loss:NaN}};
const sort=(key,d)=>Object.keys(rows).sort((a,b)=>compareNodes(a,b,key,d,n=>rows[n]));
test('numeric sorting reverses with missing values always last',()=>{
 assert.deepEqual(sort('loss',1),['B','A','C','D']);
 assert.deepEqual(sort('loss',-1),['A','B','C','D']);
});
test('name and status sorting are deterministic',()=>{
 assert.deepEqual(sort('name',-1),['D','C','B','A']);
 assert.deepEqual(sort('status',-1),['B','A','C','D']);
});
