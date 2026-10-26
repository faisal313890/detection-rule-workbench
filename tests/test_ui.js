// Controller smoke harness only: no CSS layout or real-browser download validation.
// Start server.py on 8830, then run: node tests/test_ui.js
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const nodes={},downloads=[],blobs=new Map();let printed=false;
class Element{
  constructor(){this.value='';this.textContent='';this.hidden=false;this.disabled=false;this.checked=false;this.children=[];this.handlers={};this.dataset={};this.files=[];}
  addEventListener(name,fn){this.handlers[name]=fn;}
  append(...items){this.children.push(...items);}
  replaceChildren(...items){this.children=items;}
  click(){if(this.href)downloads.push({name:this.download,blob:blobs.get(this.href)});}
}
const html=fs.readFileSync('static/index.html','utf8');
for(const [,id] of html.matchAll(/id="([^"]+)"/g))nodes[id]=new Element();
const buttons=['broad','tuned','auth','partial','invalid'].map(name=>{const el=new Element();el.dataset.sample=name;return el;});
const context={document:{getElementById:id=>{assert.ok(nodes[id],`Missing DOM ID: ${id}`);return nodes[id];},querySelectorAll:()=>buttons,createElement:()=>new Element()},
  fetch:(path,options)=>fetch('http://127.0.0.1:8830'+path,options),Blob,TextDecoder,
  URL:{createObjectURL:blob=>{const id='blob:'+blobs.size;blobs.set(id,blob);return id;},revokeObjectURL:()=>{}},
  window:{print:()=>{printed=true;}},setTimeout,console};
vm.createContext(context);vm.runInContext(fs.readFileSync('static/app.js','utf8'),context);
(async()=>{
  for(let i=0;i<100&&!nodes.status.textContent.startsWith('Example loaded');i++)await new Promise(r=>setTimeout(r,10));
  assert.match(nodes.status.textContent,/Example loaded/);
  await nodes.run.handlers.click();assert.equal(Number(nodes['valid-count'].textContent),6);assert.equal(Number(nodes['match-count'].textContent),3);
  assert.equal(nodes['event-rows'].children.length,6);
  await buttons[1].handlers.click();await nodes.run.handlers.click();assert.equal(Number(nodes['changed-count'].textContent),2);
  nodes.json.handlers.click();nodes.csv.handlers.click();nodes['rule-json'].handlers.click();nodes.print.handlers.click();
  const report=JSON.parse(await downloads[0].blob.text());assert.equal(report.candidate.counts.true_positive,3);assert.equal(report.baseline.counts.false_positive,1);
  assert.equal((await downloads[1].blob.text()).trim().split('\r\n').length,13);
  assert.equal(JSON.parse(await downloads[2].blob.text()).format,'drw/1');assert.ok(printed);
  await buttons[3].handlers.click();await nodes.run.handlers.click();assert.equal(nodes['coverage-state'].textContent,'PARTIAL');assert.equal(Number(nodes['invalid-count'].textContent),2);
  await buttons[4].handlers.click();await nodes.run.handlers.click();assert.equal(nodes.results.hidden,true);assert.match(nodes.status.textContent,/Unsupported modifier/);
  await buttons[0].handlers.click();await nodes.format.handlers.click();assert.match(nodes.status.textContent,/Rule validated/);
  nodes.clear.handlers.click();assert.equal(nodes.candidate.value,'');assert.equal(nodes.results.hidden,true);
  console.log('UI controller smoke passed: all samples, comparison, explicit rejection, format validation, JSON/CSV/rule payloads, print call, clear.');
})().catch(error=>{console.error(error);process.exitCode=1;});
