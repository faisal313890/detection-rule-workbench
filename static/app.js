'use strict';
const $=id=>document.getElementById(id);
let result=null,csvText='',busy=false;
const sampleButtons=[...document.querySelectorAll('.sample')];
function invalidate(){result=null;csvText='';$('results').hidden=true;}
function setBusy(value){busy=value;for(const element of [...sampleButtons,...['run','clear','format','candidate','baseline','events','compare','event-file'].map($)])element.disabled=value;}
async function request(path,method='GET',body){
  const options={method,headers:{'X-Rule-Workbench':'local'},cache:'no-store',credentials:'omit'};
  if(body!==undefined){options.headers['Content-Type']='application/json';options.body=JSON.stringify(body);}
  const response=await fetch('/api/'+path,options),data=await response.json();
  if(!response.ok)throw new Error(data.error||'Local request failed.');return data;
}
async function sample(name){if(busy)return;invalidate();setBusy(true);try{
  const data=await request('sample/'+name);$('candidate').value=data.candidate;$('baseline').value=data.baseline;
  $('events').value=data.events;$('compare').checked=data.compare;$('baseline-panel').hidden=!data.compare;$('event-file').value='';
  $('status').textContent=name==='invalid'?'Unsupported rule loaded. Test it to see explicit validation rejection.':'Example loaded. Review the inputs, then select Test rule.';
}catch(error){$('status').textContent=error.message;}finally{setBusy(false);}}
function textCell(row,value,cls){const cell=document.createElement('td');cell.textContent=value;if(cls)cell.className=cls;row.append(cell);}
function bool(value){return value===null?'unlabeled':value?'yes':'no';}
function percent(value){return value===null?'N/A':(value*100).toFixed(1)+'%';}
function render(){
  const r=result;$('results').hidden=false;$('coverage-state').textContent=r.status.replaceAll('_',' ').toUpperCase();
  $('valid-count').textContent=r.input.valid_events;$('match-count').textContent=r.candidate.matches;
  $('invalid-count').textContent=r.input.invalid_records;$('changed-count').textContent=r.baseline?r.changed_match_count:'—';
  $('summary').textContent=r.status==='no_valid_events'?'No valid events were available; zero matches is not a completed detection assessment.':r.status==='partial'?'Some records were invalid and excluded. Review parsing diagnostics before interpreting matches.':'All nonblank records met the normalized event schema. This does not establish complete telemetry coverage.';
  $('metric-rows').replaceChildren();
  for(const name of ['baseline','candidate']){const item=r[name];if(!item)continue;const tr=document.createElement('tr'),c=item.counts;
    for(const value of [name,item.source_eligible+' / '+item.source_excluded,item.matches,c.true_positive,c.false_positive,c.false_negative,c.true_negative,c.unlabeled,percent(item.metrics.precision),percent(item.metrics.recall)])textCell(tr,value);
    $('metric-rows').append(tr);}
  $('change-summary').textContent=r.baseline?r.changed_match_count+' event matches changed; omitted details: '+r.omitted_changed_matches+'.':'No baseline comparison requested.';
  $('change-rows').replaceChildren();for(const row of r.changed_matches){const tr=document.createElement('tr');for(const value of [row.line,row.event_id,bool(row.baseline_matched),bool(row.candidate_matched),bool(row.expected_match)])textCell(tr,value);$('change-rows').append(tr);}
  $('coverage-summary').textContent='Physical lines: '+r.input.physical_lines+' · Blank: '+r.input.blank_lines+' · Valid: '+r.input.valid_events+' · Invalid: '+r.input.invalid_records+' · Omitted diagnostics: '+r.omitted_diagnostics;
  $('missing-fields').textContent=JSON.stringify({candidate:r.candidate.missing_field_predicates,...(r.baseline?{baseline:r.baseline.missing_field_predicates}:{})},null,2);
  $('diagnostics').textContent=r.diagnostics.length?JSON.stringify(r.diagnostics,null,2):'No parsing diagnostics.';
  $('event-rows').replaceChildren();$('predicate-evidence').replaceChildren();
  $('evidence-summary').textContent='Showing '+r.candidate.rows.length+' candidate events; omitted: '+r.candidate.omitted_rows+'. CSV includes at most 200 rows per rule; full aggregate counts cover all valid events.';
  for(const row of r.candidate.rows){const tr=document.createElement('tr');textCell(tr,row.line+' / '+row.event_id);textCell(tr,row.source_matches?'eligible':'excluded');textCell(tr,bool(row.matched),row.matched?'highlight':'');textCell(tr,bool(row.expected_match));textCell(tr,row.outcome.replaceAll('_',' '));textCell(tr,Object.entries(row.selections).map(([key,value])=>key+': '+value).join('; ')||'not evaluated');$('event-rows').append(tr);
    const details=document.createElement('details'),summary=document.createElement('summary'),pre=document.createElement('pre');summary.textContent='Line '+row.line+' · '+row.event_id;pre.textContent=JSON.stringify(row,null,2);details.append(summary,pre);$('predicate-evidence').append(details);}
  $('configuration').textContent=JSON.stringify({candidate:r.candidate.rule,candidate_sha256:r.candidate.rule_sha256,baseline:r.baseline?.rule||null,baseline_sha256:r.baseline?.rule_sha256||null,events_sha256:r.input.events_sha256},null,2);
  $('limits').replaceChildren();for(const limit of r.limits){const li=document.createElement('li');li.textContent=limit;$('limits').append(li);}
  $('report-id').textContent='Report '+r.report_id+' · '+r.observed_at+' · No external requests';
}
for(const button of sampleButtons)button.addEventListener('click',()=>sample(button.dataset.sample));
for(const id of ['candidate','baseline','events'])$(id).addEventListener('input',()=>{invalidate();$('status').textContent='Inputs changed. Test again to produce current evidence.';});
$('compare').addEventListener('change',()=>{invalidate();$('baseline-panel').hidden=!$('compare').checked;$('status').textContent='Comparison setting changed. Test again.';});
$('format').addEventListener('click',async()=>{if(busy)return;invalidate();setBusy(true);try{const data=await request('validate','POST',{rule:$('candidate').value});$('candidate').value=JSON.stringify(data.rule,null,2);$('status').textContent='Rule validated and JSON formatted. Test it against events next.';}catch(e){$('status').textContent='Cannot format: '+e.message;}finally{setBusy(false);}});
$('event-file').addEventListener('change',async()=>{const file=$('event-file').files[0];if(!file)return;invalidate();if(file.size>1024*1024){$('status').textContent='File exceeds 1 MiB.';return;}setBusy(true);try{const text=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());$('events').value=text;$('status').textContent='Loaded '+file.name+'. Test the rule to review parsing coverage.';}catch(e){$('status').textContent='Cannot load UTF-8 event file: '+e.message;}finally{setBusy(false);}});
$('run').addEventListener('click',async()=>{if(busy)return;invalidate();setBusy(true);$('status').textContent='Evaluating rules locally…';try{const data=await request('run','POST',{candidate:$('candidate').value,baseline:$('baseline').value,events:$('events').value,compare:$('compare').checked});result=data.report;csvText=data.csv;render();$('status').textContent=result.status==='no_valid_events'?'No valid events to evaluate. Review diagnostics.':'Evaluation complete. Review coverage and fixture expectations.';}catch(error){$('status').textContent='Validation / evaluation stopped: '+error.message;}finally{setBusy(false);}});
$('clear').addEventListener('click',()=>{if(busy)return;invalidate();for(const id of ['candidate','baseline','events','event-file'])$(id).value='';$('compare').checked=false;$('baseline-panel').hidden=true;$('status').textContent='Session cleared. Existing downloads are unchanged.';});
function download(name,type,text){const url=URL.createObjectURL(new Blob([text],{type})),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
$('json').addEventListener('click',()=>{if(result)download('rule-report.json','application/json',JSON.stringify(result,null,2));});
$('csv').addEventListener('click',()=>{if(result)download('rule-evidence.csv','text/csv;charset=utf-8','\ufeff'+csvText);});
$('rule-json').addEventListener('click',()=>{if(result)download('candidate-rule.json','application/json',JSON.stringify(result.candidate.rule,null,2));});
$('print').addEventListener('click',()=>{if(result)window.print();});
sample('broad');
