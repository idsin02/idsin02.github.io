/* Deterministic Phase 2 correlation and tuning engine. No external requests. */
(function(root){
'use strict';
var L=root.DETECTION_LAB,D=root.PHASE2_DATA;if(!L||!D)return;
var rank={uncovered:0,indirect:1,partial:2,direct:3};
function strongest(a,b){return rank[a]>=rank[b]?a:b;}
function coverage(){
 var byTactic={};D.tactics.forEach(function(t){byTactic[t.id]={id:t.id,name:t.name,gaps:t.gaps.slice(),techniques:{}};});
 L.detections.forEach(function(d){(d.attackMappings||[]).forEach(function(m){
  var t=byTactic[m.tacticId]||(byTactic[m.tacticId]={id:m.tacticId,name:m.tactic,gaps:[],techniques:{}}),x=t.techniques[m.techniqueId];
  if(!x)x=t.techniques[m.techniqueId]={id:m.techniqueId,subTechniqueId:m.subTechniqueId||'',name:m.technique,coverage:m.coverage||'indirect',detections:[],telemetry:[]};
  x.coverage=strongest(x.coverage,m.coverage||'indirect');
  if(!x.detections.some(function(y){return y.id===d.id;}))x.detections.push({id:d.id,name:d.name,language:d.language,lab:d.lab,coverage:m.coverage||'indirect'});
  (m.telemetry||d.dataSources||[]).forEach(function(s){if(x.telemetry.indexOf(s)<0)x.telemetry.push(s);});
 });});
 return D.tactics.map(function(base){var t=byTactic[base.id],vals=Object.keys(t.techniques).map(function(k){return t.techniques[k];});return {id:t.id,name:t.name,gaps:t.gaps,techniques:vals,stats:{direct:vals.filter(function(x){return x.coverage==='direct';}).length,partial:vals.filter(function(x){return x.coverage==='partial';}).length,indirect:vals.filter(function(x){return x.coverage==='indirect';}).length,uncovered:t.gaps.length,detections:vals.reduce(function(n,x){return n+x.detections.length;},0)}};});
}
function investigationFor(scenario){
 if(D.investigations[scenario])return D.investigations[scenario];
 if(/lsass/.test(scenario))return D.investigations.lsass;
 if(/kerberoast/.test(scenario))return D.investigations['ad-kerberoast'];
 if(/encps/.test(scenario))return D.investigations.encps;
 return null;
}
function validateInvestigation(inv){
 if(!inv)return {ok:false,errors:['No shared investigation data for this scenario.']};
 var ids={},errors=[];inv.processes.forEach(function(p){if(ids[p.id])errors.push('Duplicate process '+p.id);ids[p.id]=p;});
 inv.processes.forEach(function(p){if(p.parentId&&!ids[p.parentId])errors.push('Missing parent '+p.parentId+' for '+p.id);if(p.parentId&&ids[p.parentId]&&+ids[p.parentId].pid!==+p.ppid)errors.push('PPID mismatch for '+p.id);});
 var prev=0;inv.timeline.forEach(function(e){var ts=Date.parse(e.timestamp);if(ts<prev)errors.push('Timeline not chronological at '+e.id);prev=ts;if(e.processId&&!ids[e.processId])errors.push('Missing process link '+e.processId);});
 return {ok:errors.length===0,errors:errors};
}
function iocsFor(inv){if(!inv)return[];var ids=inv.timeline.map(function(e){return e.id;});return D.iocs.filter(function(x){return x.investigation===inv.id||(x.events||[]).some(function(e){return ids.indexOf(e)>=0;});});}
function corpusKey(s){if(D.tuningCorpora[s])return s;if(/lsass/.test(s))return'lsass';if(/kerberoast/.test(s))return'ad-kerberoast';if(/encps/.test(s))return'encps';return'';}
function originalMatch(key,e){if(key==='encps')return!!e.encoded;if(key==='lsass')return!!e.dumpMarker;if(key==='ad-kerberoast')return e.count>=5||e.distinct>=5;return false;}
function tunedMatch(key,e,c){
 var hit=originalMatch(key,e);
 if(key==='encps'){
  if(c.requireUnusualParent)hit=hit&&!!e.unusualParent;
  if(c.processes&&c.processes.length)hit=hit&&c.processes.indexOf(String(e.process).toLowerCase())>=0;
 }
 if(key==='ad-kerberoast')hit=(e.count>=c.threshold||e.distinct>=c.threshold);
 if(c.excludeKnownGood)hit=hit&&!e.knownGood;
 if(c.excludedHosts.indexOf(String(e.host).toLowerCase())>=0)hit=false;
 if(c.excludedUsers.indexOf(String(e.user).toLowerCase())>=0)hit=false;
 return hit;
}
function metric(rows,match){var tp=0,fp=0,fn=0,tn=0;rows.forEach(function(e){var h=match(e);if(h&&e.malicious)tp++;else if(h&&!e.malicious)fp++;else if(!h&&e.malicious)fn++;else tn++;});var div=function(a,b){return b?+(a/b).toFixed(3):null;};return {total:rows.length,tp:tp,fp:fp,fn:fn,tn:tn,precision:div(tp,tp+fp),recall:div(tp,tp+fn),fpr:div(fp,fp+tn),detections:tp+fp};}
function tuning(d,query,cfg){
 var key=corpusKey(d.scenario),rows=D.tuningCorpora[key]||[];
 if(!rows.length)return {available:false,message:'Ground-truth tuning data is not available for this scenario; metrics are intentionally not fabricated.'};
 var c={threshold:Math.max(1,+cfg.threshold||5),timeWindow:Math.max(1,+cfg.timeWindow||15),excludeKnownGood:!!cfg.excludeKnownGood,requireUnusualParent:!!cfg.requireUnusualParent,processes:String(cfg.processes||'').toLowerCase().split(',').map(function(x){return x.trim();}).filter(Boolean),excludedHosts:String(cfg.excludedHosts||'').toLowerCase().split(',').map(function(x){return x.trim();}).filter(Boolean),excludedUsers:String(cfg.excludedUsers||'').toLowerCase().split(',').map(function(x){return x.trim();}).filter(Boolean)};
 var warnings=[];if(String(query).trim()!==String(d.query).trim())warnings.push('Manual query text is preserved but not interpreted by the local tuning engine; only the controls below affect tuned metrics.');
 var original=metric(rows,function(e){return originalMatch(key,e);}),tuned=metric(rows,function(e){return tunedMatch(key,e,c);});
 return {available:true,key:key,rows:rows,config:c,original:original,tuned:tuned,warnings:warnings,query:d.query,tunedQuery:buildTunedQuery(d,c)};
}
function buildTunedQuery(d,c){var notes=['// Tuned local variant — original rule remains unchanged.','// time window: '+c.timeWindow+'m'];if(c.excludeKnownGood)notes.push('// excludes labelled approved-management activity');if(c.requireUnusualParent)notes.push('// requires an unusual parent process');if(c.excludedHosts.length)notes.push('// excluded hosts: '+c.excludedHosts.join(', '));if(c.excludedUsers.length)notes.push('// excluded users: '+c.excludedUsers.join(', '));if(c.processes.length)notes.push('// suspicious processes: '+c.processes.join(', '));notes.push('// deterministic threshold: '+c.threshold);return notes.join('\n')+'\n'+d.query;}
function selfTest(){var inv=Object.keys(D.investigations).map(function(k){return validateInvestigation(D.investigations[k]);}),cov=coverage(),t=tuning(L.detections.find(function(x){return x.scenario==='encps';}),L.detections.find(function(x){return x.scenario==='encps';}).query,{excludeKnownGood:true,requireUnusualParent:true,threshold:5,timeWindow:15});return {investigations:inv.every(function(x){return x.ok;}),tactics:cov.length===14,coverageMappings:L.detections.every(function(x){return x.attackMappings&&x.attackMappings.length;}),iocLinks:D.iocs.every(function(i){return i.events.every(function(e){return Object.keys(D.investigations).some(function(k){return D.investigations[k].timeline.some(function(x){return x.id===e;});});});}),tuning:t.available&&t.original.total===t.tuned.total};}
root.Phase2Engine={coverage:coverage,investigationFor:investigationFor,validateInvestigation:validateInvestigation,iocsFor:iocsFor,tuning:tuning,selfTest:selfTest};
})(window);