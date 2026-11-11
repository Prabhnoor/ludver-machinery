(() => {
  'use strict';
  const root=typeof window==='undefined'?globalThis:window,model=root.PROPOSAL_VAULT_CRYPTO;
  const decoder=new TextDecoder();
  async function download(url,signal){
    const response=await fetch(url,{credentials:'same-origin',cache:'no-store',signal});
    if(!response.ok||/text\/html/i.test(response.headers.get('content-type')||''))throw Error('The protected file could not be loaded. Please try again.');
    return new Uint8Array(await response.arrayBuffer());
  }
  async function unlock(password,config){
    const salt=Uint8Array.from(atob(config.salt),c=>c.charCodeAt(0));
    const key=await model.deriveKey(password,salt,config.iterations);
    const manifest=JSON.parse(decoder.decode(await model.open(key,await download(config.manifest),'proposal-manifest-v1')));
    if(manifest.version!==1||!manifest.files?.[manifest.entry])throw Error('Invalid proposal package.');
    const read=async(path,signal)=>{
      const name=String(path).replace(/^\.\//,''),item=manifest.files[name];
      if(!item)throw Error('This file is not part of the protected proposal.');
      return model.open(key,await download(item.url,signal),name);
    };
    return {manifest,read};
  }
  function createAccess(session,doc=document){
    const imageURLs=new Map(),players=new Set();let sequence=0;
    const connected=node=>node.isConnected!==false;
    const imageURL=async path=>{
      if(!imageURLs.has(path))imageURLs.set(path,(async()=>{
        const data=await session.read(path);return URL.createObjectURL(new Blob([data],{type:session.manifest.files[path].mime}));
      })());
      try{return await imageURLs.get(path);}catch(error){imageURLs.delete(path);throw error;}
    };
    function release(record){
      record.controller?.abort();record.controller=null;
      if(record.url){record.node.pause();record.node.removeAttribute('src');record.node.load();URL.revokeObjectURL(record.url);record.url=null;}
      record.button.hidden=false;record.button.disabled=false;record.button.textContent='Play video';record.button.removeAttribute('aria-busy');
    }
    function attach(node,item){
      if(!session.manifest.files[item.src]){node.src=item.src;if(item.poster)node.poster=item.poster;return;}
      const video=node.tagName.toLowerCase()==='video';
      if(!video){imageURL(item.src).then(url=>{if(connected(node))node.src=url;}).catch(()=>node.dispatchEvent(new Event('error')));return;}
      node.preload='none';
      if(item.poster&&session.manifest.files[item.poster])imageURL(item.poster).then(url=>{if(connected(node))node.poster=url;}).catch(()=>{});
      const button=doc.createElement('button');button.type='button';button.className='vault-play';button.textContent='Play video';button.setAttribute('aria-label','Play '+(item.caption||'reference video'));node.parentNode.append(button);
      const record={node,button,url:null,controller:null};players.add(record);
      button.addEventListener('click',async event=>{
        event.preventDefault();event.stopPropagation();const ticket=++sequence;
        for(const other of players)if(other!==record)release(other);
        if(record.url){button.hidden=true;try{await node.play();}catch{button.hidden=false;}return;}
        button.disabled=true;button.textContent='Loading video…';button.setAttribute('aria-busy','true');record.controller=new AbortController();
        try{
          const data=await session.read(item.src,record.controller.signal);
          if(ticket!==sequence||!connected(node))return;
          record.url=URL.createObjectURL(new Blob([data],{type:session.manifest.files[item.src].mime}));node.src=record.url;node.load();button.hidden=true;
          try{await node.play();}catch{button.hidden=false;button.textContent='Play video';}
        }catch(error){
          if(ticket!==sequence||!connected(node)||error.name==='AbortError')return;
          button.textContent='Video could not load · retry';
        }finally{if(ticket===sequence){button.disabled=false;button.removeAttribute('aria-busy');record.controller=null;}}
      });
    }
    const observer=new MutationObserver(()=>{
      for(const record of players)if(!connected(record.node)){release(record);players.delete(record);}
    });observer.observe(doc.body,{childList:true,subtree:true});
    return {
      read:session.read,attach,
      lock(){sequence++;for(const record of players)release(record);observer.disconnect();for(const pending of imageURLs.values())pending.then(url=>URL.revokeObjectURL(url)).catch(()=>{});imageURLs.clear();root.location.reload();}
    };
  }
  root.PROPOSAL_VAULT_BOOT=Object.freeze({unlock,createAccess});
  if(typeof document==='undefined'||!document.querySelector('#accessForm'))return;
  const form=document.querySelector('#accessForm'),field=document.querySelector('#proposalPassword'),button=document.querySelector('#unlockProposal'),error=document.querySelector('#accessError'),toggle=document.querySelector('#togglePassword');
  toggle.addEventListener('click',()=>{const show=field.type==='password';field.type=show?'text':'password';toggle.textContent=show?'Hide':'Show';toggle.setAttribute('aria-label',show?'Hide password':'Show password');toggle.setAttribute('aria-pressed',String(show));});
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(button.disabled)return;error.textContent='';button.disabled=true;button.textContent='Opening proposal…';
    if(!root.crypto?.subtle){error.textContent='Open this secure website in a current browser to continue.';button.disabled=false;button.textContent='Open proposal →';return;}
    let verified=false;
    try{
      const password=field.value;field.value='';
      const session=await unlock(password,root.PROPOSAL_GATE_CONFIG);verified=true;
      const html=decoder.decode(await session.read(session.manifest.entry));
      const parsed=new DOMParser().parseFromString(html,'text/html');
      const scripts=[...parsed.querySelectorAll('script')].map(script=>script.textContent);parsed.querySelectorAll('script').forEach(script=>script.remove());
      root.PROPOSAL_VAULT=createAccess(session);
      document.head.replaceChildren(...[...parsed.head.childNodes].map(node=>document.importNode(node,true)));
      document.body.replaceChildren(...[...parsed.body.childNodes].map(node=>document.importNode(node,true)));
      for(const text of scripts){const script=document.createElement('script');script.textContent=text;document.body.append(script);}
    }catch(failure){
      error.textContent=!verified&&failure.name==='OperationError'?'Incorrect password. Please try again.':'The proposal could not be opened. Please try again.';
      field.focus();button.disabled=false;button.textContent='Open proposal →';
    }
  });
})();
