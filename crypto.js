(() => {
  'use strict';
  const root=typeof window==='undefined'?globalThis:window;
  const encoder=new TextEncoder();
  const bytes=value=>value instanceof Uint8Array?value:new Uint8Array(value);
  async function deriveKey(password,salt,iterations,usages=['decrypt']){
    if(typeof password!=='string'||!password||password.length>256)throw Error('Enter the proposal password.');
    if(!Number.isInteger(iterations)||iterations<1000)throw Error('Invalid key configuration.');
    const material=await root.crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveKey']);
    return root.crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:bytes(salt),iterations},material,{name:'AES-GCM',length:256},false,usages);
  }
  async function seal(key,value,context){
    const iv=root.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext=await root.crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:encoder.encode(context),tagLength:128},key,bytes(value));
    const result=new Uint8Array(12+ciphertext.byteLength);result.set(iv);result.set(new Uint8Array(ciphertext),12);return result;
  }
  async function open(key,value,context){
    const data=bytes(value);if(data.length<28)throw Error('Invalid protected file.');
    return new Uint8Array(await root.crypto.subtle.decrypt({name:'AES-GCM',iv:data.subarray(0,12),additionalData:encoder.encode(context),tagLength:128},key,data.subarray(12)));
  }
  root.PROPOSAL_VAULT_CRYPTO=Object.freeze({deriveKey,seal,open});
})();
