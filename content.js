(function(){
  function send(){
    try {
      const nav = performance.getEntriesByType('navigation')[0];
      const proto = nav && nav.nextHopProtocol ? nav.nextHopProtocol.toLowerCase() : null;
      chrome.runtime.sendMessage({ action:'fromContent', data:{ protocol: proto, hostname: location.hostname } }).catch(()=>{});
    } catch(e){}
  }
  try { send(); } catch(e){}
  window.addEventListener('load', send);
  setTimeout(send, 1200);
})();
