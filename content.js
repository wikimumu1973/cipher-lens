(function(){
  function proto(){
    try {
      const nav = performance.getEntriesByType('navigation')[0];
      return nav && nav.nextHopProtocol ? nav.nextHopProtocol.toLowerCase() : null;
    } catch(e){ return null; }
  }
  function send(){
    try {
      chrome.runtime.sendMessage({ action:'fromContent', data:{ protocol: proto(), hostname: location.hostname } }).catch(function(){});
    } catch(e){}
  }
  try { send(); } catch(e){}
  window.addEventListener('load', send);
  setTimeout(send, 1200);
  chrome.runtime.onMessage.addListener(function(msg, sender, sendResponse){
    if (msg && msg.action === 'readProto') sendResponse({ protocol: proto(), hostname: location.hostname });
  });
})();
