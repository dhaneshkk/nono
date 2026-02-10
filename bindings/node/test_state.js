const nono = require('.');

const caps = new nono.CapabilitySet();
caps.allowPath('/tmp', nono.AccessMode.Read);
caps.blockNetwork();

const state = nono.SandboxState.fromCaps(caps);
const json = state.toJson();
console.log('State JSON:', json.substring(0, 200), '...');

const state2 = nono.SandboxState.fromJson(json);
const caps2 = state2.toCaps();
console.log('Restored network blocked:', caps2.isNetworkBlocked);
console.log('Restored summary:', caps2.summary());
