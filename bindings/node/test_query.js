const nono = require('.');

const caps = new nono.CapabilitySet();
caps.allowPath('/tmp', nono.AccessMode.ReadWrite);

const ctx = new nono.QueryContext(caps);

// Should be allowed
let result = ctx.queryPath('/tmp/test.txt', nono.AccessMode.Read);
console.log('Query /tmp/test.txt READ:', JSON.stringify(result, null, 2));

// Should be denied
result = ctx.queryPath('/etc/passwd', nono.AccessMode.Read);
console.log('Query /etc/passwd READ:', JSON.stringify(result, null, 2));

// Network
const caps2 = new nono.CapabilitySet();
caps2.blockNetwork();
const ctx2 = new nono.QueryContext(caps2);
console.log('Network query:', JSON.stringify(ctx2.queryNetwork(), null, 2));
