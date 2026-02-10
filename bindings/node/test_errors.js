const nono = require('.');

const caps = new nono.CapabilitySet();

try {
    caps.allowPath('/nonexistent/path/xyz', nono.AccessMode.Read);
} catch (e) {
    console.log('Caught expected error:', e.message);
}

try {
    caps.allowPath('/etc/hosts', nono.AccessMode.Read);
} catch (e) {
    console.log('Caught expected error:', e.message);
}
