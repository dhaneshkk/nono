const nono = require('.');

console.log('Supported:', nono.isSupported());
const info = nono.supportInfo();
console.log('Platform:', info.platform);
console.log('Details:', info.details);
