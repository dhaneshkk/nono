const { createRequire } = require('node:module');
const localRequire = createRequire(__filename);

module.exports = localRequire('./nono_napi.node');
