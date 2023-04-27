var keccak256 = require('keccak256');

function mineBlock(message) {
    let result = 0;
    for (var i = 1; i <= 10000; i++) {
        let currentMessage = i + message;
        let currentHash = keccak256(currentMessage).toString('hex');
        //console.log("Nonce: " + i, currentHash);
        if (currentHash.indexOf('000') == 0) {
            result = i;
            break;
        }
    }
    return result;
}

let genesisNonce = mineBlock('#GENESIS');
console.log(genesisNonce);
let genesisHash = keccak256(genesisNonce + '#GENESIS').toString('hex');
console.log('GENESIS HASH', genesisHash);
let blockNonce = mineBlock('#' + genesisHash + '#Transaction 1#Transaction 2#Transaction 3');
console.log(blockNonce);
let blockHash = keccak256(blockNonce + '#' + genesisHash + '#Transaction 1#Transaction 2#Transaction 3').toString('hex');
console.log('BLOCK HASH', genesisHash);