
const SigUtils = require('./SmallSignature');


let myPrvK = '69e1fb068702e9ae65a004c0b0e08acf33480a3b7ee5a6479649cac3b7d40033';
let  my_msg ="hello this is reduce signature";
console.log('message ',my_msg);


let pubK= SigUtils.get_uncompress_public_key_from_private_key(myPrvK);
console.log('public Key ',pubK);

let smaller_sig = SigUtils.secp256k1_smaller_signature_sign(my_msg,myPrvK);
console.log('smaller_sig ',smaller_sig);

let isValid = SigUtils.secp256k1_verify_small_signature(my_msg,smaller_sig,pubK)
console.log('Verify the small signature ', isValid);