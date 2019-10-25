
/**
 * 
 * 
 
https://www.paxos.com/blockchain-101-elliptic-curve-cryptography-ec1d253ca33f/
 Defining a Curve 
Specifically, each ECC curve defines:

elliptic curve equation
(usually defined as a and b in the equation y^2= x^3+ a x + b)
p = Finite Field Prime Number
G = Generator point
n = prime number of points in the group


The curve used in Bitcoin is called secp256k1 and it has these parameters:
Equation y^2= x^3+ 7 (a = 0, b = 7)
Prime Field (p) = 2256– 232– 977
Base point (G) = (79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
Order (n) = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
The curve’s name is secp256k1, where SEC stands for Standards for Efficient Cryptography and 256 is the number of bits in the prime field.
 * 
 * 
 */
const elliptic = require('simple-js-ec-math');
const ModPoint = elliptic.ModPoint;
const Curve = elliptic.Curve;
const sha256 = require('sha256');
const bigInt = require('big-integer');

// G point of secp256k1  on Eliptic curve
const g = new ModPoint(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n
)

const secp256k1_curve = new Curve(
    0n,//a
    7n,//b
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n,//Order  n
    2n ** 256n - 2n ** 32n - 977n,//Prime Field
    g //Base point G
);

function get_pubK_from_prvK(prvK) {
    let prv_key = '';
    //  pubK =  prvK *G
    //  PubK uncompress  version is the point  in curve
    if (!(prvK instanceof bigInt)) {
        prv_key = bigInt(prvK, 16);// big number  in hex(16) format
    } else {
        prv_key = prvK;
    }
    let public_point = secp256k1_curve.multiply(secp256k1_curve.g, prv_key);
    return public_point;
}
function get_public_point_from_public_key(hex_str_pub_key) {
    /**
        Uncompressed public key is:
        0x04 + x-coordinate + y-coordinate
        Compressed public key is:
        0x02 + x-coordinate if y is even
        0x03 + x-coordinate if y is odd
        How to use this equation to derive the uncompressed public key
        y^2 mod p = (x^3 + 7) mod p
    */
   
    return ModPoint.fromSec1(hex_str_pub_key);


}

function secp256k1_sign(msg, private_key, k) {
    let prvK = private_key;
    /*
        the signature will be Signature (r,s). Where
            - Find point P on curve compromise equation:  P(xp,yp) = k*G (mod n) and r = xp ( the x axis of point P)
            - z= hash(msg)
            - s= (z + prvK*r ) * k^(-1) (mod n)
    */
    //random scalar number k
    if (!(k instanceof bigInt)) {
        k = bigInt(k, 16);// big number  in hex(16) format
    }
    if (!(prvK instanceof bigInt)) {
        prvK = bigInt(prvK, 16);// big number  in hex(16) format
    }
    let P = secp256k1_curve.multiply(secp256k1_curve.g, k);//P = k*G mod n
    let r = P.x; // x coordinate of point random point P

    let z = sha256(msg);
    z = bigInt(z, 16);
    const tmp = prvK.multiply(r).add(z); // tmp = z+ prvK*r
    const s = tmp.multiply(k.modInv(secp256k1_curve.n)).mod(secp256k1_curve.n); //s = tmp*k^(-1)(mod  n) = (z+prvK*r)*k^(-1) (mod n)

    return {
        r: bigInt(r).toString(16),/**hex string  of r */
        s: s.toString(16)
    }
}

function secp256k1_verify(msg, signature, pub_key) {
    /*  
        let Ha :  is the public point
        signature(r,s)
        the equation  for verifying is :  P(xp,yp) = z*s^-1*G + r*s^-1*Ha
        if(xp == r) ==>  valid otherwise invalid
    */

    let z = sha256(msg);
    z = bigInt(z, 16);
    let r = bigInt(signature.r, 16);
    let s = bigInt(signature.s, 16);
    let inv_s = s.modInv(secp256k1_curve.n);
    let Ha = get_public_point_from_public_key(pub_key);//derived from public key

    let tmp1 = z.multiply(inv_s).mod(secp256k1_curve.n);
    tmp1 = secp256k1_curve.multiply(secp256k1_curve.g, tmp1);

    let tmp2 = r.multiply(inv_s).mod(secp256k1_curve.n);
    tmp2 = secp256k1_curve.multiply(Ha, tmp2);

    let P = secp256k1_curve.add(tmp1, tmp2);
    return r.toString(16) == P.x.toString(16);
}


let myPrvK = '69e1fb068702e9ae65a004c0b0e08acf33480a3b7ee5a6479649cac3b7d40033';
let pubK = get_pubK_from_prvK(myPrvK);

msg = 'hello the world';

let k_nonce = sha256(msg + pubK.sec1Uncompressed);//just make unique  k

let sig = secp256k1_sign(msg, myPrvK, k_nonce);

console.log(sig);

let isvalid = secp256k1_verify(msg, sig, pubK.sec1Uncompressed);
console.log(isvalid);







