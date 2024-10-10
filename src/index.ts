import nacl from "tweetnacl";
import { Keypair } from "@solana/web3.js";
import naclUtil from "tweetnacl-util";

// Generate key pairs for both users (simulating User A and User B)
const userA = Keypair.generate(); // User A's keypair
const userB = Keypair.generate(); // User B's keypair

console.log("User A Public Key:", userA.publicKey.toBase58());
console.log("User B Public Key:", userB.publicKey.toBase58());

// Deriving a shared key using user A's private key and user B's public key
function deriveSharedSecret(privateKey: any, publicKey: any) {
  const sharedSecret = nacl.box.before(
    publicKey.toBytes(),
    privateKey.secretKey.slice(0, 32)
  ); // 32-byte secret key
  return sharedSecret;
}

const sharedSecretAB = deriveSharedSecret(userA, userB.publicKey);
console.log("Shared Secret (AB):", naclUtil.encodeBase64(sharedSecretAB)); // Debugging shared secret

// Encrypting the message
function encryptMessage(message: any, sharedSecret: any) {
  const nonce = nacl.randomBytes(nacl.box.nonceLength); // Create a random nonce
  const messageUint8 = naclUtil.decodeUTF8(message); // Convert message to Uint8Array
  const encryptedMessage = nacl.secretbox(messageUint8, nonce, sharedSecret);
  return { nonce, encryptedMessage };
}

const message = "Hello, User B!";
const { nonce, encryptedMessage } = encryptMessage(message, sharedSecretAB);
console.log("Nonce (Base64):", naclUtil.encodeBase64(nonce)); // Log the nonce for debugging
console.log(
  "Encrypted Message (Base64):",
  naclUtil.encodeBase64(encryptedMessage)
);

// Signing the encrypted message with User A's private key
function signMessage(encryptedMessage: any, senderPrivateKey: any) {
  const signature = nacl.sign.detached(
    encryptedMessage,
    senderPrivateKey.secretKey
  );
  return signature;
}

const signature = signMessage(encryptedMessage, userA);
console.log("Signature (Base64):", naclUtil.encodeBase64(signature));

// Verifying the message signature
function verifySignature(
  encryptedMessage: any,
  signature: any,
  senderPublicKey: any
) {
  return nacl.sign.detached.verify(
    encryptedMessage,
    signature,
    senderPublicKey.toBytes()
  );
}

const isValidSignature = verifySignature(
  encryptedMessage,
  signature,
  userA.publicKey
);
console.log("Is Signature Valid:", isValidSignature);

// Decrypting the message using shared secret
function decryptMessage(encryptedMessage: any, nonce: any, sharedSecret: any) {
  try {
    const decryptedMessage = nacl.secretbox.open(
      encryptedMessage,
      nonce,
      sharedSecret
    );
    if (!decryptedMessage) {
      throw new Error("Decryption failed");
    }
    return naclUtil.encodeUTF8(decryptedMessage);
  } catch (error) {
    console.error("Error decrypting message:", error);
  }
}

const sharedSecretBA = deriveSharedSecret(userB, userA.publicKey); // Same shared secret as User A derived
console.log("Shared Secret (BA):", naclUtil.encodeBase64(sharedSecretBA)); // Debugging shared secret

const decryptedMessage = decryptMessage(
  encryptedMessage,
  nonce,
  sharedSecretBA
);

console.log("Decrypted Message:", decryptedMessage);
