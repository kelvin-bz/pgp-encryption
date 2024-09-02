const fs = require('fs').promises;
const openpgp = require('openpgp');

// Function to encrypt a file with PGP
async function encryptFile(inputFile, outputFile, publicKeyArmored) {
    const fileContent = await fs.readFile(inputFile);
    const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });

    // Encrypt the file content using the public key
    const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ binary: fileContent }),
        encryptionKeys: publicKey,
        format: 'binary'
    });

    await fs.writeFile(outputFile, encrypted);
    return outputFile;
}

// Function to decrypt a file with PGP
async function decryptFile(inputFile, outputFile, privateKeyArmored, passphrase) {
    const encryptedData = await fs.readFile(inputFile);
    const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
        passphrase
    });

    // Decrypt the file content using the private key
    const message = await openpgp.readMessage({ binaryMessage: encryptedData });
    const { data: decrypted } = await openpgp.decrypt({
        message,
        decryptionKeys: privateKey,
        format: 'binary'
    });

    await fs.writeFile(outputFile, decrypted);
    return outputFile;
}

module.exports = { encryptFile, decryptFile };