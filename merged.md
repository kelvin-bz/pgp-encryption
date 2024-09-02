## zipUtils.js

```js
const fs = require('fs');
const fsPromises = require('fs').promises;
const path = require('path');
const archiver = require('archiver');
const unzipper = require('unzipper');

// Function to create a ZIP file
async function createZip(files, outputZip) {
    await fsPromises.mkdir(path.dirname(outputZip), { recursive: true });
    return new Promise((resolve, reject) => {
        const output = fs.createWriteStream(outputZip);
        const archive = archiver('zip', { zlib: { level: 9 } });

        output.on('close', () => resolve(outputZip));
        archive.on('error', reject);
        archive.pipe(output);

        files.forEach(file => archive.file(file, { name: path.basename(file) }));
        archive.finalize();
    });
}

// Function to extract a ZIP file
async function extractZip(zipFile, outputDir) {
    await fsPromises.mkdir(outputDir, { recursive: true });
    return new Promise((resolve, reject) => {
        fs.createReadStream(zipFile)
            .pipe(unzipper.Extract({ path: outputDir }))
            .on('close', () => resolve(outputDir))
            .on('error', reject);
    });
}

module.exports = { createZip, extractZip };
```

## pgpUtils.js

```js
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
```

## index.js

```js
const fsPromises = require('fs').promises;
const fs = require('fs');
const openpgp = require('openpgp');
const path = require('path');
const { createZip, extractZip } = require('./zipUtils');
const { encryptFile, decryptFile } = require('./pgpUtils');

// Function to clean the output directory
async function cleanOutputDir(outputDir) {
    try {
        await fsPromises.rmdir(outputDir, { recursive: true });
        console.log('Output directory cleaned.');
    } catch (err) {
        if (err.code !== 'ENOENT') {
            throw err;
        }
    }
}

// Main function to demonstrate the process
async function demonstrateSecureFileHandling() {
    try {
        const keysDir = './keys';
        const outputDir = './output';
        const inputFilePath = './input/test.txt';
        const privateKeyPath = path.join(keysDir, 'privateKey.asc');
        const publicKeyPath = path.join(keysDir, 'publicKey.asc');

        // Clean the output directory
        await cleanOutputDir(outputDir);

        // Ensure keys directory exists
        await fsPromises.mkdir(keysDir, { recursive: true });

        let privateKey, publicKey;

        // Check if keys already exist
        try {
            privateKey = await fsPromises.readFile(privateKeyPath, 'utf8');
            publicKey = await fsPromises.readFile(publicKeyPath, 'utf8');
            console.log('Keys loaded from disk.');
        } catch (err) {
            // Generate PGP key pair if not found
            const keyPair = await openpgp.generateKey({
                type: 'rsa',
                rsaBits: 4096,
                userIDs: [{ name: 'Test User', email: 'test@example.com' }],
                passphrase: 'secure123'
            });
            privateKey = keyPair.privateKey;
            publicKey = keyPair.publicKey;

            // Save keys to disk
            await fsPromises.writeFile(privateKeyPath, privateKey);
            await fsPromises.writeFile(publicKeyPath, publicKey);
            console.log('Keys generated and saved to disk.');
        }

        // Create a ZIP file
        const zipFile = await createZip([inputFilePath], path.join(outputDir, 'archive.zip'));
        console.log(`ZIP file created: ${zipFile}`);

        // Encrypt the ZIP file
        const encryptedFile = await encryptFile(zipFile, path.join(outputDir, 'encrypted_archive.zip.gpg'), publicKey);
        console.log(`Encrypted file created: ${encryptedFile}`);

        // Decrypt the file
        const decryptedFile = await decryptFile(encryptedFile, path.join(outputDir, 'decrypted_archive.zip'), privateKey, 'secure123');
        console.log(`Decrypted file created: ${decryptedFile}`);

        // Extract the ZIP file
        const extractionDir = path.join(outputDir, 'extracted_files');
        await extractZip(decryptedFile, extractionDir);
        console.log(`Files extracted to: ${extractionDir}`);

        // List extracted files
        const files = await fsPromises.readdir(extractionDir);
        console.log('Extracted files:');
        files.forEach(file => console.log(`- ${file}`));

    } catch (error) {
        console.error('An error occurred:', error.message);
    }
}

// Run the demonstration
demonstrateSecureFileHandling();

```

