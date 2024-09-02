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