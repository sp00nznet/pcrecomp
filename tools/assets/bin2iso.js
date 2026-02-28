#!/usr/bin/env node
// Convert a Mode1/2352 BIN image to a standard 2048-byte sector ISO
// Mode1/2352 layout per sector: 16 bytes sync/header + 2048 bytes data + 288 bytes ECC/EDC

const fs = require('fs');
const path = require('path');

const binPath = process.argv[2];
const isoPath = process.argv[3] || binPath.replace(/\.bin$/i, '.iso');

const SECTOR_RAW = 2352;
const SECTOR_DATA = 2048;
const HEADER_SIZE = 16; // sync (12) + header (4)

const stat = fs.statSync(binPath);
const sectorCount = Math.floor(stat.size / SECTOR_RAW);

console.log(`BIN file: ${binPath}`);
console.log(`Size: ${stat.size} bytes`);
console.log(`Sectors: ${sectorCount}`);
console.log(`Output: ${isoPath}`);

const fd_in = fs.openSync(binPath, 'r');
const fd_out = fs.openSync(isoPath, 'w');
const buf = Buffer.alloc(SECTOR_RAW);

for (let i = 0; i < sectorCount; i++) {
    fs.readSync(fd_in, buf, 0, SECTOR_RAW, i * SECTOR_RAW);
    // Write only the 2048-byte data portion (skip 16-byte header, ignore 288-byte ECC)
    fs.writeSync(fd_out, buf, HEADER_SIZE, SECTOR_DATA);
}

fs.closeSync(fd_in);
fs.closeSync(fd_out);

console.log(`Done! ISO written (${sectorCount * SECTOR_DATA} bytes)`);
