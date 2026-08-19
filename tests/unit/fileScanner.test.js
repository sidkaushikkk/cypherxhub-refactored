const test = require('node:test');
const assert = require('node:assert/strict');
const { detectMagicByteType, scanFile } = require('../../server/services/fileScanner');

test('File Scanner & Magic Byte Suite', async (t) => {
    await t.test('detects Windows PE Executable magic bytes (MZ)', () => {
        const peBuffer = Buffer.from([0x4D, 0x5A, 0x90, 0x00]);
        assert.equal(detectMagicByteType(peBuffer), 'EXECUTABLE_PE');
    });

    await t.test('detects Linux ELF Executable magic bytes (\x7fELF)', () => {
        const elfBuffer = Buffer.from([0x7F, 0x45, 0x4C, 0x46]);
        assert.equal(detectMagicByteType(elfBuffer), 'EXECUTABLE_ELF');
    });

    await t.test('detects PDF Document magic bytes (%PDF)', () => {
        const pdfBuffer = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D]);
        assert.equal(detectMagicByteType(pdfBuffer), 'DOCUMENT_PDF');
    });

    await t.test('detects ZIP Archive magic bytes (PK\x03\x04)', () => {
        const zipBuffer = Buffer.from([0x50, 0x4B, 0x03, 0x04]);
        assert.equal(detectMagicByteType(zipBuffer), 'ARCHIVE_ZIP');
    });

    await t.test('detects PNG Image magic bytes (\x89PNG)', () => {
        const pngBuffer = Buffer.from([0x89, 0x50, 0x4E, 0x47]);
        assert.equal(detectMagicByteType(pngBuffer), 'IMAGE_PNG');
    });

    await t.test('detects JPEG Image magic bytes (\xFF\xD8\xFF)', () => {
        const jpegBuffer = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]);
        assert.equal(detectMagicByteType(jpegBuffer), 'IMAGE_JPEG');
    });

    await t.test('flags extension vs magic byte mismatch (extension spoofing)', async () => {
        // Buffer has PE header (MZ), but original name is document.pdf
        const peHeader = Buffer.from([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
        const mockFile = {
            originalname: 'document.pdf',
            buffer: peHeader,
            size: peHeader.length
        };

        const verdict = await scanFile(mockFile);
        assert.equal(verdict.status, 'DANGEROUS');
        const mismatchIndicator = verdict.indicators.find(i => i.type === 'MAGIC_BYTE_MISMATCH');
        assert.notEqual(mismatchIndicator, undefined);
    });

    await t.test('flags double extension evasion trick (document.pdf.exe)', async () => {
        const mockFile = {
            originalname: 'document.pdf.exe',
            buffer: Buffer.from([0x4D, 0x5A, 0x90, 0x00]),
            size: 4
        };

        const verdict = await scanFile(mockFile);
        const doubleExtIndicator = verdict.indicators.find(i => i.type === 'DOUBLE_EXTENSION_EVASION');
        assert.notEqual(doubleExtIndicator, undefined);
    });

    await t.test('throws formatted error if file is missing', async () => {
        await assert.rejects(async () => {
            await scanFile(null);
        }, (err) => err.code === 'MISSING_FILE');
    });
});
