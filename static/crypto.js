/**
 * E2E Encryption Library using Web Crypto API
 * AES-GCM with PBKDF2 key derivation
 */

class E2ECrypto {
    constructor() {
        this.algorithm = 'AES-GCM';
        this.keyLength = 256;
        this.iterations = 100000; // PBKDF2 iterations
        this.ivLength = 12; // 96 bits for GCM
        this.saltLength = 16; // 128 bits
    }

    /**
     * Generate random bytes
     */
    getRandomBytes(length) {
        return window.crypto.getRandomValues(new Uint8Array(length));
    }

    /**
     * Derive encryption key from password using PBKDF2
     */
    async deriveKey(password, salt) {
        const encoder = new TextEncoder();
        
        // Import password as key material
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        
        // Derive actual encryption key
        return await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: this.iterations,
                hash: 'SHA-256'
            },
            keyMaterial,
            {
                name: this.algorithm,
                length: this.keyLength
            },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Compress data before encryption using CompressionStream API
     */
    async compressData(data) {
        try {
            // Check if CompressionStream is available
            if (typeof CompressionStream !== 'undefined') {
                const stream = new Blob([data]).stream();
                const compressedStream = stream.pipeThrough(
                    new CompressionStream('gzip')
                );
                const compressedBlob = await new Response(compressedStream).blob();
                return await compressedBlob.arrayBuffer();
            } else {
                // Fallback: no compression
                console.warn('CompressionStream not available, skipping compression');
                return data;
            }
        } catch (error) {
            console.warn('Compression failed, using uncompressed data:', error);
            return data;
        }
    }

    /**
     * Decompress data after decryption
     */
    async decompressData(data) {
        try {
            if (typeof DecompressionStream !== 'undefined') {
                const stream = new Blob([data]).stream();
                const decompressedStream = stream.pipeThrough(
                    new DecompressionStream('gzip')
                );
                const decompressedBlob = await new Response(decompressedStream).blob();
                return await decompressedBlob.arrayBuffer();
            } else {
                return data;
            }
        } catch (error) {
            console.warn('Decompression failed, returning raw data:', error);
            return data;
        }
    }

    /**
     * Encrypt file with compression
     */
    async encryptFile(fileData, password) {
        try {
            // Compress first
            const compressed = await this.compressData(fileData);
            
            // Then encrypt
            const salt = this.getRandomBytes(this.saltLength);
            const iv = this.getRandomBytes(this.ivLength);
            const key = await this.deriveKey(password, salt);
            
            const encrypted = await window.crypto.subtle.encrypt(
                {
                    name: this.algorithm,
                    iv: iv,
                    tagLength: 128
                },
                key,
                compressed
            );
            
            return {
                encrypted: encrypted,
                salt: salt,
                iv: iv
            };
        } catch (error) {
            console.error('Encryption error:', error);
            throw new Error('Encryption failed: ' + error.message);
        }
    }

    /**
     * Decrypt file and decompress
     */
    async decryptFile(encryptedPackage, password) {
        try {
            const salt = encryptedPackage.salt;
            const iv = encryptedPackage.iv;
            const encryptedData = encryptedPackage.encrypted;
            
            const key = await this.deriveKey(password, salt);
            
            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: this.algorithm,
                    iv: iv,
                    tagLength: 128
                },
                key,
                encryptedData
            );
            
            // Decompress after decryption
            const decompressed = await this.decompressData(decrypted);
            
            return decompressed;
        } catch (error) {
            console.error('Decryption error:', error);
            throw new Error('Decryption failed - wrong password or corrupted file');
        }
    }


    /**
     * Package encrypted data for storage
     * Format: [salt(16) | iv(12) | encrypted_data]
     */
    packageEncryptedData(encryptResult) {
        const saltArray = new Uint8Array(encryptResult.salt);
        const ivArray = new Uint8Array(encryptResult.iv);
        const encryptedArray = new Uint8Array(encryptResult.encrypted);
        
        // Combine all parts
        const combined = new Uint8Array(
            saltArray.length + ivArray.length + encryptedArray.length
        );
        
        combined.set(saltArray, 0);
        combined.set(ivArray, saltArray.length);
        combined.set(encryptedArray, saltArray.length + ivArray.length);
        
        return combined;
    }

    /**
     * Unpackage encrypted data from storage
     * Returns: {salt, iv, encrypted}
     */
    unpackageEncryptedData(packagedData) {
        const data = new Uint8Array(packagedData);
        
        const salt = data.slice(0, this.saltLength);
        const iv = data.slice(this.saltLength, this.saltLength + this.ivLength);
        const encrypted = data.slice(this.saltLength + this.ivLength);
        
        return {
            salt: salt,
            iv: iv,
            encrypted: encrypted
        };
    }

    /**
     * Helper: Convert ArrayBuffer to Base64
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    /**
     * Helper: Convert Base64 to ArrayBuffer
     */
    base64ToArrayBuffer(base64) {
        const binary = window.atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = E2ECrypto;
}

