//  node debug_test.js

const fs = require('fs');
const path = require('path');

// Helper function to inspect a message in detail
// function inspectMessage(msg, index) {
//     console.log(`\n--- Message ${index} Detailed Inspection ---`);
//
//     // Basic object inspection
//     console.log(`Message ${index} type:`, typeof msg);
//     console.log(`Message ${index} constructor:`, msg.constructor?.name);
//     console.log(`Message ${index} object keys:`, Object.keys(msg));
//     console.log(`Message ${index} own properties:`, Object.getOwnPropertyNames(msg));
//
//     // Try to get property descriptors
//     try {
//         const descriptors = Object.getOwnPropertyDescriptors(msg);
//         console.log(`Message ${index} property descriptors:`, Object.keys(descriptors));
//     } catch (e) {
//         console.log(`Message ${index} property descriptors failed:`, e.message);
//     }
//
//     // Check prototype chain
//     try {
//         const proto = Object.getPrototypeOf(msg);
//         console.log(`Message ${index} prototype:`, proto);
//         console.log(`Message ${index} prototype keys:`, Object.keys(proto));
//     } catch (e) {
//         console.log(`Message ${index} prototype inspection failed:`, e.message);
//     }
//
//     // Try each property individually with detailed error handling
//     console.log(`\nMessage ${index} Property Access Tests:`);
//
//     // Test from_id
//     console.log('  Testing from_id...');
//     try {
//         const fromId = msg.from_id;
//         console.log(`     from_id accessed: ${fromId} (type: ${typeof fromId})`);
//     } catch (e) {
//         console.log(`     from_id failed: ${e.message}`);
//         console.log(`       Error type: ${e.constructor?.name}`);
//         console.log(`       Error stack: ${e.stack?.split('\n').slice(0, 3).join('\n')}`);
//     }
//
//     // Test to_id
//     console.log('  Testing to_id...');
//     try {
//         const toId = msg.to_id;
//         console.log(`     to_id accessed: ${toId} (type: ${typeof toId})`);
//     } catch (e) {
//         console.log(`     to_id failed: ${e.message}`);
//         console.log(`       Error type: ${e.constructor?.name}`);
//         console.log(`       Error stack: ${e.stack?.split('\n').slice(0, 3).join('\n')}`);
//     }
//
//     // Test payload
//     console.log('  Testing payload...');
//     try {
//         const payload = msg.payload;
//         console.log(`     payload accessed: type=${typeof payload}, length=${payload?.length}`);
//         if (payload && payload.length !== undefined) {
//             console.log(`       payload is Uint8Array: ${payload instanceof Uint8Array}`);
//             console.log(`       payload buffer size: ${payload.buffer?.byteLength}`);
//         }
//     } catch (e) {
//         console.log(`     payload failed: ${e.message}`);
//         console.log(`       Error type: ${e.constructor?.name}`);
//         console.log(`       Error stack: ${e.stack?.split('\n').slice(0, 3).join('\n')}`);
//     }
//
//     // Test if message has methods
//     console.log('  Testing methods...');
//     try {
//         if (typeof msg.clone === 'function') {
//             console.log('     clone method exists');
//         }
//         if (typeof msg.free === 'function') {
//             console.log('     free method exists');
//         }
//     } catch (e) {
//         console.log(`     Method inspection failed: ${e.message}`);
//     }
// }

// Helper functions for message filtering - safer version for s390x
function filterMessages(msgs, partyId) {
    const filtered = [];
    for (let i = 0; i < msgs.length; i++) {
        try {
            if (msgs[i].from_id !== partyId) {
                filtered.push(msgs[i].clone());
            }
        } catch (e) {
            console.log(` Error accessing message ${i} from_id: ${e.message}`);
        }
    }
    return filtered;
}

function selectMessages(msgs, partyId) {
    const selected = [];
    for (let i = 0; i < msgs.length; i++) {
        try {
            const toId = msgs[i].to_id;
            // Check for broadcast (255, null, or undefined) or specific party ID
            if (toId === partyId || toId === 255 || toId === null || toId === undefined) {
                selected.push(msgs[i].clone());
            }
        } catch (e) {
            console.log(` Error accessing message ${i} to_id: ${e.message}`);
        }
    }
    return selected;
}

// Complete DKG test going through all rounds
async function testCompleteDKG() {
    try {
        console.log('=== Testing Complete DKG Protocol ===');
        
        const wasmPath = path.join(__dirname, 'pkg', 'dkls_wasm_ll.js');
        
        if (!fs.existsSync(wasmPath)) {
            console.log('WASM package not found. Run wasm-pack build first.');
            return;
        }
        
        const wasmModule = require(wasmPath);
        
        // Check if WASM was loaded properly
        if (!wasmModule || typeof wasmModule !== 'object') {
            throw new Error('WASM module is invalid');
        }
        
        // Check if __wasm is available (indicates WASM loaded)
        if (!wasmModule.__wasm) {
            throw new Error('WASM binary not initialized - __wasm is undefined');
        }
        
        // Verify KeygenSession is available
        if (!wasmModule.KeygenSession) {
            throw new Error('KeygenSession not found in WASM module');
        }
        
        console.log(' WASM module loaded successfully');
        
        const { KeygenSession } = wasmModule;
        const n = 2; // 2 participants
        const t = 2; // threshold 2
        
        console.log(`\n=== Creating ${n} KeygenSessions ===`);
        const parties = [];
        for (let i = 0; i < n; i++) {
            console.log(`Creating session for party ${i}...`);
            const session = new KeygenSession(n, t, i, null);
            parties.push(session);
            console.log(` Party ${i} session created`);
        }
        
        console.log('\n=== Round 1: Create First Messages ===');
        const msg1 = [];
        for (let i = 0; i < parties.length; i++) {
            console.log(`Creating first message for party ${i}...`);
            const message = parties[i].createFirstMessage();
            msg1.push(message);
            console.log(` Party ${i} first message created`);
        }
        
        // console.log('\n=== COMPREHENSIVE msg1 INSPECTION BEFORE ROUND 2 ===');
        // console.log(`Total msg1 messages: ${msg1.length}`);
        //
        // // Inspect each message in msg1 in detail
        // for (let i = 0; i < msg1.length; i++) {
        //     inspectMessage(msg1[i], i);
        // }
        //
        // console.log('\n=== Summary of msg1 Contents ===');
        // console.log(`msg1 array length: ${msg1.length}`);
        // console.log(`msg1 array type: ${Array.isArray(msg1) ? 'Array' : typeof msg1}`);
        // console.log(`msg1 contents:`, msg1.map((m, i) => `Message${i}`));
        //
        console.log('\n=== Round 2: Handle First Messages ===');
        const msg2 = [];
        for (let i = 0; i < parties.length; i++) {
            console.log(`Party ${i} handling first messages...`);
            const batch = filterMessages(msg1, i);
            console.log(`  - Filtered ${batch.length} messages for party ${i}`);
            
            if (batch.length > 0) {
                const responses = parties[i].handleMessages(batch, null, null);
                msg2.push(...responses);
                console.log(` Party ${i} created ${responses.length} responses`);
            } else {
                console.log(` Party ${i} has no messages to handle`);
            }
        }
        
        console.log('\n=== Round 3: Handle Second Messages ===');
        const msg3 = [];
        for (let i = 0; i < parties.length; i++) {
            console.log(`Party ${i} handling second messages...`);
            const batch = selectMessages(msg2, i);
            console.log(`  - Selected ${batch.length} messages for party ${i}`);
            
            if (batch.length > 0) {
                const responses = parties[i].handleMessages(batch, null, null);
                msg3.push(...responses);
                console.log(` Party ${i} created ${responses.length} responses`);
            } else {
                console.log(` Party ${i} has no messages to handle`);
            }
        }
        
        console.log('\n=== Round 4: Calculate Commitments and Handle Third Messages ===');
        const commitments = [];
        for (let i = 0; i < parties.length; i++) {
            console.log(`Party ${i} calculating commitment...`);
            const commitment = parties[i].calculateChainCodeCommitment();
            commitments.push(commitment);
            console.log(` Party ${i} commitment calculated (${commitment.length} bytes)`);
        }
        
        const msg4 = [];
        for (let i = 0; i < parties.length; i++) {
            console.log(`Party ${i} handling third messages...`);
            const batch = selectMessages(msg3, i);
            console.log(`  - Selected ${batch.length} messages for party ${i}`);
            
            if (batch.length > 0) {
                const responses = parties[i].handleMessages(batch, commitments, null);
                if (responses.length > 0) {
                    msg4.push(responses[0]); // Take the first response
                    console.log(` Party ${i} created final message`);
                } else {
                    console.log(` Party ${i} created no responses`);
                }
            } else {
                console.log(` Party ${i} has no messages to handle`);
            }
        }
        
        console.log('\n=== Round 5: Handle Final Messages and Extract Keyshares ===');
        const keyshares = [];
        for (let i = 0; i < parties.length; i++) {
            console.log(`Party ${i} handling final messages...`);
            const batch = filterMessages(msg4, i);
            console.log(`  - Filtered ${batch.length} final messages for party ${i}`);
            
            if (batch.length > 0) {
                parties[i].handleMessages(batch, null, null);
                console.log(` Party ${i} processed final messages`);
            } else {
                console.log(` Party ${i} has no final messages to handle`);
            }
            
            // Extract keyshare
            console.log(`Extracting keyshare for party ${i}...`);
            try {
                const keyshare = parties[i].keyshare();
                keyshares.push(keyshare);
                console.log(` Party ${i} keyshare extracted`);
            } catch (e) {
                console.log(`Party ${i} keyshare extraction failed: ${e.message}`);
            }
        }
        
        console.log('\n=== Verification ===');
        console.log(`Created ${keyshares.length} keyshares`);
        
        // Verify all keyshares have the same public key
        if (keyshares.length >= 2) {
            const pk0 = keyshares[0].publicKey;
            const pk1 = keyshares[1].publicKey;
            
            const pk0Bytes = Array.from(pk0);
            const pk1Bytes = Array.from(pk1);
            
            const sameKey = pk0Bytes.length === pk1Bytes.length && 
                           pk0Bytes.every((byte, i) => byte === pk1Bytes[i]);
            
            console.log(` Public keys match: ${sameKey}`);
            console.log(` Public key length: ${pk0Bytes.length} bytes`);
        }

        
        console.log('DKG protocol test finished');
        
    } catch (error) {
        console.error('Error during DKG test:', error.message);
        console.error('Stack:', error.stack);
    }
}

testCompleteDKG();