"use strict";

/*
 * Additional tests beyond the provided suite.
 *
 * These are NOT part of the graded tests. They exist to check the security
 * properties the handout asks for but the starter suite does not exercise:
 * swap attacks (with and without a trusted checksum), rollback attacks,
 * password-length hiding, and ciphertext tampering.
 *
 * Only password-manager.js is submitted, so this file never reaches the
 * autograder. Delete it if you prefer a clean folder.
 */

const expect = require('expect.js');
const { Keychain } = require('../password-manager');

function expectReject(promise) {
    return promise.then(
        (result) => expect().fail(`Expected failure, but function returned ${result}`),
        (error) => {},
    );
}

describe('Password manager (extra security tests)', async function () {
    this.timeout(10000);
    const password = "password123!";

    describe('swap attacks', async function () {

        it('detects a swap at load() even with NO trusted checksum', async function () {
            // The handout requires the swap defense to work independently of
            // the rollback defense, so no checksum is passed to load() here.
            const keychain = await Keychain.init(password);
            await keychain.set('www.google.com', 'google_pwd');
            await keychain.set('www.evil.com', 'evil_pwd');

            const [repr] = await keychain.dump();
            const obj = JSON.parse(repr);
            const keys = Object.getOwnPropertyNames(obj.kvs);
            const tmp = obj.kvs[keys[0]];
            obj.kvs[keys[0]] = obj.kvs[keys[1]];
            obj.kvs[keys[1]] = tmp;

            await expectReject(Keychain.load(password, JSON.stringify(obj)));
        });

        it('detects a swap lazily on get()', async function () {
            const keychain = await Keychain.init(password);
            await keychain.set('a.com', 'aaa');
            await keychain.set('b.com', 'bbb');

            const keys = Object.getOwnPropertyNames(keychain.data.kvs);
            const tmp = keychain.data.kvs[keys[0]];
            keychain.data.kvs[keys[0]] = keychain.data.kvs[keys[1]];
            keychain.data.kvs[keys[1]] = tmp;

            await expectReject(keychain.get('a.com'));
        });

        it('rejects a ciphertext that has been bit-flipped', async function () {
            const keychain = await Keychain.init(password);
            await keychain.set('t.com', 'tamper-me');

            const [repr] = await keychain.dump();
            const obj = JSON.parse(repr);
            const k = Object.getOwnPropertyNames(obj.kvs)[0];
            const bytes = Buffer.from(obj.kvs[k], 'base64');
            bytes[bytes.length - 1] ^= 0xff;
            obj.kvs[k] = bytes.toString('base64');

            await expectReject(Keychain.load(password, JSON.stringify(obj)));
        });
    });

    describe('rollback attacks', async function () {

        it('rejects an old dump presented with the current trusted checksum', async function () {
            const keychain = await Keychain.init(password);
            await keychain.set('www.google.com', 'old_pwd');
            const [oldRepr] = await keychain.dump();

            await keychain.set('www.google.com', 'new_pwd');
            const [, newChecksum] = await keychain.dump();

            await expectReject(Keychain.load(password, oldRepr, newChecksum));
        });

        it('still loads honest data when trustedDataCheck is omitted', async function () {
            const keychain = await Keychain.init(password);
            await keychain.set('x.com', 'secret');
            const [repr] = await keychain.dump();

            const restored = await Keychain.load(password, repr);
            expect(await restored.get('x.com')).to.equal('secret');
        });
    });

    describe('password length hiding', async function () {

        it('stores every record at exactly the same length', async function () {
            const keychain = await Keychain.init(password);
            await keychain.set('s1', 'a');
            await keychain.set('s2', 'x'.repeat(64));
            await keychain.set('s3', 'medium-length-pw');

            const sizes = new Set(Object.values(keychain.data.kvs).map(v => v.length));
            expect(sizes.size).to.be(1);
        });

        it('round-trips both the shortest and the longest password', async function () {
            const keychain = await Keychain.init(password);
            await keychain.set('short', 'a');
            await keychain.set('long', 'x'.repeat(64));

            expect(await keychain.get('short')).to.equal('a');
            expect(await keychain.get('long')).to.equal('x'.repeat(64));
        });
    });

    describe('master password handling', async function () {

        it('rejects a wrong password even on an empty keychain', async function () {
            const keychain = await Keychain.init(password);
            const [repr, checksum] = await keychain.dump();

            await expectReject(Keychain.load('wrongpassword', repr, checksum));
        });

        it('accepts the correct password on an empty keychain', async function () {
            const keychain = await Keychain.init(password);
            const [repr, checksum] = await keychain.dump();

            const restored = await Keychain.load(password, repr, checksum);
            expect(await restored.get('anything')).to.be(null);
        });

        it('uses a fresh salt per keychain, so identical passwords differ on disk', async function () {
            const a = await Keychain.init(password);
            const b = await Keychain.init(password);
            expect(a.data.salt).not.to.equal(b.data.salt);

            await a.set('same.com', 'pw');
            await b.set('same.com', 'pw');
            expect(Object.getOwnPropertyNames(a.data.kvs)[0])
                .not.to.equal(Object.getOwnPropertyNames(b.data.kvs)[0]);
        });

        it('leaks nothing but kvs, salt and verifier in the dump', async function () {
            const keychain = await Keychain.init(password);
            await keychain.set('d.com', 'v');
            const [repr] = await keychain.dump();

            const fields = Object.getOwnPropertyNames(JSON.parse(repr)).sort();
            expect(fields).to.eql(['kvs', 'salt', 'verifier']);
            expect(repr).not.to.contain(password);
        });
    });

    describe('updates and removals persist', async function () {

        it('updates a domain in place rather than adding a second entry', async function () {
            const keychain = await Keychain.init(password);
            await keychain.set('www.stanford.edu', 'p1');
            await keychain.set('www.stanford.edu', 'p2');

            expect(Object.getOwnPropertyNames(keychain.data.kvs)).to.have.length(1);
            expect(await keychain.get('www.stanford.edu')).to.equal('p2');
        });

        it('carries a removal through dump and load', async function () {
            const keychain = await Keychain.init(password);
            await keychain.set('r1', 'v1');
            await keychain.set('r2', 'v2');

            expect(await keychain.remove('r1')).to.be(true);
            expect(await keychain.remove('r1')).to.be(false);

            const [repr, checksum] = await keychain.dump();
            const restored = await Keychain.load(password, repr, checksum);

            expect(await restored.get('r1')).to.be(null);
            expect(await restored.get('r2')).to.equal('v2');
        });
    });
});
