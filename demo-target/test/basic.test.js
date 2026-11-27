import test from 'node:test';
import assert from 'node:assert';
import { parseQuery, isValidEmail, cartTotal } from '../src/index.js';

test('parseQuery', () => assert.deepStrictEqual(parseQuery('a=1&b=two'), { a: '1', b: 'two' }));
test('isValidEmail', () => assert.ok(isValidEmail('anna@shop.example')));
test('cartTotal', () => assert.strictEqual(cartTotal([{ price: 10, qty: 2 }]), 20));
