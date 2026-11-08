#!/usr/bin/env node
/**
 * Regressietest audit H1 (stored XSS): render het alert-feed en de
 * alert-details met aanvaller-gecontroleerde velden in een minimale fake DOM
 * en controleer dat er geen HTML uit de data in de output terechtkomt.
 *
 * Draaien: node tests/js/xss_render_test.js   (exit 0 = ok)
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '..', '..');
const PAYLOAD = '<img src=x onerror=alert(1)>';
const ATTR_PAYLOAD = '" onmouseover="alert(1)';

function fakeElement(id) {
    const el = {
        id, children: [], style: {}, dataset: {}, classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
        _html: '', textContent: '', value: '',
        get innerHTML() { return this._html; },
        set innerHTML(v) { this._html = String(v); rendered.push(this._html); },
        appendChild(c) { this.children.push(c); if (c && c._html) rendered.push(c._html); return c; },
        insertBefore(c) { return this.appendChild(c); },
        prepend(c) { return this.appendChild(c); },
        insertAdjacentHTML(_, h) { rendered.push(String(h)); },
        addEventListener() {}, removeEventListener() {}, setAttribute() {}, getAttribute() { return null; },
        querySelector() { return fakeElement('q'); }, querySelectorAll() { return []; },
        remove() {}, focus() {}, click() {}, closest() { return null; },
        getContext() { return new Proxy({}, { get: () => () => ({}) }); },
        get firstChild() { return null; }, get lastElementChild() { return null; },
    };
    return el;
}
const rendered = [];
const elements = {};
const documentStub = {
    getElementById: id => (elements[id] = elements[id] || fakeElement(id)),
    createElement: tag => fakeElement(tag),
    querySelector: () => fakeElement('q'), querySelectorAll: () => [],
    addEventListener() {}, body: fakeElement('body'), readyState: 'loading',
};
const ctx = {
    console: { log() {}, warn() {}, error() {}, debug() {}, info() {} },
    document: documentStub, setTimeout() { return 0; }, clearTimeout() {}, setInterval() { return 0; }, clearInterval() {},
    fetch: () => new Promise(() => {}), localStorage: { getItem() { return null; }, setItem() {} },
    sessionStorage: { getItem() { return null; }, setItem() {} },
    location: { href: '', pathname: '/', reload() {} }, navigator: { userAgent: 'node' },
    bootstrap: { Modal: function () { return { show() {}, hide() {} }; }, Tooltip: function () {} },
    io: () => ({ on() {}, emit() {} }), Chart: function () { return { update() {}, destroy() {} }; },
    Audio: function () { return { play() { return Promise.resolve(); } }; },
    Notification: { permission: 'denied', requestPermission() { return Promise.resolve('denied'); } },
    URLSearchParams, Date, Math, JSON, Promise, Object, Array, String, Number, Set, Map, RegExp, Intl, parseInt, parseFloat, isNaN,
    addEventListener() {}, matchMedia: () => ({ matches: false, addEventListener() {} }),
    requestAnimationFrame() { return 0; }, cancelAnimationFrame() {}, devicePixelRatio: 1, innerWidth: 1280, innerHeight: 800,
    ResizeObserver: function () { return { observe() {}, disconnect() {} }; },
};
ctx.window = ctx;
vm.createContext(ctx);
for (const f of ['web/static/js/escape.js', 'web/static/js/dashboard.js']) {
    vm.runInContext(fs.readFileSync(path.join(root, f), 'utf8'), ctx, { filename: f });
}

const evilAlert = {
    id: 1, threat_type: 'DNS_TUNNEL' + PAYLOAD, severity: 'HIGH',
    description: 'Domain Generation Algorithm detected: ' + PAYLOAD,
    source_ip: '10.0.0.1', destination_ip: '10.0.0.2',
    source_hostname: PAYLOAD, destination_hostname: ATTR_PAYLOAD,
    source_country: PAYLOAD, destination_country: PAYLOAD,
    metadata: JSON.stringify({ sni: PAYLOAD, [PAYLOAD]: 'key-als-payload' }),
    timestamp: new Date().toISOString(), acknowledged: false,
};
const group = Object.assign({}, evilAlert, {
    alerts: [evilAlert], count: 2, first_seen: evilAlert.timestamp, last_seen: evilAlert.timestamp,
});

let failures = 0;
function check(name, fn) {
    rendered.length = 0;
    try {
        fn();
    } catch (e) {
        console.error(`FAIL ${name}: exception ${e.message}`);
        failures++;
        return;
    }
    const out = rendered.join('\n');
    if (!out) {
        console.error(`FAIL ${name}: niets gerenderd`);
        failures++;
    } else if (out.includes('<img') || out.includes('onmouseover="alert')) {
        console.error(`FAIL ${name}: payload ongeëscaped in output`);
        failures++;
    } else if (/&lt;\/?(span|small|div|i|strong|tr|td|table|h6|button|code|br)\b/.test(out)) {
        console.error(`FAIL ${name}: bedoelde HTML dubbel ge-escaped (zichtbare tags): ` +
                      out.match(/.{0,40}&lt;\/?(span|small|div|i|strong|tr|td|table|h6|button|code|br)\b.{0,40}/)[0]);
        failures++;
    } else if (!out.includes('&lt;img')) {
        console.error(`FAIL ${name}: payload niet (ge-escaped) zichtbaar - render-pad niet geraakt?`);
        failures++;
    } else {
        console.log(`ok   ${name}`);
    }
}

check('alert-feed (addGroupedAlertToFeed)', () => vm.runInContext('addGroupedAlertToFeed', ctx)(group));
check('alert-details modal (showAlertDetails)', () => vm.runInContext('showAlertDetails', ctx)(group));

process.exit(failures ? 1 : 0);
