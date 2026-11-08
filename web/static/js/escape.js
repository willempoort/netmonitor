/**
 * HTML-escaping helpers (audit H1: stored XSS).
 *
 * Data in alerts, apparaten, hostnamen, DNS-namen, TLS SNI, user agents enz.
 * komt (indirect) uit netwerkverkeer en is dus door een aanvaller te sturen.
 * Zet zulke waarden NOOIT rechtstreeks in innerHTML; gebruik:
 *
 *   el.innerHTML = `<td>${escapeHtml(alert.description)}</td>`;
 *   el.innerHTML = `<button onclick="showDevice(${jsArg(device.ip_address)})">`;
 *
 * of zet tekst via element.textContent.
 */
(function (global) {
    'use strict';

    // U+2028/U+2029 zijn geldig in JSON maar beëindigen een regel in oudere JS-parsers
    const LS = String.fromCharCode(0x2028);
    const LINE_SEPARATORS = new RegExp('[' + LS + String.fromCharCode(0x2029) + ']', 'g');

    const HTML_ESCAPES = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
        '`': '&#96;',
    };

    /** Escape een waarde voor gebruik als tekst of attribuutwaarde in HTML. */
    function escapeHtml(value) {
        if (value === null || value === undefined) {
            return '';
        }
        return String(value).replace(/[&<>"'`]/g, ch => HTML_ESCAPES[ch]);
    }

    /**
     * Waarde als JavaScript-argument binnen een inline event-handler
     * (onclick="fn(${jsArg(x)})"). De browser decodeert HTML-entities vóór de
     * JS draait, dus eerst JSON (JS-literal, met quotes) en dan HTML-escapen.
     */
    function jsArg(value) {
        const json = JSON.stringify(value === undefined ? null : value)
            .replace(/</g, '\\u003c')
            .replace(/>/g, '\\u003e')
            .replace(LINE_SEPARATORS, ch => (ch === LS ? '\\u2028' : '\\u2029'));
        return escapeHtml(json);
    }

    /** Alleen http(s)-, mailto- en relatieve URL's; anders '#'. */
    function safeUrl(value) {
        const url = String(value === null || value === undefined ? '' : value).trim();
        if (/^(https?:|mailto:|\/|#|\.)/i.test(url) || !/^[a-z][a-z0-9+.-]*:/i.test(url)) {
            return escapeHtml(url);
        }
        return '#';
    }

    global.escapeHtml = escapeHtml;
    global.jsArg = jsArg;
    global.safeUrl = safeUrl;
})(window);
