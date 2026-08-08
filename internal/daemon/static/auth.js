// auth.js — attaches the daemon's hook secret to dashboard API calls.
//
// The daemon's /api/ endpoints require an X-Hook-Secret header. The browser has
// no way to read the secret's 0600 file, so `sinesync dashboard` passes a
// single-use TICKET in the URL fragment (http://127.0.0.1:PORT/#ticket=...),
// which this file exchanges via POST /api/auth/redeem for a SESSION TOKEN — not
// the hook secret.
//
// A fragment is never sent to the server, so nothing lands in a request line, an
// access log, or a Referer header. It does not solve argv: the URL is still
// handed to open/xdg-open/start, and argv is readable by every account on this
// machine via ps or /proc/<pid>/cmdline. Single-use only makes that a race —
// another local process can scrape the ticket while the browser starts and
// redeem it first, in which case this page gets a 401.
//
// Which is why what it redeems for is deliberately weak. A session token reads
// dashboard data and nothing else: no capture, no shutdown, no minting further
// tickets, and it expires. Losing the race is a bounded read-only disclosure
// rather than handing over the master credential. See internal/daemon/ticket.go.
//
// Nothing is baked into the served HTML either: GET / is unauthenticated, so
// anyone on the loopback port could simply fetch the page.
//
// This file must load before app.js so the fetch wrapper is installed before any
// API call is made.
(function () {
    'use strict';

    var STORAGE_KEY = 'sinesync.token';
    var memoryToken = null; // fallback when sessionStorage is unavailable

    function readStoredToken() {
        try {
            return sessionStorage.getItem(STORAGE_KEY);
        } catch (e) {
            return memoryToken;
        }
    }

    function storeToken(token) {
        memoryToken = token;
        try {
            sessionStorage.setItem(STORAGE_KEY, token);
        } catch (e) {
            // Private mode or a blocked storage partition — the in-memory copy
            // still covers this page load.
        }
    }

    // Read a named value out of the fragment, then strip the fragment from the
    // address bar so it is not left sitting on a shared screen or in a bookmark.
    function takeFragmentValue(name) {
        var hash = window.location.hash || '';
        if (hash.charAt(0) === '#') {
            hash = hash.slice(1);
        }
        if (!hash) {
            return null;
        }
        var found = null;
        hash.split('&').forEach(function (pair) {
            var eq = pair.indexOf('=');
            if (eq === -1) {
                return;
            }
            if (decodeURIComponent(pair.slice(0, eq)) === name) {
                found = decodeURIComponent(pair.slice(eq + 1));
            }
        });
        if (found !== null) {
            try {
                history.replaceState(null, '', window.location.pathname + window.location.search);
            } catch (e) {
                window.location.hash = '';
            }
        }
        return found;
    }

    // nativeFetch is captured before the wrapper is installed, because redeeming
    // is itself an /api/ call — routing it through the wrapper would wait on the
    // very promise it is trying to resolve.
    var nativeFetch = window.fetch.bind(window);

    // tokenReady resolves to the secret, or to null if none can be obtained.
    // Every API call awaits it, so a request issued by app.js during startup
    // does not race the redemption.
    var tokenReady = (function () {
        // A supplied ticket always wins over a stored token. The daemon
        // generates a new secret every time it starts, so a tab left open
        // across a restart holds a token that now 401s — and if the ticket were
        // discarded in favour of that stale value, `sinesync dashboard` could
        // not fix it and the only recovery would be clearing site storage.
        var ticket = takeFragmentValue('ticket');
        if (!ticket) {
            return Promise.resolve(readStoredToken());
        }

        return nativeFetch('/api/auth/redeem', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ticket: ticket })
        }).then(function (response) {
            if (!response.ok) {
                // Redemption failed — an expired or already-spent ticket. Fall
                // back to a stored token if there is one; it may still be valid
                // when the daemon has not restarted.
                return readStoredToken();
            }
            return response.json().then(function (data) {
                if (data && data.token) {
                    storeToken(data.token);
                    return data.token;
                }
                return readStoredToken();
            });
        }).catch(function () {
            return readStoredToken();
        });
    })();

    // --- visible failure ------------------------------------------------

    var bannerShown = false;

    function showAuthBanner(message) {
        if (bannerShown) {
            return;
        }
        bannerShown = true;

        function render() {
            var el = document.createElement('div');
            el.id = 'sinesync-auth-banner';
            el.setAttribute('role', 'alert');
            el.style.cssText = [
                'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
                'padding:14px 20px', 'background:#7f1d1d', 'color:#fff',
                'font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif',
                'text-align:center', 'box-shadow:0 2px 8px rgba(0,0,0,.4)'
            ].join(';');
            el.innerHTML = '<strong>Dashboard not authorized.</strong> ' + message +
                ' Open it with <code style="background:rgba(255,255,255,.18);padding:2px 6px;border-radius:4px">sinesync dashboard</code>' +
                ' so the access token is supplied.';
            document.body.appendChild(el);
        }

        if (document.body) {
            render();
        } else {
            document.addEventListener('DOMContentLoaded', render);
        }
    }

    // A scope refusal is transient and dismissible: unlike a missing token, the
    // rest of the dashboard still works, so it must not look like a dead page.
    function showScopeBanner() {
        var existing = document.getElementById('sinesync-scope-banner');
        if (existing) {
            return;
        }
        var el = document.createElement('div');
        el.id = 'sinesync-scope-banner';
        el.setAttribute('role', 'alert');
        el.style.cssText = [
            'position:fixed', 'bottom:16px', 'left:50%', 'transform:translateX(-50%)',
            'z-index:2147483647', 'padding:12px 18px', 'border-radius:8px',
            'background:#78350f', 'color:#fff', 'max-width:min(560px,92vw)',
            'font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif',
            'box-shadow:0 4px 16px rgba(0,0,0,.4)'
        ].join(';');
        el.innerHTML = '<strong>Not permitted from the dashboard.</strong> ' +
            'Deleting propagates to every synced device, so it needs the CLI: ' +
            '<code style="background:rgba(255,255,255,.18);padding:2px 6px;border-radius:4px">sinesync forget &lt;id&gt;</code>.';
        (document.body || document.documentElement).appendChild(el);
        setTimeout(function () {
            if (el.parentNode) {
                el.parentNode.removeChild(el);
            }
        }, 8000);
    }

    // --- fetch wrapper ---------------------------------------------------

    // One wrapper covers every API call site in app.js rather than editing each
    // one, so a new call site cannot forget to authenticate.
    function isDaemonAPI(url) {
        try {
            var u = new URL(url, window.location.href);
            return u.origin === window.location.origin && u.pathname.indexOf('/api/') === 0;
        } catch (e) {
            return false;
        }
    }

    window.fetch = function (input, init) {
        var url = (typeof input === 'string') ? input : (input && input.url);
        if (!isDaemonAPI(url)) {
            return nativeFetch(input, init);
        }

        return tokenReady.then(function (token) {
            if (!token) {
                showAuthBanner('No access token was supplied to this page.');
                // Fall through and let the request 401 — the app's own error
                // handling still runs, and the banner explains why.
            }

            if (typeof input === 'string') {
                var opts = Object.assign({}, init || {});
                var headers = new Headers((init && init.headers) || {});
                if (token) {
                    headers.set('X-Hook-Secret', token);
                }
                opts.headers = headers;
                return nativeFetch(input, opts);
            }
            var req = new Request(input, init);
            if (token) {
                req.headers.set('X-Hook-Secret', token);
            }
            return nativeFetch(req);
        }).then(function (response) {
            // A stale token is a real case: the daemon regenerates its secret on
            // every start, so a reloaded tab from a previous daemon will 401.
            if (response.status === 401) {
                showAuthBanner('The access token is missing or no longer valid.');
            }
            // 403 is a scope refusal, not an expiry — the dashboard session
            // deliberately cannot delete. Saying so beats a silent no-op, and
            // re-authenticating would not help.
            if (response.status === 403) {
                showScopeBanner();
            }
            return response;
        });
    };
})();
