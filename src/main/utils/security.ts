/**
 * Security utilities for the Electron main process.
 *
 * @module SecurityManager
 */

import type { Session, App } from 'electron';
import { CUSTOM_USER_AGENT } from './constants';
import { getPlatformAdapter } from '../platform/platformAdapterFactory';
import { createLogger } from './logger';

const logger = createLogger('[SecurityManager]');

/**
 * Strip security headers that prevent iframe embedding.
 * This is the key to making custom HTML menus work over external content.
 *
 * SECURITY: Only strips headers for Gemini domains to minimize attack surface.
 *
 * @param session - The default session
 */
export function setupHeaderStripping(session: Session): void {
    // Only modify headers for Gemini-related domains
    const allowedUrls = [
        '*://gemini.google.com/*',
        '*://*.gemini.google.com/*',
        '*://aistudio.google.com/*',
        '*://*.google.com/gemini/*',
        '*://accounts.google.com/*',
        '*://ogs.google.com/*',
        // Allow localhost for integration testing
        '*://localhost:*/*',
        '*://127.0.0.1:*/*',
    ];

    session.webRequest.onHeadersReceived({ urls: allowedUrls }, (details, callback) => {
        const responseHeaders = { ...details.responseHeaders };

        // Remove X-Frame-Options header (case-insensitive)
        delete responseHeaders['x-frame-options'];
        delete responseHeaders['X-Frame-Options'];

        // Remove frame-ancestors from CSP if present
        if (responseHeaders['content-security-policy']) {
            responseHeaders['content-security-policy'] = responseHeaders['content-security-policy'].map((csp) =>
                csp.replace(/frame-ancestors[^;]*(;|$)/gi, '')
            );
        }
        if (responseHeaders['Content-Security-Policy']) {
            responseHeaders['Content-Security-Policy'] = responseHeaders['Content-Security-Policy'].map((csp) =>
                csp.replace(/frame-ancestors[^;]*(;|$)/gi, '')
            );
        }

        callback({ responseHeaders });
    });

    logger.log('Header stripping enabled for Gemini domains only');
}

/**
 * Configure custom User-Agent and request headers for the session.
 * Prevents Google from blocking authentication attempts with a 403 error.
 *
 * SECURITY: Standardizes the User-Agent and removes Electron-identifying headers
 * to ensure compatibility with Google OAuth and the Gemini web app.
 *
 * @param session - The Electron session to configure
 */
export function setupUserAgent(session: Session): void {
    // 1. Set the User-Agent on the session itself
    session.setUserAgent(CUSTOM_USER_AGENT);

    // 2. Derive robust URL filters to ensure coverage matches our internally-handled domains.
    // This covers accounts.google.com, accounts.youtube.com, gemini.google.com, subdomains, etc.
    const urlFilters = [
        'https://accounts.google.com/*',
        'https://*.accounts.google.com/*',
        'https://accounts.youtube.com/*',
        'https://*.accounts.youtube.com/*',
        'https://gemini.google.com/*',
        'https://*.gemini.google.com/*',
        'https://aistudio.google.com/*',
        'https://*.aistudio.google.com/*',
        'https://ogs.google.com/*',
        'https://*.ogs.google.com/*',
    ];

    // 3. Use onBeforeSendHeaders to force the User-Agent and remove X-Requested-With.
    // This is more robust as it catches requests where the browser might try to
    // add its own headers or revert the User-Agent.
    session.webRequest.onBeforeSendHeaders(
        {
            urls: urlFilters,
        },
        (details, callback) => {
            const requestHeaders = { ...details.requestHeaders };

            // Ensure the custom User-Agent is used
            requestHeaders['User-Agent'] = CUSTOM_USER_AGENT;

            // Remove X-Requested-With which often contains the app name or Electron,
            // which Google uses to block "embedded browsers".
            delete requestHeaders['X-Requested-With'];

            callback({ requestHeaders });
        }
    );

    logger.log('Custom User-Agent and header masking configured for session');
}

/**
 * Block the creation of secure webviews to prevent unauthorized content embedding
 * or potential security bypasses within the renderer.
 *
 * @param app - The Electron app instance
 */
export function setupWebviewSecurity(app: App): void {
    app.on('web-contents-created', (_, contents) => {
        contents.on('will-attach-webview', (event) => {
            event.preventDefault();
            logger.warn('Blocked webview creation attempt in renderer');
        });
    });
    logger.log('Webview creation blocking enabled');
}

/**
 * Setup media permission handler for microphone access.
 * Allows media requests from trusted Gemini/Google domains.
 *
 * SECURITY: Only approves media permissions for Google domains.
 * All other permission requests are denied.
 *
 * @param session - The default session
 */
export function setupMediaPermissions(session: Session): void {
    session.setPermissionRequestHandler((_webContents, permission, callback, details) => {
        const url = details.requestingUrl || '';

        // Allowed permissions for Gemini/Google domains:
        // - media: Required for microphone access (voice input/Gemini Live)
        // - clipboard-sanitized-write: Required for "Copy" buttons in the UI
        const allowedPermissions = ['media', 'clipboard-sanitized-write'];

        if (allowedPermissions.includes(permission)) {
            // Use URL parser to safely validate hostname (fixes CWE-20 vulnerability)
            let hostname = '';
            try {
                hostname = new URL(url).hostname;
            } catch {
                // Invalid URL, deny permission
                logger.log(`Denying ${permission} permission: invalid URL`);
                callback(false);
                return;
            }

            // Allow only trusted Google domains
            if (hostname.endsWith('.google.com') || hostname === 'google.com') {
                logger.log(`Granting ${permission} permission to: ${url}`);
                callback(true);
                return;
            }
        }

        // Deny all other permission requests
        logger.log(`Denying ${permission} permission request from: ${url}`);
        callback(false);
    });

    // macOS: Proactively request microphone access
    const adapter = getPlatformAdapter();
    adapter.requestMediaPermissions?.(logger);

    logger.log('Media permission handler configured for Gemini domains');
}
