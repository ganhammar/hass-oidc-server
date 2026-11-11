// OIDC login panel. Shows the consent screen for a pending authorization
// request and completes the redirect back to the client. Opened without a
// pending request, it lists the applications signed in as the current user
// and lets them end those sessions. Administrators also get a Clients tab
// there, to register, edit and revoke clients.
//
// The layout mirrors Home Assistant's own login page (ha-authorize): a
// centered column with the HA icon above a card, built from HA's CSS
// variables so themes and dark mode apply.

const SCOPE_DESCRIPTIONS = {
  openid: 'Confirm who you are',
  profile: 'Your name',
  email: 'Your email address',
  groups: 'Your group memberships',
};

// Home Assistant's service worker answers a GET from its cache and refreshes
// the cache afterwards, except under /api and /auth. The lists are read again
// after every change, so they are served under /api.
const SESSIONS_URL = '/api/oidc_provider/sessions';
const CLIENTS_URL = '/api/oidc_provider/clients';

const SESSIONS_ERROR_HINT =
  'Your connected applications could not be loaded or changed. Reload the page to try again.';

const CLIENTS_ERROR_HINT = 'The clients could not be loaded. Reload the page to try again.';

const REVOKE_ERROR_HINT =
  'The client could not be revoked. Reload the page to see whether it is still listed.';

// A stored client without the dynamic marker was registered by an
// administrator, or by itself on a release that did not record that, so the
// label does not say who registered it.
const CLIENT_KINDS = {
  registered: 'Registered',
  dynamic: 'Registered by itself (dynamic registration)',
  metadata_document: 'Identified by a metadata document',
};

const STYLES = `
  .oidc-page {
    box-sizing: border-box;
    padding: 32px 0;
    min-height: 100%;
    background-color: var(--primary-background-color, #fafafa);
    color: var(--primary-text-color, #212121);
  }
  .oidc-content {
    width: 100%;
    max-width: 400px;
    margin: 0 auto;
    padding: 0 16px;
    box-sizing: content-box;
  }
  .oidc-header {
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 32px;
  }
  .oidc-header img {
    height: 56px;
    width: 56px;
  }
  .oidc-page ha-alert {
    display: block;
    margin: 16px 0;
    background-color: var(--primary-background-color, #fafafa);
  }
  .oidc-page p,
  .oidc-page li {
    font-size: var(--ha-font-size-m, 14px);
    line-height: var(--ha-line-height-normal, 20px);
  }
  .oidc-page ul {
    padding-left: 20px;
    margin: 8px 0 0;
  }
  .card-content {
    background: var(--ha-card-background, var(--card-background-color, white));
    box-shadow: var(--ha-card-box-shadow, none);
    box-sizing: border-box;
    border-radius: var(--ha-card-border-radius, var(--ha-border-radius-lg, 12px));
    border-width: var(--ha-card-border-width, 1px);
    border-style: solid;
    border-color: var(--ha-card-border-color, var(--divider-color, #e0e0e0));
    color: var(--primary-text-color);
    position: relative;
    padding: 16px;
  }
  .card-content h1:focus {
    outline: none;
  }
  .card-content h1 {
    font-size: var(--ha-font-size-3xl, 28px);
    font-weight: var(--ha-font-weight-normal, 400);
    margin-top: 16px;
    margin-bottom: 16px;
  }
  .action {
    margin-top: var(--ha-space-5, 20px);
  }
  .action ha-button {
    width: 100%;
  }
  .action + .action {
    margin-top: 8px;
  }
  .oidc-session {
    padding: 12px 0;
    border-top: 1px solid var(--divider-color, #e0e0e0);
  }
  .oidc-session .action {
    margin-top: 8px;
  }
  .oidc-session-meta {
    color: var(--secondary-text-color, #727272);
  }
  .oidc-content.oidc-wide {
    max-width: 600px;
  }
  .oidc-tabs {
    display: flex;
    gap: 8px;
    margin-bottom: 16px;
  }
  .oidc-tabs button {
    flex: 1;
    padding: 10px 8px;
    border: 0;
    border-bottom: 2px solid transparent;
    background: none;
    color: var(--secondary-text-color, #727272);
    font: inherit;
    font-size: var(--ha-font-size-m, 14px);
    cursor: pointer;
  }
  .oidc-tabs button[aria-current="page"] {
    color: var(--primary-color, #03a9f4);
    border-bottom-color: var(--primary-color, #03a9f4);
  }
  .oidc-client dl {
    margin: 8px 0 0;
    font-size: var(--ha-font-size-m, 14px);
    line-height: var(--ha-line-height-normal, 20px);
  }
  .oidc-client dt {
    color: var(--secondary-text-color, #727272);
    margin-top: 6px;
  }
  .oidc-client dd {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .oidc-client code,
  .oidc-field input[readonly] {
    font-family: var(--ha-font-family-code, monospace);
  }
  .oidc-row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 12px;
  }
  .oidc-field {
    display: block;
    margin-top: 16px;
    font-size: var(--ha-font-size-m, 14px);
  }
  .oidc-field span {
    display: block;
    margin-bottom: 4px;
  }
  .oidc-field small {
    display: block;
    margin-top: 4px;
    color: var(--secondary-text-color, #727272);
  }
  .oidc-field input[type="text"],
  .oidc-field textarea {
    box-sizing: border-box;
    width: 100%;
    padding: 10px;
    border: 1px solid var(--divider-color, #e0e0e0);
    border-radius: var(--ha-border-radius-sm, 4px);
    background: var(--primary-background-color, #fafafa);
    color: var(--primary-text-color, #212121);
    font: inherit;
  }
  .oidc-field textarea {
    min-height: 80px;
    resize: vertical;
  }
  .oidc-check {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    margin-top: 16px;
    font-size: var(--ha-font-size-m, 14px);
  }
  .oidc-copy {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .oidc-copy input {
    flex: 1;
    min-width: 0;
  }
`;

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

class OidcLoginPanel extends HTMLElement {
  set hass(hass) {
    this._hass = hass;
    if (this._hassReady) {
      this._hassReady();
    }
  }

  get hass() {
    return this._hass;
  }

  setConfig(config) {
    // Required method for custom panels
  }

  async connectedCallback() {
    const requestId = sessionStorage.getItem('oidc_request_id');
    if (!requestId) {
      try {
        await this._waitForHass();
      } catch (error) {
        this._renderError(error, SESSIONS_ERROR_HINT);
        return;
      }
      await this._renderHome();
      return;
    }

    this._requestId = requestId;
    this._renderCard(`
      <h1 tabindex="-1">One moment</h1>
      <p>Loading the authorization request.</p>
    `);

    try {
      await this._waitForHass();
      const details = await this._fetchJson(`/oidc/continue?request_id=${encodeURIComponent(requestId)}`);

      if (details.consent_required) {
        this._renderConsent(details);
      } else {
        await this._decide(true);
      }
    } catch (error) {
      if (error.status !== 400) {
        this._renderError(error);
        return;
      }
      // The stored request has expired or was already used. It stays in this
      // tab's storage until cleared, so clear it and show the applications.
      sessionStorage.removeItem('oidc_request_id');
      await this._renderHome(
        'That sign-in request is no longer valid. To sign in, start again from the application.'
      );
    }
  }

  // The page shown when no sign-in is pending: the user's connected
  // applications and, for administrators, the Clients tab.
  async _renderHome(notice = '') {
    this._home = true;
    const wantsClients = new URLSearchParams(window.location.search).get('tab') === 'clients';
    await this._showTab(wantsClients && this._isAdmin() ? 'clients' : 'sessions', notice);
  }

  _isAdmin() {
    return Boolean(this._hass?.user?.is_admin);
  }

  async _showTab(tab, notice = '') {
    this._tab = tab;
    try {
      if (tab === 'clients') {
        await this._renderClients(notice, 'info');
      } else {
        await this._renderSessions(notice);
      }
    } catch (error) {
      if (this._tab === tab) {
        this._renderError(error, tab === 'clients' ? CLIENTS_ERROR_HINT : SESSIONS_ERROR_HINT);
      }
    }
  }

  _selectTab(tab) {
    const url = new URL(window.location.href);
    if (tab === 'clients') {
      url.searchParams.set('tab', 'clients');
    } else {
      url.searchParams.delete('tab');
    }
    window.history.replaceState(window.history.state, '', url);
    this._showTab(tab);
  }

  _tabsHtml() {
    if (!this._home || !this._isAdmin()) {
      return '';
    }
    const tab = (id, label) =>
      `<button type="button" data-tab="${id}"${this._tab === id ? ' aria-current="page"' : ''}>${label}</button>`;
    return `<nav class="oidc-tabs" aria-label="Sections">${tab('sessions', 'Connected applications')}${tab('clients', 'Clients')}</nav>`;
  }

  _renderConsent(details) {
    const scopes = (details.scopes || []).map((scope) => {
      const description = Object.hasOwn(SCOPE_DESCRIPTIONS, scope) ? SCOPE_DESCRIPTIONS[scope] : scope;
      return `<li>${escapeHtml(description)}</li>`;
    });

    // A client identified by a metadata document is vouched for only by the
    // host serving that document, so the host is shown next to its name. bdi
    // keeps right-to-left text in a name from reordering what follows it.
    const clientLabel = details.client_host
      ? `<b><bdi>${escapeHtml(details.client_name)}</bdi></b> from <b><bdi>${escapeHtml(details.client_host)}</bdi></b>`
      : `<b><bdi>${escapeHtml(details.client_name)}</bdi></b>`;
    // Any program on a computer can listen on a loopback address, so a sign-in
    // that returns there is only safe when the user started it themselves.
    const loopbackNote = details.redirect_is_loopback
      ? '<p>This sends you back to an application on your own computer. Only approve if you started this sign-in yourself.</p>'
      : '';

    this._renderCard(
      `
        <h1 tabindex="-1">Approve access?</h1>
        <p>If you continue, you will be sent to <b><bdi>${escapeHtml(details.redirect_host)}</bdi></b>. The application will be able to see:</p>
        <ul>${scopes.join('')}</ul>
        ${loopbackNote}
        <div class="action">
          <ha-button id="oidc-approve">Approve</ha-button>
        </div>
        <div class="action">
          <ha-button id="oidc-deny" appearance="plain" variant="neutral">Deny</ha-button>
        </div>
      `,
      `
        <ha-alert alert-type="warning">
          You're about to give ${clientLabel} access to your Home Assistant instance.
        </ha-alert>
      `
    );

    this.querySelector('#oidc-approve').addEventListener('click', () => this._onDecision(true));
    this.querySelector('#oidc-deny').addEventListener('click', () => this._onDecision(false));
  }

  async _onDecision(approve) {
    // One decision per request, even if the buttons have not upgraded yet
    if (this._deciding) {
      return;
    }
    this._deciding = true;
    for (const button of this.querySelectorAll('ha-button')) {
      button.disabled = true;
    }
    try {
      await this._decide(approve);
    } catch (error) {
      this._deciding = false;
      this._renderError(error);
    }
  }

  async _decide(approve) {
    const data = await this._fetchJson('/oidc/continue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ request_id: this._requestId, approve }),
    });

    if (!data.redirect_url) {
      throw new Error('No redirect received from Home Assistant');
    }

    // The request is consumed either way; a reload must not replay it.
    sessionStorage.removeItem('oidc_request_id');

    this._renderCard(`
      <h1 tabindex="-1">${approve ? 'Access approved' : 'Access denied'}</h1>
      <p>Sending you back to the application.</p>
    `);
    window.location.href = data.redirect_url;
  }

  async _renderSessions(notice = '') {
    const { sessions } = await this._fetchJson(SESSIONS_URL);
    // The user may have switched tabs while the list was on its way
    if (this._home && this._tab !== 'sessions') {
      return;
    }
    const formatTime = (seconds) => (seconds ? new Date(seconds * 1000).toLocaleString() : 'never');
    const items = sessions.map((session) => {
      const host = session.client_host ? ` from <bdi>${escapeHtml(session.client_host)}</bdi>` : '';
      return `
        <div class="oidc-session">
          <b><bdi>${escapeHtml(session.client_name)}</bdi></b>${host}
          <div class="oidc-session-meta">Signed in ${escapeHtml(formatTime(session.signed_in_at))}, last used ${escapeHtml(formatTime(session.last_used_at))}</div>
          <div class="action">
            <ha-button appearance="plain" variant="danger" data-session="${escapeHtml(session.session_id)}">Sign out</ha-button>
          </div>
        </div>
      `;
    });

    this._renderCard(
      `
      <h1 tabindex="-1">Connected applications</h1>
      ${
        items.length
          ? `<p>These applications can use your Home Assistant account. Signing one out stops it from getting new access; access it already has runs out within the hour. To get access back, it has to ask you again.</p>${items.join('')}`
          : '<p>No applications are signed in with your Home Assistant account.</p>'
      }
    `,
      notice ? `<ha-alert alert-type="info">${escapeHtml(notice)}</ha-alert>` : ''
    );

    for (const button of this.querySelectorAll('ha-button[data-session]')) {
      button.addEventListener('click', () => this._endSession(button.dataset.session));
    }
  }

  async _endSession(sessionId) {
    for (const button of this.querySelectorAll('ha-button')) {
      button.disabled = true;
    }
    try {
      await this._fetchJson(`${SESSIONS_URL}/${encodeURIComponent(sessionId)}`, { method: 'DELETE' });
      await this._renderSessions();
    } catch (error) {
      this._renderError(error, SESSIONS_ERROR_HINT);
    }
  }

  async _renderClients(notice = '', noticeType = 'success') {
    const { clients } = await this._fetchJson(CLIENTS_URL);
    if (this._tab !== 'clients') {
      return;
    }
    this._clients = clients;
    const items = clients.map((client, index) => {
      const stored = client.registration !== 'metadata_document';
      const host = client.client_host ? ` from <bdi>${escapeHtml(client.client_host)}</bdi>` : '';
      const settings = stored
        ? `
            <dt>Redirect URIs</dt>
            ${client.redirect_uris.map((uri) => `<dd><bdi>${escapeHtml(uri)}</bdi></dd>`).join('') || '<dd>None</dd>'}
            <dt>Consent screen</dt>
            <dd>${client.consent_required ? 'Shown on every sign-in' : 'Skipped'}</dd>
          `
        : '';
      return `
        <div class="oidc-session oidc-client">
          <b><bdi>${escapeHtml(client.client_name)}</bdi></b>${host}
          <div class="oidc-session-meta">${escapeHtml(CLIENT_KINDS[client.registration] || client.registration)}</div>
          <dl>
            <dt>Client ID</dt>
            <dd><code><bdi>${escapeHtml(client.client_id)}</bdi></code></dd>
            ${settings}
            <dt>Active sessions</dt>
            <dd>${escapeHtml(client.active_sessions)}</dd>
          </dl>
          <div class="oidc-row">
            ${stored ? `<ha-button appearance="plain" data-edit="${index}">Edit</ha-button>` : ''}
            <ha-button appearance="plain" variant="danger" data-revoke="${index}">${stored ? 'Revoke' : 'End sessions'}</ha-button>
          </div>
        </div>
      `;
    });

    this._renderCard(
      `
        <h1 tabindex="-1">Clients</h1>
        <p>The applications that can sign users in through this Home Assistant. A client you register gets a client ID and a secret to configure in the application.</p>
        <div class="action">
          <ha-button id="oidc-register">Register a client</ha-button>
        </div>
        ${items.length ? items.join('') : '<p>No clients are registered.</p>'}
      `,
      notice ? `<ha-alert alert-type="${noticeType}">${escapeHtml(notice)}</ha-alert>` : '',
      true
    );

    this.querySelector('#oidc-register').addEventListener('click', () => this._renderClientForm());
    for (const button of this.querySelectorAll('ha-button[data-edit]')) {
      button.addEventListener('click', () => this._renderClientForm(this._clients[button.dataset.edit]));
    }
    for (const button of this.querySelectorAll('ha-button[data-revoke]')) {
      button.addEventListener('click', () => this._renderRevoke(this._clients[button.dataset.revoke]));
    }
  }

  // The form registers a client, or edits the one given. What was typed is
  // kept when the server refuses it, so the error can be fixed in place.
  _renderClientForm(client = null, values = null, error = '') {
    const current = values || {
      client_name: client?.client_name || '',
      redirect_uris: (client?.redirect_uris || []).join('\n'),
      consent_required: client?.consent_required || false,
    };
    const name = client
      ? `<p>Change where <b><bdi>${escapeHtml(client.client_name)}</bdi></b> may send users after sign-in, and whether they are asked first.</p>`
      : `
        <label class="oidc-field">
          <span>Name</span>
          <input type="text" id="oidc-name" maxlength="100" autocomplete="off" value="${escapeHtml(current.client_name)}">
          <small>Shown to users when the application asks for access.</small>
        </label>
      `;

    this._renderCard(
      `
        <h1 tabindex="-1">${client ? 'Edit client' : 'Register a client'}</h1>
        ${name}
        <label class="oidc-field">
          <span>Redirect URIs</span>
          <textarea id="oidc-uris" spellcheck="false" autocomplete="off">${escapeHtml(current.redirect_uris)}</textarea>
          <small>One per line. HTTPS is required, except for localhost.</small>
        </label>
        <label class="oidc-check">
          <input type="checkbox" id="oidc-consent" ${current.consent_required ? 'checked' : ''}>
          <span>Require consent: ask the user to approve each sign-in on a consent screen.</span>
        </label>
        <div class="action">
          <ha-button id="oidc-save">${client ? 'Save' : 'Register'}</ha-button>
        </div>
        <div class="action">
          <ha-button id="oidc-cancel" appearance="plain" variant="neutral">Cancel</ha-button>
        </div>
      `,
      error ? `<ha-alert alert-type="error">${escapeHtml(error)}</ha-alert>` : '',
      true
    );

    this.querySelector('#oidc-cancel').addEventListener('click', () => this._showTab('clients'));
    this.querySelector('#oidc-save').addEventListener('click', () => this._saveClient(client));
  }

  async _saveClient(client) {
    const values = {
      client_name: this.querySelector('#oidc-name')?.value || '',
      redirect_uris: this.querySelector('#oidc-uris').value,
      consent_required: this.querySelector('#oidc-consent').checked,
    };
    const body = {
      redirect_uris: values.redirect_uris.split('\n').map((uri) => uri.trim()).filter(Boolean),
      consent_required: values.consent_required,
    };
    if (!this._startRequest()) {
      return;
    }
    try {
      if (client) {
        await this._fetchJson(`${CLIENTS_URL}?client_id=${encodeURIComponent(client.client_id)}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        this._busy = false;
        await this._showClients(`Saved ${client.client_name}.`);
        return;
      }
      const registered = await this._fetchJson(CLIENTS_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...body, client_name: values.client_name }),
      });
      this._busy = false;
      this._renderCredentials(registered);
    } catch (error) {
      this._busy = false;
      this._renderClientForm(client, values, error.detail || error.message);
    }
  }

  // The secret is stored only as a hash, so this is the one time it is shown.
  _renderCredentials(registered) {
    const field = (id, label, value) => `
      <label class="oidc-field">
        <span>${label}</span>
        <div class="oidc-copy">
          <input type="text" id="${id}" readonly value="${escapeHtml(value)}">
          <ha-button appearance="plain" data-copy="${id}">Copy</ha-button>
        </div>
      </label>
    `;
    this._renderCard(
      `
        <h1 tabindex="-1">Client registered</h1>
        <p>Configure <b><bdi>${escapeHtml(registered.client_name)}</bdi></b> with these credentials.</p>
        ${field('oidc-client-id', 'Client ID', registered.client_id)}
        ${field('oidc-client-secret', 'Client secret', registered.client_secret)}
        <div class="action">
          <ha-button id="oidc-done">Done</ha-button>
        </div>
      `,
      '<ha-alert alert-type="warning">Copy the client secret now. Only a hash of it is stored, so it cannot be shown again.</ha-alert>',
      true
    );

    for (const button of this.querySelectorAll('ha-button[data-copy]')) {
      button.addEventListener('click', () => this._copy(button));
    }
    this.querySelector('#oidc-done').addEventListener('click', () => this._showTab('clients'));
  }

  async _copy(button) {
    const input = this.querySelector(`#${button.dataset.copy}`);
    try {
      await navigator.clipboard.writeText(input.value);
      button.textContent = 'Copied';
    } catch (error) {
      // The clipboard is unavailable outside a secure context. Selecting the
      // text leaves the user one keystroke from copying it.
      input.focus();
      input.select();
    }
  }

  _renderRevoke(client) {
    const stored = client.registration !== 'metadata_document';
    const sessions =
      client.active_sessions === 1 ? 'Its 1 session ends' : `Its ${client.active_sessions} sessions end`;
    const consequence = stored
      ? `${sessions} at once and the client is removed, so it can no longer sign users in. Access it already has runs out within the hour.`
      : `${sessions} at once. Access it already has runs out within the hour. It can ask users to sign in again unless client metadata documents are turned off.`;

    this._renderCard(
      `
        <h1 tabindex="-1">${stored ? 'Revoke client?' : 'End sessions?'}</h1>
        <p><b><bdi>${escapeHtml(client.client_name)}</bdi></b>: ${escapeHtml(consequence)}</p>
        <div class="action">
          <ha-button id="oidc-confirm" variant="danger">${stored ? 'Revoke' : 'End sessions'}</ha-button>
        </div>
        <div class="action">
          <ha-button id="oidc-cancel" appearance="plain" variant="neutral">Cancel</ha-button>
        </div>
      `,
      '',
      true
    );

    this.querySelector('#oidc-cancel').addEventListener('click', () => this._showTab('clients'));
    this.querySelector('#oidc-confirm').addEventListener('click', () => this._revokeClient(client));
  }

  async _revokeClient(client) {
    if (!this._startRequest()) {
      return;
    }
    try {
      await this._fetchJson(`${CLIENTS_URL}?client_id=${encodeURIComponent(client.client_id)}`, {
        method: 'DELETE',
      });
    } catch (error) {
      // Already gone, for instance revoked from another tab: the list shows it.
      if (error.status !== 404) {
        this._busy = false;
        this._renderError(error, REVOKE_ERROR_HINT);
        return;
      }
    }
    this._busy = false;
    const stored = client.registration !== 'metadata_document';
    await this._showClients(
      stored ? `Revoked ${client.client_name}.` : `Ended the sessions of ${client.client_name}.`
    );
  }

  async _showClients(notice) {
    try {
      await this._renderClients(notice);
    } catch (error) {
      this._renderError(error, CLIENTS_ERROR_HINT);
    }
  }

  // One request at a time, even if the buttons have not upgraded yet
  _startRequest() {
    if (this._busy) {
      return false;
    }
    this._busy = true;
    for (const button of this.querySelectorAll('ha-button, .oidc-tabs button')) {
      button.disabled = true;
    }
    return true;
  }

  async _fetchJson(url, init = {}) {
    // fetchWithAuth renews the Home Assistant access token when it has
    // expired, which a tab left open for a while needs.
    const response =
      typeof this._hass?.fetchWithAuth === 'function'
        ? await this._hass.fetchWithAuth(url, init)
        : await fetch(url, {
            ...init,
            headers: {
              ...(init.headers || {}),
              Authorization: `Bearer ${this._accessToken()}`,
            },
          });
    if (!response.ok) {
      const text = await response.text();
      const error = new Error(`${response.status} ${text}`.trim());
      error.status = response.status;
      try {
        error.detail = JSON.parse(text).message;
      } catch (parseError) {
        // Not a JSON error body; the status and text above say what happened
      }
      throw error;
    }
    return response.json();
  }

  _accessToken() {
    const hass = this._hass;
    const token =
      hass?.auth?.data?.access_token ||
      hass?.connection?.auth?.data?.access_token ||
      hass?.auth?.accessToken;
    if (typeof token !== 'string') {
      throw new Error('Home Assistant session not available');
    }
    return token;
  }

  _waitForHass() {
    if (this._hass) {
      return Promise.resolve();
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Home Assistant connection not available')), 5000);
      this._hassReady = () => {
        clearTimeout(timer);
        this._hassReady = null;
        resolve();
      };
    });
  }

  _renderError(
    error,
    hint = 'The authorization could not be completed. Close this page and try again from the application.'
  ) {
    this._renderCard(
      `
        <h1 tabindex="-1">Something went wrong</h1>
        <p>${escapeHtml(hint)}</p>
      `,
      `<ha-alert alert-type="error">${escapeHtml(error.message)}</ha-alert>`
    );
  }

  _renderCard(cardHtml, beforeCardHtml = '', wide = false) {
    this.innerHTML = `
      <style>${STYLES}</style>
      <div class="oidc-page">
        <div class="oidc-content${wide ? ' oidc-wide' : ''}">
          <div class="oidc-header">
            <img src="/static/icons/favicon-192x192.png" alt="Home Assistant">
          </div>
          ${this._tabsHtml()}
          ${beforeCardHtml}
          <div class="card-content">${cardHtml}</div>
        </div>
      </div>
    `;
    for (const button of this.querySelectorAll('.oidc-tabs button')) {
      button.addEventListener('click', () => this._selectTab(button.dataset.tab));
    }
    // Replacing the content drops keyboard focus, so a change of view moves
    // it to the new heading, which screen readers then announce.
    if (this._rendered) {
      this.querySelector('.card-content h1')?.focus();
    }
    this._rendered = true;
  }
}

customElements.define('oidc-auth-panel', OidcLoginPanel);
