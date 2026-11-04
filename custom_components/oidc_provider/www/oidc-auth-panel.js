// OIDC login panel. Shows the consent screen for a pending authorization
// request and completes the redirect back to the client.
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
      this._renderCard(`
        <h1>No pending request</h1>
        <p>There is no authorization request waiting for you. Start again from the application that sent you here.</p>
      `);
      return;
    }

    this._requestId = requestId;
    this._renderCard(`
      <h1>One moment</h1>
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
      this._renderError(error);
    }
  }

  _renderConsent(details) {
    const scopes = (details.scopes || []).map((scope) => {
      const description = Object.hasOwn(SCOPE_DESCRIPTIONS, scope) ? SCOPE_DESCRIPTIONS[scope] : scope;
      return `<li>${escapeHtml(description)}</li>`;
    });

    this._renderCard(
      `
        <h1>Approve access?</h1>
        <p>If you continue, you will be sent to <b>${escapeHtml(details.redirect_host)}</b>. The application will be able to see:</p>
        <ul>${scopes.join('')}</ul>
        <div class="action">
          <ha-button id="oidc-approve">Approve</ha-button>
        </div>
        <div class="action">
          <ha-button id="oidc-deny" appearance="plain" variant="neutral">Deny</ha-button>
        </div>
      `,
      `
        <ha-alert alert-type="warning">
          You're about to give <b>${escapeHtml(details.client_name)}</b> access to your Home Assistant instance.
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
      <h1>${approve ? 'Access approved' : 'Access denied'}</h1>
      <p>Sending you back to the application.</p>
    `);
    window.location.href = data.redirect_url;
  }

  async _fetchJson(url, init = {}) {
    const response = await fetch(url, {
      ...init,
      headers: {
        ...(init.headers || {}),
        Authorization: `Bearer ${this._accessToken()}`,
      },
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`${response.status} ${text}`.trim());
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

  _renderError(error) {
    this._renderCard(
      `
        <h1>Something went wrong</h1>
        <p>The authorization could not be completed. Close this page and try again from the application.</p>
      `,
      `<ha-alert alert-type="error">${escapeHtml(error.message)}</ha-alert>`
    );
  }

  _renderCard(cardHtml, beforeCardHtml = '') {
    this.innerHTML = `
      <style>${STYLES}</style>
      <div class="oidc-page">
        <div class="oidc-content">
          <div class="oidc-header">
            <img src="/static/icons/favicon-192x192.png" alt="Home Assistant">
          </div>
          ${beforeCardHtml}
          <div class="card-content">${cardHtml}</div>
        </div>
      </div>
    `;
  }
}

customElements.define('oidc-auth-panel', OidcLoginPanel);
