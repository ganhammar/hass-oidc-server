// OIDC login panel. Shows the consent screen for a pending authorization
// request and completes the redirect back to the client. Opened without a
// pending request, it lists the applications signed in as the current user
// and lets them change the access of those sessions or end them.
// Administrators also get a Clients tab there, to register, edit and revoke
// clients.
//
// The layout mirrors Home Assistant's own login page (ha-authorize): a
// centered column with the HA icon above a card, built from HA's CSS
// variables so themes and dark mode apply.
//
// When the request is for a resource that describes the access it offers,
// the consent screen lets the user choose that access: one of the resource's
// levels, or one setting per area in a detailed view. The resource supplies
// that text in the user's language. Changing a session's access on
// Connected applications shows the same choice, with Save and Cancel. The
// panel's own text comes from the integration's translations, through
// STRINGS_URL, with the English bundled for when they cannot be loaded.

// The panel's text in English, the same as in translations/en.json, which a
// test keeps it in step with. It is shown until the translations have
// loaded, and in their place when they cannot be.
const FALLBACK_STRINGS = {
  "panel.loading_title": "One moment",
  "panel.loading_text": "Loading the authorization request.",
  "panel.error_title": "Something went wrong",
  "panel.error_hint": "The authorization could not be completed. Close this page and try again from the application.",
  "panel.sessions_error_hint": "Your connected applications could not be loaded or changed. Reload the page to try again.",
  "panel.request_gone": "That sign-in request is no longer valid. To sign in, start again from the application.",
  "panel.client_from_host": "{client} from {host}",
  "consent.heading": "Approve access?",
  "consent.alert": "You're about to give {client} access to your Home Assistant instance.",
  "consent.redirect": "If you continue, you will be sent to {host}. The application will be able to see:",
  "consent.scope_openid": "Confirm who you are",
  "consent.scope_profile": "Your name",
  "consent.scope_email": "Your email address",
  "consent.scope_groups": "Your group memberships",
  "consent.loopback": "This sends you back to an application on your own computer. Only approve if you started this sign-in yourself.",
  "consent.approve": "Approve",
  "consent.deny": "Deny",
  "consent.changed": "The access you can allow changed after this page opened. Check your choice and approve again.",
  "consent.approved_title": "Access approved",
  "consent.denied_title": "Access denied",
  "consent.sending_back": "Sending you back to the application.",
  "access.prompt": "Choose what {app} can do.",
  "access.choose_in_detail": "Choose in detail",
  "access.back": "Back to levels",
  "access.detail_heading": "Choose in detail",
  "access.start_from": "Start from a level",
  "access.preset_locked": "{level} (not available)",
  "access.custom": "Custom",
  "access.custom_summary": "Like {level}, except:",
  "access.custom_summary_many": "Your own choice for each area, closest to {level}.",
  "access.custom_status": "Custom: like {level}, except {differences}.",
  "access.custom_status_many": "Custom: your own choice for each area, closest to {level}.",
  "access.difference": "{area}: {option}",
  "access.last_choice": "Your choice last time",
  "access.not_available": "Not available",
  "access.locked_choice": "These settings are the same as {level}. {reason}",
  "access.fine_print": "When you approve, you go back to {host}.",
  "access.fine_print_sees": "{app} will also see your {information}.",
  "access.sees_profile": "name",
  "access.sees_email": "email address",
  "access.sees_groups": "group memberships",
  "access.change_later": "You can change what {app} can do, or sign it out, at any time under Connected applications.",
  "sessions.heading": "Connected applications",
  "sessions.intro": "These applications can use your Home Assistant account. Signing one out stops it from getting new access; access it already has runs out within the hour. To get access back, it has to ask you again.",
  "sessions.empty": "No applications are signed in with your Home Assistant account.",
  "sessions.access": "Access: {level}",
  "sessions.meta": "Signed in {signed_in}, last used {last_used}",
  "sessions.never": "never",
  "sessions.change_access": "Change access",
  "sessions.sign_out": "Sign out",
  "change.heading": "Change access for {client}",
  "change.save": "Save",
  "change.cancel": "Cancel",
  "change.changed": "The access you can allow changed after this page opened. Check your choice and save again.",
  "change.saved": "Saved. The access you chose applies the next time {app} gets new access; access it already has runs out within the hour.",
  "change.gone": "{app} is no longer signed in, so its access cannot be changed.",
  "change.current": "What it has now",
  "change.current_detail": "What {app} has now: {level}",
  "change.adjusted": "You can no longer allow the access {app} has now. {reason} Saving changes it to the choice below; Cancel leaves it as it is.",
  "change.cancel_keeps": "Cancel keeps the access {app} has now."
};

// The value of the level choice that stands for a custom choice. Preset ids
// start with a letter or digit, so none can be this.
const CUSTOM = '_custom';

const ICONS = {
  info: 'M11,9H13V7H11M12,20C7.59,20 4,16.41 4,12C4,7.59 7.59,4 12,4C16.41,4 20,7.59 20,12C20,16.41 16.41,20 12,20M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M11,17H13V11H11V17Z',
  check: 'M21,7L9,19L3.5,13.5L4.91,12.09L9,16.17L19.59,5.59L21,7Z',
  chevronRight: 'M8.59,16.58L13.17,12L8.59,7.41L10,6L16,12L10,18L8.59,16.58Z',
  chevronDown: 'M7.41,8.58L12,13.17L16.59,8.58L18,10L12,16L6,10L7.41,8.58Z',
  arrowLeft: 'M20,11V13H8L13.5,18.5L12.08,19.92L4.16,12L12.08,4.08L13.5,5.5L8,11H20Z',
  lock: 'M12,17C10.89,17 10,16.1 10,15C10,13.89 10.89,13 12,13A2,2 0 0,1 14,15A2,2 0 0,1 12,17M18,20V10H6V20H18M18,8A2,2 0 0,1 20,10V20A2,2 0 0,1 18,22H6C4.89,22 4,21.1 4,20V10C4,8.89 4.89,8 6,8H7V6A5,5 0 0,1 12,1A5,5 0 0,1 17,6V8H18M12,3A3,3 0 0,0 9,6V8H15V6A3,3 0 0,0 12,3Z',
  cancel: 'M12 2C17.5 2 22 6.5 22 12S17.5 22 12 22 2 17.5 2 12 6.5 2 12 2M12 4C10.1 4 8.4 4.6 7.1 5.7L18.3 16.9C19.3 15.5 20 13.8 20 12C20 7.6 16.4 4 12 4M16.9 18.3L5.7 7.1C4.6 8.4 4 10.1 4 12C4 16.4 7.6 20 12 20C13.9 20 15.6 19.4 16.9 18.3Z',
};

// Home Assistant's service worker answers a GET from its cache and refreshes
// the cache afterwards, except under /api and /auth. The lists are read again
// after every change and the text changes with a release, so they are served
// under /api.
const SESSIONS_URL = '/api/oidc_provider/sessions';
const CLIENTS_URL = '/api/oidc_provider/clients';
const STRINGS_URL = '/api/oidc_provider/strings';

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
  .oidc-session-actions {
    display: flex;
    gap: 8px;
  }
  .oidc-session-actions ha-button {
    flex: 1 1 0;
    min-width: 0;
  }
  .oidc-session-meta {
    color: var(--secondary-text-color, #727272);
  }
  .oidc-session .access {
    margin-top: 6px;
    color: var(--secondary-text-color, #727272);
  }
  .access-level {
    color: var(--primary-text-color);
    font-weight: var(--ha-font-weight-medium, 500);
  }
  .oidc-session .access ul,
  .current-access ul {
    margin: 2px 0 0;
    padding-left: 18px;
  }

  /* Choosing access */
  .oidc-page .icon {
    width: 24px;
    height: 24px;
    fill: currentColor;
    flex: none;
  }
  .oidc-page fieldset {
    border: 0;
    margin: 0;
    padding: 0;
    min-width: 0;
  }
  .oidc-page legend {
    padding: 0;
    float: left;
    width: 100%;
  }
  .oidc-page legend + * {
    clear: both;
  }
  .prompt {
    font-size: var(--ha-font-size-m, 14px);
    line-height: 1.6;
    margin-bottom: 12px;
  }
  .hint {
    color: var(--secondary-text-color, #727272);
  }
  .fine-print {
    margin: 24px 0 0;
  }
  .text-button {
    font: inherit;
    font-size: var(--ha-font-size-m, 14px);
    font-weight: var(--ha-font-weight-medium, 500);
    line-height: 1;
    height: 40px;
    border: 0;
    border-radius: 9999px;
    background: transparent;
    color: var(--ha-color-on-primary-normal, var(--primary-color));
    display: inline-flex;
    align-items: center;
    gap: 4px;
    cursor: pointer;
    -webkit-tap-highlight-color: transparent;
  }
  .text-button.neutral {
    color: var(--ha-color-on-neutral-normal, var(--secondary-text-color));
  }
  .text-button .icon {
    width: 20px;
    height: 20px;
  }
  .text-button:focus-visible {
    outline: 2px solid var(--primary-color);
    outline-offset: 2px;
  }
  @media (hover: hover) {
    .text-button:hover {
      background: var(--ha-color-fill-primary-quiet-resting, rgba(0, 0, 0, 0.04));
    }
    .text-button.neutral:hover {
      background: var(--ha-color-fill-neutral-quiet-resting, rgba(0, 0, 0, 0.04));
    }
  }
  .inline-action {
    margin: 4px 0 0 -12px;
    padding: 0 12px;
  }
  .back-action {
    margin: 0 0 0 -12px;
    padding: 0 12px 0 8px;
  }

  /* The levels, styled like ha-select-box */
  .level-list {
    display: grid;
    gap: 12px;
  }
  .level {
    position: relative;
    display: flex;
    gap: 12px;
    padding: 12px;
    border: 1px solid var(--divider-color, #e0e0e0);
    border-radius: 12px;
    cursor: pointer;
    overflow: hidden;
  }
  .level::before {
    content: "";
    position: absolute;
    inset: 0;
    opacity: 0.2;
    background: transparent;
    pointer-events: none;
    transition: background-color 180ms ease-in-out;
  }
  @media (hover: hover) {
    .level:not(.disabled):hover::before {
      background: var(--divider-color, #e0e0e0);
    }
  }
  .level:has(input:checked) {
    border-color: var(--primary-color);
  }
  .level:has(input:checked)::before {
    background: var(--primary-color);
  }
  .level:has(input:focus-visible) {
    outline: 2px solid var(--primary-color);
    outline-offset: 2px;
  }
  .level input {
    position: absolute;
    opacity: 0;
    width: 1px;
    height: 1px;
    margin: 0;
  }
  .radio {
    position: relative;
    flex: none;
    width: 20px;
    height: 20px;
    margin-top: 1px;
    box-sizing: border-box;
    border-radius: 50%;
    border: 2px solid var(--secondary-text-color, #727272);
    display: grid;
    place-items: center;
  }
  .level input:checked ~ .radio {
    border-color: var(--primary-color);
  }
  .level input:checked ~ .radio::after {
    content: "";
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--primary-color);
  }
  .level-text {
    position: relative;
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .level-label {
    font-size: var(--ha-font-size-l, 16px);
    font-weight: var(--ha-font-weight-medium, 500);
    line-height: 1.35;
  }
  .level-description {
    font-size: var(--ha-font-size-m, 14px);
    line-height: 1.45;
    color: var(--secondary-text-color, #727272);
  }
  .level-description ul {
    margin: 2px 0 0;
    padding-left: 18px;
  }
  .badge {
    display: inline-block;
    margin-inline-start: 6px;
    padding: 1px 8px;
    border-radius: 9999px;
    border: 1px solid var(--divider-color, #e0e0e0);
    font-size: var(--ha-font-size-s, 12px);
    font-weight: var(--ha-font-weight-normal, 400);
    line-height: 1.5;
    color: var(--secondary-text-color, #727272);
    vertical-align: 1px;
    white-space: nowrap;
  }
  .level-notes {
    display: none;
  }
  .level:has(input:checked) .level-notes {
    display: block;
  }
  .level.disabled {
    cursor: not-allowed;
  }
  .level.disabled .radio,
  .level.disabled .level-label,
  .level.disabled .level-description {
    opacity: 0.5;
  }
  .limit-reason {
    display: flex;
    gap: 6px;
    align-items: flex-start;
    margin-top: 4px;
    font-size: var(--ha-font-size-m, 14px);
    line-height: 1.45;
    color: var(--secondary-text-color, #727272);
  }
  .limit-reason .icon {
    width: 16px;
    height: 16px;
    margin-top: 2px;
  }

  /* Notes, styled like a compact ha-alert of the info type */
  .note {
    position: relative;
    display: flex;
    padding: 8px;
    margin: 8px 0 0;
    border-radius: 4px;
    font-size: var(--ha-font-size-m, 14px);
    line-height: 1.45;
  }
  .note::after {
    content: "";
    position: absolute;
    inset: 0;
    border-radius: 4px;
    background: var(--info-color, #039be5);
    opacity: 0.12;
    pointer-events: none;
  }
  .note .icon {
    width: 20px;
    height: 20px;
    color: var(--info-color, #039be5);
  }
  .note-text {
    margin-inline-start: 8px;
    align-self: center;
    overflow-wrap: anywhere;
  }

  /* The detailed view */
  .start-from {
    margin: 20px 0 8px;
  }
  .start-from label {
    display: block;
    font-size: var(--ha-font-size-s, 12px);
    color: var(--secondary-text-color, #727272);
    margin-bottom: 4px;
  }
  .select-wrap {
    position: relative;
  }
  .select-wrap select {
    appearance: none;
    width: 100%;
    height: 48px;
    padding: 0 40px 0 12px;
    font: inherit;
    font-size: var(--ha-font-size-l, 16px);
    color: var(--primary-text-color);
    background: transparent;
    border: 1px solid var(--input-outlined-idle-border-color, rgba(0, 0, 0, 0.38));
    border-radius: 4px;
    cursor: pointer;
  }
  .select-wrap select:hover {
    border-color: var(--input-outlined-hover-border-color, rgba(0, 0, 0, 0.87));
  }
  .select-wrap select:focus-visible {
    outline: 2px solid var(--primary-color);
    outline-offset: -1px;
    border-color: transparent;
  }
  .select-wrap select option {
    color: initial;
  }
  .select-wrap .icon {
    position: absolute;
    right: 10px;
    top: 12px;
    pointer-events: none;
    color: var(--secondary-text-color, #727272);
  }
  .custom-status {
    margin: 8px 0 0;
  }
  .areas {
    container-type: inline-size;
  }
  .area-section h2 {
    font-size: var(--ha-font-size-xl, 20px);
    font-weight: var(--ha-font-weight-normal, 400);
    line-height: 1.3;
    margin: 28px 0 0;
  }
  .area {
    display: grid;
    gap: 8px;
    padding: 14px 0;
    border-bottom: 1px solid var(--divider-color, #e0e0e0);
  }
  .area:has(+ .section-notes) {
    border-bottom: 0;
  }
  .area-head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px 8px;
  }
  .area-name {
    font-size: var(--ha-font-size-l, 16px);
    font-weight: var(--ha-font-weight-medium, 500);
    line-height: 1.35;
  }
  .area-desc {
    color: var(--secondary-text-color, #727272);
    margin: 0;
  }
  .oidc-page .area-desc {
    line-height: 1.45;
  }
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    height: 24px;
    padding: 0 8px 0 6px;
    border-radius: 9999px;
    border: 1px solid var(--divider-color, #e0e0e0);
    font-size: var(--ha-font-size-s, 12px);
    color: var(--secondary-text-color, #727272);
  }
  .pill .icon {
    width: 14px;
    height: 14px;
  }
  @container (min-width: 460px) {
    .area {
      grid-template-columns: minmax(0, 1fr) 216px;
      column-gap: 16px;
      align-items: center;
    }
    .area > .area-detail {
      grid-column: 1 / -1;
    }
  }

  /* None, Read, Full: styled like ha-control-select */
  .segmented {
    position: relative;
    display: flex;
    gap: 4px;
    padding: 4px;
    height: 40px;
    box-sizing: border-box;
    border-radius: 10px;
    width: calc(
      (100% - 8px - (var(--most) - 1) * 4px) * var(--count) / var(--most) + (var(--count) - 1) * 4px +
        8px
    );
  }
  .segmented::before {
    content: "";
    position: absolute;
    inset: 0;
    border-radius: 10px;
    background: var(--disabled-color, #bdbdbd);
    opacity: 0.2;
  }
  .seg {
    position: relative;
    flex: 1 1 0;
    min-width: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 4px;
    padding: 0 8px;
    border-radius: 6px;
    font-size: var(--ha-font-size-m, 14px);
    font-weight: var(--ha-font-weight-medium, 500);
    white-space: nowrap;
    cursor: pointer;
    user-select: none;
    -webkit-tap-highlight-color: transparent;
  }
  .seg::before {
    content: "";
    position: absolute;
    inset: 0;
    border-radius: 6px;
    background: var(--primary-color);
    opacity: 0;
    transition: opacity 80ms ease-in-out;
  }
  @media (hover: hover) {
    .seg:not(:has(input:disabled)):not(:has(input:checked)):hover::before {
      opacity: 0.2;
    }
  }
  .seg input {
    position: absolute;
    inset: 0;
    margin: 0;
    opacity: 0;
    cursor: inherit;
  }
  .seg span,
  .seg .icon {
    position: relative;
    pointer-events: none;
  }
  .seg .icon {
    width: 16px;
    height: 16px;
  }
  .seg .check {
    display: none;
  }
  .seg:has(input:checked) {
    background: var(--primary-color);
    color: var(--text-primary-color, #fff);
  }
  .seg:has(input:checked) .check {
    display: block;
  }
  .seg:has(input:focus-visible) {
    box-shadow: 0 0 0 2px var(--primary-color);
  }
  .seg:has(input:disabled) {
    cursor: not-allowed;
    color: var(--disabled-text-color, #bdbdbd);
  }
  .visually-hidden {
    position: absolute !important;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
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

function icon(name, cls = '') {
  return `<svg class="icon ${cls}" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="${ICONS[name]}"/></svg>`;
}

// Marks a placeholder value as markup, which is inserted as it is
function markup(value) {
  return { markup: value };
}

// The user's choice of access at a resource, and what follows from it: which
// levels match, what is locked by the user's ceiling, and which notes hold.
class AccessChoice {
  constructor(model, start = null) {
    this.model = model;
    this.presets = model.presets;
    this.groups = model.sections.flatMap((section) => section.groups);
    this.group = Object.fromEntries(this.groups.map((group) => [group.id, group]));
    this.limits = (model.ceiling && model.ceiling.groups) || {};
    this.unavailable = model.unavailable || {};
    this.most = Math.max(...this.groups.map((group) => group.options.length));

    // The levels the resource locks for this user. Their exact choice cannot
    // be approved either, also when it is made in the detailed view.
    const lockedIds = (model.ceiling && model.ceiling.locked_presets) || [];
    this.lockedByCeiling = this.presets.filter((preset) => lockedIds.includes(preset.id));
    // A level is locked as well when it adds nothing the user may grant to the
    // one before it, or when the ceiling holds it at a locked level's choice
    this.locked = new Set(lockedIds);
    let previous = null;
    for (const preset of this.presets) {
      const rows = this.presetRows(preset);
      if ((previous && this.same(rows, previous)) || this.lockedChoice(rows)) {
        this.locked.add(preset.id);
      }
      previous = rows;
    }

    // The first time the default level, afterwards the user's last choice,
    // or the rows in start when they are given. A locked default gives way to
    // the nearest open level below it, or else above it, and the screen never
    // opens on a locked level's choice. A group the description gained since
    // the choice was made starts as in that level. The last choice is marked
    // as such only when the ceiling leaves it as it was.
    const opening = this.openingPreset(model.default_preset);
    const base = opening ? opening.options : this.lowestRows();
    const remembered = model.remembered ? { ...base, ...model.remembered } : null;
    const wanted = start ? { ...base, ...start } : remembered;
    const rows = wanted && this.clamp(wanted);
    this.rows = rows && !this.lockedChoice(rows) ? rows : this.clamp(base);
    const match = this.matching(this.rows);
    this.selected = match ? match.id : CUSTOM;
    this.customRows = match ? null : { ...this.rows };
    this.lastChoice = remembered && this.same(this.rows, remembered) ? this.selected : null;

    // When changing a session's access, what the session has now: the level
    // that stands for it as the ceiling holds the levels, else the level it
    // is exactly, which may be locked, else Custom. None without a choice.
    this.granted = model.granted ? { ...base, ...model.granted } : null;
    const level =
      this.granted &&
      (this.matching(this.granted) || this.presets.find((preset) => this.same(preset.options, this.granted)));
    this.current = this.granted ? (level ? level.id : CUSTOM) : null;
    this.view = 'simple';
  }

  // Whether an option of the simple view is what the session has now: its
  // level, or Custom while that shows the session's own choice
  isCurrent(id) {
    if (this.current !== id) {
      return false;
    }
    return id !== CUSTOM || (this.customRows !== null && this.same(this.customRows, this.granted));
  }

  // The level the screen opens on: the given one, or the nearest open level
  // below it, or else above it. None when every level is locked.
  openingPreset(id) {
    const index = Math.max(0, this.presets.findIndex((preset) => preset.id === id));
    const order = [...this.presets.slice(0, index + 1).reverse(), ...this.presets.slice(index + 1)];
    return order.find((preset) => !this.locked.has(preset.id)) || null;
  }

  lowestRows() {
    return Object.fromEntries(this.groups.map((group) => [group.id, group.options[0].id]));
  }

  // The level the ceiling locks whose exact choice the rows are, if any
  lockedChoice(rows) {
    return this.lockedByCeiling.find((preset) => this.same(preset.options, rows)) || null;
  }

  optionIds(gid) {
    return this.group[gid].options.map((option) => option.id);
  }

  option(gid, oid) {
    return this.group[gid].options.find((option) => option.id === oid);
  }

  // The highest option the user may choose in a group
  highestAllowed(gid) {
    const limit = this.limits[gid];
    return limit ? this.optionIds(gid).indexOf(limit.max) : this.group[gid].options.length - 1;
  }

  clamp(rows) {
    return Object.fromEntries(
      this.groups.map((group) => {
        const ids = this.optionIds(group.id);
        const index = Math.max(0, ids.indexOf(rows[group.id]));
        return [group.id, ids[Math.min(index, this.highestAllowed(group.id))]];
      })
    );
  }

  presetRows(preset) {
    return this.clamp(preset.options);
  }

  same(a, b) {
    return this.groups.every((group) => a[group.id] === b[group.id]);
  }

  matching(rows) {
    return (
      this.presets.find((preset) => !this.locked.has(preset.id) && this.same(this.presetRows(preset), rows)) ||
      null
    );
  }

  // The level a custom choice is closest to, and the groups where it differs
  closest(rows) {
    let best = null;
    for (const preset of this.presets) {
      if (this.locked.has(preset.id)) {
        continue;
      }
      const target = this.presetRows(preset);
      const differences = this.groups.filter((group) => target[group.id] !== rows[group.id]);
      if (!best || differences.length < best.differences.length) {
        best = { preset, differences };
      }
    }
    return best;
  }

  holds(clause, ownGroup) {
    if ('group' in clause) {
      return clause.in.includes(this.rows[clause.group]);
    }
    const skipped = new Set([...(clause.except || []), ownGroup]);
    return this.groups.some((group) => {
      if (skipped.has(group.id)) {
        return false;
      }
      const index = this.optionIds(group.id).indexOf(this.rows[group.id]);
      return clause.some_group === 'below_highest' ? index < group.options.length - 1 : index === 0;
    });
  }

  // The notes whose conditions hold for the current choice. A note on an
  // option leaves its own group out of conditions on some other group.
  visibleNotes(notes, ownGroup = null) {
    return (notes || []).filter((note) => (note.when || []).every((clause) => this.holds(clause, ownGroup)));
  }

  choosePreset(id) {
    this.selected = id;
    this.rows =
      id === CUSTOM ? { ...this.customRows } : this.presetRows(this.presets.find((preset) => preset.id === id));
  }

  chooseOption(gid, oid) {
    this.rows = { ...this.rows, [gid]: oid };
    const match = this.matching(this.rows);
    this.selected = match ? match.id : CUSTOM;
    if (!match) {
      this.customRows = { ...this.rows };
    }
  }
}

class OidcLoginPanel extends HTMLElement {
  constructor() {
    super();
    this._strings = { ...FALLBACK_STRINGS };
  }

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
        await this._loadStrings();
      } catch (error) {
        this._renderError(error, 'panel.sessions_error_hint');
        return;
      }
      await this._renderHome();
      return;
    }

    this._requestId = requestId;
    this._renderCard(`
      <h1 tabindex="-1">${this._t('panel.loading_title')}</h1>
      <p>${this._t('panel.loading_text')}</p>
    `);

    try {
      await this._waitForHass();
      const [details] = await Promise.all([this._fetchJson(this._continueUrl()), this._loadStrings()]);

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
      await this._renderHome(this._t('panel.request_gone'));
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
    this._changing = null;
    try {
      if (tab === 'clients') {
        await this._renderClients(notice, 'info');
      } else {
        await this._renderSessions(notice);
      }
    } catch (error) {
      if (this._tab === tab) {
        this._renderError(error, tab === 'clients' ? CLIENTS_ERROR_HINT : 'panel.sessions_error_hint');
      }
    }
  }

  // The service worker answers a repeated GET of one address from its cache,
  // so asking again for a request already read needs an address of its own.
  _continueUrl(again = false) {
    const requestId = encodeURIComponent(this._requestId);
    const url = `/oidc/continue?request_id=${requestId}&language=${encodeURIComponent(this._language())}`;
    return again ? `${url}&again=${Date.now()}` : url;
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
    return `<nav class="oidc-tabs" aria-label="Sections">${tab('sessions', this._t('sessions.heading'))}${tab('clients', 'Clients')}</nav>`;
  }

  _language() {
    return this._hass?.locale?.language || this._hass?.language || 'en';
  }

  // The panel's text in the user's language. When it cannot be loaded, the
  // bundled English stands in, so signing in does not depend on it.
  async _loadStrings() {
    try {
      const { strings } = await this._fetchJson(`${STRINGS_URL}?language=${encodeURIComponent(this._language())}`);
      this._strings = { ...FALLBACK_STRINGS, ...strings };
    } catch (error) {
      console.warn('OIDC login panel: showing the bundled English text', error);
      this._strings = { ...FALLBACK_STRINGS };
    }
  }

  // A translated string as markup. Its text is escaped, then each {name} is
  // replaced with values[name]: plain text is escaped, markup() goes in as is.
  _t(key, values = {}) {
    const template = Object.hasOwn(this._strings, key) ? this._strings[key] : key;
    return escapeHtml(template).replace(/\{(\w+)\}/g, (placeholder, name) => {
      if (!Object.hasOwn(values, name)) {
        return placeholder;
      }
      const value = values[name];
      return value && typeof value === 'object' ? value.markup : escapeHtml(value);
    });
  }

  _list(items, type) {
    try {
      return new Intl.ListFormat(this._language(), { type }).format(items);
    } catch (error) {
      return items.join(', ');
    }
  }

  _clientLabel(details) {
    // A client identified by a metadata document is vouched for only by the
    // host serving that document, so the host is shown next to its name. bdi
    // keeps right-to-left text in a name from reordering what follows it.
    const name = `<b><bdi>${escapeHtml(details.client_name)}</bdi></b>`;
    if (!details.client_host) {
      return name;
    }
    return this._t('panel.client_from_host', {
      client: markup(name),
      host: markup(`<b><bdi>${escapeHtml(details.client_host)}</bdi></b>`),
    });
  }

  _noticeHtml() {
    return this._notice ? `<ha-alert alert-type="info">${this._notice}</ha-alert>` : '';
  }

  _consentAlert(details) {
    return `
        <ha-alert alert-type="warning">
          ${this._t('consent.alert', { client: markup(this._clientLabel(details)) })}
        </ha-alert>
        ${this._noticeHtml()}
      `;
  }

  // What is above the card of a choice of access: on the consent screen, who
  // is asking; when changing a session's access, notices, if any
  _choiceAlert() {
    return this._changing ? `${this._adjustedAlert()}${this._noticeHtml()}` : this._consentAlert(this._details);
  }

  // When the person may no longer allow what a session has now, the choice
  // opens on one they may make, which this says, with the ceiling's reasons
  _adjustedAlert() {
    const reasons = this._access.model.adjusted;
    if (!reasons) {
      return '';
    }
    const reason = markup(reasons.map((text) => this._res(text)).join(' '));
    return `
        <ha-alert alert-type="warning">
          ${this._t('change.adjusted', { app: markup(this._appName()), reason })}
        </ha-alert>`;
  }

  // previous is the choice on the screen before it was loaded again: its rows
  // are kept as far as the access offered now allows, and so is its view.
  _renderConsent(details, previous = null) {
    this._details = details;
    if (details.access) {
      this._access = new AccessChoice(details.access, previous && previous.rows);
      this._access.view = (previous && previous.view) || 'simple';
      this._renderAccess();
      return;
    }
    this._access = null;

    const scopes = (details.scopes || []).map((scope) => {
      const key = `consent.scope_${scope}`;
      const description = Object.hasOwn(this._strings, key) ? this._t(key) : escapeHtml(scope);
      return `<li>${description}</li>`;
    });

    // Any program on a computer can listen on a loopback address, so a sign-in
    // that returns there is only safe when the user started it themselves.
    const loopbackNote = details.redirect_is_loopback ? `<p>${this._t('consent.loopback')}</p>` : '';

    this._renderCard(
      `
        <h1 tabindex="-1">${this._t('consent.heading')}</h1>
        <p>${this._t('consent.redirect', { host: markup(`<b><bdi>${escapeHtml(details.redirect_host)}</bdi></b>`) })}</p>
        <ul>${scopes.join('')}</ul>
        ${loopbackNote}
        <div class="action">
          <ha-button id="oidc-approve">${this._t('consent.approve')}</ha-button>
        </div>
        <div class="action">
          <ha-button id="oidc-deny" appearance="plain" variant="neutral">${this._t('consent.deny')}</ha-button>
        </div>
      `,
      this._consentAlert(details)
    );

    this._wireDecision();
  }

  _wireDecision() {
    if (this._changing) {
      this.querySelector('#oidc-save').addEventListener('click', () => this._onSave());
      this.querySelector('#oidc-cancel-change').addEventListener('click', () => this._leaveChange());
      return;
    }
    this.querySelector('#oidc-approve').addEventListener('click', () => this._onDecision(true));
    this.querySelector('#oidc-deny').addEventListener('click', () => this._onDecision(false));
  }

  // ---- Choosing access ----------------------------------------------------

  _appName(name = this._details.client_name) {
    return `<bdi>${escapeHtml(name)}</bdi>`;
  }

  // Text from the resource as markup, with {app} as the application's name.
  // The name goes in through a function, so $ patterns in it stay as written.
  _res(text, name = this._details?.client_name) {
    const app = this._appName(name);
    return escapeHtml(text).replaceAll('{app}', () => app);
  }

  // The same, for places that only take text, such as a select's options
  _resText(text) {
    const app = this._details.client_name;
    return escapeHtml(text.replaceAll('{app}', () => app));
  }

  _notesHtml(notes) {
    return notes
      .map((note) => `<span class="note">${icon('info')}<span class="note-text">${this._res(note.text)}</span></span>`)
      .join('');
  }

  // The badge on the option chosen last time, on the consent screen, or on
  // what the session has now, when changing a session's access
  _badge(id) {
    const access = this._access;
    if (access.lastChoice === id) {
      return `<span class="badge">${this._t('access.last_choice')}</span>`;
    }
    return access.isCurrent(id) ? `<span class="badge">${this._t('change.current')}</span>` : '';
  }

  _difference(group, rows, access = this._access, name = undefined) {
    return this._t('access.difference', {
      area: markup(this._res(group.title, name)),
      option: markup(this._res(access.option(group.id, rows[group.id]).label, name)),
    });
  }

  _summaryHtml(rows, access = this._access, name = undefined) {
    const { preset, differences } = access.closest(rows);
    const level = markup(this._res(preset.title, name));
    if (differences.length > 3) {
      return this._t('access.custom_summary_many', { level });
    }
    const items = differences
      .map((group) => `<li>${this._difference(group, rows, access, name)}</li>`)
      .join('');
    return `${this._t('access.custom_summary', { level })}<ul>${items}</ul>`;
  }

  _statusHtml(rows) {
    const { preset, differences } = this._access.closest(rows);
    const level = markup(this._res(preset.title));
    if (differences.length > 3) {
      return this._t('access.custom_status_many', { level });
    }
    const list = this._list(
      differences.map((group) => this._difference(group, rows)),
      'unit'
    );
    return this._t('access.custom_status', { level, differences: markup(list) });
  }

  _accessFooter() {
    if (this._changing) {
      const keep = this._access.model.adjusted
        ? `<p class="hint">${this._t('change.cancel_keeps', { app: markup(this._appName()) })}</p>`
        : '';
      return `
      ${keep}
      <div id="oidc-locked-choice" aria-live="polite"></div>
      <div class="action">
        <ha-button id="oidc-save">${this._t('change.save')}</ha-button>
      </div>
      <div class="action">
        <ha-button id="oidc-cancel-change" appearance="plain" variant="neutral">${this._t('change.cancel')}</ha-button>
      </div>`;
    }
    const details = this._details;
    const host = markup(`<b><bdi>${escapeHtml(details.redirect_host)}</bdi></b>`);
    const scopes = details.scopes || [];
    const sees = ['profile', 'email', 'groups']
      .filter((scope) => scopes.includes(scope))
      .map((scope) => this._t(`access.sees_${scope}`));
    let finePrint = this._t('access.fine_print', { host });
    if (sees.length) {
      const information = markup(this._list(sees, 'conjunction'));
      finePrint += ` ${this._t('access.fine_print_sees', { app: markup(this._appName()), information })}`;
    }
    // Any program on a computer can listen on a loopback address, so a sign-in
    // that returns there is only safe when the user started it themselves.
    const loopbackNote = details.redirect_is_loopback ? `<p>${this._t('consent.loopback')}</p>` : '';
    return `
      <p class="fine-print">${finePrint}</p>
      ${loopbackNote}
      <p class="hint">${this._t('access.change_later', { app: markup(this._appName()) })}</p>
      <div id="oidc-locked-choice" aria-live="polite"></div>
      <div class="action">
        <ha-button id="oidc-approve">${this._t('consent.approve')}</ha-button>
      </div>
      <div class="action">
        <ha-button id="oidc-deny" appearance="plain" variant="neutral">${this._t('consent.deny')}</ha-button>
      </div>`;
  }

  _renderAccess() {
    if (this._access.view === 'detailed') {
      this._renderDetailed();
    } else {
      this._renderSimple();
    }
  }

  _levelOption(preset) {
    const access = this._access;
    const id = `oidc-level-${escapeHtml(preset.id)}`;
    const locked = access.locked.has(preset.id);
    const describedBy = [`${id}-desc`, `${id}-notes`, locked ? `${id}-locked` : ''].filter(Boolean).join(' ');
    const reason = locked
      ? `<span class="limit-reason" id="${id}-locked">${icon('lock')}<span>${this._res(access.model.ceiling.reason)}</span></span>`
      : '';
    return `
      <label class="level${locked ? ' disabled' : ''}">
        <input type="radio" name="oidc-level" value="${escapeHtml(preset.id)}" ${access.selected === preset.id ? 'checked' : ''} ${locked ? 'disabled' : ''}
          aria-labelledby="${id}-label" aria-describedby="${describedBy}">
        <span class="radio" aria-hidden="true"></span>
        <span class="level-text">
          <span class="level-label" id="${id}-label">${this._res(preset.title)}${this._badge(preset.id)}</span>
          <span class="level-description" id="${id}-desc">${this._res(preset.description)}</span>
          <span class="level-notes" id="${id}-notes" data-preset="${escapeHtml(preset.id)}"></span>
          ${reason}
        </span>
      </label>`;
  }

  _customOption() {
    const access = this._access;
    if (!access.customRows) {
      return '';
    }
    return `
      <label class="level">
        <input type="radio" name="oidc-level" value="${CUSTOM}" ${access.selected === CUSTOM ? 'checked' : ''}
          aria-labelledby="oidc-level-custom-label" aria-describedby="oidc-level-custom-desc">
        <span class="radio" aria-hidden="true"></span>
        <span class="level-text">
          <span class="level-label" id="oidc-level-custom-label">${this._t('access.custom')}${this._badge(CUSTOM)}</span>
          <span class="level-description" id="oidc-level-custom-desc">${this._summaryHtml(access.customRows)}</span>
        </span>
      </label>`;
  }

  _updateLevelNotes() {
    const access = this._access;
    for (const preset of access.presets) {
      const notes = this.querySelector(`.level-notes[data-preset="${CSS.escape(preset.id)}"]`);
      notes.innerHTML = this._notesHtml(access.visibleNotes(preset.notes));
    }
  }

  // The heading of the simple view. When changing a session's access, it
  // names the application, with when that session signed in and was last
  // used, which tells two sessions of one application apart.
  _choiceHeading() {
    const session = this._changing;
    if (!session) {
      return `<h1 tabindex="-1">${this._t('consent.heading')}</h1>`;
    }
    const name = `<bdi>${escapeHtml(session.client_name)}</bdi>`;
    const client = session.client_host
      ? this._t('panel.client_from_host', {
          client: markup(name),
          host: markup(`<bdi>${escapeHtml(session.client_host)}</bdi>`),
        })
      : name;
    return `
        <h1 tabindex="-1">${this._t('change.heading', { client: markup(client) })}</h1>
        <p class="hint">${this._sessionMeta(session)}</p>`;
  }

  _renderSimple() {
    const access = this._access;
    const prompt = access.model.prompt
      ? this._res(access.model.prompt)
      : this._t('access.prompt', { app: markup(this._appName()) });

    this._renderCard(
      `
        ${this._choiceHeading()}
        <fieldset>
          <legend class="prompt">${prompt}</legend>
          <div class="level-list">
            ${access.presets.map((preset) => this._levelOption(preset)).join('')}
            ${this._customOption()}
          </div>
        </fieldset>
        <button type="button" class="text-button inline-action" id="oidc-to-detailed">
          ${this._t('access.choose_in_detail')} ${icon('chevronRight')}
        </button>
        ${this._accessFooter()}
      `,
      this._choiceAlert()
    );

    this._updateLevelNotes();
    for (const input of this.querySelectorAll('input[name="oidc-level"]')) {
      input.addEventListener('change', () => {
        access.choosePreset(input.value);
        this._updateLevelNotes();
        this._updateApproval();
      });
    }
    this.querySelector('#oidc-to-detailed').addEventListener('click', () => {
      access.view = 'detailed';
      this._renderAccess();
      this.querySelector('#oidc-back').focus();
    });
    this._wireDecision();
    this._updateApproval();
  }

  _areaRow(group) {
    const access = this._access;
    const id = `oidc-area-${escapeHtml(group.id)}`;
    const unavailable = access.unavailable[group.id];
    const limit = access.limits[group.id];
    const highest = access.highestAllowed(group.id);
    const segments = group.options
      .map((option, index) => {
        const locked = index > highest;
        const describedBy = `${id}-opt-${escapeHtml(option.id)}${locked ? ` ${id}-limit` : ''}`;
        return `
          <label class="seg">
            <input type="radio" name="${id}" value="${escapeHtml(option.id)}" ${access.rows[group.id] === option.id ? 'checked' : ''} ${locked ? 'disabled' : ''}
              aria-describedby="${describedBy}">
            ${locked ? icon('lock') : icon('check', 'check')}<span>${this._res(option.label)}</span>
          </label>`;
      })
      .join('');
    const optionDescriptions = group.options
      .map(
        (option) =>
          `<span class="visually-hidden" id="${id}-opt-${escapeHtml(option.id)}">${this._res(option.description)}</span>`
      )
      .join('');
    return `
      <div class="area" role="radiogroup" aria-labelledby="${id}-name"${unavailable ? ` aria-describedby="${id}-unavailable"` : ''} data-area="${escapeHtml(group.id)}">
        <div class="area-head">
          <span class="area-name" id="${id}-name">${this._res(group.title)}</span>
          ${unavailable ? `<span class="pill">${icon('cancel')}${this._t('access.not_available')}</span>` : ''}
        </div>
        <div class="segmented" style="--count: ${group.options.length}; --most: ${access.most}">${segments}</div>
        <div class="area-detail">
          <p class="area-desc" data-description></p>
          <div data-notes></div>
          ${unavailable ? `<div class="limit-reason" id="${id}-unavailable">${icon('cancel')}<span>${this._res(unavailable)}</span></div>` : ''}
          ${limit ? `<div class="limit-reason" id="${id}-limit">${icon('lock')}<span>${this._res(limit.reason)}</span></div>` : ''}
          ${optionDescriptions}
        </div>
      </div>`;
  }

  _presetSelect() {
    const access = this._access;
    const options = access.presets
      .map((preset) => {
        const locked = access.locked.has(preset.id);
        const title = this._resText(preset.title);
        const label = locked ? this._t('access.preset_locked', { level: markup(title) }) : title;
        return `<option value="${escapeHtml(preset.id)}" ${locked ? 'disabled' : ''}>${label}</option>`;
      })
      .join('');
    return `
      <div class="start-from">
        <label for="oidc-preset">${this._t('access.start_from')}</label>
        <div class="select-wrap">
          <select id="oidc-preset" aria-describedby="oidc-custom-status">${options}<option value="${CUSTOM}" disabled>${this._t('access.custom')}</option></select>
          ${icon('chevronDown')}
        </div>
        <p class="hint custom-status" id="oidc-custom-status" aria-live="polite"></p>
      </div>`;
  }

  // When changing a session's access, the detailed view says under its
  // heading what the session has now, in the words of the list of
  // applications: the level, or Custom with how it differs from the closest
  _currentHtml() {
    const access = this._access;
    if (access.current === null) {
      return '';
    }
    const custom = access.current === CUSTOM;
    const title = custom
      ? this._t('access.custom')
      : this._res(access.presets.find((preset) => preset.id === access.current).title);
    const line = this._t('change.current_detail', {
      app: markup(this._appName()),
      level: markup(`<span class="access-level">${title}</span>`),
    });
    const summary = custom ? `<div>${this._summaryHtml(access.granted)}</div>` : '';
    return `<div class="hint current-access">${line}${summary}</div>`;
  }

  _renderDetailed() {
    const access = this._access;
    const sections = access.model.sections
      .map(
        (section) => `
          <section class="area-section" aria-labelledby="oidc-section-${escapeHtml(section.id)}">
            <h2 id="oidc-section-${escapeHtml(section.id)}">${this._res(section.title)}</h2>
            ${section.groups.map((group) => this._areaRow(group)).join('')}
            <div class="section-notes" data-section="${escapeHtml(section.id)}" aria-live="polite"></div>
          </section>`
      )
      .join('');
    const intro = access.model.detail_intro ? `<p>${this._res(access.model.detail_intro)}</p>` : '';

    this._renderCard(
      `
        <button type="button" class="text-button neutral back-action" id="oidc-back">${icon('arrowLeft')}${this._t('access.back')}</button>
        <h1 tabindex="-1">${this._t('access.detail_heading')}</h1>
        ${this._currentHtml()}
        ${intro}
        ${this._presetSelect()}
        <div class="areas">${sections}</div>
        ${this._accessFooter()}
      `,
      this._choiceAlert(),
      true
    );

    this.querySelector('#oidc-back').addEventListener('click', () => {
      access.view = 'simple';
      this._renderAccess();
      const checked = this.querySelector('input[name="oidc-level"]:checked');
      (checked || this.querySelector('input[name="oidc-level"]')).focus();
    });
    this.querySelector('#oidc-preset').addEventListener('change', (event) => {
      access.choosePreset(event.target.value);
      for (const group of access.groups) {
        const input = this.querySelector(
          `input[name="oidc-area-${CSS.escape(group.id)}"][value="${CSS.escape(access.rows[group.id])}"]`
        );
        input.checked = true;
      }
      this._updateDetailed();
    });
    for (const group of access.groups) {
      for (const input of this.querySelectorAll(`input[name="oidc-area-${CSS.escape(group.id)}"]`)) {
        input.addEventListener('change', () => {
          access.chooseOption(group.id, input.value);
          this._updateDetailed();
        });
      }
    }
    this._wireDecision();
    this._updateDetailed();
  }

  // Each row says what its current setting means, with the notes that hold
  _updateDetailed() {
    const access = this._access;
    for (const group of access.groups) {
      const row = this.querySelector(`.area[data-area="${CSS.escape(group.id)}"]`);
      const option = access.option(group.id, access.rows[group.id]);
      row.querySelector('[data-description]').innerHTML = this._res(option.description);
      row.querySelector('[data-notes]').innerHTML = this._notesHtml(access.visibleNotes(option.notes, group.id));
    }
    for (const section of access.model.sections) {
      const notes = this.querySelector(`.section-notes[data-section="${CSS.escape(section.id)}"]`);
      notes.innerHTML = this._notesHtml(access.visibleNotes(section.notes));
    }
    this.querySelector('#oidc-preset').value = access.selected;
    this.querySelector('#oidc-custom-status').innerHTML =
      access.selected === CUSTOM ? this._statusHtml(access.rows) : '';
    this._updateApproval();
  }

  // A choice that is exactly a level the ceiling locks cannot be approved or
  // saved. Approve or Save is turned off and the reason shown right above it,
  // in either view.
  _updateApproval() {
    const access = this._access;
    const locked = access.lockedChoice(access.rows);
    this.querySelector('#oidc-locked-choice').innerHTML = locked
      ? `<div class="limit-reason">${icon('lock')}<span>${this._t('access.locked_choice', {
          level: markup(this._res(locked.title)),
          reason: markup(this._res(access.model.ceiling.reason)),
        })}</span></div>`
      : '';
    this.querySelector(this._changing ? '#oidc-save' : '#oidc-approve').toggleAttribute('disabled', Boolean(locked));
  }

  // ---- Deciding -----------------------------------------------------------

  async _onDecision(approve) {
    // One decision per request, even if the buttons have not upgraded yet,
    // and no approval of a choice the ceiling locks
    if (this._deciding || (approve && this._access && this._access.lockedChoice(this._access.rows))) {
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
      if (approve && error.status === 400 && (await this._consentAgain())) {
        return;
      }
      this._renderError(error);
    }
  }

  // An approval refused while the request is still pending means the screen
  // no longer fits what the resource allows, as when the user's ceiling was
  // lowered after it loaded. The screen is shown again from the resource's
  // current answers, with a notice. False when the request is gone.
  async _consentAgain() {
    let details;
    try {
      details = await this._fetchJson(this._continueUrl(true));
    } catch (error) {
      return false;
    }
    const previous = this._access && { rows: this._access.rows, view: this._access.view };
    this._notice = this._t('consent.changed');
    this._renderConsent(details, previous);
    return true;
  }

  async _decide(approve) {
    const body = { request_id: this._requestId, approve };
    if (approve && this._access) {
      body.access = { options: this._access.rows };
    }
    const data = await this._fetchJson('/oidc/continue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!data.redirect_url) {
      throw new Error('No redirect received from Home Assistant');
    }

    // The request is consumed either way; a reload must not replay it.
    sessionStorage.removeItem('oidc_request_id');

    const changeLater =
      approve && this._access
        ? `<p class="hint">${this._t('access.change_later', { app: markup(this._appName()) })}</p>`
        : '';
    this._renderCard(`
      <h1 tabindex="-1">${this._t(approve ? 'consent.approved_title' : 'consent.denied_title')}</h1>
      <p>${this._t('consent.sending_back')}</p>
      ${changeLater}
    `);
    window.location.href = data.redirect_url;
  }

  // ---- Connected applications ---------------------------------------------

  // What a session was granted at its resource: the level's title, or Custom
  // with how it differs from the closest level
  _sessionAccess(session, resources) {
    const model = session.access && resources[session.access.resource];
    if (!model) {
      return '';
    }
    const access = new AccessChoice({ ...model, remembered: session.access.options });
    const name = session.client_name;
    if (access.selected !== CUSTOM) {
      const preset = access.presets.find((candidate) => candidate.id === access.selected);
      const level = markup(`<span class="access-level">${this._res(preset.title, name)}</span>`);
      return `<div class="access">${this._t('sessions.access', { level })}</div>`;
    }
    const level = markup(`<span class="access-level">${this._t('access.custom')}</span>`);
    return `
      <div class="access">
        ${this._t('sessions.access', { level })}
        <div>${this._summaryHtml(access.rows, access, name)}</div>
      </div>`;
  }

  _sessionMeta(session) {
    const formatTime = (seconds) =>
      seconds ? escapeHtml(new Date(seconds * 1000).toLocaleString()) : this._t('sessions.never');
    return this._t('sessions.meta', {
      signed_in: markup(formatTime(session.signed_in_at)),
      last_used: markup(formatTime(session.last_used_at)),
    });
  }

  async _renderSessions(notice = '') {
    const { sessions, resources = {} } = await this._fetchJson(
      `${SESSIONS_URL}?language=${encodeURIComponent(this._language())}`
    );
    // The user may have switched tabs while the list was on its way
    if (this._home && this._tab !== 'sessions') {
      return;
    }
    this._sessions = sessions;
    const items = sessions.map((session, index) => {
      const name = `<b><bdi>${escapeHtml(session.client_name)}</bdi></b>`;
      const label = session.client_host
        ? this._t('panel.client_from_host', {
            client: markup(name),
            host: markup(`<bdi>${escapeHtml(session.client_host)}</bdi>`),
          })
        : name;
      // Offered for every session whose resource describes the access it
      // offers, also one that has no choice of it yet
      const change = session.access_offered_by
        ? `<ha-button appearance="plain" data-change="${index}">${this._t('sessions.change_access')}</ha-button>`
        : '';
      return `
        <div class="oidc-session">
          ${label}
          ${this._sessionAccess(session, resources)}
          <div class="oidc-session-meta">${this._sessionMeta(session)}</div>
          <div class="action oidc-session-actions">
            ${change}
            <ha-button appearance="plain" variant="danger" data-session="${escapeHtml(session.session_id)}">${this._t('sessions.sign_out')}</ha-button>
          </div>
        </div>
      `;
    });

    this._renderCard(
      `
      <h1 tabindex="-1">${this._t('sessions.heading')}</h1>
      ${items.length ? `<p>${this._t('sessions.intro')}</p>${items.join('')}` : `<p>${this._t('sessions.empty')}</p>`}
    `,
      notice ? `<ha-alert alert-type="info">${notice}</ha-alert>` : ''
    );

    for (const button of this.querySelectorAll('ha-button[data-session]')) {
      button.addEventListener('click', () => this._endSession(button.dataset.session));
    }
    for (const button of this.querySelectorAll('ha-button[data-change]')) {
      button.addEventListener('click', () => this._openChange(this._sessions[button.dataset.change]));
    }
  }

  // ---- Changing a session's access ----------------------------------------

  _changeUrl(session) {
    return `${SESSIONS_URL}/${encodeURIComponent(session.session_id)}/access`;
  }

  // Opens the choice of a session's access on what the session has now, or
  // for a session without a choice yet, on what it would get by default. The
  // user's ceiling and locked levels apply as they are now.
  async _openChange(session) {
    if (!this._startRequest()) {
      return;
    }
    let details;
    try {
      details = await this._fetchJson(`${this._changeUrl(session)}?language=${encodeURIComponent(this._language())}`);
    } catch (error) {
      this._busy = false;
      await this._changeFailed(session, error);
      return;
    }
    this._busy = false;
    // The user may have switched tabs while the choice was on its way
    if (this._tab !== 'sessions') {
      return;
    }
    this._notice = '';
    this._renderChange(session, details);
  }

  // previous is the choice on the screen before it was loaded again: its rows
  // are kept as far as the access offered now allows, and so is its view.
  _renderChange(session, details, previous = null) {
    this._changing = session;
    this._details = details;
    this._access = new AccessChoice(details.access, previous ? previous.rows : details.access.current);
    this._access.view = (previous && previous.view) || 'simple';
    this._renderAccess();
  }

  async _onSave() {
    const access = this._access;
    if (this._busy || access.lockedChoice(access.rows)) {
      return;
    }
    const session = this._changing;
    this._startRequest();
    try {
      await this._fetchJson(this._changeUrl(session), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ options: access.rows }),
      });
    } catch (error) {
      this._busy = false;
      if (error.status === 400 && (await this._changeAgain())) {
        return;
      }
      await this._changeFailed(session, error);
      return;
    }
    this._busy = false;
    await this._leaveChange(this._t('change.saved', { app: markup(this._appName(session.client_name)) }));
  }

  // A choice refused while the session is still there means the screen no
  // longer fits what the resource allows, as when the user's ceiling was
  // lowered after it loaded. The choice is shown again from the resource's
  // current answers, with a notice. False when it cannot be.
  async _changeAgain() {
    let details;
    try {
      details = await this._fetchJson(`${this._changeUrl(this._changing)}?language=${encodeURIComponent(this._language())}`);
    } catch (error) {
      return false;
    }
    const previous = { rows: this._access.rows, view: this._access.view };
    this._notice = this._t('change.changed');
    this._renderChange(this._changing, details, previous);
    return true;
  }

  // A session that is gone, signed out elsewhere or expired, is no longer
  // listed, which the list says. Anything else is an error.
  async _changeFailed(session, error) {
    if (error.status === 404) {
      await this._leaveChange(this._t('change.gone', { app: markup(this._appName(session.client_name)) }));
      return;
    }
    this._changing = null;
    this._renderError(error, 'panel.sessions_error_hint');
  }

  async _leaveChange(notice = '') {
    this._access = null;
    this._notice = '';
    await this._showTab('sessions', notice);
  }

  async _endSession(sessionId) {
    for (const button of this.querySelectorAll('ha-button')) {
      button.disabled = true;
    }
    try {
      await this._fetchJson(`${SESSIONS_URL}/${encodeURIComponent(sessionId)}`, { method: 'DELETE' });
      await this._renderSessions();
    } catch (error) {
      this._renderError(error, 'panel.sessions_error_hint');
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

  // ---- Plumbing -----------------------------------------------------------

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

  _renderError(error, hint = 'panel.error_hint') {
    this._renderCard(
      `
        <h1 tabindex="-1">${this._t('panel.error_title')}</h1>
        <p>${Object.hasOwn(this._strings, hint) ? this._t(hint) : escapeHtml(hint)}</p>
      `,
      `<ha-alert alert-type="error">${escapeHtml(error.detail || error.message)}</ha-alert>`
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
