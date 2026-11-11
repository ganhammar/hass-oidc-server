// OIDC login panel. Shows the consent screen for a pending authorization
// request and completes the redirect back to the client. Opened without a
// pending request, it lists the applications signed in as the current user
// and lets them end those sessions.
//
// The layout mirrors Home Assistant's own login page (ha-authorize): a
// centered column with the HA icon above a card, built from HA's CSS
// variables so themes and dark mode apply.
//
// When the request is for a resource that describes the access it offers,
// the consent screen lets the user choose that access: one of the resource's
// levels, or one setting per area in a detailed view. The resource supplies
// that text in the user's language. The panel's own text comes from the
// integration's translations, through /oidc/strings, with the English bundled
// for when they cannot be loaded.

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
  "access.change_later": "You can sign {app} out at any time under Connected applications.",
  "sessions.heading": "Connected applications",
  "sessions.intro": "These applications can use your Home Assistant account. Signing one out stops it from getting new access; access it already has runs out within the hour. To get access back, it has to ask you again.",
  "sessions.empty": "No applications are signed in with your Home Assistant account.",
  "sessions.access": "Access: {level}",
  "sessions.meta": "Signed in {signed_in}, last used {last_used}",
  "sessions.never": "never",
  "sessions.sign_out": "Sign out"
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
  .oidc-content.wide {
    max-width: 560px;
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
  .oidc-session .access {
    margin-top: 6px;
    color: var(--secondary-text-color, #727272);
  }
  .access-level {
    color: var(--primary-text-color);
    font-weight: var(--ha-font-weight-medium, 500);
  }
  .oidc-session .access ul {
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
    this.view = 'simple';
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
        await this._renderSessions();
      } catch (error) {
        this._renderError(error, 'panel.sessions_error_hint');
      }
      return;
    }

    this._requestId = requestId;
    this._renderCard(`
      <h1>${this._t('panel.loading_title')}</h1>
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
      try {
        await this._renderSessions(this._t('panel.request_gone'));
      } catch (sessionsError) {
        this._renderError(sessionsError, 'panel.sessions_error_hint');
      }
    }
  }

  _continueUrl() {
    const requestId = encodeURIComponent(this._requestId);
    return `/oidc/continue?request_id=${requestId}&language=${encodeURIComponent(this._language())}`;
  }

  _language() {
    return this._hass?.locale?.language || this._hass?.language || 'en';
  }

  // The panel's text in the user's language. When it cannot be loaded, the
  // bundled English stands in, so signing in does not depend on it.
  async _loadStrings() {
    try {
      const { strings } = await this._fetchJson(`/oidc/strings?language=${encodeURIComponent(this._language())}`);
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

  _consentAlert(details) {
    const notice = this._notice ? `<ha-alert alert-type="info">${this._notice}</ha-alert>` : '';
    return `
        <ha-alert alert-type="warning">
          ${this._t('consent.alert', { client: markup(this._clientLabel(details)) })}
        </ha-alert>
        ${notice}
      `;
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
        <h1>${this._t('consent.heading')}</h1>
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

  _badge() {
    return `<span class="badge">${this._t('access.last_choice')}</span>`;
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
          <span class="level-label" id="${id}-label">${this._res(preset.title)}${access.lastChoice === preset.id ? this._badge() : ''}</span>
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
          <span class="level-label" id="oidc-level-custom-label">${this._t('access.custom')}${access.lastChoice === CUSTOM ? this._badge() : ''}</span>
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

  _renderSimple() {
    const access = this._access;
    const prompt = access.model.prompt
      ? this._res(access.model.prompt)
      : this._t('access.prompt', { app: markup(this._appName()) });

    this._renderCard(
      `
        <h1>${this._t('consent.heading')}</h1>
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
      this._consentAlert(this._details)
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
        <h1>${this._t('access.detail_heading')}</h1>
        ${intro}
        ${this._presetSelect()}
        <div class="areas">${sections}</div>
        ${this._accessFooter()}
      `,
      this._consentAlert(this._details),
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

  // A choice that is exactly a level the ceiling locks cannot be approved.
  // Approve is turned off and the reason shown right above it, in either view.
  _updateApproval() {
    const access = this._access;
    const locked = access.lockedChoice(access.rows);
    this.querySelector('#oidc-locked-choice').innerHTML = locked
      ? `<div class="limit-reason">${icon('lock')}<span>${this._t('access.locked_choice', {
          level: markup(this._res(locked.title)),
          reason: markup(this._res(access.model.ceiling.reason)),
        })}</span></div>`
      : '';
    this.querySelector('#oidc-approve').toggleAttribute('disabled', Boolean(locked));
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
      details = await this._fetchJson(this._continueUrl());
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
      <h1>${this._t(approve ? 'consent.approved_title' : 'consent.denied_title')}</h1>
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

  async _renderSessions(notice = '') {
    const { sessions, resources = {} } = await this._fetchJson(
      `/oidc/sessions?language=${encodeURIComponent(this._language())}`
    );
    const formatTime = (seconds) =>
      seconds ? escapeHtml(new Date(seconds * 1000).toLocaleString()) : this._t('sessions.never');
    const items = sessions.map((session) => {
      const name = `<b><bdi>${escapeHtml(session.client_name)}</bdi></b>`;
      const label = session.client_host
        ? this._t('panel.client_from_host', {
            client: markup(name),
            host: markup(`<bdi>${escapeHtml(session.client_host)}</bdi>`),
          })
        : name;
      return `
        <div class="oidc-session">
          ${label}
          ${this._sessionAccess(session, resources)}
          <div class="oidc-session-meta">${this._t('sessions.meta', {
            signed_in: markup(formatTime(session.signed_in_at)),
            last_used: markup(formatTime(session.last_used_at)),
          })}</div>
          <div class="action">
            <ha-button appearance="plain" variant="danger" data-session="${escapeHtml(session.session_id)}">${this._t('sessions.sign_out')}</ha-button>
          </div>
        </div>
      `;
    });

    this._renderCard(
      `
      <h1>${this._t('sessions.heading')}</h1>
      ${items.length ? `<p>${this._t('sessions.intro')}</p>${items.join('')}` : `<p>${this._t('sessions.empty')}</p>`}
    `,
      notice ? `<ha-alert alert-type="info">${notice}</ha-alert>` : ''
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
      await this._fetchJson(`/oidc/sessions/${encodeURIComponent(sessionId)}`, { method: 'DELETE' });
      await this._renderSessions();
    } catch (error) {
      this._renderError(error, 'panel.sessions_error_hint');
    }
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
        <h1>${this._t('panel.error_title')}</h1>
        <p>${this._t(hint)}</p>
      `,
      `<ha-alert alert-type="error">${escapeHtml(error.message)}</ha-alert>`
    );
  }

  _renderCard(cardHtml, beforeCardHtml = '', wide = false) {
    this.innerHTML = `
      <style>${STYLES}</style>
      <div class="oidc-page">
        <div class="oidc-content${wide ? ' wide' : ''}">
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
