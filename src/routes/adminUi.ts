export function renderAdminUiHtml(): string {
  return `<!DOCTYPE html>
<html lang="en" data-carbon-theme="g100">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Threema OnPrem Admin — IBM Carbon</title>
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet" />
<style>
  /* IBM Carbon Design System v11 Tokens (G100 Dark default + G10 Light) */
  :root,
  html[data-carbon-theme="g100"] {
    --cds-background: #161616;
    --cds-background-hover: rgba(141, 141, 141, 0.16);
    --cds-layer-01: #262626;
    --cds-layer-02: #393939;
    --cds-layer-03: #525252;
    --cds-layer-hover-01: #333333;
    --cds-layer-hover-02: #474747;
    --cds-field-01: #262626;
    --cds-field-02: #393939;
    --cds-border-subtle-00: #393939;
    --cds-border-subtle-01: #525252;
    --cds-border-strong-01: #8d8d8d;
    --cds-text-primary: #f4f4f4;
    --cds-text-secondary: #c6c6c6;
    --cds-text-helper: #a8a8a8;
    --cds-text-placeholder: #6f6f6f;
    --cds-text-on-color: #ffffff;
    --cds-interactive: #0f62fe;
    --cds-button-primary: #0f62fe;
    --cds-button-primary-hover: #0353e9;
    --cds-button-secondary: #6f6f6f;
    --cds-button-secondary-hover: #606060;
    --cds-button-tertiary: #ffffff;
    --cds-button-danger-primary: #da1e28;
    --cds-button-danger-hover: #b81921;
    --cds-focus: #ffffff;
    --cds-support-error: #fa4d56;
    --cds-support-success: #42be65;
    --cds-support-warning: #f1c21b;
    --cds-support-info: #4589ff;
    --cds-tag-bg-green: #0e6027;
    --cds-tag-text-green: #a7f0ba;
    --cds-tag-bg-blue: #0043ce;
    --cds-tag-text-blue: #d0e2ff;
    --cds-tag-bg-red: #a2191f;
    --cds-tag-text-red: #ffd7d9;
    --cds-tag-bg-warm: #565151;
    --cds-tag-text-warm: #e5e0df;
    --cds-tag-bg-amber: #684e00;
    --cds-tag-text-amber: #ffd9be;
    --cds-overlay: rgba(22, 22, 22, 0.72);
    --cds-font-sans: "IBM Plex Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    --cds-font-mono: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }

  html[data-carbon-theme="g10"] {
    --cds-background: #f4f4f4;
    --cds-background-hover: rgba(141, 141, 141, 0.12);
    --cds-layer-01: #ffffff;
    --cds-layer-02: #f4f4f4;
    --cds-layer-03: #e0e0e0;
    --cds-layer-hover-01: #e8e8e8;
    --cds-layer-hover-02: #e5e5e5;
    --cds-field-01: #f4f4f4;
    --cds-field-02: #ffffff;
    --cds-border-subtle-00: #e0e0e0;
    --cds-border-subtle-01: #c6c6c6;
    --cds-border-strong-01: #8d8d8d;
    --cds-text-primary: #161616;
    --cds-text-secondary: #525252;
    --cds-text-helper: #6f6f6f;
    --cds-text-placeholder: #a8a8a8;
    --cds-text-on-color: #ffffff;
    --cds-interactive: #0f62fe;
    --cds-button-primary: #0f62fe;
    --cds-button-primary-hover: #0353e9;
    --cds-button-secondary: #393939;
    --cds-button-secondary-hover: #4c4c4c;
    --cds-button-tertiary: #0f62fe;
    --cds-button-danger-primary: #da1e28;
    --cds-button-danger-hover: #b81921;
    --cds-focus: #0f62fe;
    --cds-support-error: #da1e28;
    --cds-support-success: #24a148;
    --cds-support-warning: #f1c21b;
    --cds-support-info: #0043ce;
    --cds-tag-bg-green: #a7f0ba;
    --cds-tag-text-green: #0e6027;
    --cds-tag-bg-blue: #d0e2ff;
    --cds-tag-text-blue: #0043ce;
    --cds-tag-bg-red: #ffd7d9;
    --cds-tag-text-red: #a2191f;
    --cds-tag-bg-warm: #e5e0df;
    --cds-tag-text-warm: #3c3838;
    --cds-tag-bg-amber: #ffd9be;
    --cds-tag-text-amber: #684e00;
    --cds-overlay: rgba(22, 22, 22, 0.55);
  }

  * {
    box-sizing: border-box;
    border-radius: 0;
  }

  body {
    margin: 0;
    font-family: var(--cds-font-sans);
    background: var(--cds-background);
    color: var(--cds-text-primary);
    font-size: 14px;
    line-height: 1.42857;
    letter-spacing: 0.16px;
    -webkit-font-smoothing: antialiased;
  }

  /* Carbon UI Shell Header (always G100 dark per IBM Carbon specification) */
  .cds--header {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    height: 48px;
    background: #161616;
    border-bottom: 1px solid #393939;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0;
    z-index: 8000;
    color: #f4f4f4;
  }

  .cds--header__brand {
    display: flex;
    align-items: center;
    height: 100%;
    padding: 0 16px;
    gap: 8px;
    font-size: 14px;
    color: #f4f4f4;
    text-decoration: none;
    border-right: 1px solid #393939;
  }

  .cds--header__prefix {
    font-weight: 400;
    color: #c6c6c6;
  }

  .cds--header__name {
    font-weight: 600;
    color: #ffffff;
    letter-spacing: 0.1px;
  }

  .cds--header__status-dot {
    width: 8px;
    height: 8px;
    background: #42be65;
    display: inline-block;
    margin-right: 4px;
  }

  .cds--header__global {
    display: flex;
    align-items: center;
    height: 100%;
  }

  .cds--header__org {
    padding: 0 16px;
    font-size: 12px;
    color: #c6c6c6;
    border-left: 1px solid #393939;
    height: 100%;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .cds--header__action {
    height: 48px;
    min-width: 48px;
    padding: 0 16px;
    background: transparent;
    border: none;
    border-left: 1px solid #393939;
    color: #f4f4f4;
    font-family: var(--cds-font-sans);
    font-size: 13px;
    font-weight: 400;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    transition: background-color 110ms cubic-bezier(0.2, 0, 0.38, 0.9);
  }

  .cds--header__action:hover {
    background: #262626;
  }

  .cds--header__action--danger:hover {
    background: #da1e28;
    color: #ffffff;
  }

  /* Carbon UI Shell Layout (Side Nav + Content) */
  .cds--shell {
    display: flex;
    min-height: 100vh;
    padding-top: 48px;
  }

  .cds--side-nav {
    width: 256px;
    flex-shrink: 0;
    background: var(--cds-layer-01);
    border-right: 1px solid var(--cds-border-subtle-00);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    position: fixed;
    top: 48px;
    bottom: 0;
    left: 0;
    z-index: 6000;
    overflow-y: auto;
  }

  .cds--side-nav__section-label {
    padding: 16px 16px 8px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.32px;
    color: var(--cds-text-helper);
  }

  .cds--side-nav__items {
    list-style: none;
    margin: 0;
    padding: 0;
  }

  .cds--side-nav__link,
  .tab {
    width: 100%;
    height: 40px;
    padding: 0 16px;
    background: transparent;
    border: none;
    border-left: 4px solid transparent;
    color: var(--cds-text-secondary);
    font-family: var(--cds-font-sans);
    font-size: 14px;
    font-weight: 400;
    text-align: left;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: space-between;
    transition: background-color 110ms, color 110ms, border-color 110ms;
  }

  .tab:hover {
    background: var(--cds-layer-hover-01);
    color: var(--cds-text-primary);
  }

  .tab.active {
    background: var(--cds-layer-02);
    color: var(--cds-text-primary);
    font-weight: 600;
    border-left-color: var(--cds-interactive);
  }

  .cds--side-nav__footer {
    padding: 16px;
    border-top: 1px solid var(--cds-border-subtle-00);
    font-size: 12px;
    color: var(--cds-text-helper);
  }

  .cds--content {
    flex: 1;
    margin-left: 256px;
    padding: 32px 32px 64px;
    max-width: 1600px;
  }

  @media (max-width: 960px) {
    .cds--side-nav {
      position: static;
      width: 100%;
      border-right: none;
      border-bottom: 1px solid var(--cds-border-subtle-00);
    }
    .cds--side-nav__items {
      display: flex;
      flex-wrap: wrap;
    }
    .tab {
      width: auto;
      border-left: none;
      border-bottom: 3px solid transparent;
    }
    .tab.active {
      border-left-color: transparent;
      border-bottom-color: var(--cds-interactive);
    }
    .cds--side-nav__footer {
      display: none;
    }
    .cds--shell {
      flex-direction: column;
    }
    .cds--content {
      margin-left: 0;
      padding: 20px 16px 48px;
    }
  }

  /* Carbon Page Header */
  .cds--page-header {
    margin-bottom: 24px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--cds-border-subtle-00);
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
  }

  .cds--page-header__breadcrumb {
    font-size: 12px;
    color: var(--cds-text-helper);
    margin-bottom: 4px;
    letter-spacing: 0.32px;
  }

  .cds--page-header__title {
    margin: 0;
    font-size: 28px;
    font-weight: 400;
    line-height: 1.28572;
    letter-spacing: 0;
  }

  /* Carbon 16-Column CSS Grid Helpers */
  .cds--grid-kpi {
    display: grid;
    gap: 16px;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    margin-bottom: 24px;
  }

  .cds--grid-2 {
    display: grid;
    gap: 16px;
    grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
    margin-bottom: 24px;
  }

  /* Carbon Tile (Card) */
  .cds--tile {
    background: var(--cds-layer-01);
    border: 1px solid var(--cds-border-subtle-00);
    padding: 16px;
    margin-bottom: 16px;
    position: relative;
  }

  .cds--tile--kpi {
    padding: 16px;
    min-height: 124px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    border-top: 3px solid var(--cds-interactive);
    margin-bottom: 0;
  }

  .cds--tile--kpi-green {
    border-top-color: var(--cds-support-success);
  }

  .cds--tile__title {
    margin: 0 0 4px;
    font-size: 16px;
    font-weight: 600;
    color: var(--cds-text-primary);
  }

  .cds--tile__subtitle {
    margin: 0 0 16px;
    font-size: 12px;
    color: var(--cds-text-secondary);
  }

  .kpi-label {
    font-size: 12px;
    font-weight: 500;
    color: var(--cds-text-secondary);
    letter-spacing: 0.32px;
  }

  .kpi-val {
    font-size: 32px;
    font-weight: 300;
    line-height: 1.25;
    margin: 8px 0 4px;
    color: var(--cds-text-primary);
    font-variant-numeric: tabular-nums;
  }

  .kpi-sub {
    font-size: 12px;
    color: var(--cds-text-helper);
  }

  /* Carbon Data Table Container */
  .cds--data-table-container {
    background: var(--cds-layer-01);
    border: 1px solid var(--cds-border-subtle-00);
    margin-bottom: 24px;
  }

  .cds--data-table-header {
    padding: 16px 16px 12px;
    background: var(--cds-layer-01);
    border-bottom: 1px solid var(--cds-border-subtle-00);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
  }

  .cds--data-table-header__title {
    margin: 0;
    font-size: 18px;
    font-weight: 600;
    color: var(--cds-text-primary);
  }

  .cds--data-table-header__description {
    margin: 2px 0 0;
    font-size: 12px;
    color: var(--cds-text-secondary);
  }

  .cds--table-toolbar {
    display: flex;
    align-items: center;
    background: var(--cds-layer-01);
    border-bottom: 1px solid var(--cds-border-subtle-00);
    height: 48px;
  }

  .cds--toolbar-search {
    flex: 1;
    height: 100%;
    border: none;
    border-bottom: 1px solid transparent;
    background: var(--cds-layer-01);
    color: var(--cds-text-primary);
    padding: 0 16px;
    font-size: 14px;
    font-family: var(--cds-font-sans);
  }

  .cds--toolbar-search:focus {
    outline: 2px solid var(--cds-focus);
    outline-offset: -2px;
    background: var(--cds-layer-02);
  }

  table.cds--data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
  }

  table.cds--data-table thead th {
    background: var(--cds-layer-02);
    color: var(--cds-text-primary);
    font-weight: 600;
    font-size: 12px;
    letter-spacing: 0.32px;
    text-transform: uppercase;
    padding: 12px 16px;
    text-align: left;
    border-bottom: 1px solid var(--cds-border-subtle-01);
  }

  table.cds--data-table tbody td {
    padding: 12px 16px;
    border-bottom: 1px solid var(--cds-border-subtle-00);
    color: var(--cds-text-secondary);
    vertical-align: middle;
  }

  table.cds--data-table tbody tr:hover td {
    background: var(--cds-layer-hover-01);
    color: var(--cds-text-primary);
  }

  /* Carbon Tags (Pills remain 999px per Carbon v11 Tag component) */
  .cds--tag {
    display: inline-flex;
    align-items: center;
    height: 24px;
    padding: 0 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 400;
    line-height: 1;
    white-space: nowrap;
  }

  .cds--tag--green {
    background: var(--cds-tag-bg-green);
    color: var(--cds-tag-text-green);
  }

  .cds--tag--blue {
    background: var(--cds-tag-bg-blue);
    color: var(--cds-tag-text-blue);
  }

  .cds--tag--red {
    background: var(--cds-tag-bg-red);
    color: var(--cds-tag-text-red);
  }

  .cds--tag--warm-gray {
    background: var(--cds-tag-bg-warm);
    color: var(--cds-tag-text-warm);
  }

  .cds--tag--amber {
    background: var(--cds-tag-bg-amber);
    color: var(--cds-tag-text-amber);
  }

  /* Carbon Form Controls (sharp 0px corners, 1px solid #8d8d8d bottom border, 2px focus outline) */
  .cds--form-item {
    margin-bottom: 16px;
  }

  .cds--label {
    display: block;
    font-size: 12px;
    font-weight: 400;
    color: var(--cds-text-secondary);
    margin-bottom: 8px;
    letter-spacing: 0.32px;
  }

  .cds--text-input,
  input[type="text"],
  input[type="password"],
  input[type="number"],
  select,
  textarea {
    width: 100%;
    height: 40px;
    background: var(--cds-field-02);
    border: none;
    border-bottom: 1px solid var(--cds-border-strong-01);
    color: var(--cds-text-primary);
    padding: 0 16px;
    font-size: 14px;
    font-family: var(--cds-font-sans);
    transition: background-color 70ms, outline 70ms;
  }

  textarea {
    height: auto;
    min-height: 92px;
    padding: 11px 16px;
    font-family: var(--cds-font-mono);
    font-size: 12px;
  }

  input[type="file"] {
    width: 100%;
    padding: 8px 0;
    color: var(--cds-text-secondary);
    font-size: 13px;
  }

  input:focus,
  select:focus,
  textarea:focus {
    outline: 2px solid var(--cds-focus);
    outline-offset: -2px;
  }

  .form-row {
    display: grid;
    gap: 16px;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    margin-bottom: 16px;
  }

  .checkbox-row {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    font-size: 14px;
    color: var(--cds-text-primary);
    cursor: pointer;
    margin: 6px 16px 6px 0;
  }

  .checkbox-row input[type="checkbox"] {
    width: 16px;
    height: 16px;
    accent-color: var(--cds-interactive);
    margin: 0;
  }

  /* Carbon Buttons (Sharp 0px corners, right-padded, expressive height) */
  .cds--btn,
  button.primary,
  button.secondary,
  button.danger,
  button.ghost,
  button.small {
    display: inline-flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    min-height: 40px;
    padding: 0 16px;
    border: 1px solid transparent;
    font-family: var(--cds-font-sans);
    font-size: 14px;
    font-weight: 400;
    letter-spacing: 0.16px;
    cursor: pointer;
    text-decoration: none;
    transition: background-color 70ms cubic-bezier(0, 0, 0.38, 0.9), border-color 70ms;
  }

  button.primary,
  .cds--btn--primary {
    background: var(--cds-button-primary);
    color: #ffffff;
  }

  button.primary:hover,
  .cds--btn--primary:hover {
    background: var(--cds-button-primary-hover);
  }

  button.secondary,
  .cds--btn--secondary {
    background: var(--cds-button-secondary);
    color: #ffffff;
  }

  button.secondary:hover,
  .cds--btn--secondary:hover {
    background: var(--cds-button-secondary-hover);
  }

  button.danger,
  .cds--btn--danger {
    background: var(--cds-button-danger-primary);
    color: #ffffff;
  }

  button.danger:hover,
  .cds--btn--danger:hover {
    background: var(--cds-button-danger-hover);
  }

  button.ghost,
  .cds--btn--ghost {
    background: transparent;
    color: var(--cds-text-primary);
    border-color: var(--cds-border-subtle-01);
  }

  button.ghost:hover,
  .cds--btn--ghost:hover {
    background: var(--cds-layer-hover-01);
  }

  button.small {
    min-height: 32px;
    padding: 0 12px;
    font-size: 12px;
  }

  button.small:not(.primary):not(.danger) {
    background: var(--cds-layer-02);
    color: var(--cds-text-primary);
    border-color: var(--cds-border-subtle-01);
  }

  button.small:not(.primary):not(.danger):hover {
    background: var(--cds-layer-hover-02);
  }

  .btn-group {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }

  /* Carbon Structured List (Key-Value pairs) */
  .cds--structured-list {
    width: 100%;
    border-top: 1px solid var(--cds-border-subtle-00);
  }

  .kv {
    display: grid;
    grid-template-columns: 200px 1fr;
    gap: 16px;
    padding: 12px 8px;
    border-bottom: 1px solid var(--cds-border-subtle-00);
    font-size: 13px;
    align-items: center;
  }

  .kv:hover {
    background: var(--cds-layer-hover-01);
  }

  .kv__key {
    color: var(--cds-text-secondary);
    font-weight: 500;
  }

  .kv__val {
    color: var(--cds-text-primary);
    overflow-wrap: anywhere;
  }

  .mono {
    font-family: var(--cds-font-mono);
    font-size: 12px;
  }

  /* Carbon Toast Notification */
  .cds--toast-notification {
    position: fixed;
    bottom: 24px;
    right: 24px;
    z-index: 9500;
    min-width: 300px;
    max-width: 420px;
    background: var(--cds-layer-01);
    color: var(--cds-text-primary);
    border: 1px solid var(--cds-border-subtle-01);
    border-left: 4px solid var(--cds-support-success);
    padding: 14px 16px;
    box-shadow: 0 6px 16px rgba(0, 0, 0, 0.45);
    font-size: 13px;
  }

  .cds--toast-notification--error {
    border-left-color: var(--cds-support-error);
  }

  /* Carbon Modal */
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: var(--cds-overlay);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 9000;
    padding: 16px;
  }

  .cds--modal-container {
    width: 100%;
    max-width: 580px;
    background: var(--cds-layer-01);
    border: 1px solid var(--cds-border-subtle-01);
    box-shadow: 0 12px 32px rgba(0, 0, 0, 0.55);
  }

  .cds--modal-header {
    padding: 16px 24px 12px;
    border-bottom: 1px solid var(--cds-border-subtle-00);
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
  }

  .cds--modal-header__label {
    font-size: 12px;
    color: var(--cds-text-secondary);
    margin: 0 0 2px;
  }

  .cds--modal-header__heading {
    font-size: 20px;
    font-weight: 400;
    margin: 0;
    color: var(--cds-text-primary);
  }

  .cds--modal-content {
    padding: 20px 24px 24px;
  }

  /* Carbon Login Screen */
  .login-wrap {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    background:
      linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px) 0 0 / 64px 64px,
      linear-gradient(0deg, rgba(255,255,255,0.025) 1px, transparent 1px) 0 0 / 64px 64px,
      var(--cds-background);
  }

  .login-box {
    width: 100%;
    max-width: 420px;
    background: var(--cds-layer-01);
    border: 1px solid var(--cds-border-subtle-00);
    border-top: 4px solid var(--cds-interactive);
    padding: 32px;
    box-shadow: 0 12px 32px rgba(0, 0, 0, 0.45);
  }

  .login-eyebrow {
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.32px;
    text-transform: uppercase;
    color: var(--cds-support-info);
    margin-bottom: 6px;
  }

  .logo-preview {
    max-height: 48px;
    max-width: 200px;
    border: 1px solid var(--cds-border-subtle-01);
    background: var(--cds-layer-02);
    padding: 6px;
    margin-top: 8px;
  }

  .hidden {
    display: none !important;
  }
</style>
</head>
<body>

<!-- IBM Carbon Login View -->
<div id="login-view" class="login-wrap">
  <div class="login-box">
    <div class="login-eyebrow">IBM Carbon v11 // OnPrem Management</div>
    <h1 style="margin:0 0 8px;font-size:28px;font-weight:400;">Threema OnPrem Admin</h1>
    <p style="margin:0 0 24px;color:var(--cds-text-secondary);font-size:14px;">
      Authenticate with your <span class="mono">ADMIN_API_KEY</span> to administer identities, Work licenses, MDM policies, and live CSP/D2M sessions.
    </p>
    <form id="login-form">
      <div class="cds--form-item">
        <label class="cds--label" for="admin-key-input">Admin API Key (X-Admin-Key)</label>
        <input id="admin-key-input" class="cds--text-input" type="password" autocomplete="current-password" placeholder="Enter X-Admin-Key" required />
      </div>
      <div id="login-error" style="color:var(--cds-support-error);font-size:12px;margin:8px 0;"></div>
      <button type="submit" class="primary" style="width:100%;margin-top:16px;">
        <span>Continue to Console</span>
        <span aria-hidden="true">&rarr;</span>
      </button>
    </form>
  </div>
</div>

<!-- IBM Carbon UI Shell Application View -->
<div id="app-view" class="hidden">
  <header class="cds--header" role="banner">
    <div class="cds--header__brand">
      <span class="cds--header__status-dot"></span>
      <span class="cds--header__prefix">Threema</span>
      <span class="cds--header__name">OnPrem Admin</span>
    </div>
    <div class="cds--header__global">
      <div class="cds--header__org">
        <span>Organization:</span>
        <span id="hdr-org" class="cds--tag cds--tag--blue">OnPrem</span>
      </div>
      <button id="btn-theme" class="cds--header__action" title="Switch Carbon Theme (G100 / G10)">
        <span id="theme-label">Theme: G100</span>
      </button>
      <button id="btn-refresh" class="cds--header__action" title="Refresh Cluster State">
        <span>Refresh</span>
      </button>
      <button id="btn-logout" class="cds--header__action cds--header__action--danger" title="Sign Out">
        <span>Sign Out</span>
      </button>
    </div>
  </header>

  <div class="cds--shell">
    <nav class="cds--side-nav" aria-label="Side navigation">
      <div>
        <div class="cds--side-nav__section-label">Cluster Administration</div>
        <div class="cds--side-nav__items">
          <button class="tab active" data-tab="overview">
            <span>Overview &amp; Live Sessions</span>
          </button>
          <button class="tab" data-tab="identities">
            <span>Directory Identities</span>
            <span id="nav-count-identities" class="mono"></span>
          </button>
          <button class="tab" data-tab="accounts">
            <span>Work License Accounts</span>
            <span id="nav-count-accounts" class="mono"></span>
          </button>
          <button class="tab" data-tab="mdm">
            <span>Organization &amp; MDM</span>
          </button>
          <button class="tab" data-tab="devices">
            <span>D2M Devices &amp; Secrets</span>
            <span id="nav-count-devices" class="mono"></span>
          </button>
          <button class="tab" data-tab="reports">
            <span>Reports &amp; Maintenance</span>
            <span id="nav-count-reports" class="mono"></span>
          </button>
        </div>
      </div>
      <div class="cds--side-nav__footer">
        <div>Design System: <strong>IBM Carbon v11</strong></div>
        <div id="footer-uptime" class="mono" style="margin-top:4px;"></div>
      </div>
    </nav>

    <main class="cds--content">
      <section id="tab-overview"></section>
      <section id="tab-identities" class="hidden"></section>
      <section id="tab-accounts" class="hidden"></section>
      <section id="tab-mdm" class="hidden"></section>
      <section id="tab-devices" class="hidden"></section>
      <section id="tab-reports" class="hidden"></section>
    </main>
  </div>
</div>

<div id="modal-root" class="modal-backdrop hidden"></div>
<div id="toast" class="cds--toast-notification hidden" role="status"></div>

<script>
(() => {
  const STORAGE_KEY = "threema_onprem_admin_key";
  const THEME_KEY = "threema_onprem_carbon_theme";
  let adminKey = sessionStorage.getItem(STORAGE_KEY) || "";
  let currentTheme = localStorage.getItem(THEME_KEY) || "g100";
  let activeTab = "overview";
  let identityFilter = "";
  let accountFilter = "";
  let state = { status: null, accounts: [], identities: [], mdm: null, devices: [], remoteSecrets: [], reports: [] };

  const $ = (id) => document.getElementById(id);
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  function applyTheme(theme) {
    currentTheme = theme === "g10" ? "g10" : "g100";
    document.documentElement.setAttribute("data-carbon-theme", currentTheme);
    localStorage.setItem(THEME_KEY, currentTheme);
    const lbl = $("theme-label");
    if (lbl) lbl.textContent = "Theme: " + currentTheme.toUpperCase();
  }
  applyTheme(currentTheme);

  function toast(msg, isErr = false) {
    const el = $("toast");
    el.innerHTML =
      '<div style="font-weight:600;margin-bottom:2px;">' + (isErr ? "Error Notification" : "Action Completed") + '</div>' +
      '<div style="color:var(--cds-text-secondary);">' + esc(msg) + '</div>';
    el.classList.toggle("cds--toast-notification--error", Boolean(isErr));
    el.classList.remove("hidden");
    clearTimeout(el._t);
    el._t = setTimeout(() => el.classList.add("hidden"), 3400);
  }

  async function api(path, opts = {}) {
    const headers = Object.assign({}, opts.headers || {}, { "x-admin-key": adminKey });
    if (opts.body && typeof opts.body === "string" && !headers["content-type"]) {
      headers["content-type"] = "application/json";
    }
    const res = await fetch("/admin" + path, { ...opts, headers });
    if (res.status === 401) {
      sessionStorage.removeItem(STORAGE_KEY);
      adminKey = "";
      $("app-view").classList.add("hidden");
      $("login-view").classList.remove("hidden");
      throw new Error("Unauthorized");
    }
    const ct = res.headers.get("content-type") || "";
    const data = ct.includes("json") ? await res.json() : await res.text();
    if (!res.ok) {
      throw new Error((data && data.error) || ("HTTP " + res.status));
    }
    return data;
  }

  function showModal(title, bodyHtml, onMount) {
    const root = $("modal-root");
    root.innerHTML =
      '<div class="cds--modal-container" role="dialog" aria-modal="true">' +
        '<div class="cds--modal-header">' +
          '<div>' +
            '<p class="cds--modal-header__label">Threema OnPrem Directory</p>' +
            '<h3 class="cds--modal-header__heading">' + esc(title) + '</h3>' +
          '</div>' +
          '<button id="modal-close" class="small">Close &times;</button>' +
        '</div>' +
        '<div class="cds--modal-content">' + bodyHtml + '</div>' +
      '</div>';
    root.classList.remove("hidden");
    $("modal-close").onclick = () => root.classList.add("hidden");
    if (onMount) onMount(() => root.classList.add("hidden"));
  }

  async function loadAll() {
    const [status, accs, ids, mdm, devs, secrets, reps] = await Promise.all([
      api("/status"),
      api("/accounts"),
      api("/identities"),
      api("/mdm"),
      api("/devices"),
      api("/remote-secrets"),
      api("/reports")
    ]);
    state = {
      status,
      accounts: accs.accounts || [],
      identities: ids.identities || [],
      mdm: mdm.mdm,
      devices: devs.groups || [],
      remoteSecrets: secrets.remoteSecrets || [],
      reports: reps.reports || []
    };
    $("hdr-org").textContent = (state.mdm && state.mdm.orgName) || "OnPrem";
    $("nav-count-identities").textContent = state.identities.length;
    $("nav-count-accounts").textContent = state.accounts.length;
    $("nav-count-devices").textContent = state.devices.length;
    $("nav-count-reports").textContent = state.reports.length;
    if (state.status) {
      $("footer-uptime").textContent = "Uptime: " + fmtUptime(state.status.uptimeSeconds);
    }
    renderActiveTab();
  }

  function renderActiveTab() {
    for (const btn of document.querySelectorAll(".tab")) {
      btn.classList.toggle("active", btn.dataset.tab === activeTab);
    }
    for (const sec of document.querySelectorAll("section[id^='tab-']")) {
      sec.classList.toggle("hidden", sec.id !== "tab-" + activeTab);
    }
    if (activeTab === "overview") renderOverview();
    else if (activeTab === "identities") renderIdentities();
    else if (activeTab === "accounts") renderAccounts();
    else if (activeTab === "mdm") renderMdm();
    else if (activeTab === "devices") renderDevices();
    else if (activeTab === "reports") renderReports();
  }

  function fmtBytes(n) {
    if (!n) return "0 B";
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
    return (n / 1048576).toFixed(2) + " MB";
  }

  function fmtUptime(s) {
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = Math.floor(s % 60);
    return h + "h " + m + "m " + sec + "s";
  }

  function renderPageHeader(breadcrumb, title) {
    return (
      '<div class="cds--page-header">' +
        '<div>' +
          '<div class="cds--page-header__breadcrumb">' + esc(breadcrumb) + '</div>' +
          '<h1 class="cds--page-header__title">' + esc(title) + '</h1>' +
        '</div>' +
      '</div>'
    );
  }

  function renderOverview() {
    const st = state.status;
    if (!st) return;
    const onlineSessions = (st.live.csp && st.live.csp.sessions) || [];
    const el = $("tab-overview");
    el.innerHTML =
      renderPageHeader("Cluster Administration / Telemetry", "Overview & Live Sessions") +
      '<div class="cds--grid-kpi">' +
        '<div class="cds--tile cds--tile--kpi cds--tile--kpi-green">' +
          '<div class="kpi-label">Active CSP Sessions</div>' +
          '<div class="kpi-val">' + st.live.csp.activeSessions + '</div>' +
          '<div class="kpi-sub">' + st.live.csp.activeIdentities + ' online identities</div>' +
        '</div>' +
        '<div class="cds--tile cds--tile--kpi">' +
          '<div class="kpi-label">D2M Multi-Device Mediator</div>' +
          '<div class="kpi-val">' + st.live.d2m.activeConnections + '</div>' +
          '<div class="kpi-sub">' + st.live.d2m.activeGroups + ' active groups &bull; ' + st.live.d2m.activeTransactions + ' active tx</div>' +
        '</div>' +
        '<div class="cds--tile cds--tile--kpi">' +
          '<div class="kpi-label">Directory Identities</div>' +
          '<div class="kpi-val">' + st.counts.activeIdentities + '</div>' +
          '<div class="kpi-sub">' + st.counts.inactiveIdentities + ' inactive &bull; ' + st.counts.revokedIdentities + ' revoked</div>' +
        '</div>' +
        '<div class="cds--tile cds--tile--kpi">' +
          '<div class="kpi-label">TURN VoIP Relay</div>' +
          '<div class="kpi-val">' + (st.live.turn.enabled ? st.live.turn.activeAllocations : "Disabled") + '</div>' +
          '<div class="kpi-sub">External IP: <span class="mono">' + esc(st.live.turn.externalIp || "-") + '</span></div>' +
        '</div>' +
        '<div class="cds--tile cds--tile--kpi">' +
          '<div class="kpi-label">Encrypted Storage</div>' +
          '<div class="kpi-val">' + st.counts.blobs + '</div>' +
          '<div class="kpi-sub">' + fmtBytes(st.counts.blobTotalBytes) + ' blobs &bull; ' + st.counts.safeBackups + ' Safe backups</div>' +
        '</div>' +
        '<div class="cds--tile cds--tile--kpi">' +
          '<div class="kpi-label">Offline Queue &amp; Uptime</div>' +
          '<div class="kpi-val">' + st.counts.queuedMessages + '</div>' +
          '<div class="kpi-sub">Up ' + fmtUptime(st.uptimeSeconds) + '</div>' +
        '</div>' +
      '</div>' +
      '<div class="cds--grid-2">' +
        '<div class="cds--tile">' +
          '<h2 class="cds--tile__title">Provisioning Endpoints &amp; Cryptographic Keys</h2>' +
          '<p class="cds--tile__subtitle">OPPF Ed25519 signature verification and CSP Curve25519 public identity</p>' +
          '<div class="cds--structured-list">' +
            '<div class="kv"><span class="kv__key">OPPF Config URL</span><span class="kv__val mono">' + esc(st.addresses.httpOrigin + "/config.oppf") + '</span></div>' +
            '<div class="kv"><span class="kv__key">OPPF Fallback URL</span><span class="kv__val mono">' + esc(st.addresses.httpOrigin + "/config.fallback.oppf") + '</span></div>' +
            '<div class="kv"><span class="kv__key">CSP TCP Endpoint</span><span class="kv__val mono">' + esc(st.config.cspHost + ":" + st.addresses.cspPort) + '</span></div>' +
            '<div class="kv"><span class="kv__key">OPPF Ed25519 Public Key</span><span class="kv__val mono">' + esc(st.keys.oppfPublicKeyBase64) + '</span></div>' +
            '<div class="kv"><span class="kv__key">CSP Curve25519 Public Key</span><span class="kv__val mono">' + esc(st.keys.cspPublicKeyBase64) + '</span></div>' +
            '<div class="kv"><span class="kv__key">Rendezvous Channels</span><span class="kv__val">' + st.live.rendezvous.pairedChannels + ' paired / ' + st.live.rendezvous.waitingChannels + ' waiting</span></div>' +
          '</div>' +
        '</div>' +
        '<div class="cds--tile">' +
          '<h2 class="cds--tile__title">Broadcast CSP Server Alert (0xe1)</h2>' +
          '<p class="cds--tile__subtitle">Deliver an immediate system alert packet to one Threema ID or all connected CSP clients</p>' +
          '<form id="alert-form">' +
            '<div class="cds--form-item">' +
              '<label class="cds--label" for="alert-id">Target Threema ID (leave blank to broadcast to all online sessions)</label>' +
              '<input id="alert-id" type="text" placeholder="e.g. E6AE7BOM or blank for broadcast" />' +
            '</div>' +
            '<div class="cds--form-item">' +
              '<label class="cds--label" for="alert-msg">Alert Message Payload</label>' +
              '<input id="alert-msg" type="text" required placeholder="Scheduled maintenance window at 23:00 UTC" />' +
            '</div>' +
            '<button type="submit" class="primary"><span>Send Server Alert</span><span aria-hidden="true">&rarr;</span></button>' +
          '</form>' +
        '</div>' +
      '</div>' +
      '<div class="cds--data-table-container">' +
        '<div class="cds--data-table-header">' +
          '<div>' +
            '<h2 class="cds--data-table-header__title">Live CSP Client Connections (' + onlineSessions.length + ')</h2>' +
            '<p class="cds--data-table-header__description">Direct TCP (port 5222) and D2M WebSocket proxy connections currently authenticated</p>' +
          '</div>' +
        '</div>' +
        (onlineSessions.length === 0
          ? '<div style="padding:24px 16px;color:var(--cds-text-helper);">No active client sessions connected.</div>'
          : '<table class="cds--data-table"><thead><tr><th>Identity</th><th>Transport</th><th>Multi-Device</th><th>Queue State</th><th>CSP Device ID</th><th>Client Info</th></tr></thead><tbody>' +
            onlineSessions.map((s) =>
              '<tr>' +
                '<td class="mono" style="color:var(--cds-text-primary);font-weight:600;">' + esc(s.identity) + '</td>' +
                '<td><span class="cds--tag cds--tag--warm-gray">' + esc(s.transportKind) + '</span></td>' +
                '<td>' + (s.isMultiDevice ? '<span class="cds--tag cds--tag--blue">Multi-Device</span>' : "Single") + '</td>' +
                '<td>' + (s.incomingUnblocked ? '<span class="cds--tag cds--tag--green">Active Receiver</span>' : '<span class="cds--tag cds--tag--amber">Standby</span>') + '</td>' +
                '<td class="mono">' + esc(s.cspDeviceId || "-") + '</td>' +
                '<td class="mono">' + esc(s.clientInfo || "-") + '</td>' +
              '</tr>'
            ).join("") + '</tbody></table>') +
      '</div>';

    $("alert-form").onsubmit = async (e) => {
      e.preventDefault();
      try {
        const identity = $("alert-id").value.trim() || null;
        const message = $("alert-msg").value.trim();
        const r = await api("/alert", { method: "POST", body: JSON.stringify({ identity, message }) });
        toast("Alert delivered to " + r.deliveredCount + " session(s)");
        $("alert-msg").value = "";
      } catch (err) { toast(err.message, true); }
    };
  }

  function renderIdentities() {
    const onlineSet = new Set(((state.status && state.status.live.csp.sessions) || []).map((s) => s.identity));
    const q = identityFilter.trim().toLowerCase();
    const filtered = state.identities.filter((id) => {
      if (!q) return true;
      const hay = [id.id, id.publicNickname, id.firstName, id.lastName, id.jobTitle, id.department, id.category].filter(Boolean).join(" ").toLowerCase();
      return hay.includes(q);
    });

    const el = $("tab-identities");
    el.innerHTML =
      renderPageHeader("Cluster Administration / Directory", "Registered Identities") +
      '<div class="cds--data-table-container">' +
        '<div class="cds--data-table-header">' +
          '<div>' +
            '<h2 class="cds--data-table-header__title">Threema Identities (' + filtered.length + ' of ' + state.identities.length + ')</h2>' +
            '<p class="cds--data-table-header__description">Manage public nicknames, Work directory attributes, and revocation states</p>' +
          '</div>' +
        '</div>' +
        '<div class="cds--table-toolbar">' +
          '<input id="identity-search" class="cds--toolbar-search" type="text" placeholder="Filter by Threema ID, nickname, name, department..." value="' + esc(identityFilter) + '" />' +
        '</div>' +
        '<table class="cds--data-table"><thead><tr><th>Threema ID</th><th>Status</th><th>Public Nickname</th><th>Work Name / Title</th><th>Dept / Category</th><th>Work Sync</th><th>Actions</th></tr></thead><tbody>' +
        filtered.map((id) => {
          const badge = id.state === 1
            ? '<span class="cds--tag cds--tag--green">Active</span>'
            : (id.state === 2 ? '<span class="cds--tag cds--tag--amber">Inactive</span>' : '<span class="cds--tag cds--tag--red">Revoked</span>');
          const online = onlineSet.has(id.id) ? ' <span class="cds--tag cds--tag--blue">Online</span>' : '';
          const fullName = [id.firstName, id.lastName].filter(Boolean).join(" ") || "-";
          return '<tr>' +
            '<td class="mono" style="color:var(--cds-text-primary);font-weight:600;">' + esc(id.id) + online + '</td>' +
            '<td>' + badge + '</td>' +
            '<td>' + esc(id.publicNickname || "-") + '</td>' +
            '<td>' + esc(fullName) + (id.jobTitle ? '<div style="color:var(--cds-text-helper);font-size:12px;">' + esc(id.jobTitle) + '</div>' : '') + '</td>' +
            '<td>' + esc([id.department, id.category].filter(Boolean).join(" / ") || "-") + '</td>' +
            '<td>' + (id.workEnabled ? '<span class="cds--tag cds--tag--green">Visible</span>' : '<span class="cds--tag cds--tag--warm-gray">Hidden</span>') + '</td>' +
            '<td><div class="btn-group">' +
              '<button class="small" data-edit-id="' + esc(id.id) + '">Edit</button>' +
              (id.state === 1 ? '<button class="small danger" data-revoke-id="' + esc(id.id) + '">Revoke</button>' : '') +
              '<button class="small danger" data-del-id="' + esc(id.id) + '">Delete</button>' +
            '</div></td></tr>';
        }).join("") +
        '</tbody></table></div>';

    const searchInput = $("identity-search");
    if (searchInput) {
      searchInput.oninput = (e) => {
        identityFilter = e.target.value;
        const pos = e.target.selectionStart;
        renderIdentities();
        const next = $("identity-search");
        if (next) { next.focus(); next.setSelectionRange(pos, pos); }
      };
    }

    for (const btn of el.querySelectorAll("[data-edit-id]")) {
      btn.onclick = () => {
        const item = state.identities.find((x) => x.id === btn.dataset.editId);
        if (!item) return;
        showModal("Edit Identity " + item.id,
          '<form id="edit-id-form">' +
          '<div class="form-row">' +
            '<div><label class="cds--label">Public Nickname</label><input name="publicNickname" type="text" value="' + esc(item.publicNickname || "") + '" /></div>' +
            '<div><label class="cds--label">Activity State</label><select name="state">' +
              '<option value="1"' + (item.state === 1 ? " selected" : "") + '>Active (1)</option>' +
              '<option value="2"' + (item.state === 2 ? " selected" : "") + '>Inactive (2)</option>' +
              '<option value="0"' + (item.state === 0 ? " selected" : "") + '>Revoked (0)</option>' +
            '</select></div>' +
          '</div>' +
          '<div class="form-row">' +
            '<div><label class="cds--label">First Name</label><input name="firstName" type="text" value="' + esc(item.firstName || "") + '" /></div>' +
            '<div><label class="cds--label">Last Name</label><input name="lastName" type="text" value="' + esc(item.lastName || "") + '" /></div>' +
          '</div>' +
          '<div class="form-row">' +
            '<div><label class="cds--label">Job Title</label><input name="jobTitle" type="text" value="' + esc(item.jobTitle || "") + '" /></div>' +
            '<div><label class="cds--label">Department</label><input name="department" type="text" value="' + esc(item.department || "") + '" /></div>' +
          '</div>' +
          '<div class="form-row">' +
            '<div><label class="cds--label">Category ID</label><input name="category" type="text" value="' + esc(item.category || "") + '" /></div>' +
            '<div><label class="cds--label">Customer Specific ID (CSI)</label><input name="csi" type="text" value="' + esc(item.csi || "") + '" /></div>' +
          '</div>' +
          '<div style="margin:12px 0 20px;">' +
            '<label class="checkbox-row"><input type="checkbox" name="workEnabled"' + (item.workEnabled ? " checked" : "") + ' /> Include in Work Directory &amp; Automatic Contacts Sync</label>' +
          '</div>' +
          '<button type="submit" class="primary"><span>Save Identity Changes</span><span aria-hidden="true">&rarr;</span></button>' +
          '</form>',
          (closeModal) => {
            $("edit-id-form").onsubmit = async (e) => {
              e.preventDefault();
              const f = e.target;
              try {
                await api("/identities/" + encodeURIComponent(item.id), {
                  method: "PATCH",
                  body: JSON.stringify({
                    publicNickname: f.publicNickname.value,
                    firstName: f.firstName.value,
                    lastName: f.lastName.value,
                    jobTitle: f.jobTitle.value,
                    department: f.department.value,
                    category: f.category.value,
                    csi: f.csi.value,
                    state: Number(f.state.value),
                    workEnabled: f.workEnabled.checked
                  })
                });
                closeModal();
                toast("Updated identity " + item.id);
                await loadAll();
              } catch (err) { toast(err.message, true); }
            };
          }
        );
      };
    }

    for (const btn of el.querySelectorAll("[data-revoke-id]")) {
      btn.onclick = async () => {
        const id = btn.dataset.revokeId;
        if (!confirm("Revoke Threema ID " + id + " and disconnect active sessions?")) return;
        try {
          await api("/identities/" + encodeURIComponent(id), { method: "PATCH", body: JSON.stringify({ state: 0 }) });
          toast("Revoked " + id);
          await loadAll();
        } catch (err) { toast(err.message, true); }
      };
    }

    for (const btn of el.querySelectorAll("[data-del-id]")) {
      btn.onclick = async () => {
        const id = btn.dataset.delId;
        if (!confirm("Permanently delete identity " + id + "?")) return;
        try {
          await api("/identities/" + encodeURIComponent(id), { method: "DELETE" });
          toast("Deleted " + id);
          await loadAll();
        } catch (err) { toast(err.message, true); }
      };
    }
  }

  function renderAccounts() {
    const q = accountFilter.trim().toLowerCase();
    const filtered = state.accounts.filter((a) => {
      if (!q) return true;
      const ids = (a.identities || []).map((i) => i.id).join(" ");
      return [a.username, a.firstName, a.lastName, a.department, ids].filter(Boolean).join(" ").toLowerCase().includes(q);
    });

    const el = $("tab-accounts");
    el.innerHTML =
      renderPageHeader("Cluster Administration / Licensing", "Work License Accounts") +
      '<div class="cds--tile" style="margin-bottom:24px;">' +
        '<h2 class="cds--tile__title">Provision New Work License Account</h2>' +
        '<p class="cds--tile__subtitle">Credentials used during Threema Work app onboarding (/directory/check_license &amp; /work/fetch2)</p>' +
        '<form id="new-acc-form">' +
          '<div class="form-row">' +
            '<div><label class="cds--label">Username *</label><input name="username" type="text" required placeholder="alice@company.local" /></div>' +
            '<div><label class="cds--label">Password *</label><input name="password" type="password" required placeholder="Initial license password" /></div>' +
            '<div><label class="cds--label">First Name (template)</label><input name="firstName" type="text" placeholder="Alice" /></div>' +
            '<div><label class="cds--label">Last Name (template)</label><input name="lastName" type="text" placeholder="Roth" /></div>' +
            '<div><label class="cds--label">Department</label><input name="department" type="text" placeholder="Security" /></div>' +
          '</div>' +
          '<button type="submit" class="primary"><span>Create Work Account</span><span aria-hidden="true">+</span></button>' +
        '</form>' +
      '</div>' +
      '<div class="cds--data-table-container">' +
        '<div class="cds--data-table-header">' +
          '<div>' +
            '<h2 class="cds--data-table-header__title">Work Accounts (' + filtered.length + ' of ' + state.accounts.length + ')</h2>' +
            '<p class="cds--data-table-header__description">Manage license activation state, password resets, and linked Threema identities</p>' +
          '</div>' +
        '</div>' +
        '<div class="cds--table-toolbar">' +
          '<input id="account-search" class="cds--toolbar-search" type="text" placeholder="Filter by username, profile name, or linked Threema ID..." value="' + esc(accountFilter) + '" />' +
        '</div>' +
        '<table class="cds--data-table"><thead><tr><th>Username</th><th>Status</th><th>Linked Identities</th><th>Template Profile</th><th>Actions</th></tr></thead><tbody>' +
        filtered.map((a) => {
          const ids = (a.identities || []).map((i) => i.id).join(", ") || "-";
          const prof = [a.firstName, a.lastName, a.department].filter(Boolean).join(" / ") || "-";
          return '<tr>' +
            '<td class="mono" style="color:var(--cds-text-primary);font-weight:600;">' + esc(a.username) + '</td>' +
            '<td>' + (a.enabled ? '<span class="cds--tag cds--tag--green">Enabled</span>' : '<span class="cds--tag cds--tag--red">Disabled</span>') + '</td>' +
            '<td class="mono">' + esc(ids) + '</td>' +
            '<td>' + esc(prof) + '</td>' +
            '<td><div class="btn-group">' +
              '<button class="small" data-toggle-acc="' + esc(a.id) + '">' + (a.enabled ? "Disable" : "Enable") + '</button>' +
              '<button class="small" data-pw-acc="' + esc(a.id) + '">Reset Password</button>' +
              '<button class="small danger" data-del-acc="' + esc(a.id) + '">Delete</button>' +
            '</div></td></tr>';
        }).join("") +
        '</tbody></table></div>';

    const searchInput = $("account-search");
    if (searchInput) {
      searchInput.oninput = (e) => {
        accountFilter = e.target.value;
        const pos = e.target.selectionStart;
        renderAccounts();
        const next = $("account-search");
        if (next) { next.focus(); next.setSelectionRange(pos, pos); }
      };
    }

    $("new-acc-form").onsubmit = async (e) => {
      e.preventDefault();
      const f = e.target;
      try {
        await api("/accounts", {
          method: "POST",
          body: JSON.stringify({
            username: f.username.value.trim(),
            password: f.password.value,
            firstName: f.firstName.value.trim() || undefined,
            lastName: f.lastName.value.trim() || undefined,
            department: f.department.value.trim() || undefined
          })
        });
        toast("Created account " + f.username.value.trim());
        f.reset();
        await loadAll();
      } catch (err) { toast(err.message, true); }
    };

    for (const btn of el.querySelectorAll("[data-toggle-acc]")) {
      btn.onclick = async () => {
        const acc = state.accounts.find((x) => x.id === btn.dataset.toggleAcc);
        if (!acc) return;
        try {
          await api("/accounts/" + encodeURIComponent(acc.id), {
            method: "PATCH",
            body: JSON.stringify({ enabled: !acc.enabled })
          });
          toast((acc.enabled ? "Disabled " : "Enabled ") + acc.username);
          await loadAll();
        } catch (err) { toast(err.message, true); }
      };
    }

    for (const btn of el.querySelectorAll("[data-pw-acc]")) {
      btn.onclick = async () => {
        const acc = state.accounts.find((x) => x.id === btn.dataset.pwAcc);
        if (!acc) return;
        const nextPw = prompt("Enter new password for " + acc.username + ":");
        if (!nextPw) return;
        try {
          await api("/accounts/" + encodeURIComponent(acc.id), {
            method: "PATCH",
            body: JSON.stringify({ password: nextPw })
          });
          toast("Password updated for " + acc.username);
        } catch (err) { toast(err.message, true); }
      };
    }

    for (const btn of el.querySelectorAll("[data-del-acc]")) {
      btn.onclick = async () => {
        const acc = state.accounts.find((x) => x.id === btn.dataset.delAcc);
        if (!acc || !confirm("Delete Work account " + acc.username + "?")) return;
        try {
          await api("/accounts/" + encodeURIComponent(acc.id), { method: "DELETE" });
          toast("Deleted " + acc.username);
          await loadAll();
        } catch (err) { toast(err.message, true); }
      };
    }
  }

  function renderMdm() {
    const m = state.mdm || {};
    const el = $("tab-mdm");
    el.innerHTML =
      renderPageHeader("Cluster Administration / Policy", "Organization & MDM Configuration") +
      '<div class="cds--tile" style="margin-bottom:24px;">' +
        '<h2 class="cds--tile__title">Work Directory &amp; MDM Policy Payload</h2>' +
        '<p class="cds--tile__subtitle">Delivered to Threema Work clients via POST /work/fetch2 and signed OPPF configuration</p>' +
        '<form id="mdm-form">' +
          '<div class="form-row">' +
            '<div><label class="cds--label">Organization Name</label><input name="orgName" type="text" value="' + esc(m.orgName || "") + '" /></div>' +
            '<div><label class="cds--label">Support Contact / Help URL</label><input name="support" type="text" value="' + esc(m.support || "") + '" /></div>' +
            '<div><label class="cds--label">Work Check Interval (seconds)</label><input name="checkInterval" type="number" min="60" value="' + esc(m.checkInterval || 86400) + '" /></div>' +
          '</div>' +
          '<div class="form-row">' +
            '<div><label class="cds--label">Light Logo External URL (optional override)</label><input name="logoLight" type="text" value="' + esc(m.logoLight || "") + '" /></div>' +
            '<div><label class="cds--label">Dark Logo External URL (optional override)</label><input name="logoDark" type="text" value="' + esc(m.logoDark || "") + '" /></div>' +
          '</div>' +
          '<div class="form-row">' +
            '<div><label class="cds--label">Work Directory Categories JSON</label><textarea name="categories">' + esc(JSON.stringify(m.categories || {}, null, 2)) + '</textarea></div>' +
            '<div><label class="cds--label">Threema MDM Parameters JSON</label><textarea name="params">' + esc(JSON.stringify(m.params || {}, null, 2)) + '</textarea></div>' +
          '</div>' +
          '<div style="margin:8px 0 20px;">' +
            '<label class="checkbox-row"><input type="checkbox" name="directoryEnabled"' + (m.directoryEnabled ? " checked" : "") + ' /> Enable Work Directory Search</label>' +
            '<label class="checkbox-row"><input type="checkbox" name="override"' + (m.override ? " checked" : "") + ' /> Enforce MDM Override</label>' +
            '<label class="checkbox-row"><input type="checkbox" name="remoteSecretEnabled"' + (m.remoteSecretEnabled ? " checked" : "") + ' /> Enable OPPF Remote Secret Feature</label>' +
          '</div>' +
          '<button type="submit" class="primary"><span>Save MDM Configuration</span><span aria-hidden="true">&rarr;</span></button>' +
        '</form>' +
      '</div>' +
      '<div class="cds--grid-2">' +
        '<div class="cds--tile">' +
          '<h3 class="cds--tile__title">Self-Hosted Light Logo (/work/logo/light)</h3>' +
          '<p class="cds--tile__subtitle">Displayed in light-mode Threema Work app headers</p>' +
          '<input id="logo-light-file" type="file" accept="image/png,image/svg+xml,image/jpeg" />' +
          (m.hasLogoLightData
            ? '<div><img class="logo-preview" src="/work/logo/light?t=' + Date.now() + '" alt="Light logo" /></div>'
            : '<p style="color:var(--cds-text-helper);font-size:12px;">No uploaded light logo.</p>') +
          '<div class="btn-group" style="margin-top:14px;">' +
            '<button id="up-light" class="small primary">Upload Light Logo</button>' +
            '<button id="del-light" class="small danger">Remove</button>' +
          '</div>' +
        '</div>' +
        '<div class="cds--tile">' +
          '<h3 class="cds--tile__title">Self-Hosted Dark Logo (/work/logo/dark)</h3>' +
          '<p class="cds--tile__subtitle">Displayed in dark-mode Threema Work app headers</p>' +
          '<input id="logo-dark-file" type="file" accept="image/png,image/svg+xml,image/jpeg" />' +
          (m.hasLogoDarkData
            ? '<div><img class="logo-preview" src="/work/logo/dark?t=' + Date.now() + '" alt="Dark logo" /></div>'
            : '<p style="color:var(--cds-text-helper);font-size:12px;">No uploaded dark logo.</p>') +
          '<div class="btn-group" style="margin-top:14px;">' +
            '<button id="up-dark" class="small primary">Upload Dark Logo</button>' +
            '<button id="del-dark" class="small danger">Remove</button>' +
          '</div>' +
        '</div>' +
      '</div>';

    $("mdm-form").onsubmit = async (e) => {
      e.preventDefault();
      const f = e.target;
      try {
        const categories = JSON.parse(f.categories.value || "{}");
        const params = JSON.parse(f.params.value || "{}");
        await api("/mdm", {
          method: "PUT",
          body: JSON.stringify({
            orgName: f.orgName.value.trim(),
            support: f.support.value.trim() || null,
            checkInterval: Number(f.checkInterval.value) || 86400,
            logoLight: f.logoLight.value.trim() || null,
            logoDark: f.logoDark.value.trim() || null,
            directoryEnabled: f.directoryEnabled.checked,
            override: f.override.checked,
            remoteSecretEnabled: f.remoteSecretEnabled.checked,
            categories,
            params
          })
        });
        toast("Saved MDM settings");
        await loadAll();
      } catch (err) { toast(err.message, true); }
    };

    const bindLogo = (variant, fileInputId, upBtnId, delBtnId) => {
      $(upBtnId).onclick = async () => {
        const file = $(fileInputId).files[0];
        if (!file) { toast("Select an image file first", true); return; }
        try {
          const buf = await file.arrayBuffer();
          await api("/mdm/logo/" + variant, {
            method: "PUT",
            headers: { "content-type": file.type || "image/png" },
            body: buf
          });
          toast("Uploaded " + variant + " logo");
          await loadAll();
        } catch (err) { toast(err.message, true); }
      };
      $(delBtnId).onclick = async () => {
        try {
          await api("/mdm/logo/" + variant, { method: "DELETE" });
          toast("Removed " + variant + " logo");
          await loadAll();
        } catch (err) { toast(err.message, true); }
      };
    };
    bindLogo("light", "logo-light-file", "up-light", "del-light");
    bindLogo("dark", "logo-dark-file", "up-dark", "del-dark");
  }

  function renderDevices() {
    const el = $("tab-devices");
    el.innerHTML =
      renderPageHeader("Cluster Administration / Multi-Device & Security", "D2M Device Groups & Remote Secrets") +
      '<div class="cds--tile" style="margin-bottom:24px;">' +
        '<h2 class="cds--tile__title">D2M Multi-Device Groups (' + state.devices.length + ')</h2>' +
        '<p class="cds--tile__subtitle">Desktop 2.0 &amp; mobile device slots synchronized through the Device-to-Mediator (D2M) reflection bus</p>' +
        (state.devices.length === 0
          ? '<p style="color:var(--cds-text-helper);margin:0;">No multi-device groups registered yet.</p>'
          : state.devices.map((g) =>
              '<div class="cds--data-table-container" style="margin-bottom:16px;">' +
                '<div class="cds--data-table-header">' +
                  '<div class="mono"><strong>Device Group ID:</strong> ' + esc(g.dgid) + '</div>' +
                  '<span class="cds--tag cds--tag--blue">nextReflectId=' + g.nextReflectId + ' &bull; ' + g.storedEvents + ' stored events</span>' +
                '</div>' +
                '<table class="cds--data-table"><thead><tr><th>Device Slot ID</th><th>Expiration Policy</th><th>Connection State</th><th>Min Reflect ID</th><th>Actions</th></tr></thead><tbody>' +
                g.devices.map((d) =>
                  '<tr>' +
                    '<td class="mono" style="color:var(--cds-text-primary);">' + esc(d.deviceId) + '</td>' +
                    '<td><span class="cds--tag cds--tag--warm-gray">' + (d.expirationPolicy === 0 ? "VOLATILE" : "PERSISTENT") + '</span></td>' +
                    '<td>' + (d.dropped
                      ? '<span class="cds--tag cds--tag--red">Dropped</span>'
                      : (d.online
                          ? '<span class="cds--tag cds--tag--green">Online' + (d.isLeader ? ' (Leader)' : '') + '</span>'
                          : '<span class="cds--tag cds--tag--amber">Offline</span>')) + '</td>' +
                    '<td class="mono">' + d.minReflectId + '</td>' +
                    '<td>' + (!d.dropped
                      ? '<button class="small danger" data-drop-dgid="' + esc(g.dgid) + '" data-drop-dev="' + esc(d.deviceId) + '">Drop Device</button>'
                      : '-') + '</td>' +
                  '</tr>'
                ).join("") +
                '</tbody></table></div>'
            ).join("")) +
      '</div>' +
      '<div class="cds--data-table-container">' +
        '<div class="cds--data-table-header">' +
          '<div>' +
            '<h2 class="cds--data-table-header__title">Remote Secrets (' + state.remoteSecrets.length + ')</h2>' +
            '<p class="cds--data-table-header__description">Server-enforced remote secret tokens (/work/api-client/v1/remote-secret) for instant device lockout</p>' +
          '</div>' +
        '</div>' +
        (state.remoteSecrets.length === 0
          ? '<div style="padding:20px 16px;color:var(--cds-text-helper);">No remote secrets registered.</div>'
          : '<table class="cds--data-table"><thead><tr><th>Identity</th><th>Token Hash</th><th>Access State</th><th>Last Updated</th><th>Actions</th></tr></thead><tbody>' +
            state.remoteSecrets.map((rs) =>
              '<tr>' +
                '<td class="mono" style="color:var(--cds-text-primary);font-weight:600;">' + esc(rs.identityId) + '</td>' +
                '<td class="mono">' + esc(rs.authTokenHash.slice(0, 16)) + '...</td>' +
                '<td>' + (rs.blocked ? '<span class="cds--tag cds--tag--red">Blocked (Locked)</span>' : '<span class="cds--tag cds--tag--green">Allowed</span>') + '</td>' +
                '<td>' + esc(rs.updatedAt) + '</td>' +
                '<td><div class="btn-group">' +
                  '<button class="small" data-rs-toggle="' + esc(rs.authTokenHash) + '" data-rs-blocked="' + (rs.blocked ? "0" : "1") + '">' + (rs.blocked ? "Unblock" : "Block (Lock Device)") + '</button>' +
                  '<button class="small danger" data-rs-del="' + esc(rs.authTokenHash) + '">Delete</button>' +
                '</div></td>' +
              '</tr>'
            ).join("") + '</tbody></table>') +
      '</div>';

    for (const btn of el.querySelectorAll("[data-drop-dgid]")) {
      btn.onclick = async () => {
        if (!confirm("Drop device " + btn.dataset.dropDev + "?")) return;
        try {
          await api("/devices/" + encodeURIComponent(btn.dataset.dropDgid) + "/" + encodeURIComponent(btn.dataset.dropDev), { method: "DELETE" });
          toast("Dropped device slot");
          await loadAll();
        } catch (err) { toast(err.message, true); }
      };
    }

    for (const btn of el.querySelectorAll("[data-rs-toggle]")) {
      btn.onclick = async () => {
        try {
          await api("/remote-secrets/" + encodeURIComponent(btn.dataset.rsToggle), {
            method: "PATCH",
            body: JSON.stringify({ blocked: btn.dataset.rsBlocked === "1" })
          });
          toast("Updated remote secret lock status");
          await loadAll();
        } catch (err) { toast(err.message, true); }
      };
    }

    for (const btn of el.querySelectorAll("[data-rs-del]")) {
      btn.onclick = async () => {
        try {
          await api("/remote-secrets/" + encodeURIComponent(btn.dataset.rsDel), { method: "DELETE" });
          toast("Deleted remote secret");
          await loadAll();
        } catch (err) { toast(err.message, true); }
      };
    }
  }

  function renderReports() {
    const el = $("tab-reports");
    el.innerHTML =
      renderPageHeader("Cluster Administration / Housekeeping", "Reports & Storage Maintenance") +
      '<div class="cds--tile" style="margin-bottom:24px;">' +
        '<h2 class="cds--tile__title">Housekeeping &amp; TTL Garbage Collection</h2>' +
        '<p class="cds--tile__subtitle">Purges expired challenges/tokens, delivered &amp; stale queued messages, expired blobs (with disk files), stale volatile slots, acked D2M reflections, and expired Safe backups.</p>' +
        '<button id="btn-cleanup" class="primary"><span>Run Maintenance Cleanup Now</span><span aria-hidden="true">&rarr;</span></button>' +
        '<pre id="cleanup-out" class="mono" style="margin-top:16px;padding:12px;background:var(--cds-layer-02);color:var(--cds-text-secondary);white-space:pre-wrap;display:none;"></pre>' +
      '</div>' +
      '<div class="cds--data-table-container">' +
        '<div class="cds--data-table-header">' +
          '<div>' +
            '<h2 class="cds--data-table-header__title">Spam &amp; Abuse Reports (' + state.reports.length + ')</h2>' +
            '<p class="cds--data-table-header__description">Reports submitted by clients via POST /directory/report_id and /directory/report_message</p>' +
          '</div>' +
        '</div>' +
        (state.reports.length === 0
          ? '<div style="padding:20px 16px;color:var(--cds-text-helper);">No spam reports submitted.</div>'
          : '<table class="cds--data-table"><thead><tr><th>ID</th><th>Kind</th><th>Reporter</th><th>Payload</th><th>Created</th><th>Action</th></tr></thead><tbody>' +
            state.reports.map((r) =>
              '<tr>' +
                '<td class="mono">#' + r.id + '</td>' +
                '<td><span class="cds--tag cds--tag--warm-gray">' + esc(r.kind) + '</span></td>' +
                '<td class="mono" style="color:var(--cds-text-primary);">' + esc(r.reporterIdentity) + '</td>' +
                '<td class="mono" style="max-width:440px;overflow-wrap:anywhere;">' + esc(r.payloadJson) + '</td>' +
                '<td>' + esc(r.createdAt) + '</td>' +
                '<td><button class="small danger" data-del-rep="' + r.id + '">Dismiss</button></td>' +
              '</tr>'
            ).join("") + '</tbody></table>') +
      '</div>';

    $("btn-cleanup").onclick = async () => {
      try {
        const res = await api("/cleanup", { method: "POST" });
        const out = $("cleanup-out");
        out.style.display = "block";
        out.textContent = JSON.stringify(res.stats, null, 2);
        toast("Cleanup finished");
        await loadAll();
      } catch (err) { toast(err.message, true); }
    };

    for (const btn of el.querySelectorAll("[data-del-rep]")) {
      btn.onclick = async () => {
        try {
          await api("/reports/" + encodeURIComponent(btn.dataset.delRep), { method: "DELETE" });
          toast("Dismissed report #" + btn.dataset.delRep);
          await loadAll();
        } catch (err) { toast(err.message, true); }
      };
    }
  }

  for (const btn of document.querySelectorAll(".tab")) {
    btn.onclick = () => {
      activeTab = btn.dataset.tab;
      renderActiveTab();
    };
  }

  $("btn-theme").onclick = () => {
    applyTheme(currentTheme === "g100" ? "g10" : "g100");
  };
  $("btn-refresh").onclick = () => loadAll().then(() => toast("Cluster state refreshed")).catch((err) => toast(err.message, true));
  $("btn-logout").onclick = () => {
    sessionStorage.removeItem(STORAGE_KEY);
    adminKey = "";
    $("app-view").classList.add("hidden");
    $("login-view").classList.remove("hidden");
  };

  $("login-form").onsubmit = async (e) => {
    e.preventDefault();
    $("login-error").textContent = "";
    adminKey = $("admin-key-input").value;
    try {
      await loadAll();
      sessionStorage.setItem(STORAGE_KEY, adminKey);
      $("login-view").classList.add("hidden");
      $("app-view").classList.remove("hidden");
    } catch (err) {
      $("login-error").textContent = "Authentication failed: " + err.message;
    }
  };

  if (adminKey) {
    loadAll()
      .then(() => {
        $("login-view").classList.add("hidden");
        $("app-view").classList.remove("hidden");
      })
      .catch(() => {
        $("login-view").classList.remove("hidden");
      });
  }
})();
</script>
</body>
</html>
`;
}
