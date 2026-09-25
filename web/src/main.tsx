import '@fontsource-variable/manrope';
import React from 'react';
import ReactDOM from 'react-dom/client';
import { AdminApp } from './admin/AdminApp';
import { App } from './App';
import './components/nyu/nyu.css';
import { applyAppearance } from './lib/settings';
import { load } from './lib/web/core';
import './styles/app.css';
import './styles/vault.css';
import './styles/tokens.css';
import './styles/web.css';

// Dark by default, like the other UwU apps; the settings switch to light or follow the system.
applyAppearance();
// The crypto starts loading right away, while the page draws.
void load();

const root = document.getElementById('root');
if (!root) throw new Error('#root missing from index.html');

// One app, two places: the vault at `/`, the admin portal at `/admin`.
const admin = location.pathname.replace(/\/+$/, '') === '/admin';

ReactDOM.createRoot(root).render(
  <React.StrictMode>{admin ? <AdminApp /> : <App />}</React.StrictMode>,
);
