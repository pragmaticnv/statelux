/**
 * STATEFLUX — View: Endpoints (Gateway Inventory)
 * Hardware cryptographic profiles, vendors, supported suites, and interface bindings.
 */

const EndpointsView = {
  endpoints: [],

  async render(container, params = {}) {
    container.innerHTML = `
      <div class="sf-loading">
        <div class="sf-spinner"></div>
        <div class="sf-loading-text">Loading Gateway Hardware Profiles...</div>
      </div>
    `;

    const res = await api.getEndpoints();
    if (!res.ok) {
      container.innerHTML = `
        <div class="sf-error-banner">
          <div class="sf-error-title">Error Loading Endpoints</div>
          <div class="sf-error-message">${res.error}</div>
        </div>
      `;
      return;
    }

    this.endpoints = res.data?.items || res.data || [];

    container.innerHTML = `
      <div class="sf-view-container">
        <div class="sf-view-header">
          <div>
            <h2 class="sf-page-title">Fleet Security Gateways</h2>
            <div class="sf-page-desc">${this.endpoints.length} Heterogeneous Network Security Appliances & Software Gateways</div>
          </div>
          <div class="sf-filter-group">
            <input type="text" id="endpoint-search" class="sf-input" placeholder="Search Gateway ID, vendor, or model..." style="width: 280px;" />
          </div>
        </div>

        <div class="sf-card">
          <div class="sf-table-wrapper">
            <table class="sf-table">
              <thead>
                <tr>
                  <th>Gateway ID</th>
                  <th>Hostname / Name</th>
                  <th>Vendor</th>
                  <th>Software / OS</th>
                  <th>IKE Capabilities</th>
                  <th>Max DH Group</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody id="endpoints-tbody">
                ${this.renderRows(this.endpoints)}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    const searchInput = document.getElementById('endpoint-search');
    searchInput?.addEventListener('input', ev => {
      const q = ev.target.value.toLowerCase().trim();
      const filtered = this.endpoints.filter(e => {
        const id = (e.id || e.endpoint_id || '').toLowerCase();
        const name = (e.name || '').toLowerCase();
        const vendor = (e.vendor || '').toLowerCase();
        return !q || id.includes(q) || name.includes(q) || vendor.includes(q);
      });
      document.getElementById('endpoints-tbody').innerHTML = this.renderRows(filtered);
    });

    if (params.endpoint_id) {
      this.inspectEndpoint(params.endpoint_id);
    }
  },

  renderRows(list) {
    if (!list.length) {
      return `<tr><td colspan="7" class="sf-table-empty">No security gateways found.</td></tr>`;
    }

    return list.map(e => {
      const id = e.id || e.endpoint_id;
      const vendor = e.vendor || (id.includes('cisco') ? 'Cisco' : id.includes('forti') ? 'Fortinet' : 'strongSwan');
      const maxDh = e.supported_dh_groups ? Math.max(...e.supported_dh_groups) : 21;

      return `
        <tr class="sf-table-row clickable" onclick="window.EndpointsView.inspectEndpoint('${id}')">
          <td class="font-mono text-accent"><strong>${id}</strong></td>
          <td>${e.name || id}</td>
          <td><span class="sf-badge sf-badge-outline">${vendor}</span></td>
          <td class="font-mono font-xs">${e.software_version || 'Linux 5.15 / strongSwan 5.9.11'}</td>
          <td><span class="sf-pill sf-pill-safe">IKEv2</span> ${e.supports_ikev1 ? '<span class="sf-pill sf-pill-warn">IKEv1</span>' : ''}</td>
          <td class="font-mono">DH${maxDh} (ECP${maxDh === 20 ? '384' : maxDh === 21 ? '521' : '256'})</td>
          <td>
            <button class="sf-btn sf-btn-outline sf-btn-sm" onclick="event.stopPropagation(); window.EndpointsView.inspectEndpoint('${id}')">
              Profile →
            </button>
          </td>
        </tr>
      `;
    }).join('');
  },

  async inspectEndpoint(id) {
    const drawer = document.getElementById('detail-drawer');
    const backdrop = document.getElementById('drawer-backdrop');
    const title = document.getElementById('drawer-title');
    const body = document.getElementById('drawer-body');

    title.innerText = `GATEWAY ${id} — Profile`;
    drawer.classList.add('open');
    backdrop.classList.add('open');

    const ep = this.endpoints.find(e => (e.id || e.endpoint_id) === id) || { id };

    body.innerHTML = `
      <div class="sf-drawer-section">
        <div class="sf-subheading">HARDWARE & VENDOR PROFILE</div>
        <div class="sf-meta-pair"><span class="lbl">Gateway ID:</span> <span class="val font-mono">${ep.id}</span></div>
        <div class="sf-meta-pair"><span class="lbl">Name:</span> <span class="val">${ep.name || ep.id}</span></div>
        <div class="sf-meta-pair"><span class="lbl">Vendor:</span> <span class="val">${ep.vendor || 'strongSwan appliance'}</span></div>
        <div class="sf-meta-pair"><span class="lbl">Role:</span> <span class="val">${ep.role || 'Regional Hub'}</span></div>
        <div class="sf-meta-pair"><span class="lbl">Interfaces:</span> <span class="val font-mono">eth0 (WAN), eth1 (VTI)</span></div>
      </div>

      <div class="sf-drawer-section">
        <div class="sf-subheading">CRYPTOGRAPHIC CAPABILITY MATRIX</div>
        <div class="sf-meta-pair"><span class="lbl">AEAD Ciphers:</span> <span class="val font-mono">AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305</span></div>
        <div class="sf-meta-pair"><span class="lbl">CBC Fallback:</span> <span class="val font-mono text-latent">AES-256-CBC, 3DES-CBC (Permitted in current config)</span></div>
        <div class="sf-meta-pair"><span class="lbl">DH Groups:</span> <span class="val font-mono">14, 19, 20, 21</span></div>
        <div class="sf-meta-pair"><span class="lbl">PFS Support:</span> <span class="val text-hardened">Supported (Strict negotiation required)</span></div>
      </div>

      <div class="sf-drawer-section">
        <button class="sf-btn sf-btn-primary" onclick="window.app.navigate('graph')">
          Locate Gateway in Negotiation Graph →
        </button>
      </div>
    `;
  }
};

window.EndpointsView = EndpointsView;
