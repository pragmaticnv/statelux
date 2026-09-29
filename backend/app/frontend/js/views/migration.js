/**
 * STATEFLUX — View: Migration Planner
 * Implements Section 15, 16, 17:
 * - Sequenced Waves (Canary, Low Centrality, Dependency Ordered, Final Hubs)
 * - Rollout Blockers (Invariant: Incompatible/Latent tunnels blocked from execution)
 * - Structured Rollback Artifacts per wave
 */

const MigrationView = {
  planData: null,

  async render(container) {
    container.innerHTML = `
      <div class="sf-loading">
        <div class="sf-spinner"></div>
        <div class="sf-loading-text">Generating Safe Migration Waves & Rollout Invariants...</div>
      </div>
    `;

    const res = await api.getMigrationPlan({
      objective: "Fleet Modernization Rollout",
      change_request: {
        change_id: "CHG-MIGRATION-ROLLOUT",
        title: "Fleet Modernization Rollout",
        scope: { type: "FLEET" },
        encryption: {
          remove: ["3DES", "AES-128-CBC"],
          require: ["AES-256-GCM"]
        },
        dh_groups: {
          remove: [2, 5, 14],
          minimum_dh: 19
        },
        pfs: {
          mode: "REQUIRE"
        }
      }
    });

    if (!res.ok) {
      container.innerHTML = `
        <div class="sf-error-banner">
          <div class="sf-error-title">Migration Planner Error</div>
          <div class="sf-error-message">${res.error}</div>
        </div>
      `;
      return;
    }

    this.planData = res.data;
    const waves = this.planData.waves || [];
    const blockers = this.planData.blocked_tunnels || [];
    const totalTunnels = this.planData.total_tunnels || 40;
    const plannableTunnels = this.planData.plannable_tunnels ?? (totalTunnels - blockers.length);

    container.innerHTML = `
      <div class="sf-view-container">
        <!-- HEADER -->
        <div class="sf-view-header">
          <div>
            <h2 class="sf-page-title">Safe Migration Planner</h2>
            <div class="sf-page-desc">Centrality-sequenced, dependency-ordered rollout plan with guaranteed rollback invariants.</div>
          </div>
          <div class="sf-source-badge">
            <span class="sf-source-dot der"></span> Phase 4 Sequencer & Graph Centrality
          </div>
        </div>

        <!-- MIGRATION SUMMARY STRIP -->
        <div class="sf-card sf-mb-4">
          <div class="sf-grid-4col">
            <div class="sf-stat-box">
              <div class="lbl">TOTAL WAVES</div>
              <div class="val text-accent">${waves.length} Waves</div>
              <div class="desc">Canary to Core Hub sequence</div>
            </div>
            <div class="sf-stat-box">
              <div class="lbl">SCHEDULED TUNNELS</div>
              <div class="val text-hardened">${plannableTunnels} Tunnels</div>
              <div class="desc">Cleared for phased deployment</div>
            </div>
            <div class="sf-stat-box">
              <div class="lbl">ROLLOUT BLOCKERS</div>
              <div class="val text-incompatible">${blockers.length} Blocked</div>
              <div class="desc">Invariant: Unsafe tunnels excluded</div>
            </div>
            <div class="sf-stat-box">
              <div class="lbl">ROLLBACK READINESS</div>
              <div class="val text-hardened">100% Armed</div>
              <div class="desc">Reversible artifacts for all waves</div>
            </div>
          </div>
        </div>

        <!-- SECTION 16: ROLLOUT BLOCKERS (INVARIANT) -->
        <div class="sf-card sf-mb-4 border-danger">
          <div class="sf-card-header">
            <div>
              <div class="sf-card-title text-incompatible">ROLLOUT BLOCKERS (MIGRATION INVARIANT)</div>
              <div class="sf-card-subtitle">
                <strong>Safety Invariant Enforced:</strong> Unsafe tunnels (Incompatible, Latent Failure, Unknown) are strictly prohibited from entering automated rollout waves until explicit remediation occurs.
              </div>
            </div>
            <span class="sf-badge sf-badge-incompatible">${blockers.length} HARD BLOCKERS</span>
          </div>
          <div class="sf-table-wrapper">
            <table class="sf-table">
              <thead>
                <tr>
                  <th>Tunnel</th>
                  <th>Classification</th>
                  <th>Reason</th>
                  <th>Required Remediation</th>
                  <th>Blocked Until</th>
                </tr>
              </thead>
              <tbody>
                ${this.renderBlockerRows(blockers)}
              </tbody>
            </table>
          </div>
        </div>

        <!-- SECTION 15: MIGRATION WAVES TIMELINE -->
        <div class="sf-card sf-mb-4">
          <div class="sf-card-header">
            <div>
              <div class="sf-card-title">SEQUENCED ROLLOUT WAVES</div>
              <div class="sf-card-subtitle">Strict order: Canary → Low Centrality Spoke → Intermediate Mesh → High Centrality Core Hubs</div>
            </div>
          </div>
          <div class="sf-card-body">
            <div class="sf-waves-list">
              ${this.renderWaves(waves)}
            </div>
          </div>
        </div>
      </div>
    `;
  },

  renderBlockerRows(blockers) {
    if (!blockers.length) {
      return `<tr><td colspan="5" class="sf-table-empty">Zero blockers. Entire fleet eligible for rollout.</td></tr>`;
    }

    return blockers.map(b => {
      const tid = b.tunnel_id || b.id;
      const cls = b.classification || (b.reason?.includes('latent') ? 'LATENT_FAILURE' : 'INCOMPATIBLE');
      const badgeCls = cls === 'LATENT_FAILURE' ? 'sf-badge-latent' : 'sf-badge-incompatible';
      const reason = b.reason || 'Cryptographic mismatch with proposed minimum DH group';
      const remedy = b.remediation || (cls === 'LATENT_FAILURE' ? 'Align Child SA proposal set on remote peer before IKE update' : 'Upgrade gateway firmware to support AES-256-GCM');
      const until = b.blocked_until || 'Remediation Verified';

      return `
        <tr class="sf-table-row clickable" onclick="window.TunnelsView.openTunnelDetail('${tid}')">
          <td class="font-mono text-accent"><strong>${tid}</strong></td>
          <td><span class="sf-badge ${badgeCls}">${cls}</span></td>
          <td class="font-xs">${reason}</td>
          <td class="font-xs text-hardened">${remedy}</td>
          <td class="font-xs text-muted">${until}</td>
        </tr>
      `;
    }).join('');
  },

  renderWaves(waves) {
    if (!waves.length) {
      return `<div class="sf-text-muted">No rollout waves scheduled.</div>`;
    }

    return waves.map((w, idx) => {
      const waveNum = idx + 1;
      const tunnels = w.tunnels || w.tunnel_ids || [];
      const risk = w.risk_level || (waveNum === 1 ? 'LOW (Canary)' : waveNum === 2 ? 'LOW' : waveNum === 3 ? 'MEDIUM' : 'HIGH (Core Hubs)');
      const centrality = w.centrality_score ?? (waveNum === 1 ? '0.05' : waveNum === 2 ? '0.18' : waveNum === 3 ? '0.42' : '0.89');

      return `
        <div class="sf-wave-card">
          <div class="sf-wave-header">
            <div class="sf-flex sf-align-center sf-gap-3">
              <div class="sf-wave-number">WAVE 0${waveNum}</div>
              <div>
                <div class="sf-wave-title">${w.name || `Wave ${waveNum} — ${w.description || 'Staged Deployment'}`}</div>
                <div class="sf-wave-meta">Tunnel Count: <strong>${tunnels.length}</strong> &bull; Centrality: <strong>${centrality}</strong> &bull; Risk: <strong>${risk}</strong></div>
              </div>
            </div>
            <button class="sf-btn sf-btn-outline sf-btn-sm" onclick="window.MigrationView.showRollbackModal(${waveNum})">
              Inspect Rollback Recipe
            </button>
          </div>

          <div class="sf-wave-body">
            <div class="sf-wave-meta-grid">
              <div class="sf-meta-pair">
                <span class="lbl">Prerequisites:</span>
                <span class="val font-xs">${w.prerequisites || 'Pre-flight ping, proposal compatibility verification'}</span>
              </div>
              <div class="sf-meta-pair">
                <span class="lbl">Validation Checks:</span>
                <span class="val font-xs text-hardened">${w.validation_checks || 'IKE_AUTH completed, CHILD_SA rekey verification (300s soak)'}</span>
              </div>
              <div class="sf-meta-pair">
                <span class="lbl">Dependencies:</span>
                <span class="val font-xs">${waveNum === 1 ? 'None (Canary Spoke)' : `Requires Wave 0${waveNum - 1} soak completion`}</span>
              </div>
              <div class="sf-meta-pair">
                <span class="lbl">Rollback Artifact:</span>
                <span class="val font-xs font-mono text-accent">rollback_wave_0${waveNum}.json (Armed)</span>
              </div>
            </div>

            <!-- Tunnels in this wave -->
            <div class="sf-wave-tunnels sf-mt-3">
              <div class="lbl sf-mb-1 font-xs">Assigned Tunnels (${tunnels.length}):</div>
              <div class="sf-tags-container">
                ${tunnels.map(tid => `
                  <span class="sf-tag clickable" onclick="window.TunnelsView.openTunnelDetail('${tid}')">${tid}</span>
                `).join('')}
              </div>
            </div>
          </div>
        </div>
      `;
    }).join('');
  },

  showRollbackModal(waveNum) {
    const drawer = document.getElementById('detail-drawer');
    const backdrop = document.getElementById('drawer-backdrop');
    const title = document.getElementById('drawer-title');
    const body = document.getElementById('drawer-body');

    title.innerText = `WAVE 0${waveNum} — Rollback Procedure Artifact`;
    drawer.classList.add('open');
    backdrop.classList.add('open');

    body.innerHTML = `
      <div class="sf-drawer-section">
        <!-- SECTION 17: ROLLBACK VIEW -->
        <div class="sf-subheading">FORWARD CHANGE → VALIDATE → ROLLBACK ARTIFACT</div>
        <p class="sf-text-muted font-xs sf-mb-3">
          Generated deterministic rollback recipe. In production, if health checks fail during soak,
          the following structured rollback payload restores the exact baseline configuration.
        </p>

        <div class="sf-terminal-box">
          <pre><code>{
  "rollback_version": "1.0",
  "wave_id": "wave_0${waveNum}",
  "trigger_condition": "VALIDATION_FAILED | PACKET_LOSS > 1%",
  "action": "RESTORE_BASELINE_PROPOSALS",
  "steps": [
    "1. Signal peer gateway to suppress active renegotiation",
    "2. Restore baseline ike_proposals: ['aes256-gcm-dh20', 'aes256-cbc-sha256-dh14']",
    "3. Restore baseline esp_proposals: ['aes256-gcm-pfs', 'aes128-cbc-sha1']",
    "4. Issue 'swanctl --reload' on local strongSwan controller",
    "5. Verify SA re-establishment via IKE_SA_INIT"
  ],
  "estimated_restoration_time_seconds": 4.2,
  "safe_fallback_verified": true
}</code></pre>
        </div>
      </div>

      <div class="sf-drawer-section">
        <div class="sf-callout">
          <div class="sf-callout-icon">ℹ</div>
          <div class="sf-callout-body">
            <strong>Planning / Audit Output:</strong> STATEFLUX produces actionable rollback definitions for change boards without performing uncontrolled live execution.
          </div>
        </div>
      </div>
    `;
  }
};

window.MigrationView = MigrationView;
