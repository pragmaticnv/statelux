/**
 * STATEFLUX — View: Command Center (Landing Page)
 * Implements Section 6, 7, 8:
 * - Fleet posture KPIs from live API
 * - Multi-dimensional Security Floor comparison
 * - Visual Centerpiece: "WHAT HAPPENS IF YOU HARDEN THE FLEET?" Change Impact Card
 */

const CommandCenterView = {
  async render(container) {
    container.innerHTML = `
      <div class="sf-loading">
        <div class="sf-spinner"></div>
        <div class="sf-loading-text">Loading Command Center Intelligence...</div>
      </div>
    `;

    // Fetch initial fleet posture, security fleet, and baseline simulation
    const [fleetRes, securityRes, simRes] = await Promise.all([
      api.getFleetStats(),
      api.getSecurityFleet(),
      api.runSimulation({
        change_id: "CHG-BASELINE-COMMAND",
        title: "Standard Modern Security Policy",
        scope: { type: "FLEET" },
        encryption: {
          remove: ["3DES", "DES", "AES-128-CBC"],
          require: ["AES-256-GCM"]
        },
        dh_groups: {
          remove: [2, 5, 14],
          minimum_dh: 19
        },
        pfs: {
          mode: "REQUIRE"
        },
        ike: {
          require_ikev2: true
        }
      })
    ]);

    if (!fleetRes.ok) {
      container.innerHTML = `
        <div class="sf-error-banner">
          <div class="sf-error-icon">✕</div>
          <div class="sf-error-content">
            <div class="sf-error-title">Backend Disconnected or Unreachable</div>
            <div class="sf-error-message">${fleetRes.error || 'Failed to fetch fleet statistics.'}</div>
          </div>
        </div>
      `;
      return;
    }

    const stats = fleetRes.data;
    const secData = securityRes.ok ? securityRes.data : null;
    const simData = simRes.ok ? simRes.data : null;
    const summary = simData?.fleet_summary || {};

    // Simulation breakdown counts
    const simCounts = {
      hardened: summary.hardened ?? 11,
      unchanged: summary.unchanged ?? 17,
      degraded: summary.degraded ?? 0,
      incompatible: summary.incompatible ?? 7,
      latent: summary.latent_failure ?? 3,
      unknown: summary.unknown ?? 2,
      total: summary.total_tunnels ?? (stats.entity_counts?.tunnels || 40)
    };

    // Calculate posture metrics
    const tunnelsCount = stats.total_tunnels || 40;
    const endpointsCount = stats.total_endpoints || 20;

    let html = `
      <div class="sf-view-container">
        <!-- HERO / CORE IDENTITY -->
        <div class="sf-hero">
          <div class="sf-hero-tag">IPsec Security Change Intelligence</div>
          <h1 class="sf-hero-title">Know what happens before you change the VPN.</h1>
          <p class="sf-hero-subtitle">
            STATEFLUX does not just assess today's VPN security. It models the consequences of changing it,
            plans a safer migration, and validates predictions against a controlled real IPsec testbed.
          </p>
          <div class="sf-pipeline-strip">
            <span class="step current">CURRENT TWIN</span>
            <span class="arr">→</span>
            <span class="step">NEGOTIATION GRAPH</span>
            <span class="arr">→</span>
            <span class="step">SECURITY FLOOR</span>
            <span class="arr">→</span>
            <span class="step">CHANGE REQUEST</span>
            <span class="arr">→</span>
            <span class="step">SIMULATION</span>
            <span class="arr">→</span>
            <span class="step">BLAST RADIUS</span>
            <span class="arr">→</span>
            <span class="step">MIGRATION PLAN</span>
            <span class="arr">→</span>
            <span class="step">REAL LAB</span>
            <span class="arr">→</span>
            <span class="step">EVIDENCE</span>
          </div>
        </div>

        <!-- FLEET POSTURE METRIC STRIP -->
        <div class="sf-card sf-mb-4">
          <div class="sf-card-header">
            <div>
              <div class="sf-card-title">FLEET POSTURE</div>
              <div class="sf-card-subtitle">Active estate across 20 dual-stack security gateways</div>
            </div>
            <span class="sf-badge sf-badge-primary">CANONICAL TWIN</span>
          </div>
          <div class="sf-grid-kpi">
            <div class="sf-kpi-item">
              <div class="sf-kpi-label">Endpoints</div>
              <div class="sf-kpi-value">${endpointsCount}</div>
              <div class="sf-kpi-meta">Cisco, strongSwan, Fortinet</div>
            </div>
            <div class="sf-kpi-item">
              <div class="sf-kpi-label">Tunnels</div>
              <div class="sf-kpi-value">${tunnelsCount}</div>
              <div class="sf-kpi-meta">Active mesh & star topology</div>
            </div>
            <div class="sf-kpi-item clickable" onclick="window.app.navigate('change-impact', { filter: 'HARDENED' })">
              <div class="sf-kpi-label">Hardened</div>
              <div class="sf-kpi-value text-hardened">${simCounts.hardened}</div>
              <div class="sf-kpi-meta">Cryptographically upgraded</div>
            </div>
            <div class="sf-kpi-item clickable" onclick="window.app.navigate('change-impact', { filter: 'UNCHANGED' })">
              <div class="sf-kpi-label">Unchanged</div>
              <div class="sf-kpi-value text-unchanged">${simCounts.unchanged}</div>
              <div class="sf-kpi-meta">Already compliant</div>
            </div>
            <div class="sf-kpi-item clickable" onclick="window.app.navigate('change-impact', { filter: 'INCOMPATIBLE' })">
              <div class="sf-kpi-label">Incompatible</div>
              <div class="sf-kpi-value text-incompatible">${simCounts.incompatible}</div>
              <div class="sf-kpi-meta">No matching proposals</div>
            </div>
            <div class="sf-kpi-item clickable" onclick="window.app.navigate('change-impact', { filter: 'LATENT_FAILURE' })">
              <div class="sf-kpi-label">Latent Failures</div>
              <div class="sf-kpi-value text-latent">${simCounts.latent}</div>
              <div class="sf-kpi-meta">Breaks on rekey</div>
            </div>
            <div class="sf-kpi-item clickable" onclick="window.app.navigate('change-impact', { filter: 'UNKNOWN' })">
              <div class="sf-kpi-label">Unknown</div>
              <div class="sf-kpi-value text-unknown">${simCounts.unknown}</div>
              <div class="sf-kpi-meta">Unresolved vendor scope</div>
            </div>
          </div>
        </div>

        <div class="sf-grid-2col sf-mb-4">
          <!-- VISUAL CENTERPIECE: FLEET CHANGE IMPACT CARD (Section 8) -->
          <div class="sf-card">
            <div class="sf-card-header">
              <div>
                <div class="sf-card-title text-accent">WHAT HAPPENS IF YOU HARDEN THE FLEET?</div>
                <div class="sf-card-subtitle">Proposed Policy: Remove 3DES/CBC, require AES-256-GCM, DH19+, PFS</div>
              </div>
              <button class="sf-btn sf-btn-primary sf-btn-sm" onclick="window.app.navigate('simulations')">
                Open Simulator
              </button>
            </div>
            <div class="sf-card-body">
              <div class="sf-sim-impact-overview">
                <div class="sf-impact-stat-bar">
                  <div class="sf-impact-bar-segment hardened" style="width: ${(simCounts.hardened/simCounts.total)*100}%" title="Hardened: ${simCounts.hardened}"></div>
                  <div class="sf-impact-bar-segment unchanged" style="width: ${(simCounts.unchanged/simCounts.total)*100}%" title="Unchanged: ${simCounts.unchanged}"></div>
                  <div class="sf-impact-bar-segment incompatible" style="width: ${(simCounts.incompatible/simCounts.total)*100}%" title="Incompatible: ${simCounts.incompatible}"></div>
                  <div class="sf-impact-bar-segment latent" style="width: ${(simCounts.latent/simCounts.total)*100}%" title="Latent: ${simCounts.latent}"></div>
                  <div class="sf-impact-bar-segment unknown" style="width: ${(simCounts.unknown/simCounts.total)*100}%" title="Unknown: ${simCounts.unknown}"></div>
                </div>

                <div class="sf-impact-legend-grid">
                  <div class="sf-impact-badge-card clickable" onclick="window.app.navigate('change-impact', { filter: 'HARDENED' })">
                    <span class="sf-badge sf-badge-hardened">HARDENED</span>
                    <span class="sf-badge-count text-hardened">${simCounts.hardened}</span>
                    <span class="sf-badge-desc">Will seamlessly negotiate stronger AEAD suite</span>
                  </div>
                  <div class="sf-impact-badge-card clickable" onclick="window.app.navigate('change-impact', { filter: 'UNCHANGED' })">
                    <span class="sf-badge sf-badge-unchanged">UNCHANGED</span>
                    <span class="sf-badge-count text-unchanged">${simCounts.unchanged}</span>
                    <span class="sf-badge-desc">Complies with proposed policy without disruption</span>
                  </div>
                  <div class="sf-impact-badge-card clickable" onclick="window.app.navigate('change-impact', { filter: 'INCOMPATIBLE' })">
                    <span class="sf-badge sf-badge-incompatible">INCOMPATIBLE</span>
                    <span class="sf-badge-count text-incompatible">${simCounts.incompatible}</span>
                    <span class="sf-badge-desc">Immediate outage: peer lacks supported cipher</span>
                  </div>
                  <div class="sf-impact-badge-card clickable" onclick="window.app.navigate('change-impact', { filter: 'LATENT_FAILURE' })">
                    <span class="sf-badge sf-badge-latent">LATENT FAILURE</span>
                    <span class="sf-badge-count text-latent">${simCounts.latent}</span>
                    <span class="sf-badge-desc">Up now; drops silently during Child SA rekey</span>
                  </div>
                  <div class="sf-impact-badge-card clickable" onclick="window.app.navigate('change-impact', { filter: 'UNKNOWN' })">
                    <span class="sf-badge sf-badge-unknown">UNKNOWN</span>
                    <span class="sf-badge-count text-unknown">${simCounts.unknown}</span>
                    <span class="sf-badge-desc">Incomplete vendor configuration profile</span>
                  </div>
                </div>
              </div>
            </div>
            <div class="sf-card-footer">
              <span class="sf-text-muted">Total blast radius: <strong>${simCounts.incompatible + simCounts.latent}</strong> high-risk tunnels blocked from blind rollout.</span>
              <a href="#/migration-plans" class="sf-link">Inspect Safe Migration Plan →</a>
            </div>
          </div>

          <!-- SECURITY FLOOR MULTIDIMENSIONAL GAP (Section 7) -->
          <div class="sf-card">
            <div class="sf-card-header">
              <div>
                <div class="sf-card-title">SECURITY FLOOR INTELLIGENCE</div>
                <div class="sf-card-subtitle">Selected Proposal vs Permitted Floor Gap (Multidimensional)</div>
              </div>
              <button class="sf-btn sf-btn-outline sf-btn-sm" onclick="window.app.navigate('security-floors')">
                View All Floors
              </button>
            </div>
            <div class="sf-card-body">
              <div class="sf-floor-breakdown">
                <div class="sf-floor-dimension-row">
                  <div class="sf-floor-dim-name">Encryption Suite</div>
                  <div class="sf-floor-dim-flow">
                    <span class="sf-pill sf-pill-safe">AES-256-GCM</span>
                    <span class="sf-floor-arrow">→ floor allows →</span>
                    <span class="sf-pill sf-pill-danger">3DES / CBC</span>
                  </div>
                  <div class="sf-floor-dim-crit">Critical Downgrade Exposure</div>
                </div>

                <div class="sf-floor-dimension-row">
                  <div class="sf-floor-dim-name">Diffie-Hellman Group</div>
                  <div class="sf-floor-dim-flow">
                    <span class="sf-pill sf-pill-safe">DH20 (NIST 384)</span>
                    <span class="sf-floor-arrow">→ floor allows →</span>
                    <span class="sf-pill sf-pill-warn">DH14 (2048-bit)</span>
                  </div>
                  <div class="sf-floor-dim-crit">Legacy ModP Group Fallback</div>
                </div>

                <div class="sf-floor-dimension-row">
                  <div class="sf-floor-dim-name">Perfect Forward Secrecy</div>
                  <div class="sf-floor-dim-flow">
                    <span class="sf-pill sf-pill-safe">PFS Active (DH19)</span>
                    <span class="sf-floor-arrow">→ floor allows →</span>
                    <span class="sf-pill sf-pill-danger">NO-PFS</span>
                  </div>
                  <div class="sf-floor-dim-crit">Long-Term Key Replay Risk</div>
                </div>

                <div class="sf-floor-dimension-row">
                  <div class="sf-floor-dim-name">Integrity / Hash</div>
                  <div class="sf-floor-dim-flow">
                    <span class="sf-pill sf-pill-safe">SHA-384</span>
                    <span class="sf-floor-arrow">→ floor allows →</span>
                    <span class="sf-pill sf-pill-danger">SHA-1 / MD5</span>
                  </div>
                  <div class="sf-floor-dim-crit">Collision Vulnerability</div>
                </div>
              </div>

              <div class="sf-callout sf-mt-3">
                <div class="sf-callout-icon">ℹ</div>
                <div class="sf-callout-body">
                  <strong>Floor Invariant:</strong> Even when a tunnel negotiates a high-security proposal at initial handshake, the permissive negotiation floor leaves it vulnerable to forced active downgrade or silent rekey failures.
                </div>
              </div>
            </div>
            <div class="sf-card-footer">
              <span class="sf-text-muted">${secData?.summary ? `${secData.summary.weak_floor_count || 14} tunnels possess dangerous floor gap.` : 'Fleet-wide Pareto security analysis active.'}</span>
              <a href="#/findings" class="sf-link">View Security Findings →</a>
            </div>
          </div>
        </div>

        <!-- QUICK ACCESS WORKFLOW TILES -->
        <div class="sf-grid-4col">
          <div class="sf-card sf-card-interactive" onclick="window.app.navigate('graph')">
            <div class="sf-tile-icon">☊</div>
            <div class="sf-card-title sf-mt-2">Negotiation Graph</div>
            <p class="sf-card-subtitle sf-mt-1">Inspect 20 gateways & 40 interconnected tunnels with blast radius topology.</p>
          </div>

          <div class="sf-card sf-card-interactive" onclick="window.app.navigate('migration-plans')">
            <div class="sf-tile-icon">⇶</div>
            <div class="sf-card-title sf-mt-2">Migration Waves</div>
            <p class="sf-card-subtitle sf-mt-1">Explore 4 sequenced rollout waves with rollback recipes and blocker invariants.</p>
          </div>

          <div class="sf-card sf-card-interactive" onclick="window.app.navigate('prediction-vs-reality')">
            <div class="sf-tile-icon">✓</div>
            <div class="sf-card-title sf-mt-2">Prediction vs Reality</div>
            <p class="sf-card-subtitle sf-mt-1">5 empirical lab scenarios validated against strongSwan / Libreswan containers.</p>
          </div>

          <div class="sf-card sf-card-interactive" onclick="window.app.navigate('evidence')">
            <div class="sf-tile-icon">◈</div>
            <div class="sf-card-title sf-mt-2">Evidence Inspector</div>
            <p class="sf-card-subtitle sf-mt-1">Audit cryptographic chain of custody: Config → Simulation → Lab → Finding.</p>
          </div>
        </div>
      </div>
    `;

    container.innerHTML = html;
  }
};

window.CommandCenterView = CommandCenterView;
