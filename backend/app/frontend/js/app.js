/**
 * STATEFLUX — Main Application Controller & Router
 * Implements:
 * - Hash-based client routing
 * - Health monitoring & status updates
 * - Modal drawer management
 * - 12-Step Guided Demonstration Engine (Section 32)
 */

class StatefluxApp {
  constructor() {
    this.currentView = null;
    this.viewContainer = document.getElementById('app-view');
    this.headerTitle = document.getElementById('header-title');
    this.drawer = document.getElementById('detail-drawer');
    this.drawerBackdrop = document.getElementById('drawer-backdrop');
    this.drawerClose = document.getElementById('drawer-close');

    this.init();
  }

  async init() {
    // Setup drawer listeners
    this.drawerClose?.addEventListener('click', () => this.closeDrawer());
    this.drawerBackdrop?.addEventListener('click', () => this.closeDrawer());

    // Setup demo button listener
    document.getElementById('btn-run-demo')?.addEventListener('click', () => this.startGuidedDemo());

    // Setup hash change listener
    window.addEventListener('hashchange', () => this.handleRoute());

    // Initial health check
    await this.checkSystemHealth();

    // Initial route
    this.handleRoute();
  }

  async checkSystemHealth() {
    const res = await api.getHealth();
    const backendDot = document.getElementById('status-backend-dot');
    const backendText = document.getElementById('status-backend-text');
    const evidenceDot = document.getElementById('status-evidence-dot');
    const labDot = document.getElementById('status-lab-dot');

    if (res.ok) {
      backendDot?.classList.add('online');
      evidenceDot?.classList.add('online');
      labDot?.classList.add('online');
    } else {
      backendDot?.classList.remove('online');
      backendDot?.classList.add('offline');
      if (backendText) backendText.innerText = 'Backend Offline';
    }
  }

  navigate(route, params = {}) {
    this.params = params;
    window.location.hash = `#/${route}`;
  }

  handleRoute() {
    const hash = window.location.hash.replace('#/', '') || 'command-center';
    const [path, queryString] = hash.split('?');
    const params = { ...this.params };

    if (queryString) {
      const q = new URLSearchParams(queryString);
      q.forEach((v, k) => { params[k] = v; });
    }

    // Update active nav styling
    const navItems = document.querySelectorAll('.sf-nav-item');
    const normalizedPath = path.replace(/\//g, '-');
    navItems.forEach(item => {
      const view = item.getAttribute('data-view') || '';
      const normalizedView = view.replace(/\//g, '-');
      if (view === path || normalizedView === normalizedPath) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    // Update header title
    const formattedTitle = path.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    if (this.headerTitle) this.headerTitle.innerText = formattedTitle;

    // Dispatch to views
    this.closeDrawer();

    switch (path) {
      case 'command-center':
        window.CommandCenterView.render(this.viewContainer);
        break;
      case 'fleet':
      case 'tunnels':
        window.TunnelsView.render(this.viewContainer, params);
        break;
      case 'endpoints':
        window.EndpointsView.render(this.viewContainer, params);
        break;
      case 'graph':
        window.GraphView.render(this.viewContainer, params);
        break;
      case 'findings':
        window.EvidenceView.render(this.viewContainer, { ...params, view: 'findings' });
        break;
      case 'security-floors':
        window.CommandCenterView.render(this.viewContainer);
        break;
      case 'evidence':
        window.EvidenceView.render(this.viewContainer, params);
        break;
      case 'simulations':
      case 'change-impact':
        window.SimulatorView.render(this.viewContainer, params);
        break;
      case 'migration-plans':
        window.MigrationView.render(this.viewContainer, params);
        break;
      case 'lab':
      case 'prediction-vs-reality':
        window.LabView.render(this.viewContainer, params);
        break;
      case 'reports/executive':
        window.ReportsView.render(this.viewContainer, { report_type: 'executive' });
        break;
      case 'reports/technical':
        window.ReportsView.render(this.viewContainer, { report_type: 'technical' });
        break;
      case 'reports/change-impact':
        window.ReportsView.render(this.viewContainer, { report_type: 'change-impact' });
        break;
      case 'reports/lab-validation':
        window.ReportsView.render(this.viewContainer, { report_type: 'lab-validation' });
        break;
      case 'ai-reasoning':
        window.AIReasoningView.render(this.viewContainer, params);
        break;
      default:
        window.CommandCenterView.render(this.viewContainer);
        break;
    }
  }

  openTunnelDetail(id) {
    if (window.TunnelsView) {
      window.TunnelsView.openTunnelDetail(id);
    }
  }

  closeDrawer() {
    this.drawer?.classList.remove('open');
    this.drawerBackdrop?.classList.remove('open');
  }

  /**
   * SECTION 32: CRITICAL 12-STEP DEMO FLOW
   * Guides the user or evaluator through the complete unbroken story:
   * TODAY -> WHAT IF -> WHAT BREAKS -> HOW MANY -> WHICH ONES -> MIGRATION ORDER -> LAB VALIDATION -> EVIDENCE -> AI -> REPORT
   */
  async startGuidedDemo() {
    const showToast = (stepNum, stepTitle, stepExplanation) => {
      let toast = document.getElementById('demo-guide-toast');
      if (!toast) {
        toast = document.createElement('div');
        toast.id = 'demo-guide-toast';
        toast.className = 'sf-demo-toast';
        document.body.appendChild(toast);
      }
      toast.innerHTML = `
        <div class="sf-demo-toast-header">
          <span class="sf-demo-toast-step">STEP ${stepNum} OF 12</span>
          <span class="sf-demo-toast-title">${stepTitle}</span>
        </div>
        <div class="sf-demo-toast-desc">${stepExplanation}</div>
      `;
      toast.classList.add('visible');
    };

    const sleep = (ms) => new Promise(res => setTimeout(res, ms));

    // STEP 1: Command Center
    showToast(1, "Command Center", "Inspecting 40 tunnels, current fleet security posture, and dormant security floor risks.");
    this.navigate('command-center');
    await sleep(2500);

    // STEP 2: Negotiation Graph
    showToast(2, "Negotiation Graph", "Observing interconnected topology across 20 dual-stack security gateways.");
    this.navigate('graph');
    await sleep(2500);

    // STEP 3: Security Floor
    showToast(3, "Security Floor Panel", "Auditing multi-dimensional gap: Selected Suite (AES-256-GCM / DH20) vs Permitted Floor (3DES / DH14).");
    this.navigate('command-center');
    const floorEl = document.querySelector('.sf-floor-breakdown');
    if (floorEl) floorEl.scrollIntoView({ behavior: 'smooth' });
    await sleep(2500);

    // STEP 4: Change Simulator
    showToast(4, "Change Impact Simulator", "Configuring policy: Prohibit 3DES & CBC, require AES-256-GCM, enforce DH19+, require PFS.");
    this.navigate('simulations');
    await sleep(2000);

    // STEP 5: Simulation
    showToast(5, "Execute Policy Simulation", "Calling POST /api/v1/simulations to model consequences before modifying production VPN.");
    if (window.SimulatorView) window.SimulatorView.executeSimulation();
    await sleep(2500);

    // STEP 6: Blast Radius
    showToast(6, "Fleet Blast Radius", "Deterministic output: 11 Hardened, 17 Unchanged, 7 Incompatible, 3 Latent Failures, 2 Unknown.");
    const simResEl = document.getElementById('simulation-results-container');
    if (simResEl) simResEl.scrollIntoView({ behavior: 'smooth' });
    await sleep(3000);

    // STEP 7: Migration Planner
    showToast(7, "Safe Migration Planner", "Sequenced Rollout: Canary (Wave 1) to Core Hubs (Wave 4). Invariant: Unsafe tunnels strictly blocked.");
    this.navigate('migration-plans');
    await sleep(3000);

    // STEP 8: Prediction vs Reality
    showToast(8, "Prediction vs Reality Validation", "Empirical validation against controlled strongSwan/Libreswan container testbed (5/5 scenarios matched).");
    this.navigate('prediction-vs-reality');
    await sleep(2500);

    // STEP 9: LAB-05
    showToast(9, "LAB-05: Rekey Latent Failure", "Predicted: LATENT_FAILURE. Real daemon observed: NO_PROPOSAL_CHOSEN during CREATE_CHILD_SA rekey.");
    if (window.LabView) window.LabView.inspectScenario('LAB-05');
    await sleep(3500);

    // STEP 10: Evidence Chain
    showToast(10, "Cryptographic Evidence Chain", "Tracing 5-link provenance: Config (E-001) → Negotiation (E-005) → Simulation (E-008) → Lab Log (E-013) → PCAP (E-014).");
    this.navigate('evidence', { finding_id: 'FIND-LATENT-01' });
    await sleep(3000);

    // STEP 11: Grounded AI
    showToast(11, "Grounded AI Reasoning", "Examining strict evidence-bound reasoning: Observed Facts, Derived Facts, and Remediation.");
    this.navigate('ai-reasoning', { finding_id: 'FIND-LATENT-01' });
    await sleep(3000);

    // STEP 12: Change-Impact Report
    showToast(12, "Change-Impact Report Complete", "Comprehensive audit generated for engineering change boards. The full STATEFLUX story is complete.");
    this.navigate('reports/change-impact');
    await sleep(3500);

    const toast = document.getElementById('demo-guide-toast');
    if (toast) toast.classList.remove('visible');
  }
}

// Instantiate on DOM load
window.addEventListener('DOMContentLoaded', () => {
  window.app = new StatefluxApp();
});
