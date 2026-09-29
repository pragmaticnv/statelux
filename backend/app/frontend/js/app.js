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
  /**
   * SECTION 32: INTERACTIVE 12-STEP GUIDED DEMO CONTROLLER
   * Allows manual navigation via Previous (◀) and Next (▶) arrows
   * or automated progression with a 10-second countdown timer and Pause/Play control.
   */
  startGuidedDemo() {
    this.demoSteps = [
      {
        num: 1,
        title: "1. Fleet Security & Command Center",
        desc: "Auditing 40 interconnected tunnels, active cipher suites, and dormant cryptographic downgrade risks across 20 dual-stack gateways.",
        action: () => this.navigate('command-center')
      },
      {
        num: 2,
        title: "2. Topological Negotiation Graph",
        desc: "Visualizing the multi-gateway topology graph and pairwise proposal compatibility frontiers in real time.",
        action: () => this.navigate('graph')
      },
      {
        num: 3,
        title: "3. Dynamic Security Floor Analysis",
        desc: "Measuring the gap between selected ciphers (AES-256-GCM / DH20) and the weakest permitted security floor (3DES / DH14).",
        action: () => {
          this.navigate('command-center');
          setTimeout(() => {
            const floorEl = document.querySelector('.sf-floor-breakdown') || document.getElementById('floor-analysis-card');
            if (floorEl) floorEl.scrollIntoView({ behavior: 'smooth' });
          }, 250);
        }
      },
      {
        num: 4,
        title: "4. Change Request Configuration",
        desc: "Targeting cryptographic hardening: Prohibit 3DES & CBC, require AES-256-GCM, enforce DH19+, and mandate PFS.",
        action: () => this.navigate('simulations')
      },
      {
        num: 5,
        title: "5. Policy Change Simulation Execution",
        desc: "Executing deterministic what-if simulation to calculate future proposal intersections before touching production VPNs.",
        action: () => {
          this.navigate('simulations');
          setTimeout(() => {
            if (window.SimulatorView && typeof window.SimulatorView.executeSimulation === 'function') {
              window.SimulatorView.executeSimulation();
            }
          }, 350);
        }
      },
      {
        num: 6,
        title: "6. Fleet Blast-Radius Breakdown",
        desc: "Deterministic outcome: 10 Hardened, 14 Unchanged, 7 Incompatible breaks, 7 Latent Rekey Failures, 2 Unknown.",
        action: () => {
          this.navigate('simulations');
          setTimeout(() => {
            const simResEl = document.getElementById('simulation-results-container');
            if (simResEl) simResEl.scrollIntoView({ behavior: 'smooth' });
          }, 400);
        }
      },
      {
        num: 7,
        title: "7. Staged Migration Sequencing",
        desc: "Topological rollout waves: Canary (Wave 1) -> Regional (Wave 2) -> Core Hubs (Wave 3/4) with automated rollback safeguards.",
        action: () => this.navigate('migration-plans')
      },
      {
        num: 8,
        title: "8. Real IPsec Testbed Validation",
        desc: "Empirical verification against containerized strongSwan 5.9.8 and Libreswan 4.12 daemons (5/5 scenarios matched).",
        action: () => this.navigate('prediction-vs-reality')
      },
      {
        num: 9,
        title: "9. LAB-05: Latent Rekey Failure in Real Daemon",
        desc: "Simulation predicted LATENT_FAILURE. Real daemon confirmed: tunnel stayed UP until CREATE_CHILD_SA rekey collapsed.",
        action: () => {
          this.navigate('prediction-vs-reality');
          setTimeout(() => {
            if (window.LabView && typeof window.LabView.inspectScenario === 'function') {
              window.LabView.inspectScenario('LAB-05');
            }
          }, 350);
        }
      },
      {
        num: 10,
        title: "10. Unbroken Evidence & Provenance Chain",
        desc: "Tracing cryptographic finding provenance: Configuration -> Proposal Matrix -> Simulation -> Syslog Events -> PCAP Capture.",
        action: () => this.navigate('evidence', { finding_id: 'FIND-LATENT-01' })
      },
      {
        num: 11,
        title: "11. Grounded AI Fact Synthesis",
        desc: "Evaluating fact-bound reasoning strictly explaining observed logs and deterministic remediation without hallucination.",
        action: () => this.navigate('ai-reasoning', { finding_id: 'FIND-LATENT-01' })
      },
      {
        num: 12,
        title: "12. Publication-Grade Change-Impact Report",
        desc: "Generating standalone boardroom executive and technical audit reports with direct native vector PDF export.",
        action: () => this.navigate('reports/change-impact')
      }
    ];

    this.demoState = {
      active: true,
      stepIndex: 0,
      timer: null,
      timeLeft: 10,
      totalTime: 10,
      isPaused: false
    };

    // Attach keyboard listener if not already attached
    if (!this._demoKeyHandlerAttached) {
      document.addEventListener('keydown', (e) => {
        if (!this.demoState || !this.demoState.active) return;
        if (e.key === 'ArrowRight') {
          e.preventDefault();
          this.nextDemoStep();
        } else if (e.key === 'ArrowLeft') {
          e.preventDefault();
          this.prevDemoStep();
        } else if (e.key === ' ') {
          e.preventDefault();
          this.toggleDemoPause();
        } else if (e.key === 'Escape') {
          e.preventDefault();
          this.exitDemo();
        }
      });
      this._demoKeyHandlerAttached = true;
    }

    this.renderDemoStep();
  }

  renderDemoStep() {
    if (!this.demoState || !this.demoState.active) return;

    const step = this.demoSteps[this.demoState.stepIndex];
    if (!step) return;

    // Execute step view transition
    try {
      step.action();
    } catch (err) {
      console.warn('Demo step action error:', err);
    }

    let toast = document.getElementById('demo-guide-toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'demo-guide-toast';
      toast.className = 'sf-demo-toast';
      document.body.appendChild(toast);
    }

    const isFirst = this.demoState.stepIndex === 0;
    const isLast = this.demoState.stepIndex === this.demoSteps.length - 1;
    const pauseText = this.demoState.isPaused ? '▶ Play' : '⏸ Pause';

    toast.innerHTML = `
      <div class="sf-demo-toast-top">
        <span class="sf-demo-toast-step">STEP ${step.num} OF ${this.demoSteps.length}</span>
        <button class="sf-demo-toast-close" id="btn-demo-close" title="Exit Demo (Esc)">&times;</button>
      </div>
      <div class="sf-demo-toast-title">${step.title}</div>
      <div class="sf-demo-toast-desc">${step.desc}</div>
      <div class="sf-demo-progress-bar">
        <div class="sf-demo-progress-fill" id="demo-progress-fill" style="width: 100%"></div>
      </div>
      <div class="sf-demo-toast-controls">
        <div class="sf-demo-controls-left">
          <button class="sf-demo-btn" id="btn-demo-prev" ${isFirst ? 'disabled' : ''} title="Previous Step (Left Arrow)">
            ◀ Prev
          </button>
          <button class="sf-demo-btn" id="btn-demo-pause" title="Pause / Resume 10s Timer (Spacebar)">
            <span id="demo-pause-icon">${pauseText}</span>
            <span class="sf-demo-timer-badge" id="demo-timer-countdown">(${this.demoState.timeLeft}s)</span>
          </button>
        </div>
        <button class="sf-demo-btn sf-demo-btn-primary" id="btn-demo-next" title="${isLast ? 'Complete Demo' : 'Next Step (Right Arrow)'}">
          ${isLast ? 'Finish Demo ✓' : 'Next ▶'}
        </button>
      </div>
    `;

    toast.classList.add('visible');

    // Bind button events
    document.getElementById('btn-demo-close')?.addEventListener('click', () => this.exitDemo());
    document.getElementById('btn-demo-prev')?.addEventListener('click', () => this.prevDemoStep());
    document.getElementById('btn-demo-next')?.addEventListener('click', () => this.nextDemoStep());
    document.getElementById('btn-demo-pause')?.addEventListener('click', () => this.toggleDemoPause());

    // Start 10-second timer countdown
    this.demoState.timeLeft = 10;
    this.startDemoCountdown();
  }

  startDemoCountdown() {
    if (this.demoState.timer) {
      clearInterval(this.demoState.timer);
      this.demoState.timer = null;
    }

    if (this.demoState.isPaused) {
      this.updateDemoCountdownUI();
      return;
    }

    const intervalMs = 100;
    const totalSteps = (this.demoState.totalTime * 1000) / intervalMs;
    let elapsedSteps = 0;

    this.demoState.timer = setInterval(() => {
      if (this.demoState.isPaused) return;

      elapsedSteps++;
      const remainingMs = Math.max(0, (this.demoState.totalTime * 1000) - (elapsedSteps * intervalMs));
      this.demoState.timeLeft = Math.ceil(remainingMs / 1000);

      const percent = (remainingMs / (this.demoState.totalTime * 1000)) * 100;
      const fillEl = document.getElementById('demo-progress-fill');
      if (fillEl) fillEl.style.width = `${percent}%`;

      const countdownEl = document.getElementById('demo-timer-countdown');
      if (countdownEl) countdownEl.textContent = `(${this.demoState.timeLeft}s)`;

      if (remainingMs <= 0) {
        clearInterval(this.demoState.timer);
        this.demoState.timer = null;
        if (this.demoState.stepIndex < this.demoSteps.length - 1) {
          this.nextDemoStep();
        } else {
          this.exitDemo();
        }
      }
    }, intervalMs);
  }

  updateDemoCountdownUI() {
    const pauseEl = document.getElementById('demo-pause-icon');
    if (pauseEl) pauseEl.textContent = this.demoState.isPaused ? '▶ Play' : '⏸ Pause';

    const countdownEl = document.getElementById('demo-timer-countdown');
    if (countdownEl) countdownEl.textContent = `(${this.demoState.timeLeft}s)`;
  }

  prevDemoStep() {
    if (!this.demoState || !this.demoState.active) return;
    if (this.demoState.stepIndex > 0) {
      this.demoState.stepIndex--;
      this.renderDemoStep();
    }
  }

  nextDemoStep() {
    if (!this.demoState || !this.demoState.active) return;
    if (this.demoState.stepIndex < this.demoSteps.length - 1) {
      this.demoState.stepIndex++;
      this.renderDemoStep();
    } else {
      this.exitDemo();
    }
  }

  toggleDemoPause() {
    if (!this.demoState || !this.demoState.active) return;
    this.demoState.isPaused = !this.demoState.isPaused;
    this.updateDemoCountdownUI();
    if (!this.demoState.isPaused && !this.demoState.timer) {
      this.startDemoCountdown();
    }
  }

  exitDemo() {
    if (this.demoState) {
      if (this.demoState.timer) {
        clearInterval(this.demoState.timer);
        this.demoState.timer = null;
      }
      this.demoState.active = false;
    }
    const toast = document.getElementById('demo-guide-toast');
    if (toast) toast.classList.remove('visible');
  }
}

// Instantiate on DOM load
window.addEventListener('DOMContentLoaded', () => {
  window.app = new StatefluxApp();
});
