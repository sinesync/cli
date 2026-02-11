// sine~sync Dashboard

// State
let currentView = 'overview';
let observations = [];
let stats = {};
let pagination = { page: 1, limit: 50, total: 0, totalPages: 0 };
let currentSearch = '';

// Date range state (persists across tab switches)
let dateRange = { from: null, to: null };

// Cache for analytics data to avoid refetching on tab switch
let analyticsCache = {};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initSineWave();
    initNavigation();
    initDateRange();
    initModal();
    initSearch();
    initSync();
    initHelpTooltips();
    loadStats();
    loadSyncStatus();
    loadObservations();
});

// Sine wave animation in header (matches website SineWave component)
function initSineWave() {
    const canvas = document.getElementById('sine-canvas');
    const ctx = canvas.getContext('2d');

    function resize() {
        const dpr = window.devicePixelRatio || 1;
        canvas.width = canvas.offsetWidth * dpr;
        canvas.height = canvas.offsetHeight * dpr;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    resize();
    window.addEventListener('resize', resize);

    let time = 0;

    const rainbowColors = [
        '#ff0080', '#ff0040', '#ff8000', '#ffff00',
        '#00ff80', '#00d4ff', '#0080ff', '#8000ff', '#ff0080'
    ];

    function draw() {
        const w = canvas.offsetWidth;
        const h = canvas.offsetHeight;
        ctx.clearRect(0, 0, w, h);

        const amplitude = h * 0.15;
        const frequency = 0.008;
        const speed = 0.02;
        const yOffset = h - amplitude;

        // Rainbow gradient with flowing color shift
        const gradient = ctx.createLinearGradient(0, 0, w, 0);
        const colorShift = (time * 0.002) % rainbowColors.length;
        for (let i = 0; i < rainbowColors.length; i++) {
            const colorIndex = Math.floor((i + colorShift) % rainbowColors.length);
            gradient.addColorStop(i / (rainbowColors.length - 1), rainbowColors[colorIndex]);
        }

        // Draw sine wave path
        ctx.beginPath();
        for (let x = 0; x <= w; x += 2) {
            const y = yOffset + Math.sin(x * frequency + time * speed) * amplitude;
            if (x === 0) {
                ctx.moveTo(x, y);
            } else {
                ctx.lineTo(x, y);
            }
        }

        ctx.strokeStyle = gradient;
        ctx.lineWidth = 5;
        ctx.lineCap = 'round';

        // Multi-layer glow
        ctx.shadowBlur = 40;
        ctx.shadowColor = 'rgba(255, 0, 128, 0.8)';
        ctx.stroke();

        ctx.shadowBlur = 80;
        ctx.shadowColor = 'rgba(0, 212, 255, 0.4)';
        ctx.stroke();

        time += 1;
        requestAnimationFrame(draw);
    }

    draw();
}

// Date Range Picker
function initDateRange() {
    // Default: 90 days
    setDatePreset(90);

    // Preset buttons
    document.querySelectorAll('.preset-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const days = parseInt(btn.dataset.days);
            document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            setDatePreset(days);
            onDateRangeChanged();
        });
    });

    // Custom date inputs (both use local time via T00:00:00/T23:59:59)
    document.getElementById('date-from').addEventListener('change', () => {
        document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
        const fromVal = document.getElementById('date-from').value;
        const toVal = document.getElementById('date-to').value;
        dateRange.from = fromVal ? Math.floor(new Date(fromVal + 'T00:00:00').getTime() / 1000) : null;
        dateRange.to = toVal ? Math.floor(new Date(toVal + 'T23:59:59').getTime() / 1000) : null;
        onDateRangeChanged();
    });
    document.getElementById('date-to').addEventListener('change', () => {
        document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
        const fromVal = document.getElementById('date-from').value;
        const toVal = document.getElementById('date-to').value;
        dateRange.from = fromVal ? Math.floor(new Date(fromVal + 'T00:00:00').getTime() / 1000) : null;
        dateRange.to = toVal ? Math.floor(new Date(toVal + 'T23:59:59').getTime() / 1000) : null;
        onDateRangeChanged();
    });
}

function localDateStr(d) {
    return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}

function setDatePreset(days) {
    const now = new Date();
    if (days === 0) {
        dateRange.from = null;
        dateRange.to = null;
        document.getElementById('date-from').value = '';
        document.getElementById('date-to').value = '';
    } else {
        const fromDate = new Date(now.getTime() - days * 86400000);
        dateRange.from = Math.floor(fromDate.getTime() / 1000);
        dateRange.to = Math.floor(now.getTime() / 1000);
        document.getElementById('date-from').value = localDateStr(fromDate);
        document.getElementById('date-to').value = localDateStr(now);
    }
}

function onDateRangeChanged() {
    analyticsCache = {}; // Clear cache
    loadCurrentView();
}

function getDateParams() {
    const params = new URLSearchParams();
    if (dateRange.from) params.set('from', dateRange.from);
    if (dateRange.to) params.set('to', dateRange.to);
    return params;
}

// Navigation
function initNavigation() {
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const view = btn.dataset.view;
            showView(view);
        });
    });
}

function showView(view) {
    currentView = view;

    // Update nav buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.view === view);
    });

    // Show view
    document.querySelectorAll('.view').forEach(v => {
        v.classList.toggle('active', v.id === `view-${view}`);
    });

    // Show/hide date range bar for analytics views
    const analyticsViews = ['activity', 'sessions', 'codebase', 'insights'];
    const dateBar = document.getElementById('date-range-bar');
    if (dateBar) {
        dateBar.style.display = analyticsViews.includes(view) ? '' : 'none';
    }

    loadCurrentView();
}

function loadCurrentView() {
    switch (currentView) {
        case 'projects': loadProjects(); break;
        case 'tags': loadTags(); break;
        case 'memories': loadObservations(); break;
        case 'activity': loadActivityTab(); break;
        case 'sessions': loadSessionsTab(); break;
        case 'codebase': loadCodebaseTab(); break;
        case 'insights': loadInsightsTab(); break;
    }
}

// Modal
function initModal() {
    const modal = document.getElementById('modal');
    const backdrop = modal.querySelector('.modal-backdrop');
    const closeBtn = modal.querySelector('.modal-close');

    backdrop.addEventListener('click', closeModal);
    closeBtn.addEventListener('click', closeModal);

    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') closeModal();
    });
}

function openModal(content) {
    const modal = document.getElementById('modal');
    document.getElementById('modal-body').innerHTML = content;
    modal.classList.remove('hidden');
}

function closeModal() {
    document.getElementById('modal').classList.add('hidden');
}

// Sync
function initSync() {
    const syncBtn = document.getElementById('sync-now-btn');
    if (syncBtn) {
        syncBtn.addEventListener('click', triggerSync);
    }
    // Auto-refresh sync status
    setInterval(() => {
        loadSyncStatus().then(() => {
            // Adjust polling based on activity (handled in loadSyncStatus)
        });
    }, 5000); // Check every 5 seconds
}

async function loadSyncStatus() {
    try {
        const response = await fetch('/api/sync');
        const data = await response.json();
        renderSyncStatus(data);
    } catch (e) {
        console.error('Failed to load sync status:', e);
    }
}

async function triggerSync() {
    const syncBtn = document.getElementById('sync-now-btn');
    syncBtn.disabled = true;

    try {
        await fetch('/api/sync', { method: 'POST' });
        // Poll for status updates
        setTimeout(loadSyncStatus, 1000);
        setTimeout(loadSyncStatus, 3000);
        setTimeout(loadSyncStatus, 5000);
    } catch (e) {
        console.error('Failed to trigger sync:', e);
    } finally {
        setTimeout(() => { syncBtn.disabled = false; }, 2000);
    }
}

function renderSyncStatus(data) {
    const syncIcon = document.getElementById('sync-icon');
    const syncLocal = document.getElementById('sync-local');
    const syncCount = document.getElementById('sync-count');
    const syncLast = document.getElementById('sync-last');
    const syncProgress = document.getElementById('sync-progress');
    const syncError = document.getElementById('sync-error');

    // If any required element is missing, skip updating sync status UI
    if (!syncIcon || !syncCount || !syncLast || !syncError) {
        return;
    }

    // Update icon state
    syncIcon.classList.remove('syncing', 'error', 'success');
    if (data.syncing || (data.backfill && data.backfill.running)) {
        syncIcon.classList.add('syncing');
        syncIcon.innerHTML = '&#8635;'; // Rotating arrow
    } else if (data.syncError) {
        syncIcon.classList.add('error');
        syncIcon.innerHTML = '&#9888;'; // Warning
    } else {
        syncIcon.classList.add('success');
        syncIcon.innerHTML = '&#9729;'; // Cloud
    }

    // Update stats
    if (syncLocal) {
        syncLocal.textContent = data.localCount || 0;
    }
    syncCount.textContent = data.syncedCount || 0;
    syncLast.textContent = data.lastSync ? formatDate(data.lastSync) : '—';

    // Show backfill or sync progress
    if (syncProgress) {
        if (data.backfill && data.backfill.running) {
            const pct = data.backfill.total > 0 ? Math.round(100 * data.backfill.progress / data.backfill.total) : 0;
            syncProgress.textContent = `Embedding: ${data.backfill.progress}/${data.backfill.total} (${pct}%)`;
            syncProgress.classList.remove('hidden');
        } else if (data.syncing) {
            syncProgress.textContent = 'Syncing...';
            syncProgress.classList.remove('hidden');
        } else if (data.claudeMem && data.claudeMem.embeddingBacklog > 0) {
            syncProgress.textContent = `${data.claudeMem.embeddingBacklog} pending embeddings`;
            syncProgress.classList.remove('hidden');
        } else {
            syncProgress.classList.add('hidden');
        }
    }

    // Show/hide error
    if (data.syncError) {
        syncError.textContent = data.syncError;
        syncError.classList.remove('hidden');
    } else {
        syncError.classList.add('hidden');
    }
}

// Help Tooltips (replace unreliable native title attributes)
function initHelpTooltips() {
    const tt = document.getElementById('d3-tooltip');
    if (!tt) return;

    document.addEventListener('mouseenter', e => {
        const help = e.target.closest('.chart-help');
        if (!help) return;
        const text = help.getAttribute('title') || help.dataset.help;
        if (!text) return;
        // Stash and remove title so native tooltip doesn't also show
        if (help.getAttribute('title')) {
            help.dataset.help = text;
            help.removeAttribute('title');
        }
        tt.textContent = text;
        tt.style.opacity = '1';
        const rect = help.getBoundingClientRect();
        tt.style.left = (rect.left + window.scrollX + rect.width / 2) + 'px';
        tt.style.top = (rect.bottom + window.scrollY + 6) + 'px';
    }, true);

    document.addEventListener('mouseleave', e => {
        if (e.target.closest('.chart-help')) {
            tt.style.opacity = '0';
        }
    }, true);
}

// Search
function initSearch() {
    const input = document.getElementById('search-input');
    const btn = document.getElementById('search-btn');

    btn.addEventListener('click', () => doSearch(input.value));
    input.addEventListener('keypress', e => {
        if (e.key === 'Enter') doSearch(input.value);
    });

    // Filters - reset to page 1 when changed
    document.getElementById('filter-project').addEventListener('change', () => loadObservations(1));
    document.getElementById('filter-type').addEventListener('change', () => loadObservations(1));
    document.getElementById('filter-classification').addEventListener('change', () => loadObservations(1));
    document.getElementById('filter-starred').addEventListener('change', () => loadObservations(1));
}

async function doSearch(query, page = 1) {
    currentSearch = query.trim();

    if (!currentSearch) {
        loadObservations();
        return;
    }

    const params = new URLSearchParams();
    params.set('q', currentSearch);
    params.set('page', page);
    params.set('limit', pagination.limit);

    try {
        const response = await fetch(`/api/search?${params}`);
        const data = await response.json();
        observations = data.observations;
        pagination = {
            page: data.page,
            limit: data.limit,
            total: data.total,
            totalPages: data.totalPages,
            hasNext: data.hasNext,
            hasPrev: data.hasPrev
        };
        renderObservations(observations);
        renderPagination();
    } catch (e) {
        console.error('Failed to search:', e);
    }
}

// === Analytics fetch helpers ===

async function fetchAnalytics(endpoint) {
    const cacheKey = endpoint + '|' + dateRange.from + '|' + dateRange.to;
    if (analyticsCache[cacheKey]) return analyticsCache[cacheKey];

    const params = getDateParams();
    const url = `/api/analytics/${endpoint}${params.toString() ? '?' + params : ''}`;
    try {
        const response = await fetch(url);
        const data = await response.json();
        analyticsCache[cacheKey] = data;
        return data;
    } catch (e) {
        console.error(`Failed to load analytics/${endpoint}:`, e);
        return null;
    }
}

// === Tab Loaders ===

async function loadActivityTab() {
    const [heatmap, byHour, typeTrend] = await Promise.all([
        fetchAnalytics('activity-heatmap'),
        fetchAnalytics('activity-by-hour'),
        fetchAnalytics('type-trend')
    ]);

    SineCharts.renderHeatmap('#chart-activity-heatmap', heatmap ? heatmap.days : []);
    SineCharts.renderStackedBarByHour('#chart-activity-by-hour', byHour ? byHour.hours : []);
    SineCharts.renderStackedArea('#chart-type-trend', typeTrend ? typeTrend.series : []);
}

let sessionData = null; // Shared between session charts
async function loadSessionsTab() {
    const data = await fetchAnalytics('sessions');
    sessionData = data ? data.sessions : [];

    SineCharts.renderSessionTimeline('#chart-session-timeline', sessionData);
    SineCharts.renderHistogram('#chart-session-histogram', sessionData);
    SineCharts.renderScatter('#chart-prompt-scatter', sessionData);
}

async function loadCodebaseTab() {
    const [hotspots, breakdown, concepts] = await Promise.all([
        fetchAnalytics('file-hotspots'),
        fetchAnalytics('project-breakdown'),
        fetchAnalytics('concepts')
    ]);

    SineCharts.renderTreemap('#chart-file-treemap', hotspots ? hotspots.files : []);
    SineCharts.renderGroupedBar('#chart-project-breakdown', breakdown ? breakdown.projects : []);
    SineCharts.renderBubbleChart('#chart-concept-cloud', concepts ? concepts.concepts : []);
}

async function loadInsightsTab() {
    const [summary, bugfixRatio, devices] = await Promise.all([
        fetchAnalytics('summary'),
        fetchAnalytics('bugfix-ratio'),
        fetchAnalytics('devices')
    ]);

    if (summary) renderMetricCards(summary);
    SineCharts.renderBugfixTrend('#chart-bugfix-trend', bugfixRatio ? bugfixRatio.series : []);
    SineCharts.renderDeviceChart('#chart-devices', devices || { series: [], devices: [] });
}

function renderMetricCards(summary) {
    const cards = [
        { id: 'metric-obs-per-day', data: summary.observationsPerDay, format: v => v.toFixed(1), color: '#00d4ff' },
        { id: 'metric-session-duration', data: summary.avgSessionDuration, format: v => v.toFixed(0) + 'm', color: '#9d4edd' },
        { id: 'metric-bugfix-ratio', data: summary.bugfixRatio, format: v => (v * 100).toFixed(0) + '%', color: '#ff4444' },
        { id: 'metric-files-per-day', data: summary.uniqueFilesPerDay, format: v => v.toFixed(1), color: '#00ff88' }
    ];

    cards.forEach(({ id, data, format, color }) => {
        const card = document.getElementById(id);
        if (!card || !data) return;

        card.querySelector('.metric-value').textContent = format(data.current);

        const deltaEl = card.querySelector('.metric-delta');
        const delta = data.delta;
        if (delta > 0) {
            deltaEl.textContent = '+' + (typeof delta === 'number' && delta < 1 ? delta.toFixed(2) : delta.toFixed(1));
            deltaEl.className = 'metric-delta positive';
        } else if (delta < 0) {
            deltaEl.textContent = (typeof delta === 'number' && Math.abs(delta) < 1 ? delta.toFixed(2) : delta.toFixed(1));
            deltaEl.className = 'metric-delta negative';
        } else {
            deltaEl.textContent = '0';
            deltaEl.className = 'metric-delta neutral';
        }

        SineCharts.renderSparkline(
            '#' + id + ' .metric-sparkline',
            data.sparkline,
            color
        );
    });
}

// API calls
async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        stats = await response.json();
        renderStats();
    } catch (e) {
        console.error('Failed to load stats:', e);
    }
}

async function loadObservations(page = 1) {
    const params = new URLSearchParams();

    const project = document.getElementById('filter-project')?.value;
    const type = document.getElementById('filter-type')?.value;
    const classification = document.getElementById('filter-classification')?.value;
    const starred = document.getElementById('filter-starred')?.checked;
    const searchInput = document.getElementById('search-input')?.value?.trim();

    if (project) params.set('project', project);
    if (type) params.set('type', type);
    if (classification) params.set('classification', classification);
    if (starred) params.set('starred', 'true');
    if (searchInput) params.set('search', searchInput);

    params.set('page', page);
    params.set('limit', pagination.limit);

    try {
        const response = await fetch(`/api/observations?${params}`);
        const data = await response.json();
        observations = data.observations;
        pagination = {
            page: data.page,
            limit: data.limit,
            total: data.total,
            totalPages: data.totalPages,
            hasNext: data.hasNext,
            hasPrev: data.hasPrev
        };
        renderObservations(observations);
        renderPagination();
        updateFilters();
    } catch (e) {
        console.error('Failed to load observations:', e);
    }
}

async function loadProjects() {
    try {
        const response = await fetch('/api/projects');
        const projects = await response.json();
        renderProjects(projects);
    } catch (e) {
        console.error('Failed to load projects:', e);
    }
}

async function loadTags() {
    try {
        const response = await fetch('/api/tags');
        const tags = await response.json();
        renderTags(tags);
    } catch (e) {
        console.error('Failed to load tags:', e);
    }
}

async function loadObservationDetail(id) {
    try {
        const response = await fetch(`/api/observations/${id}`);
        const obs = await response.json();
        renderObservationDetail(obs);
    } catch (e) {
        console.error('Failed to load observation:', e);
    }
}

async function updateObservation(id, updates) {
    try {
        const response = await fetch(`/api/observations/${id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(updates)
        });
        return await response.json();
    } catch (e) {
        console.error('Failed to update observation:', e);
    }
}

// Render functions
function renderStats() {
    document.getElementById('stat-total').textContent = stats.totalObservations || 0;
    document.getElementById('stat-starred').textContent = stats.starred || 0;
    document.getElementById('stat-tagged').textContent = stats.tagged || 0;
    document.getElementById('stat-recent').textContent = stats.recentWeek || 0;

    // Type chart
    renderBarChart('chart-types', stats.byType || {});

    // Projects chart
    renderBarChart('chart-projects', stats.byProject || {}, 5);

    // Classification chart
    renderBarChart('chart-classification', stats.byClassification || {});

    // Vaults
    renderVaults();
}

function renderBarChart(containerId, data, limit = 10) {
    const container = document.getElementById(containerId);
    const entries = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, limit);

    if (entries.length === 0) {
        container.innerHTML = '<p class="loading">No data</p>';
        return;
    }

    const max = Math.max(...entries.map(e => e[1]));

    container.innerHTML = entries.map(([label, value]) => `
        <div class="chart-bar">
            <span class="chart-bar-label" title="${label}">${label}</span>
            <div class="chart-bar-track">
                <div class="chart-bar-fill" style="width: ${(value / max) * 100}%"></div>
            </div>
            <span class="chart-bar-value">${value}</span>
        </div>
    `).join('');
}

async function renderVaults() {
    try {
        const response = await fetch('/api/vaults');
        const data = await response.json();

        const container = document.getElementById('chart-vaults');

        if (!data.vaults || data.vaults.length === 0) {
            container.innerHTML = '<p class="loading">No vaults configured</p>';
            return;
        }

        container.innerHTML = data.vaults.map(v => `
            <div class="vault-item ${v.isDefault ? 'default' : ''}" data-vault-id="${v.id}">
                <div class="vault-header">
                    <span class="vault-name">
                        <span class="vault-icon">~</span>
                        ${escapeHtml(v.name || v.id.slice(0, 8))}
                    </span>
                    ${v.isDefault ? '<span class="vault-badge default">default</span>' : ''}
                </div>
                <div class="vault-stats">
                    <span class="vault-count">${v.itemCount}</span>
                    <span class="vault-count-label">items</span>
                </div>
                ${v.projects && v.projects.length > 0 ? `
                    <div class="vault-projects">
                        ${v.projects.slice(0, 3).map(p => `<span class="vault-project">→ ${escapeHtml(p)}</span>`).join('')}
                        ${v.projects.length > 3 ? `<span class="vault-project-more">+${v.projects.length - 3} more</span>` : ''}
                    </div>
                ` : '<div class="vault-projects"><span class="vault-project-empty">No projects assigned</span></div>'}
            </div>
        `).join('');

        // Add click handlers to filter by vault
        container.querySelectorAll('.vault-item').forEach(item => {
            item.addEventListener('click', () => {
                const vaultId = item.dataset.vaultId;
                const vault = data.vaults.find(v => v.id === vaultId);
                if (vault && vault.projects && vault.projects.length > 0) {
                    // Filter to first project in vault
                    document.getElementById('filter-project').value = vault.projects[0];
                    showView('memories');
                    loadObservations();
                }
            });
        });
    } catch (e) {
        console.error('Failed to load vaults:', e);
        const container = document.getElementById('chart-vaults');
        if (container) {
            container.innerHTML = '<p class="loading">Failed to load vaults</p>';
        }
    }
}

function renderObservations(obs) {
    const container = document.getElementById('memories-list');

    if (!obs || obs.length === 0) {
        container.innerHTML = '<p class="loading">No memories found</p>';
        return;
    }

    container.innerHTML = obs.map(o => `
        <div class="memory-card ${o.starred ? 'starred' : ''}" data-id="${o.id}">
            <div class="memory-header">
                <span class="memory-title">${escapeHtml(o.title)}</span>
                <div class="memory-meta">
                    <span class="memory-badge type-${o.type}">${o.type}</span>
                    ${o.project ? `<span class="memory-badge">${o.project}</span>` : ''}
                    ${o.classification ? `<span class="memory-badge">${o.classification}</span>` : ''}
                    ${o.score ? `<span class="memory-badge">~${(o.score * 100).toFixed(0)}%</span>` : ''}
                </div>
            </div>
            <p class="memory-summary">${escapeHtml(truncate(o.summary, 200))}</p>
            <div class="memory-footer">
                <div class="memory-tags">
                    ${(o.tags || []).map(t => `<span class="tag">#${t}</span>`).join('')}
                </div>
                <span class="memory-date">${formatDate(o.createdAt)}</span>
            </div>
        </div>
    `).join('');

    // Add click handlers
    container.querySelectorAll('.memory-card').forEach(card => {
        card.addEventListener('click', () => loadObservationDetail(card.dataset.id));
    });
}

function renderPagination() {
    let container = document.getElementById('pagination');
    if (!container) {
        // Create pagination container if it doesn't exist
        const memoriesList = document.getElementById('memories-list');
        container = document.createElement('div');
        container.id = 'pagination';
        container.className = 'pagination';
        memoriesList.parentNode.insertBefore(container, memoriesList.nextSibling);
    }

    if (pagination.totalPages <= 1) {
        container.innerHTML = `<span class="pagination-info">${pagination.total} memories</span>`;
        return;
    }

    const { page, totalPages, total, hasPrev, hasNext } = pagination;

    // Calculate page range to show
    let startPage = Math.max(1, page - 2);
    let endPage = Math.min(totalPages, page + 2);

    if (endPage - startPage < 4) {
        if (startPage === 1) endPage = Math.min(5, totalPages);
        else startPage = Math.max(1, totalPages - 4);
    }

    let pagesHtml = '';
    for (let i = startPage; i <= endPage; i++) {
        pagesHtml += `<button class="page-btn ${i === page ? 'active' : ''}" data-page="${i}">${i}</button>`;
    }

    container.innerHTML = `
        <button class="page-btn" data-page="1" ${page === 1 ? 'disabled' : ''}>«</button>
        <button class="page-btn" data-page="${page - 1}" ${!hasPrev ? 'disabled' : ''}>‹</button>
        ${pagesHtml}
        <button class="page-btn" data-page="${page + 1}" ${!hasNext ? 'disabled' : ''}>›</button>
        <button class="page-btn" data-page="${totalPages}" ${page === totalPages ? 'disabled' : ''}>»</button>
        <span class="pagination-info">${total} memories</span>
    `;

    // Add click handlers
    container.querySelectorAll('.page-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const newPage = parseInt(btn.dataset.page);
            if (newPage && newPage !== pagination.page) {
                if (currentSearch) {
                    doSearch(currentSearch, newPage);
                } else {
                    loadObservations(newPage);
                }
            }
        });
    });
}

function renderObservationDetail(obs) {
    const tagsHtml = (obs.tags || []).map(t =>
        `<span class="tag">#${t}</span>`
    ).join('');

    const factsHtml = (obs.facts || []).map(f =>
        `<li>${escapeHtml(f)}</li>`
    ).join('');

    const conceptsHtml = (obs.concepts || []).map(c =>
        `<span class="tag">${escapeHtml(c)}</span>`
    ).join(' ');

    const filesHtml = (obs.files || []).map(f =>
        `<li><code>${escapeHtml(f)}</code></li>`
    ).join('');

    const content = `
        <div class="detail-header">
            <h2 class="detail-title">${escapeHtml(obs.title)}</h2>
            <p class="detail-summary">${escapeHtml(obs.summary)}</p>
        </div>

        <div class="detail-section">
            <h4>Tags</h4>
            <div class="detail-tags" id="detail-tags">
                ${tagsHtml}
                <input type="text" id="new-tag-input" placeholder="Add tag...">
            </div>
        </div>

        <div class="detail-section">
            <h4>Classification</h4>
            <select id="detail-classification">
                <option value="" ${!obs.classification ? 'selected' : ''}>None</option>
                <option value="public" ${obs.classification === 'public' ? 'selected' : ''}>Public</option>
                <option value="team" ${obs.classification === 'team' ? 'selected' : ''}>Team</option>
                <option value="private" ${obs.classification === 'private' ? 'selected' : ''}>Private</option>
                <option value="sensitive" ${obs.classification === 'sensitive' ? 'selected' : ''}>Sensitive</option>
            </select>
        </div>

        ${obs.details ? `
            <div class="detail-section">
                <h4>Details</h4>
                <p>${escapeHtml(obs.details)}</p>
            </div>
        ` : ''}

        ${factsHtml ? `
            <div class="detail-section">
                <h4>Facts</h4>
                <ul>${factsHtml}</ul>
            </div>
        ` : ''}

        ${conceptsHtml ? `
            <div class="detail-section">
                <h4>Concepts</h4>
                <div>${conceptsHtml}</div>
            </div>
        ` : ''}

        ${filesHtml ? `
            <div class="detail-section">
                <h4>Files</h4>
                <ul>${filesHtml}</ul>
            </div>
        ` : ''}

        <div class="detail-actions">
            <button class="detail-btn ${obs.starred ? 'starred' : ''}" id="btn-star">
                ${obs.starred ? '★ Starred' : '☆ Star'}
            </button>
            <button class="detail-btn" id="btn-archive">
                ${obs.archived ? 'Unarchive' : 'Archive'}
            </button>
            <button class="detail-btn primary" id="btn-save">Save Changes</button>
            <button class="detail-btn danger" id="btn-delete">Delete</button>
        </div>

        <div class="detail-section" style="margin-top: 1rem;">
            <small style="color: var(--text-secondary)">
                ID: ${obs.id}<br>
                Source: ${obs.source || 'sinesync'}<br>
                Project: ${obs.project || 'none'}<br>
                Created: ${formatDate(obs.createdAt)}<br>
                Updated: ${formatDate(obs.updatedAt)}
            </small>
        </div>
    `;

    openModal(content);

    // Event handlers
    document.getElementById('btn-star').addEventListener('click', async () => {
        await updateObservation(obs.id, { starred: !obs.starred });
        loadObservationDetail(obs.id);
        loadStats();
    });

    document.getElementById('btn-archive').addEventListener('click', async () => {
        await updateObservation(obs.id, { archived: !obs.archived });
        closeModal();
        loadObservations();
        loadStats();
    });

    document.getElementById('btn-save').addEventListener('click', async () => {
        const newTag = document.getElementById('new-tag-input').value.trim();
        let tags = obs.tags || [];
        if (newTag && !tags.includes(newTag)) {
            tags = [...tags, newTag];
        }

        await updateObservation(obs.id, {
            tags,
            classification: document.getElementById('detail-classification').value || null
        });

        loadObservationDetail(obs.id);
        loadStats();
    });

    document.getElementById('btn-delete').addEventListener('click', async () => {
        if (confirm('Delete this memory? This will remove it from all synced devices and cannot be undone.')) {
            await fetch(`/api/observations/${obs.id}`, { method: 'DELETE' });
            closeModal();
            loadObservations();
            loadStats();
        }
    });

    document.getElementById('new-tag-input').addEventListener('keypress', async e => {
        if (e.key === 'Enter') {
            const newTag = e.target.value.trim();
            if (newTag) {
                let tags = obs.tags || [];
                if (!tags.includes(newTag)) {
                    tags = [...tags, newTag];
                    await updateObservation(obs.id, { tags });
                    loadObservationDetail(obs.id);
                }
            }
        }
    });
}

function renderProjects(projects) {
    const container = document.getElementById('projects-list');

    if (!projects || projects.length === 0) {
        container.innerHTML = '<p class="loading">No projects found</p>';
        return;
    }

    container.innerHTML = projects.map(p => `
        <div class="project-card" data-project="${p.name}">
            <div class="project-name">${escapeHtml(p.name)}</div>
            <div class="project-count">${p.count}</div>
            ${p.vault ? `<div class="project-vault">→ ${p.vault}</div>` : ''}
        </div>
    `).join('');

    container.querySelectorAll('.project-card').forEach(card => {
        card.addEventListener('click', () => {
            document.getElementById('filter-project').value = card.dataset.project;
            showView('memories');
            loadObservations();
        });
    });
}

function renderTags(tags) {
    const container = document.getElementById('tags-cloud');

    if (!tags || tags.length === 0) {
        container.innerHTML = '<p class="loading">No tags found. Add tags to memories to see them here.</p>';
        return;
    }

    container.innerHTML = tags.map(t => `
        <div class="tag-item" data-tag="${t.name}">
            <span>#${escapeHtml(t.name)}</span>
            <span class="tag-count">${t.count}</span>
        </div>
    `).join('');

    container.querySelectorAll('.tag-item').forEach(item => {
        item.addEventListener('click', () => {
            showView('memories');
            // Would need to add tag filter support
        });
    });
}

function updateFilters() {
    // Update project filter options
    const projectSelect = document.getElementById('filter-project');
    const projects = [...new Set(observations.map(o => o.project).filter(Boolean))];

    const currentProject = projectSelect.value;
    projectSelect.innerHTML = '<option value="">All Projects</option>' +
        projects.map(p => `<option value="${p}" ${p === currentProject ? 'selected' : ''}>${p}</option>`).join('');

    // Update type filter options
    const typeSelect = document.getElementById('filter-type');
    const types = [...new Set(observations.map(o => o.type).filter(Boolean))];

    const currentType = typeSelect.value;
    typeSelect.innerHTML = '<option value="">All Types</option>' +
        types.map(t => `<option value="${t}" ${t === currentType ? 'selected' : ''}>${t}</option>`).join('');
}

// Utilities
function escapeHtml(str) {
    if (!str) return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function truncate(str, len) {
    if (!str) return '';
    return str.length > len ? str.slice(0, len) + '...' : str;
}

function formatDate(dateStr) {
    if (!dateStr) return '';
    const date = new Date(dateStr);
    const now = new Date();
    const diff = now - date;

    if (diff < 60000) return 'just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    if (diff < 604800000) return `${Math.floor(diff / 86400000)}d ago`;

    return date.toLocaleDateString();
}
