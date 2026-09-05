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

// content is a DOM node (element or DocumentFragment), never a markup string.
function openModal(content) {
    const modal = document.getElementById('modal');
    document.getElementById('modal-body').replaceChildren(content);
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
        syncIcon.textContent = '\u21BB'; // Rotating arrow
    } else if (data.syncError) {
        syncIcon.classList.add('error');
        syncIcon.textContent = '\u26A0'; // Warning
    } else {
        syncIcon.classList.add('success');
        syncIcon.textContent = '\u2601'; // Cloud
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
        container.replaceChildren(loadingMessage('No data'));
        return;
    }

    const max = Math.max(...entries.map(e => e[1]));

    container.replaceChildren(...entries.map(([label, value]) =>
        el('div', { class: 'chart-bar' }, [
            el('span', { class: 'chart-bar-label', title: label, text: label }),
            el('div', { class: 'chart-bar-track' }, [
                el('div', { class: 'chart-bar-fill', style: { width: `${(value / max) * 100}%` } })
            ]),
            el('span', { class: 'chart-bar-value', text: value })
        ])
    ));
}

async function renderVaults() {
    try {
        const response = await fetch('/api/vaults');
        const data = await response.json();

        const container = document.getElementById('chart-vaults');

        if (!data.vaults || data.vaults.length === 0) {
            container.replaceChildren(loadingMessage('No vaults configured'));
            return;
        }

        container.replaceChildren(...data.vaults.map(v => {
            const projects = v.projects || [];

            const projectsRow = projects.length > 0
                ? el('div', { class: 'vault-projects' }, [
                    ...projects.slice(0, 3).map(p =>
                        el('span', { class: 'vault-project', text: `→ ${p}` })
                    ),
                    projects.length > 3
                        ? el('span', { class: 'vault-project-more', text: `+${projects.length - 3} more` })
                        : null
                ])
                : el('div', { class: 'vault-projects' }, [
                    el('span', { class: 'vault-project-empty', text: 'No projects assigned' })
                ]);

            const item = el('div', {
                class: 'vault-item',
                dataset: { vaultId: v.id }
            }, [
                el('div', { class: 'vault-header' }, [
                    el('span', { class: 'vault-name' }, [
                        el('span', { class: 'vault-icon', text: '~' }),
                        ' ' + (v.name || v.id.slice(0, 8))
                    ]),
                    v.isDefault ? el('span', { class: 'vault-badge default', text: 'default' }) : null
                ]),
                el('div', { class: 'vault-stats' }, [
                    el('span', { class: 'vault-count', text: v.itemCount }),
                    el('span', { class: 'vault-count-label', text: 'items' })
                ]),
                projectsRow
            ]);

            if (v.isDefault) item.classList.add('default');

            // Click filters the memories view by the vault's first project
            item.addEventListener('click', () => {
                if (projects.length > 0) {
                    document.getElementById('filter-project').value = projects[0];
                    showView('memories');
                    loadObservations();
                }
            });

            return item;
        }));
    } catch (e) {
        console.error('Failed to load vaults:', e);
        const container = document.getElementById('chart-vaults');
        if (container) {
            container.replaceChildren(loadingMessage('Failed to load vaults'));
        }
    }
}

function renderObservations(obs) {
    const container = document.getElementById('memories-list');

    if (!obs || obs.length === 0) {
        container.replaceChildren(loadingMessage('No memories found'));
        return;
    }

    container.replaceChildren(...obs.map(o => {
        const typeBadge = el('span', { class: 'memory-badge', text: o.type });
        addClassToken(typeBadge, 'type-', o.type);

        const card = el('div', {
            class: 'memory-card',
            dataset: { id: o.id }
        }, [
            el('div', { class: 'memory-header' }, [
                el('span', { class: 'memory-title', text: o.title }),
                el('div', { class: 'memory-meta' }, [
                    typeBadge,
                    o.project ? el('span', { class: 'memory-badge', text: o.project }) : null,
                    o.classification ? el('span', { class: 'memory-badge', text: o.classification }) : null,
                    o.score ? el('span', { class: 'memory-badge', text: `~${(o.score * 100).toFixed(0)}%` }) : null
                ])
            ]),
            el('p', { class: 'memory-summary', text: truncate(o.summary, 200) }),
            el('div', { class: 'memory-footer' }, [
                el('div', { class: 'memory-tags' },
                    (o.tags || []).map(t => el('span', { class: 'tag', text: `#${t}` }))
                ),
                el('span', { class: 'memory-date', text: formatDate(o.createdAt) })
            ])
        ]);

        if (o.starred) card.classList.add('starred');

        card.addEventListener('click', () => loadObservationDetail(card.dataset.id));

        return card;
    }));
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
        container.replaceChildren(
            el('span', { class: 'pagination-info', text: `${pagination.total} memories` })
        );
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

    const pageBtn = (label, targetPage, disabled, active) => {
        const btn = el('button', {
            class: 'page-btn',
            text: label,
            disabled: !!disabled,
            dataset: { page: String(targetPage) }
        });
        if (active) btn.classList.add('active');
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
        return btn;
    };

    const pageButtons = [];
    for (let i = startPage; i <= endPage; i++) {
        pageButtons.push(pageBtn(String(i), i, false, i === page));
    }

    container.replaceChildren(
        pageBtn('«', 1, page === 1, false),
        pageBtn('‹', page - 1, !hasPrev, false),
        ...pageButtons,
        pageBtn('›', page + 1, !hasNext, false),
        pageBtn('»', totalPages, page === totalPages, false),
        el('span', { class: 'pagination-info', text: `${total} memories` })
    );
}

function renderObservationDetail(obs) {
    const facts = obs.facts || [];
    const concepts = obs.concepts || [];
    const files = obs.files || [];

    const section = (heading, body) =>
        el('div', { class: 'detail-section' }, [el('h4', { text: heading }), body]);

    const classificationSelect = el('select', { id: 'detail-classification' },
        [
            ['', 'None'],
            ['public', 'Public'],
            ['team', 'Team'],
            ['private', 'Private'],
            ['sensitive', 'Sensitive']
        ].map(([value, label]) => el('option', {
            value,
            text: label,
            selected: (obs.classification || '') === value
        }))
    );

    const newTagInput = el('input', {
        type: 'text',
        id: 'new-tag-input',
        placeholder: 'Add tag...'
    });

    const starBtn = el('button', {
        class: 'detail-btn',
        id: 'btn-star',
        text: obs.starred ? '★ Starred' : '☆ Star'
    });
    if (obs.starred) starBtn.classList.add('starred');

    const archiveBtn = el('button', {
        class: 'detail-btn',
        id: 'btn-archive',
        text: obs.archived ? 'Unarchive' : 'Archive'
    });
    const saveBtn = el('button', { class: 'detail-btn primary', id: 'btn-save', text: 'Save Changes' });
    const deleteBtn = el('button', { class: 'detail-btn danger', id: 'btn-delete', text: 'Delete' });

    const meta = el('small', { style: { color: 'var(--text-secondary)' } }, [
        `ID: ${obs.id}`, el('br'),
        `Source: ${obs.source || 'sinesync'}`, el('br'),
        `Project: ${obs.project || 'none'}`, el('br'),
        `Created: ${formatDate(obs.createdAt)}`, el('br'),
        `Updated: ${formatDate(obs.updatedAt)}`
    ]);

    const content = frag([
        el('div', { class: 'detail-header' }, [
            el('h2', { class: 'detail-title', text: obs.title }),
            el('p', { class: 'detail-summary', text: obs.summary })
        ]),

        section('Tags', el('div', { class: 'detail-tags', id: 'detail-tags' }, [
            ...(obs.tags || []).map(t => el('span', { class: 'tag', text: `#${t}` })),
            newTagInput
        ])),

        section('Classification', classificationSelect),

        obs.details ? section('Details', el('p', { text: obs.details })) : null,

        facts.length > 0
            ? section('Facts', el('ul', {}, facts.map(f => el('li', { text: f }))))
            : null,

        concepts.length > 0
            ? section('Concepts', el('div', {}, concepts.flatMap((c, i) => [
                i > 0 ? ' ' : null,
                el('span', { class: 'tag', text: c })
            ])))
            : null,

        files.length > 0
            ? section('Files', el('ul', {}, files.map(f =>
                el('li', {}, [el('code', { text: f })])
            )))
            : null,

        el('div', { class: 'detail-actions' }, [starBtn, archiveBtn, saveBtn, deleteBtn]),

        el('div', { class: 'detail-section', style: { marginTop: '1rem' } }, [meta])
    ]);

    openModal(content);

    // Event handlers
    starBtn.addEventListener('click', async () => {
        await updateObservation(obs.id, { starred: !obs.starred });
        loadObservationDetail(obs.id);
        loadStats();
    });

    archiveBtn.addEventListener('click', async () => {
        await updateObservation(obs.id, { archived: !obs.archived });
        closeModal();
        loadObservations();
        loadStats();
    });

    saveBtn.addEventListener('click', async () => {
        const newTag = newTagInput.value.trim();
        let tags = obs.tags || [];
        if (newTag && !tags.includes(newTag)) {
            tags = [...tags, newTag];
        }

        await updateObservation(obs.id, {
            tags,
            classification: classificationSelect.value || null
        });

        loadObservationDetail(obs.id);
        loadStats();
    });

    deleteBtn.addEventListener('click', async () => {
        if (confirm('Delete this memory? This will remove it from all synced devices and cannot be undone.')) {
            await fetch(`/api/observations/${obs.id}`, { method: 'DELETE' });
            closeModal();
            loadObservations();
            loadStats();
        }
    });

    newTagInput.addEventListener('keypress', async e => {
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
        container.replaceChildren(loadingMessage('No projects found'));
        return;
    }

    container.replaceChildren(...projects.map(p => {
        const card = el('div', {
            class: 'project-card',
            dataset: { project: p.name }
        }, [
            el('div', { class: 'project-name', text: p.name }),
            el('div', { class: 'project-count', text: p.count }),
            p.vault ? el('div', { class: 'project-vault', text: `→ ${p.vault}` }) : null
        ]);

        card.addEventListener('click', () => {
            document.getElementById('filter-project').value = card.dataset.project;
            showView('memories');
            loadObservations();
        });

        return card;
    }));
}

function renderTags(tags) {
    const container = document.getElementById('tags-cloud');

    if (!tags || tags.length === 0) {
        container.replaceChildren(
            loadingMessage('No tags found. Add tags to memories to see them here.')
        );
        return;
    }

    container.replaceChildren(...tags.map(t => {
        const item = el('div', {
            class: 'tag-item',
            dataset: { tag: t.name }
        }, [
            el('span', { text: `#${t.name}` }),
            el('span', { class: 'tag-count', text: t.count })
        ]);

        item.addEventListener('click', () => {
            showView('memories');
            // Would need to add tag filter support
        });

        return item;
    }));
}

function updateFilters() {
    // Update project filter options
    const projectSelect = document.getElementById('filter-project');
    const projects = [...new Set(observations.map(o => o.project).filter(Boolean))];

    const currentProject = projectSelect.value;
    projectSelect.replaceChildren(
        el('option', { value: '', text: 'All Projects' }),
        ...projects.map(p => el('option', { value: p, text: p, selected: p === currentProject }))
    );

    // Update type filter options
    const typeSelect = document.getElementById('filter-type');
    const types = [...new Set(observations.map(o => o.type).filter(Boolean))];

    const currentType = typeSelect.value;
    typeSelect.replaceChildren(
        el('option', { value: '', text: 'All Types' }),
        ...types.map(t => el('option', { value: t, text: t, selected: t === currentType }))
    );
}

// Utilities
// DOM builder. `opts` keys: class -> className, text -> textContent,
// dataset/style -> Object.assign, anything else -> a property on the element.
// Every value coming from the API therefore lands in textContent or a
// property, never in parsed markup.
function el(tag, opts = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(opts)) {
        if (value === undefined || value === null) continue;
        switch (key) {
            case 'class': node.className = value; break;
            case 'text': node.textContent = value; break;
            case 'dataset': Object.assign(node.dataset, value); break;
            case 'style': Object.assign(node.style, value); break;
            default: node[key] = value;
        }
    }
    for (const child of (Array.isArray(children) ? children : [children])) {
        if (child === undefined || child === null || child === false) continue;
        node.append(child); // strings append as text nodes
    }
    return node;
}

function frag(children) {
    const f = document.createDocumentFragment();
    for (const child of children) {
        if (child === undefined || child === null || child === false) continue;
        f.append(child);
    }
    return f;
}

function loadingMessage(text) {
    return el('p', { class: 'loading', text });
}

// Adds `prefix + value` as a class only when value is a bare token, so an
// API-supplied value can neither throw in classList nor smuggle extra classes.
function addClassToken(node, prefix, value) {
    if (typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value)) {
        node.classList.add(prefix + value);
    }
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
