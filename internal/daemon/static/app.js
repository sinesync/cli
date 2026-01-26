// sine~sync Dashboard

// State
let currentView = 'overview';
let observations = [];
let stats = {};
let pagination = { page: 1, limit: 50, total: 0, totalPages: 0 };
let currentSearch = '';

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initSineWave();
    initNavigation();
    initModal();
    initSearch();
    initSync();
    loadStats();
    loadSyncStatus();
    loadObservations();
});

// Sine wave animation in header
function initSineWave() {
    const canvas = document.getElementById('sine-canvas');
    const ctx = canvas.getContext('2d');

    function resize() {
        canvas.width = canvas.offsetWidth;
        canvas.height = canvas.offsetHeight;
    }

    resize();
    window.addEventListener('resize', resize);

    let phase = 0;

    function draw() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        ctx.beginPath();
        ctx.strokeStyle = '#00d4ff';
        ctx.lineWidth = 2;

        for (let x = 0; x < canvas.width; x++) {
            const y = canvas.height / 2 +
                      Math.sin((x / 50) + phase) * 10 +
                      Math.sin((x / 30) + phase * 1.5) * 5;

            if (x === 0) {
                ctx.moveTo(x, y);
            } else {
                ctx.lineTo(x, y);
            }
        }

        ctx.stroke();
        phase += 0.02;
        requestAnimationFrame(draw);
    }

    draw();
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

    // Load view data
    if (view === 'projects') loadProjects();
    if (view === 'tags') loadTags();
    if (view === 'memories') loadObservations();
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
    // Auto-refresh sync status every 30 seconds
    setInterval(loadSyncStatus, 30000);
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
    const syncCount = document.getElementById('sync-count');
    const syncLast = document.getElementById('sync-last');
    const syncError = document.getElementById('sync-error');

    // If any required element is missing, skip updating sync status UI
    if (!syncIcon || !syncCount || !syncLast || !syncError) {
        return;
    }

    // Update icon state
    syncIcon.classList.remove('syncing', 'error', 'success');
    if (data.syncing) {
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
    syncCount.textContent = data.syncedCount || 0;
    syncLast.textContent = data.lastSync ? formatDate(data.lastSync) : '—';

    // Show/hide error
    if (data.syncError) {
        syncError.textContent = data.syncError;
        syncError.classList.remove('hidden');
    } else {
        syncError.classList.add('hidden');
    }
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
        const vaults = await response.json();

        const container = document.getElementById('chart-vaults');

        if (!vaults || vaults.length === 0) {
            container.innerHTML = '<p class="loading">No vaults configured</p>';
            return;
        }

        container.innerHTML = vaults.map(v => `
            <div class="vault-item">
                <span class="vault-name">
                    <span class="vault-icon">~</span>
                    ${v.Name || v.ID}
                </span>
                <span class="vault-backend">${v.Backend?.Type || 'sinesync'}</span>
            </div>
        `).join('');
    } catch (e) {
        console.error('Failed to load vaults:', e);
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
