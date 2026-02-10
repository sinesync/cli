// sine~sync D3.js Charts Module

const SineCharts = (() => {
    // Consistent type color palette
    const TYPE_COLORS = {
        bugfix: '#ff4444',
        feature: '#00ff88',
        decision: '#9d4edd',
        discovery: '#00d4ff',
        change: '#8888aa',
        refactor: '#ffd700'
    };

    const DEFAULT_COLOR = '#8888aa';

    function getTypeColor(type) {
        return TYPE_COLORS[type] || DEFAULT_COLOR;
    }

    function esc(value) {
        if (value === null || value === undefined) return '';
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    // All known types for consistent stacking order
    const TYPE_ORDER = ['feature', 'change', 'discovery', 'decision', 'refactor', 'bugfix'];

    function allTypes(data) {
        const types = new Set();
        data.forEach(d => {
            if (d.byType) Object.keys(d.byType).forEach(t => types.add(t));
        });
        return TYPE_ORDER.filter(t => types.has(t)).concat([...types].filter(t => !TYPE_ORDER.includes(t)));
    }

    const tooltip = () => d3.select('#d3-tooltip');

    function showTooltip(event, html) {
        const tt = tooltip();
        tt.html(html)
            .style('opacity', 1)
            .style('left', (event.pageX + 12) + 'px')
            .style('top', (event.pageY - 10) + 'px');
    }

    function hideTooltip() {
        tooltip().style('opacity', 0);
    }

    function clearChart(selector) {
        d3.select(selector).selectAll('*').remove();
    }

    function emptyState(selector, msg) {
        clearChart(selector);
        d3.select(selector).append('p').attr('class', 'loading').text(msg || 'No data available');
    }

    // === Calendar Heatmap ===
    function renderHeatmap(selector, data) {
        clearChart(selector);
        if (!data || data.length === 0) { emptyState(selector); return; }

        const container = d3.select(selector);
        const width = container.node().clientWidth || 800;
        const leftMargin = 36;

        const maxCount = d3.max(data, d => d.count) || 1;
        const colorScale = d3.scaleSequential(d3.interpolateGreens).domain([0, maxCount]);

        // Parse dates (append T12:00:00 to avoid UTC midnight timezone shift)
        const dateMap = new Map(data.map(d => [d.date, d]));
        const dates = data.map(d => new Date(d.date + 'T12:00:00'));
        const minDate = d3.min(dates);
        const maxDate = d3.max(dates);

        // Generate all days in range
        const allDays = d3.timeDays(
            d3.timeWeek.floor(minDate),
            d3.timeDay.offset(maxDate, 1)
        );

        // Calculate cell size based on actual number of weeks to fill width
        const numWeeks = d3.timeWeek.count(d3.timeWeek.floor(minDate), maxDate) + 1;
        const cellSize = Math.min(18, Math.max(8, Math.floor((width - leftMargin - 10) / numWeeks)));
        const height = cellSize * 7 + 40;

        const svg = container.append('svg')
            .attr('width', width).attr('height', height);

        const g = svg.append('g').attr('transform', `translate(${leftMargin}, 20)`);

        // Day labels
        const dayLabels = ['', 'Mon', '', 'Wed', '', 'Fri', ''];
        g.selectAll('.day-label')
            .data(dayLabels)
            .join('text')
            .attr('class', 'day-label')
            .attr('x', -4)
            .attr('y', (d, i) => i * cellSize + cellSize * 0.75)
            .attr('text-anchor', 'end')
            .attr('font-size', '9px')
            .attr('fill', '#8888aa')
            .text(d => d);

        // Cells
        g.selectAll('.day')
            .data(allDays)
            .join('rect')
            .attr('class', 'day')
            .attr('width', cellSize - 2)
            .attr('height', cellSize - 2)
            .attr('x', d => d3.timeWeek.count(d3.timeWeek.floor(minDate), d) * cellSize)
            .attr('y', d => d.getDay() * cellSize)
            .attr('rx', 2)
            .attr('fill', d => {
                const key = d3.timeFormat('%Y-%m-%d')(d);
                const entry = dateMap.get(key);
                return entry ? colorScale(entry.count) : '#1a1a2e';
            })
            .attr('stroke', '#0a0a1a')
            .attr('stroke-width', 1)
            .on('mouseover', (event, d) => {
                const key = d3.timeFormat('%Y-%m-%d')(d);
                const entry = dateMap.get(key);
                const count = entry ? entry.count : 0;
                let typeBreakdown = '';
                if (entry && entry.byType) {
                    typeBreakdown = Object.entries(entry.byType)
                        .sort((a, b) => b[1] - a[1])
                        .map(([t, c]) => `<span style="color:${getTypeColor(t)}">${esc(t)}: ${c}</span>`)
                        .join('<br>');
                }
                showTooltip(event, `<strong>${esc(key)}</strong><br>${count} observations${typeBreakdown ? '<br>' + typeBreakdown : ''}`);
            })
            .on('mouseout', hideTooltip);

        // Month labels
        const months = d3.timeMonths(d3.timeMonth.floor(minDate), d3.timeMonth.offset(maxDate, 1));
        g.selectAll('.month-label')
            .data(months)
            .join('text')
            .attr('class', 'month-label')
            .attr('x', d => d3.timeWeek.count(d3.timeWeek.floor(minDate), d) * cellSize)
            .attr('y', -4)
            .attr('font-size', '9px')
            .attr('fill', '#8888aa')
            .text(d => d3.timeFormat('%b')(d));
    }

    // === Stacked Bar Chart (Activity by Hour) ===
    function renderStackedBarByHour(selector, data) {
        clearChart(selector);
        if (!data || data.length === 0) { emptyState(selector); return; }

        const container = d3.select(selector);
        const width = container.node().clientWidth || 600;
        const height = 300;
        const margin = { top: 20, right: 20, bottom: 40, left: 50 };

        const svg = container.append('svg')
            .attr('width', width).attr('height', height);
        const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

        const innerW = width - margin.left - margin.right;
        const innerH = height - margin.top - margin.bottom;

        const types = allTypes(data);

        const x = d3.scaleBand().domain(data.map(d => d.hour)).range([0, innerW]).padding(0.15);
        const maxY = d3.max(data, d => d.count) || 1;
        const y = d3.scaleLinear().domain([0, maxY]).nice().range([innerH, 0]);

        // Stack
        const stackData = data.map(d => {
            const row = { hour: d.hour };
            types.forEach(t => { row[t] = (d.byType && d.byType[t]) || 0; });
            return row;
        });

        const stack = d3.stack().keys(types)(stackData);

        g.selectAll('.layer')
            .data(stack)
            .join('g')
            .attr('class', 'layer')
            .attr('fill', d => getTypeColor(d.key))
            .selectAll('rect')
            .data(d => d)
            .join('rect')
            .attr('x', d => x(d.data.hour))
            .attr('y', d => y(d[1]))
            .attr('height', d => y(d[0]) - y(d[1]))
            .attr('width', x.bandwidth())
            .attr('rx', 1)
            .on('mouseover', (event, d) => {
                const hour = d.data.hour;
                const entry = data.find(h => h.hour === hour);
                let html = `<strong>${hour}:00</strong> - ${entry.count} total<br>`;
                if (entry.byType) {
                    html += Object.entries(entry.byType)
                        .sort((a, b) => b[1] - a[1])
                        .map(([t, c]) => `<span style="color:${getTypeColor(t)}">${esc(t)}: ${c}</span>`)
                        .join('<br>');
                }
                showTooltip(event, html);
            })
            .on('mouseout', hideTooltip);

        // Axes
        g.append('g')
            .attr('transform', `translate(0,${innerH})`)
            .call(d3.axisBottom(x).tickValues(d3.range(0, 24, 3)).tickFormat(d => `${d}h`))
            .selectAll('text').attr('fill', '#8888aa');

        g.append('g')
            .call(d3.axisLeft(y).ticks(5))
            .selectAll('text').attr('fill', '#8888aa');

        g.selectAll('.domain, .tick line').attr('stroke', '#2a2a4a');

        // Legend
        const legend = svg.append('g')
            .attr('transform', `translate(${margin.left + 10}, ${margin.top})`);
        types.forEach((t, i) => {
            const lg = legend.append('g').attr('transform', `translate(${i * 80}, 0)`);
            lg.append('rect').attr('width', 10).attr('height', 10).attr('fill', getTypeColor(t)).attr('rx', 2);
            lg.append('text').attr('x', 14).attr('y', 9).attr('font-size', '9px').attr('fill', '#8888aa').text(t);
        });
    }

    // === Stacked Area Chart (Type Trend) ===
    function renderStackedArea(selector, data) {
        clearChart(selector);
        if (!data || data.length === 0) { emptyState(selector); return; }

        const container = d3.select(selector);
        const width = container.node().clientWidth || 600;
        const height = 300;
        const margin = { top: 20, right: 20, bottom: 40, left: 50 };

        const svg = container.append('svg')
            .attr('width', width).attr('height', height);
        const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

        const innerW = width - margin.left - margin.right;
        const innerH = height - margin.top - margin.bottom;

        const types = allTypes(data);
        const stackRows = data.map(d => {
            const row = { period: d.period, startDate: d.startDate };
            types.forEach(t => { row[t] = (d.byType && d.byType[t]) || 0; });
            return row;
        });

        const x = d3.scalePoint()
            .domain(data.map(d => d.period))
            .range([0, innerW]);

        const maxY = d3.max(stackRows, d => types.reduce((sum, t) => sum + d[t], 0)) || 1;
        const y = d3.scaleLinear().domain([0, maxY]).nice().range([innerH, 0]);

        const stack = d3.stack().keys(types)(stackRows);

        const area = d3.area()
            .x(d => x(d.data.period))
            .y0(d => y(d[0]))
            .y1(d => y(d[1]))
            .curve(d3.curveMonotoneX);

        g.selectAll('.area-layer')
            .data(stack)
            .join('path')
            .attr('class', 'area-layer')
            .attr('d', area)
            .attr('fill', d => getTypeColor(d.key))
            .attr('opacity', 0.7);

        // X axis - show every Nth label to avoid overlap
        const tickInterval = Math.max(1, Math.floor(data.length / 8));
        g.append('g')
            .attr('transform', `translate(0,${innerH})`)
            .call(d3.axisBottom(x).tickValues(data.filter((_, i) => i % tickInterval === 0).map(d => d.period)))
            .selectAll('text').attr('fill', '#8888aa').attr('font-size', '8px')
            .attr('transform', 'rotate(-30)').attr('text-anchor', 'end');

        g.append('g')
            .call(d3.axisLeft(y).ticks(5))
            .selectAll('text').attr('fill', '#8888aa');

        g.selectAll('.domain, .tick line').attr('stroke', '#2a2a4a');
    }

    // === Gantt-style Session Timeline (swim lanes by project) ===
    function renderSessionTimeline(selector, sessions) {
        clearChart(selector);
        if (!sessions || sessions.length === 0) { emptyState(selector, 'No session data'); return; }

        const container = d3.select(selector);
        const width = container.node().clientWidth || 800;
        const barHeight = 20;
        const lanePadding = 4;
        const laneGap = 8;
        const margin = { top: 20, right: 20, bottom: 40, left: 130 };
        const innerW = width - margin.left - margin.right;

        // Time scale
        const extents = d3.extent(sessions, d => d.startedAt * 1000);
        const maxEnd = d3.max(sessions, d => {
            if (d.endedAt) return new Date(d.endedAt).getTime();
            return d.startedAt * 1000 + d.durationMinutes * 60000;
        });
        const x = d3.scaleTime()
            .domain([new Date(extents[0]), new Date(maxEnd || extents[1])])
            .range([0, innerW]);

        // Group sessions by project
        const projects = [...new Set(sessions.map(s => s.project || 'unknown'))];
        const projectColor = d3.scaleOrdinal(d3.schemeSet2).domain(projects);

        function getSessionEnd(s) {
            if (s.endedAt) return new Date(s.endedAt).getTime();
            return s.startedAt * 1000 + s.durationMinutes * 60000;
        }

        // One row per session, grouped by project, sorted by time within each group
        const laneLayout = [];
        const projMeta = new Map(); // project name -> { startRow, rowCount }
        let currentRow = 0;

        projects.forEach(proj => {
            const projSessions = sessions
                .filter(s => (s.project || 'unknown') === proj)
                .sort((a, b) => a.startedAt - b.startedAt);

            projMeta.set(proj, { startRow: currentRow, rowCount: projSessions.length });

            projSessions.forEach(s => {
                laneLayout.push({ session: s, project: proj, row: currentRow });
                currentRow++;
            });
        });

        const totalRows = currentRow;
        const height = Math.max(200, totalRows * (barHeight + lanePadding) + margin.top + margin.bottom + laneGap * projects.length);

        const svg = container.append('svg')
            .attr('width', width).attr('height', height);
        const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

        // Compute y position for a given global row, accounting for lane gaps between projects
        function yForRow(row) {
            let y = 0;
            let accumulated = 0;
            for (const proj of projects) {
                const meta = projMeta.get(proj);
                if (row < accumulated + meta.rowCount) {
                    return y + (row - accumulated) * (barHeight + lanePadding);
                }
                y += meta.rowCount * (barHeight + lanePadding) + laneGap;
                accumulated += meta.rowCount;
            }
            return y;
        }

        const chartHeight = yForRow(totalRows - 1) + barHeight;

        // Draw project swim lane backgrounds and labels
        projects.forEach(proj => {
            const meta = projMeta.get(proj);
            const yStart = yForRow(meta.startRow) - 2;
            const yEnd = yForRow(meta.startRow + meta.rowCount - 1) + barHeight + 2;

            // Background band
            g.append('rect')
                .attr('x', -4).attr('y', yStart)
                .attr('width', innerW + 8).attr('height', yEnd - yStart)
                .attr('fill', projectColor(proj)).attr('opacity', 0.04)
                .attr('rx', 3);

            // Label
            g.append('text')
                .attr('x', -8)
                .attr('y', (yStart + yEnd) / 2 + 4)
                .attr('text-anchor', 'end')
                .attr('font-size', '11px')
                .attr('fill', projectColor(proj))
                .attr('font-weight', '600')
                .text(proj.length > 16 ? proj.slice(0, 16) + '...' : proj);
        });

        // Draw session bars
        g.selectAll('.session-bar')
            .data(laneLayout)
            .join('rect')
            .attr('class', 'session-bar')
            .attr('x', d => x(new Date(d.session.startedAt * 1000)))
            .attr('y', d => yForRow(d.row))
            .attr('width', d => {
                const start = d.session.startedAt * 1000;
                const end = getSessionEnd(d.session);
                return Math.max(4, x(new Date(end)) - x(new Date(start)));
            })
            .attr('height', barHeight)
            .attr('fill', d => projectColor(d.project))
            .attr('rx', 3)
            .attr('opacity', 0.8)
            .on('mouseover', (event, d) => {
                const s = d.session;
                showTooltip(event, `
                    <strong>${esc(s.project)}</strong><br>
                    ${s.observationCount} observations, ${s.promptCount} prompts<br>
                    Duration: ${Math.round(s.durationMinutes)}min<br>
                    ${esc(s.summary || '')}
                `);
            })
            .on('mouseout', hideTooltip);

        // Time axis
        g.append('g')
            .attr('transform', `translate(0,${chartHeight + 8})`)
            .call(d3.axisBottom(x).ticks(6).tickFormat(d3.timeFormat('%b %d %H:%M')))
            .selectAll('text').attr('fill', '#8888aa').attr('font-size', '9px');

        g.selectAll('.domain, .tick line').attr('stroke', '#2a2a4a');
    }

    // === Histogram (Session Size Distribution) ===
    function renderHistogram(selector, sessions) {
        clearChart(selector);
        if (!sessions || sessions.length === 0) { emptyState(selector, 'No session data'); return; }

        const container = d3.select(selector);
        const width = container.node().clientWidth || 600;
        const height = 300;
        const margin = { top: 20, right: 20, bottom: 40, left: 50 };

        const svg = container.append('svg')
            .attr('width', width).attr('height', height);
        const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

        const innerW = width - margin.left - margin.right;
        const innerH = height - margin.top - margin.bottom;

        const values = sessions.map(s => s.observationCount);
        const x = d3.scaleLinear()
            .domain([0, d3.max(values) || 10])
            .nice()
            .range([0, innerW]);

        const bins = d3.bin().domain(x.domain()).thresholds(15)(values);

        const y = d3.scaleLinear()
            .domain([0, d3.max(bins, d => d.length)])
            .nice()
            .range([innerH, 0]);

        g.selectAll('.bar')
            .data(bins)
            .join('rect')
            .attr('class', 'bar')
            .attr('x', d => x(d.x0) + 1)
            .attr('y', d => y(d.length))
            .attr('width', d => Math.max(1, x(d.x1) - x(d.x0) - 2))
            .attr('height', d => innerH - y(d.length))
            .attr('fill', '#00d4ff')
            .attr('opacity', 0.7)
            .attr('rx', 1)
            .on('mouseover', (event, d) => {
                showTooltip(event, `${d.x0}-${d.x1} observations: ${d.length} sessions`);
            })
            .on('mouseout', hideTooltip);

        g.append('g')
            .attr('transform', `translate(0,${innerH})`)
            .call(d3.axisBottom(x).ticks(8))
            .selectAll('text').attr('fill', '#8888aa');

        g.append('g')
            .call(d3.axisLeft(y).ticks(5))
            .selectAll('text').attr('fill', '#8888aa');

        g.selectAll('.domain, .tick line').attr('stroke', '#2a2a4a');

        g.append('text')
            .attr('x', innerW / 2).attr('y', innerH + 35)
            .attr('text-anchor', 'middle').attr('fill', '#8888aa').attr('font-size', '11px')
            .text('Observations per session');
    }

    // === Scatter Plot (Prompt Efficiency) ===
    function renderScatter(selector, sessions) {
        clearChart(selector);
        if (!sessions || sessions.length === 0) { emptyState(selector, 'No session data'); return; }

        const container = d3.select(selector);
        const width = container.node().clientWidth || 600;
        const height = 300;
        const margin = { top: 20, right: 20, bottom: 40, left: 50 };

        const svg = container.append('svg')
            .attr('width', width).attr('height', height);
        const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

        const innerW = width - margin.left - margin.right;
        const innerH = height - margin.top - margin.bottom;

        const x = d3.scaleLinear()
            .domain([0, d3.max(sessions, d => d.promptCount) || 10])
            .nice().range([0, innerW]);

        const y = d3.scaleLinear()
            .domain([0, d3.max(sessions, d => d.observationCount) || 10])
            .nice().range([innerH, 0]);

        const sizeScale = d3.scaleSqrt()
            .domain([0, d3.max(sessions, d => d.durationMinutes) || 60])
            .range([3, 15]);

        const projects = [...new Set(sessions.map(s => s.project))];
        const color = d3.scaleOrdinal(d3.schemeSet2).domain(projects);

        g.selectAll('.dot')
            .data(sessions)
            .join('circle')
            .attr('class', 'dot')
            .attr('cx', d => x(d.promptCount))
            .attr('cy', d => y(d.observationCount))
            .attr('r', d => sizeScale(d.durationMinutes))
            .attr('fill', d => color(d.project))
            .attr('opacity', 0.7)
            .attr('stroke', '#0a0a1a')
            .attr('stroke-width', 1)
            .on('mouseover', (event, d) => {
                showTooltip(event, `
                    <strong>${esc(d.project)}</strong><br>
                    ${d.promptCount} prompts, ${d.observationCount} observations<br>
                    Efficiency: ${d.promptCount > 0 ? (d.observationCount / d.promptCount).toFixed(1) : '?'} obs/prompt<br>
                    Duration: ${Math.round(d.durationMinutes)}min
                `);
            })
            .on('mouseout', hideTooltip);

        // Diagonal reference line (1:1 efficiency)
        const diagMax = Math.min(x.domain()[1], y.domain()[1]);
        g.append('line')
            .attr('x1', x(0)).attr('y1', y(0))
            .attr('x2', x(diagMax)).attr('y2', y(diagMax))
            .attr('stroke', '#2a2a4a').attr('stroke-dasharray', '4,4');

        g.append('g')
            .attr('transform', `translate(0,${innerH})`)
            .call(d3.axisBottom(x).ticks(6))
            .selectAll('text').attr('fill', '#8888aa');

        g.append('g')
            .call(d3.axisLeft(y).ticks(6))
            .selectAll('text').attr('fill', '#8888aa');

        g.selectAll('.domain, .tick line').attr('stroke', '#2a2a4a');

        g.append('text')
            .attr('x', innerW / 2).attr('y', innerH + 35)
            .attr('text-anchor', 'middle').attr('fill', '#8888aa').attr('font-size', '11px')
            .text('Prompts');

        g.append('text')
            .attr('transform', 'rotate(-90)')
            .attr('x', -innerH / 2).attr('y', -35)
            .attr('text-anchor', 'middle').attr('fill', '#8888aa').attr('font-size', '11px')
            .text('Observations');
    }

    // === Treemap (File Hotspots) ===
    function renderTreemap(selector, files) {
        clearChart(selector);
        if (!files || files.length === 0) { emptyState(selector, 'No file data'); return; }

        const container = d3.select(selector);
        const width = container.node().clientWidth || 800;
        const height = 400;

        const svg = container.append('svg')
            .attr('width', width).attr('height', height);

        const root = d3.hierarchy({ children: files })
            .sum(d => d.totalCount)
            .sort((a, b) => b.value - a.value);

        d3.treemap()
            .size([width, height])
            .padding(2)
            .round(true)(root);

        const nodes = svg.selectAll('.treemap-node')
            .data(root.leaves())
            .join('g')
            .attr('class', 'treemap-node')
            .attr('transform', d => `translate(${d.x0},${d.y0})`);

        nodes.append('rect')
            .attr('width', d => d.x1 - d.x0)
            .attr('height', d => d.y1 - d.y0)
            .attr('fill', d => getTypeColor(d.data.dominantType))
            .attr('opacity', 0.7)
            .attr('rx', 2)
            .on('mouseover', (event, d) => {
                const data = d.data;
                let typeHtml = '';
                if (data.byType) {
                    typeHtml = Object.entries(data.byType)
                        .sort((a, b) => b[1] - a[1])
                        .map(([t, c]) => `<span style="color:${getTypeColor(t)}">${esc(t)}: ${c}</span>`)
                        .join('<br>');
                }
                showTooltip(event, `
                    <strong>${esc(data.path)}</strong><br>
                    Total: ${data.totalCount} (modified: ${data.modifiedCount}, read: ${data.readCount})<br>
                    ${typeHtml}
                `);
            })
            .on('mouseout', hideTooltip);

        nodes.append('text')
            .attr('x', 4).attr('y', 14)
            .attr('font-size', '10px')
            .attr('fill', '#e0e0f0')
            .text(d => {
                const w = d.x1 - d.x0;
                const name = (d.data.path || '').split(/[\\/]/).pop() || '';
                return w > 50 ? name : '';
            })
            .attr('clip-path', d => {
                const w = d.x1 - d.x0;
                return w > 50 ? null : 'none';
            });
    }

    // === Grouped Bar Chart (Project Comparison) ===
    function renderGroupedBar(selector, projects) {
        clearChart(selector);
        if (!projects || projects.length === 0) { emptyState(selector, 'No project data'); return; }

        const container = d3.select(selector);
        const width = container.node().clientWidth || 600;
        const height = 300;
        const margin = { top: 20, right: 20, bottom: 60, left: 50 };

        const svg = container.append('svg')
            .attr('width', width).attr('height', height);
        const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

        const innerW = width - margin.left - margin.right;
        const innerH = height - margin.top - margin.bottom;

        const topProjects = projects.slice(0, 8);
        const types = allTypes(topProjects);

        const x0 = d3.scaleBand()
            .domain(topProjects.map(p => p.name))
            .range([0, innerW]).padding(0.2);

        const x1 = d3.scaleBand()
            .domain(types)
            .range([0, x0.bandwidth()]).padding(0.05);

        const maxVal = d3.max(topProjects, p =>
            d3.max(types, t => (p.byType && p.byType[t]) || 0)
        ) || 1;

        const y = d3.scaleLinear().domain([0, maxVal]).nice().range([innerH, 0]);

        const projGroups = g.selectAll('.proj-group')
            .data(topProjects)
            .join('g')
            .attr('class', 'proj-group')
            .attr('transform', d => `translate(${x0(d.name)},0)`);

        projGroups.selectAll('rect')
            .data(d => types.map(t => ({ type: t, count: (d.byType && d.byType[t]) || 0, project: d.name })))
            .join('rect')
            .attr('x', d => x1(d.type))
            .attr('y', d => y(d.count))
            .attr('width', x1.bandwidth())
            .attr('height', d => innerH - y(d.count))
            .attr('fill', d => getTypeColor(d.type))
            .attr('rx', 1)
            .on('mouseover', (event, d) => {
                showTooltip(event, `<strong>${esc(d.project)}</strong><br><span style="color:${getTypeColor(d.type)}">${esc(d.type)}: ${d.count}</span>`);
            })
            .on('mouseout', hideTooltip);

        g.append('g')
            .attr('transform', `translate(0,${innerH})`)
            .call(d3.axisBottom(x0))
            .selectAll('text').attr('fill', '#8888aa').attr('font-size', '9px')
            .attr('transform', 'rotate(-30)').attr('text-anchor', 'end');

        g.append('g')
            .call(d3.axisLeft(y).ticks(5))
            .selectAll('text').attr('fill', '#8888aa');

        g.selectAll('.domain, .tick line').attr('stroke', '#2a2a4a');
    }

    // === Packed Circles (Technology Cloud) ===
    function renderBubbleChart(selector, concepts) {
        clearChart(selector);
        if (!concepts || concepts.length === 0) { emptyState(selector, 'No concept data'); return; }

        const container = d3.select(selector);
        const width = container.node().clientWidth || 600;
        const height = 350;

        const svg = container.append('svg')
            .attr('width', width).attr('height', height);

        const root = d3.hierarchy({ children: concepts })
            .sum(d => d.count);

        d3.pack()
            .size([width, height])
            .padding(3)(root);

        const nodes = svg.selectAll('.bubble')
            .data(root.leaves())
            .join('g')
            .attr('class', 'bubble')
            .attr('transform', d => `translate(${d.x},${d.y})`);

        // Determine dominant type for color
        nodes.append('circle')
            .attr('r', d => d.r)
            .attr('fill', d => {
                const byType = d.data.byType || {};
                const dominant = Object.entries(byType).sort((a, b) => b[1] - a[1])[0];
                return dominant ? getTypeColor(dominant[0]) : DEFAULT_COLOR;
            })
            .attr('opacity', 0.65)
            .attr('stroke', '#0a0a1a')
            .attr('stroke-width', 1)
            .on('mouseover', (event, d) => {
                const data = d.data;
                let typeHtml = '';
                if (data.byType) {
                    typeHtml = Object.entries(data.byType)
                        .sort((a, b) => b[1] - a[1])
                        .map(([t, c]) => `<span style="color:${getTypeColor(t)}">${esc(t)}: ${c}</span>`)
                        .join('<br>');
                }
                showTooltip(event, `
                    <strong>${esc(data.name)}</strong> (${data.count})<br>
                    ${typeHtml}
                    ${data.projects && data.projects.length > 0 ? '<br>Projects: ' + esc(data.projects.join(', ')) : ''}
                `);
            })
            .on('mouseout', hideTooltip);

        nodes.append('text')
            .attr('text-anchor', 'middle')
            .attr('dy', '0.3em')
            .attr('font-size', d => Math.max(8, Math.min(14, d.r / 2.5)) + 'px')
            .attr('fill', '#e0e0f0')
            .text(d => d.r > 20 ? d.data.name : '');
    }

    // === Sparkline ===
    function renderSparkline(selector, data, color) {
        const container = d3.select(selector);
        container.selectAll('*').remove();
        if (!data || data.length === 0) return;

        const width = container.node().clientWidth || 120;
        const height = 30;

        const svg = container.append('svg')
            .attr('width', width).attr('height', height);

        const x = d3.scaleLinear().domain([0, data.length - 1]).range([2, width - 2]);
        const y = d3.scaleLinear().domain([0, d3.max(data) || 1]).range([height - 2, 2]);

        const line = d3.line()
            .x((d, i) => x(i))
            .y(d => y(d))
            .curve(d3.curveMonotoneX);

        svg.append('path')
            .datum(data)
            .attr('d', line)
            .attr('fill', 'none')
            .attr('stroke', color || '#00d4ff')
            .attr('stroke-width', 1.5);
    }

    // === Line Chart with Healthy Zone (Bugfix Ratio Trend) ===
    function renderBugfixTrend(selector, data) {
        clearChart(selector);
        if (!data || data.length === 0) { emptyState(selector); return; }

        const container = d3.select(selector);
        const width = container.node().clientWidth || 600;
        const height = 300;
        const margin = { top: 20, right: 20, bottom: 40, left: 50 };

        const svg = container.append('svg')
            .attr('width', width).attr('height', height);
        const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

        const innerW = width - margin.left - margin.right;
        const innerH = height - margin.top - margin.bottom;

        const x = d3.scalePoint()
            .domain(data.map(d => d.period))
            .range([0, innerW]);

        const y = d3.scaleLinear().domain([0, 1]).range([innerH, 0]);

        // Healthy zone band (10-25%)
        g.append('rect')
            .attr('x', 0).attr('y', y(0.25))
            .attr('width', innerW).attr('height', y(0.10) - y(0.25))
            .attr('fill', '#00ff88').attr('opacity', 0.08);

        g.append('text')
            .attr('x', innerW - 4).attr('y', y(0.175) + 4)
            .attr('text-anchor', 'end').attr('font-size', '9px')
            .attr('fill', '#00ff88').attr('opacity', 0.5)
            .text('healthy zone');

        // Line
        const line = d3.line()
            .x(d => x(d.period))
            .y(d => y(d.bugfixRatio))
            .curve(d3.curveMonotoneX);

        g.append('path')
            .datum(data)
            .attr('d', line)
            .attr('fill', 'none')
            .attr('stroke', '#ff4444')
            .attr('stroke-width', 2);

        // Dots
        g.selectAll('.ratio-dot')
            .data(data)
            .join('circle')
            .attr('class', 'ratio-dot')
            .attr('cx', d => x(d.period))
            .attr('cy', d => y(d.bugfixRatio))
            .attr('r', 4)
            .attr('fill', d => d.bugfixRatio > 0.25 ? '#ff4444' : d.bugfixRatio < 0.10 ? '#00d4ff' : '#00ff88')
            .on('mouseover', (event, d) => {
                showTooltip(event, `
                    <strong>${esc(d.period)}</strong><br>
                    Bugfix ratio: ${(d.bugfixRatio * 100).toFixed(0)}%<br>
                    ${d.bugfixCount} bugfix / ${d.total} total<br>
                    Features: ${d.featureCount}
                `);
            })
            .on('mouseout', hideTooltip);

        // Axes
        const tickInterval = Math.max(1, Math.floor(data.length / 8));
        g.append('g')
            .attr('transform', `translate(0,${innerH})`)
            .call(d3.axisBottom(x).tickValues(data.filter((_, i) => i % tickInterval === 0).map(d => d.period)))
            .selectAll('text').attr('fill', '#8888aa').attr('font-size', '8px')
            .attr('transform', 'rotate(-30)').attr('text-anchor', 'end');

        g.append('g')
            .call(d3.axisLeft(y).ticks(5).tickFormat(d => (d * 100) + '%'))
            .selectAll('text').attr('fill', '#8888aa');

        g.selectAll('.domain, .tick line').attr('stroke', '#2a2a4a');
    }

    // === Stacked Bar by Device ===
    function renderDeviceChart(selector, data) {
        clearChart(selector);
        if (!data || !data.series || data.series.length === 0) { emptyState(selector, 'No device data'); return; }

        const container = d3.select(selector);
        const width = container.node().clientWidth || 600;
        const height = 300;
        const margin = { top: 20, right: 100, bottom: 40, left: 50 };

        const svg = container.append('svg')
            .attr('width', width).attr('height', height);
        const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

        const innerW = width - margin.left - margin.right;
        const innerH = height - margin.top - margin.bottom;

        const devices = data.devices || [];
        const series = data.series;

        const deviceColors = d3.scaleOrdinal(d3.schemeSet2).domain(devices);

        const stackRows = series.map(d => {
            const row = { date: d.date };
            devices.forEach(dev => { row[dev] = (d.byDevice && d.byDevice[dev]) || 0; });
            return row;
        });

        const x = d3.scaleBand().domain(series.map(d => d.date)).range([0, innerW]).padding(0.15);

        const maxY = d3.max(stackRows, d => devices.reduce((s, dev) => s + d[dev], 0)) || 1;
        const y = d3.scaleLinear().domain([0, maxY]).nice().range([innerH, 0]);

        const stack = d3.stack().keys(devices)(stackRows);

        g.selectAll('.device-layer')
            .data(stack)
            .join('g')
            .attr('class', 'device-layer')
            .attr('fill', d => deviceColors(d.key))
            .selectAll('rect')
            .data(d => d)
            .join('rect')
            .attr('x', d => x(d.data.date))
            .attr('y', d => y(d[1]))
            .attr('height', d => y(d[0]) - y(d[1]))
            .attr('width', x.bandwidth())
            .attr('rx', 1)
            .on('mouseover', (event, d) => {
                const date = d.data.date;
                let html = `<strong>${esc(date)}</strong><br>`;
                devices.forEach(dev => {
                    const count = d.data[dev] || 0;
                    if (count > 0) {
                        html += `<span style="color:${deviceColors(dev)}">${esc(dev)}: ${count}</span><br>`;
                    }
                });
                showTooltip(event, html);
            })
            .on('mouseout', hideTooltip);

        // X axis
        const tickInterval = Math.max(1, Math.floor(series.length / 10));
        g.append('g')
            .attr('transform', `translate(0,${innerH})`)
            .call(d3.axisBottom(x).tickValues(series.filter((_, i) => i % tickInterval === 0).map(d => d.date)))
            .selectAll('text').attr('fill', '#8888aa').attr('font-size', '8px')
            .attr('transform', 'rotate(-30)').attr('text-anchor', 'end');

        g.append('g')
            .call(d3.axisLeft(y).ticks(5))
            .selectAll('text').attr('fill', '#8888aa');

        g.selectAll('.domain, .tick line').attr('stroke', '#2a2a4a');

        // Legend
        const legend = svg.append('g')
            .attr('transform', `translate(${width - margin.right + 10}, ${margin.top})`);
        devices.forEach((dev, i) => {
            const lg = legend.append('g').attr('transform', `translate(0, ${i * 18})`);
            lg.append('rect').attr('width', 10).attr('height', 10).attr('fill', deviceColors(dev)).attr('rx', 2);
            lg.append('text').attr('x', 14).attr('y', 9).attr('font-size', '9px').attr('fill', '#8888aa')
                .text(dev.length > 12 ? dev.slice(0, 12) + '...' : dev);
        });
    }

    // Public API
    return {
        renderHeatmap,
        renderStackedBarByHour,
        renderStackedArea,
        renderSessionTimeline,
        renderHistogram,
        renderScatter,
        renderTreemap,
        renderGroupedBar,
        renderBubbleChart,
        renderSparkline,
        renderBugfixTrend,
        renderDeviceChart,
        TYPE_COLORS,
        getTypeColor
    };
})();
