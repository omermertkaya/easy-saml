document.addEventListener('DOMContentLoaded', () => {
    const eventsTableBody = document.getElementById('eventsTableBody');
    const refreshBtn = document.getElementById('refreshBtn');
    const autoRefreshToggle = document.getElementById('autoRefreshToggle');
    let autoRefreshInterval;

    // Run if the table exists (Dashboard or Admin)
    if (!eventsTableBody) return;

    // Helper to format date
    function formatDate(dateString) {
        return new Date(dateString).toLocaleString('tr-TR');
    }

    // Helper to get badge class
    function getBadgeClass(stage) {
        if (stage === 'SP') return 'info';
        if (stage === 'IdP') return 'warning';
        return 'secondary';
    }

    // Function to render events
    function renderEvents(events) {
        eventsTableBody.innerHTML = '';

        if (events.length === 0) {
            eventsTableBody.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center text-muted py-5">
                        <i class="bi bi-journal-x fs-1 d-block mb-2"></i>
                        Henüz kayıtlı olay yok.
                    </td>
                </tr>
            `;
            return;
        }

        events.forEach(event => {
            const rowId = `event-${Math.floor(event.id)}`;
            const hasData = !!event.data;

            const row = document.createElement('tr');
            row.innerHTML = `
                <td class="text-nowrap text-muted">${formatDate(event.timestamp)}</td>
                <td><span class="badge rounded-pill bg-${getBadgeClass(event.stage)}">${event.stage}</span></td>
                <td class="fw-bold text-dark">${event.title}</td>
                <td class="text-muted">${event.message}</td>
                <td class="text-center">
                    ${hasData ? `
                        <a class="btn btn-link btn-sm p-0 text-secondary" data-bs-toggle="collapse" href="#${rowId}" role="button" aria-expanded="false">
                            <i class="bi bi-file-earmark-code"></i>
                        </a>
                    ` : ''}
                </td>
            `;
            eventsTableBody.appendChild(row);

            if (hasData) {
                const dataRow = document.createElement('tr');
                dataRow.className = 'collapse';
                dataRow.id = rowId;
                dataRow.innerHTML = `
                    <td colspan="5" class="bg-light p-3 border-bottom">
                         <pre class="mb-0 small text-muted bg-white p-2 border rounded" style="white-space: pre-wrap; font-size: 0.75rem;">${JSON.stringify(event.data, null, 2)}</pre>
                    </td>
                `;
                eventsTableBody.appendChild(dataRow);
            }
        });
    }

    // Function to fetch events
    async function fetchEvents() {
        try {
            if (refreshBtn) {
                refreshBtn.disabled = true;
                refreshBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Yükleniyor...';
            }

            const response = await fetch('/api/events');
            if (!response.ok) throw new Error('Veri çekilemedi');

            const events = await response.json();
            renderEvents(events);
        } catch (error) {
            console.error('Events fetch error:', error);
            // Optional: show toast
        } finally {
            if (refreshBtn) {
                refreshBtn.disabled = false;
                refreshBtn.innerHTML = '<i class="bi bi-arrow-clockwise me-1"></i>Yenile';
            }
        }
    }

    // Event Listeners
    if (refreshBtn) {
        refreshBtn.addEventListener('click', fetchEvents);
    }

    if (autoRefreshToggle) {
        autoRefreshToggle.addEventListener('change', (e) => {
            if (e.target.checked) {
                fetchEvents(); // Immediate fetch
                autoRefreshInterval = setInterval(fetchEvents, 3000); // Poll every 3s
            } else {
                clearInterval(autoRefreshInterval);
            }
        });
    }
});
