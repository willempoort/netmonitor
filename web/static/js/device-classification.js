/**
 * Device Classification Management
 * Handles devices, templates, and service providers in the dashboard
 */

// ==================== Global State ====================
let allDevices = [];
let allTemplates = [];
let allProviders = [];

// Sorting state for devices table
let deviceSortColumn = 'ip_address';
let deviceSortDirection = 'asc';

// ==================== Initialization ====================

// Load badge counts immediately
(function() {
    // Try to load counts now, and also on DOMContentLoaded
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initDeviceClassification);
    } else {
        // DOM already loaded
        initDeviceClassification();
    }
})();

function initDeviceClassification() {
    // Load badge counts immediately on page load
    loadDeviceCountsOnly();

    // Load data when the Device Classification section is expanded
    const deviceClassificationCollapse = document.getElementById('deviceClassificationCollapse');
    if (deviceClassificationCollapse) {
        deviceClassificationCollapse.addEventListener('shown.bs.collapse', function() {
            loadDevices();
            loadTemplates();
            loadProviders();
            loadClassificationStats();
        });
    }

    // Setup search and filter handlers
    const deviceSearch = document.getElementById('device-search');
    if (deviceSearch) {
        deviceSearch.addEventListener('input', filterDevicesTable);
    }

    const templateFilter = document.getElementById('device-filter-template');
    if (templateFilter) {
        templateFilter.addEventListener('change', filterDevicesTable);
    }

    const templateCategoryFilter = document.getElementById('template-filter-category');
    if (templateCategoryFilter) {
        templateCategoryFilter.addEventListener('change', filterTemplatesGrid);
    }

    const providerCategoryFilter = document.getElementById('provider-filter-category');
    if (providerCategoryFilter) {
        providerCategoryFilter.addEventListener('change', filterProvidersTable);
    }
}

// ==================== Devices Functions ====================

// Load just the counts for the header badges (lightweight, called on page load)
async function loadDeviceCountsOnly() {
    console.log('[DeviceClassification] loadDeviceCountsOnly called');

    try {
        const response = await fetch('/api/device-classification/stats', {
            credentials: 'same-origin'  // Include cookies for authentication
        });

        console.log('[DeviceClassification] API response status:', response.status);

        // Check if response is OK (not a redirect to login)
        if (!response.ok) {
            console.warn('[DeviceClassification] Device stats API returned:', response.status);
            try {
                const errorBody = await response.json();
                console.error('[DeviceClassification] Error details:', errorBody);
            } catch (e) {
                console.error('[DeviceClassification] Could not parse error response');
            }
            return;
        }

        const result = await response.json();
        console.log('[DeviceClassification] API result:', result);

        if (result.success && result.stats && result.stats.devices) {
            const stats = result.stats;
            const countEl = document.getElementById('devices-count');
            const classifiedEl = document.getElementById('devices-classified');

            console.log('[DeviceClassification] Elements found:', !!countEl, !!classifiedEl);
            console.log('[DeviceClassification] Stats:', stats.devices.total, stats.devices.classified);

            if (countEl) countEl.textContent = stats.devices.total || 0;
            if (classifiedEl) classifiedEl.textContent = stats.devices.classified || 0;

            console.log('[DeviceClassification] Badge counts updated');
        } else {
            console.warn('[DeviceClassification] Invalid response structure:', result);
        }
    } catch (error) {
        console.error('[DeviceClassification] Error loading device counts:', error);
    }
}

async function loadDevices() {
    try {
        const response = await fetch('/api/devices');
        const result = await response.json();

        if (result.success) {
            allDevices = result.devices;
            renderDevicesTable(allDevices);
            updateDeviceCounts();
            populateTemplateFilter();
        } else {
            showError('Failed to load devices: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error loading devices:', error);
        showError('Network error while loading devices');
    }
}

function renderDevicesTable(devices) {
    const tbody = document.getElementById('devices-table');
    if (!tbody) return;

    if (!devices || devices.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center text-muted">
                    No devices discovered yet. Devices will appear here once network monitoring is active.
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = devices.map(device => {
        const learningStatus = getLearningStatusBadge(device);
        const templateBadge = device.template_name
            ? `<span class="badge bg-success">${device.template_name}</span>`
            : `<span class="badge bg-secondary">Unclassified</span>`;

        const lastSeen = device.last_seen
            ? formatRelativeTime(new Date(device.last_seen))
            : '-';

        const vendorInfo = device.vendor
            ? `<small class="text-muted d-block">${device.vendor}</small>`
            : '';

        return `
            <tr style="cursor: pointer;" onclick="showDeviceDetails('${device.ip_address}')">
                <td><code>${device.ip_address}</code></td>
                <td>${device.hostname || '-'}</td>
                <td>
                    <code>${device.mac_address || '-'}</code>
                    ${vendorInfo}
                </td>
                <td>${templateBadge}</td>
                <td>${learningStatus}</td>
                <td>${lastSeen}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="event.stopPropagation(); showDeviceDetails('${device.ip_address}')">
                        <i class="bi bi-eye"></i>
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function getLearningStatusBadge(device) {
    const behavior = device.learned_behavior || {};
    // Support both old format (packet_count) and new format (traffic_summary.total_packets)
    const packetCount = behavior.packet_count ||
                        behavior.traffic_summary?.total_packets ||
                        0;

    if (packetCount === 0) {
        return `<span class="badge bg-secondary">Not Started</span>`;
    } else if (packetCount < 100) {
        return `<span class="badge bg-warning">Learning (${packetCount})</span>`;
    } else {
        return `<span class="badge bg-success">Ready</span>`;
    }
}

// ==================== Sorting Functions ====================

function sortDevices(column) {
    // Toggle direction if same column, otherwise default to ascending
    if (deviceSortColumn === column) {
        deviceSortDirection = deviceSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        deviceSortColumn = column;
        deviceSortDirection = 'asc';
    }

    // Update sort indicators in headers
    updateSortIndicators();

    // Re-render with current filter applied
    filterDevicesTable();
}

function updateSortIndicators() {
    // Remove all existing sort indicators
    document.querySelectorAll('.device-sort-header').forEach(header => {
        header.classList.remove('sort-asc', 'sort-desc');
        const indicator = header.querySelector('.sort-indicator');
        if (indicator) indicator.textContent = '';
    });

    // Add indicator to current sort column
    const currentHeader = document.querySelector(`.device-sort-header[data-sort="${deviceSortColumn}"]`);
    if (currentHeader) {
        currentHeader.classList.add(`sort-${deviceSortDirection}`);
        const indicator = currentHeader.querySelector('.sort-indicator');
        if (indicator) {
            indicator.textContent = deviceSortDirection === 'asc' ? ' ▲' : ' ▼';
        }
    }
}

function compareDevices(a, b, column) {
    let valA, valB;

    switch (column) {
        case 'ip_address':
            // Sort IP addresses numerically
            valA = ipToNumber(a.ip_address || '');
            valB = ipToNumber(b.ip_address || '');
            break;
        case 'hostname':
            valA = (a.hostname || '').toLowerCase();
            valB = (b.hostname || '').toLowerCase();
            break;
        case 'mac_vendor':
            // Sort by vendor first, then MAC
            valA = ((a.vendor || '') + (a.mac_address || '')).toLowerCase();
            valB = ((b.vendor || '') + (b.mac_address || '')).toLowerCase();
            break;
        default:
            valA = a[column] || '';
            valB = b[column] || '';
    }

    if (valA < valB) return -1;
    if (valA > valB) return 1;
    return 0;
}

function ipToNumber(ip) {
    // Convert IP address to number for proper sorting
    // Handle CIDR notation by stripping it
    const cleanIp = ip.split('/')[0];
    const parts = cleanIp.split('.');
    if (parts.length !== 4) return 0;
    return parts.reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function filterDevicesTable() {
    const searchTerm = (document.getElementById('device-search')?.value || '').toLowerCase();
    const templateFilter = document.getElementById('device-filter-template')?.value || '';

    let filtered = allDevices;

    if (searchTerm) {
        filtered = filtered.filter(d =>
            (d.ip_address || '').toLowerCase().includes(searchTerm) ||
            (d.hostname || '').toLowerCase().includes(searchTerm) ||
            (d.mac_address || '').toLowerCase().includes(searchTerm) ||
            (d.vendor || '').toLowerCase().includes(searchTerm)
        );
    }

    if (templateFilter === 'unclassified') {
        filtered = filtered.filter(d => !d.template_id);
    } else if (templateFilter) {
        filtered = filtered.filter(d => d.template_id == templateFilter);
    }

    // Apply sorting
    filtered = [...filtered].sort((a, b) => {
        const result = compareDevices(a, b, deviceSortColumn);
        return deviceSortDirection === 'asc' ? result : -result;
    });

    renderDevicesTable(filtered);
}

function updateDeviceCounts() {
    const total = allDevices.length;
    const classified = allDevices.filter(d => d.template_id).length;

    document.getElementById('devices-count').textContent = total;
    document.getElementById('devices-classified').textContent = classified;
}

function populateTemplateFilter() {
    const select = document.getElementById('device-filter-template');
    if (!select) return;

    // Keep first two options (All, Unclassified)
    while (select.options.length > 2) {
        select.remove(2);
    }

    // Add templates
    allTemplates.forEach(template => {
        const option = document.createElement('option');
        option.value = template.id;
        option.textContent = template.name;
        select.appendChild(option);
    });
}

async function showDeviceDetails(ipAddress) {
    try {
        const response = await fetch(`/api/devices/${ipAddress}`);
        const result = await response.json();

        if (!result.success) {
            showError('Device not found');
            return;
        }

        const device = result.device;

        // Populate device details
        document.getElementById('device-detail-ip').value = ipAddress;
        document.getElementById('device-detail-ip-display').textContent = ipAddress;
        document.getElementById('device-detail-hostname').textContent = device.hostname || '-';
        document.getElementById('device-detail-mac').textContent = device.mac_address || '-';
        document.getElementById('device-detail-vendor').textContent = device.vendor || 'Unknown';

        // Learning status
        const behavior = device.learned_behavior || {};
        // Support both old format (packet_count) and new format (traffic_summary.total_packets)
        const packetCount = behavior.packet_count ||
                            behavior.traffic_summary?.total_packets ||
                            0;
        const portsCount = behavior.typical_ports?.length ||
                          behavior.ports?.outbound_destination_ports?.length ||
                          0;
        document.getElementById('device-detail-packets').textContent = packetCount;
        document.getElementById('device-detail-ports').textContent = portsCount;
        let statusText = 'Not Started';
        if (packetCount > 0 && packetCount < 100) statusText = 'Learning';
        else if (packetCount >= 100) statusText = 'Ready';
        document.getElementById('device-detail-status').textContent = statusText;

        // Populate template dropdown
        await populateDeviceTemplateSelect(device.template_id);

        // Show/hide create template option
        const createTemplateCard = document.getElementById('create-template-from-device-card');
        if (packetCount >= 50) {
            createTemplateCard.style.display = 'block';
        } else {
            createTemplateCard.style.display = 'none';
        }

        // Load classification hints
        loadDeviceClassificationHints(ipAddress);

        // Show modal
        const modal = new bootstrap.Modal(document.getElementById('deviceDetailsModal'));
        modal.show();

    } catch (error) {
        console.error('Error loading device details:', error);
        showError('Failed to load device details');
    }
}

async function populateDeviceTemplateSelect(currentTemplateId) {
    const select = document.getElementById('device-template-select');
    if (!select) return;

    // Clear existing options except first
    while (select.options.length > 1) {
        select.remove(1);
    }

    // Ensure templates are loaded
    if (allTemplates.length === 0) {
        await loadTemplates();
    }

    // Add templates
    allTemplates.forEach(template => {
        const option = document.createElement('option');
        option.value = template.id;
        option.textContent = template.name;
        if (template.id == currentTemplateId) {
            option.selected = true;
        }
        select.appendChild(option);
    });
}

async function loadDeviceClassificationHints(ipAddress) {
    try {
        const response = await fetch(`/api/devices/${ipAddress}/classification-hints`);
        const result = await response.json();

        const hintsContainer = document.getElementById('device-classification-hints');
        const hintsList = document.getElementById('device-hints-list');

        if (result.success && result.hints && result.hints.suggested_templates && result.hints.suggested_templates.length > 0) {
            hintsList.innerHTML = result.hints.suggested_templates.map(hint =>
                `<li><strong>${hint.name}</strong> - ${hint.reason}</li>`
            ).join('');
            hintsContainer.style.display = 'block';
        } else {
            hintsContainer.style.display = 'none';
        }
    } catch (error) {
        console.error('Error loading classification hints:', error);
    }
}

async function assignDeviceTemplate() {
    const ipAddress = document.getElementById('device-detail-ip').value;
    const templateId = document.getElementById('device-template-select').value;

    try {
        const response = await fetch(`/api/devices/${ipAddress}/template`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                template_id: templateId ? parseInt(templateId) : 0,
                method: 'manual'
            })
        });

        const result = await response.json();

        if (result.success) {
            showSuccess('Template assigned successfully');
            loadDevices();
        } else {
            showError('Failed to assign template: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error assigning template:', error);
        showError('Network error while assigning template');
    }
}

async function deleteDevice() {
    const ipAddress = document.getElementById('device-detail-ip').value;

    if (!confirm(`Are you sure you want to delete device ${ipAddress}?`)) {
        return;
    }

    try {
        const response = await fetch(`/api/devices/${ipAddress}`, {
            method: 'DELETE'
        });

        const result = await response.json();

        if (result.success) {
            showSuccess('Device deleted');
            bootstrap.Modal.getInstance(document.getElementById('deviceDetailsModal')).hide();
            loadDevices();
        } else {
            showError('Failed to delete device: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error deleting device:', error);
        showError('Network error while deleting device');
    }
}

async function createTemplateFromDevice() {
    const ipAddress = document.getElementById('device-detail-ip').value;
    const templateName = document.getElementById('new-template-from-device-name').value.trim();
    const category = document.getElementById('new-template-from-device-category').value;

    if (!templateName) {
        showError('Please enter a template name');
        return;
    }

    try {
        const response = await fetch('/api/device-templates/from-device', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ip_address: ipAddress,
                template_name: templateName,
                category: category,
                assign_to_device: true
            })
        });

        const result = await response.json();

        if (result.success) {
            showSuccess(`Template "${templateName}" created with ${result.behaviors_added} behavior rules`);
            document.getElementById('new-template-from-device-name').value = '';
            loadTemplates();
            loadDevices();
            bootstrap.Modal.getInstance(document.getElementById('deviceDetailsModal')).hide();
        } else {
            showError('Failed to create template: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error creating template from device:', error);
        showError('Network error while creating template');
    }
}

// ==================== Templates Functions ====================

async function loadTemplates() {
    try {
        const response = await fetch('/api/device-templates');
        const result = await response.json();

        if (result.success) {
            allTemplates = result.templates;
            renderTemplatesGrid(allTemplates);
        } else {
            showError('Failed to load templates: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error loading templates:', error);
        showError('Network error while loading templates');
    }
}

function renderTemplatesGrid(templates) {
    const grid = document.getElementById('templates-grid');
    if (!grid) return;

    if (!templates || templates.length === 0) {
        grid.innerHTML = `
            <div class="col-12 text-center text-muted p-4">
                No templates defined yet. Create a template to get started.
            </div>
        `;
        return;
    }

    grid.innerHTML = templates.map(template => {
        const icon = getTemplateIcon(template.icon);
        const typeBadge = template.is_builtin
            ? `<span class="badge bg-info">Built-in</span>`
            : `<span class="badge bg-secondary">Custom</span>`;
        const categoryBadge = `<span class="badge bg-outline-secondary">${template.category}</span>`;

        return `
            <div class="col-md-4 col-lg-3 mb-3">
                <div class="card bg-dark border-secondary h-100" style="cursor: pointer;" onclick="showTemplateDetails(${template.id})">
                    <div class="card-body text-center">
                        <div class="fs-2 mb-2">${icon}</div>
                        <h6 class="card-title">${template.name}</h6>
                        <div class="mb-2">
                            ${typeBadge}
                            ${categoryBadge}
                        </div>
                        <small class="text-muted">${template.device_count || 0} devices</small>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function getTemplateIcon(iconName) {
    const icons = {
        'device': '📱',
        'camera': '📷',
        'tv': '📺',
        'speaker': '🔊',
        'server': '🖥️',
        'router': '🌐',
        'printer': '🖨️',
        'other': '⚙️'
    };
    return icons[iconName] || '📱';
}

function filterTemplatesGrid() {
    const categoryFilter = document.getElementById('template-filter-category')?.value || '';

    let filtered = allTemplates;
    if (categoryFilter) {
        filtered = filtered.filter(t => t.category === categoryFilter);
    }

    renderTemplatesGrid(filtered);
}

function showCreateTemplateModal() {
    document.getElementById('template-name').value = '';
    document.getElementById('template-category').value = 'other';
    document.getElementById('template-description').value = '';
    document.getElementById('template-icon').value = 'device';

    const modal = new bootstrap.Modal(document.getElementById('createTemplateModal'));
    modal.show();
}

async function createTemplate() {
    const name = document.getElementById('template-name').value.trim();
    const category = document.getElementById('template-category').value;
    const description = document.getElementById('template-description').value.trim();
    const icon = document.getElementById('template-icon').value;

    if (!name) {
        showError('Please enter a template name');
        return;
    }

    try {
        const response = await fetch('/api/device-templates', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name,
                category,
                description,
                icon
            })
        });

        const result = await response.json();

        if (result.success) {
            showSuccess('Template created successfully');
            bootstrap.Modal.getInstance(document.getElementById('createTemplateModal')).hide();
            loadTemplates();
        } else {
            showError('Failed to create template: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error creating template:', error);
        showError('Network error while creating template');
    }
}

async function showTemplateDetails(templateId) {
    try {
        const response = await fetch(`/api/device-templates/${templateId}`);
        const result = await response.json();

        if (!result.success) {
            showError('Template not found');
            return;
        }

        const template = result.template;

        // Populate template details
        document.getElementById('template-detail-id').value = templateId;
        document.getElementById('template-detail-name').textContent = template.name;
        document.getElementById('template-detail-category').textContent = template.category;
        document.getElementById('template-detail-type').textContent = template.is_builtin ? 'Built-in' : 'Custom';
        document.getElementById('template-detail-description').textContent = template.description || 'No description';

        // Show/hide delete button based on template type
        const deleteBtn = document.getElementById('delete-template-btn');
        deleteBtn.style.display = template.is_builtin ? 'none' : 'block';

        // Store current template ID for behavior management
        window.currentTemplateId = templateId;
        window.currentTemplateBuiltin = template.is_builtin;

        // Hide the add behavior form when opening modal
        hideAddBehaviorForm();

        // Populate behaviors table
        renderBehaviorsTable(template.behaviors || [], template.is_builtin);

        // Load devices using this template
        loadTemplateDevices(templateId);

        // Show modal
        const modal = new bootstrap.Modal(document.getElementById('templateDetailsModal'));
        modal.show();

    } catch (error) {
        console.error('Error loading template details:', error);
        showError('Failed to load template details');
    }
}

async function loadTemplateDevices(templateId) {
    try {
        const response = await fetch(`/api/devices?template_id=${templateId}`);
        const result = await response.json();

        const container = document.getElementById('template-devices-list');

        if (result.success && result.devices && result.devices.length > 0) {
            container.innerHTML = result.devices.map(d =>
                `<span class="badge bg-secondary me-1 mb-1">${d.ip_address} ${d.hostname ? '(' + d.hostname + ')' : ''}</span>`
            ).join('');
        } else {
            container.innerHTML = '<span class="text-muted">No devices assigned to this template.</span>';
        }
    } catch (error) {
        console.error('Error loading template devices:', error);
    }
}

async function deleteTemplate() {
    const templateId = document.getElementById('template-detail-id').value;

    if (!confirm('Are you sure you want to delete this template?')) {
        return;
    }

    try {
        const response = await fetch(`/api/device-templates/${templateId}`, {
            method: 'DELETE'
        });

        const result = await response.json();

        if (result.success) {
            showSuccess('Template deleted');
            bootstrap.Modal.getInstance(document.getElementById('templateDetailsModal')).hide();
            loadTemplates();
            loadDevices();
        } else {
            showError('Failed to delete template: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error deleting template:', error);
        showError('Network error while deleting template');
    }
}

// ==================== Service Providers Functions ====================

async function loadProviders() {
    try {
        const response = await fetch('/api/service-providers');
        const result = await response.json();

        if (result.success) {
            allProviders = result.providers;
            renderProvidersTable(allProviders);
        } else {
            showError('Failed to load providers: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error loading providers:', error);
        showError('Network error while loading providers');
    }
}

function renderProvidersTable(providers) {
    const tbody = document.getElementById('providers-table');
    if (!tbody) return;

    if (!providers || providers.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center text-muted">
                    No service providers defined yet.
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = providers.map(provider => {
        const ipRanges = provider.ip_ranges || [];
        const domains = provider.domains || [];
        const typeBadge = provider.is_builtin
            ? `<span class="badge bg-info">Built-in</span>`
            : `<span class="badge bg-secondary">Custom</span>`;

        return `
            <tr>
                <td><strong>${provider.name}</strong></td>
                <td><span class="badge bg-outline-secondary">${provider.category}</span></td>
                <td><small>${ipRanges.slice(0, 3).join(', ')}${ipRanges.length > 3 ? '...' : ''}</small></td>
                <td><small>${domains.slice(0, 3).join(', ')}${domains.length > 3 ? '...' : ''}</small></td>
                <td>${typeBadge}</td>
                <td>
                    ${!provider.is_builtin ? `
                        <button class="btn btn-sm btn-outline-danger" onclick="deleteProvider(${provider.id})">
                            <i class="bi bi-trash"></i>
                        </button>
                    ` : ''}
                </td>
            </tr>
        `;
    }).join('');
}

function filterProvidersTable() {
    const categoryFilter = document.getElementById('provider-filter-category')?.value || '';

    let filtered = allProviders;
    if (categoryFilter) {
        filtered = filtered.filter(p => p.category === categoryFilter);
    }

    renderProvidersTable(filtered);
}

function showCreateProviderModal() {
    document.getElementById('provider-name').value = '';
    document.getElementById('provider-category').value = 'streaming';
    document.getElementById('provider-ip-ranges').value = '';
    document.getElementById('provider-domains').value = '';
    document.getElementById('provider-description').value = '';

    const modal = new bootstrap.Modal(document.getElementById('createProviderModal'));
    modal.show();
}

async function createProvider() {
    const name = document.getElementById('provider-name').value.trim();
    const category = document.getElementById('provider-category').value;
    const ipRangesText = document.getElementById('provider-ip-ranges').value.trim();
    const domainsText = document.getElementById('provider-domains').value.trim();
    const description = document.getElementById('provider-description').value.trim();

    if (!name) {
        showError('Please enter a provider name');
        return;
    }

    const ipRanges = ipRangesText ? ipRangesText.split('\n').map(s => s.trim()).filter(s => s) : [];
    const domains = domainsText ? domainsText.split('\n').map(s => s.trim()).filter(s => s) : [];

    if (ipRanges.length === 0 && domains.length === 0) {
        showError('Please enter at least one IP range or domain');
        return;
    }

    try {
        const response = await fetch('/api/service-providers', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name,
                category,
                ip_ranges: ipRanges,
                domains,
                description
            })
        });

        const result = await response.json();

        if (result.success) {
            showSuccess('Provider added successfully');
            bootstrap.Modal.getInstance(document.getElementById('createProviderModal')).hide();
            loadProviders();
        } else {
            showError('Failed to add provider: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error creating provider:', error);
        showError('Network error while creating provider');
    }
}

async function deleteProvider(providerId) {
    if (!confirm('Are you sure you want to delete this provider?')) {
        return;
    }

    try {
        const response = await fetch(`/api/service-providers/${providerId}`, {
            method: 'DELETE'
        });

        const result = await response.json();

        if (result.success) {
            showSuccess('Provider deleted');
            loadProviders();
        } else {
            showError('Failed to delete provider: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error deleting provider:', error);
        showError('Network error while deleting provider');
    }
}

// ==================== Statistics Functions ====================

async function loadClassificationStats() {
    try {
        const response = await fetch('/api/device-classification/stats');
        const result = await response.json();

        if (result.success) {
            const stats = result.stats;

            // Update stat cards
            document.getElementById('stat-total-devices').textContent = stats.devices.total;
            document.getElementById('stat-classified').textContent = stats.devices.classified;
            document.getElementById('stat-unclassified').textContent = stats.devices.unclassified;

            // Devices by template
            const byTemplate = stats.devices.by_template || {};
            const templateDiv = document.getElementById('devices-by-template');
            if (Object.keys(byTemplate).length > 0) {
                templateDiv.innerHTML = Object.entries(byTemplate)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 10)
                    .map(([name, count]) => `
                        <div class="d-flex justify-content-between mb-1">
                            <span>${name}</span>
                            <span class="badge bg-secondary">${count}</span>
                        </div>
                    `).join('');
            } else {
                templateDiv.innerHTML = '<p class="text-muted">No data available</p>';
            }

            // Devices by vendor
            const byVendor = stats.devices.by_vendor || {};
            const vendorDiv = document.getElementById('devices-by-vendor');
            if (Object.keys(byVendor).length > 0) {
                vendorDiv.innerHTML = Object.entries(byVendor)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 10)
                    .map(([name, count]) => `
                        <div class="d-flex justify-content-between mb-1">
                            <span>${name}</span>
                            <span class="badge bg-secondary">${count}</span>
                        </div>
                    `).join('');
            } else {
                vendorDiv.innerHTML = '<p class="text-muted">No data available</p>';
            }
        }
    } catch (error) {
        console.error('Error loading classification stats:', error);
    }
}

// ==================== Behavior Management Functions ====================

function renderBehaviorsTable(behaviors, isBuiltin) {
    const behaviorsTable = document.getElementById('template-behaviors-table');

    if (behaviors.length === 0) {
        behaviorsTable.innerHTML = `
            <tr>
                <td colspan="5" class="text-center text-muted">No behaviors defined</td>
            </tr>
        `;
    } else {
        behaviorsTable.innerHTML = behaviors.map(b => {
            // Format parameters for display
            let valueDisplay = '-';
            if (b.parameters) {
                if (b.parameters.ports) {
                    valueDisplay = Array.isArray(b.parameters.ports)
                        ? b.parameters.ports.join(', ')
                        : b.parameters.ports;
                }
                else if (b.parameters.port_range) valueDisplay = b.parameters.port_range;
                else if (b.parameters.protocols) {
                    valueDisplay = Array.isArray(b.parameters.protocols)
                        ? b.parameters.protocols.join(', ')
                        : b.parameters.protocols;
                }
                else if (b.parameters.limit) valueDisplay = b.parameters.limit + ' MB/h';
                else if (b.parameters.destinations) {
                    valueDisplay = Array.isArray(b.parameters.destinations)
                        ? b.parameters.destinations.join(', ')
                        : b.parameters.destinations;
                }
                else if (b.parameters.schedule) valueDisplay = b.parameters.schedule;
                else if (Object.keys(b.parameters).length > 0) {
                    valueDisplay = JSON.stringify(b.parameters);
                }
            }

            const deleteBtn = isBuiltin ? '' : `
                <button class="btn btn-sm btn-outline-danger" onclick="deleteBehaviorRule(${b.id})" title="Delete rule">
                    <i class="bi bi-trash"></i>
                </button>
            `;

            const actionClass = b.action === 'allow' ? 'success' : (b.action === 'suppress' ? 'info' : 'warning');

            return `
                <tr>
                    <td><code>${b.behavior_type}</code></td>
                    <td>${valueDisplay}</td>
                    <td><span class="badge bg-${actionClass}">${b.action}</span></td>
                    <td>${b.description || '-'}</td>
                    <td>${deleteBtn}</td>
                </tr>
            `;
        }).join('');
    }
}

function showAddBehaviorForm() {
    if (window.currentTemplateBuiltin) {
        showError('Cannot modify built-in templates');
        return;
    }
    document.getElementById('add-behavior-form').style.display = 'block';
    document.getElementById('new-behavior-type').value = 'allowed_ports';
    document.getElementById('new-behavior-value').value = '';
    document.getElementById('new-behavior-action').value = 'allow';
    document.getElementById('new-behavior-description').value = '';
    updateBehaviorPlaceholder();
}

function hideAddBehaviorForm() {
    const form = document.getElementById('add-behavior-form');
    if (form) {
        form.style.display = 'none';
    }
}

// Update placeholder text based on selected behavior type
function updateBehaviorPlaceholder() {
    const type = document.getElementById('new-behavior-type').value;
    const input = document.getElementById('new-behavior-value');

    const placeholders = {
        'allowed_ports': 'e.g., 443 or 5060-5090 or 80,443,8080',
        'allowed_protocols': 'e.g., TCP, UDP, ICMP',
        'bandwidth_limit': 'e.g., 100 (MB per hour)',
        'connection_behavior': 'e.g., max_connections:50',
        'expected_destinations': 'e.g., 8.8.8.8 or google.com',
        'time_restrictions': 'e.g., 08:00-18:00',
        'dns_behavior': 'e.g., allowed_domains:*.google.com',
        'traffic_pattern': 'e.g., bidirectional'
    };

    input.placeholder = placeholders[type] || 'Enter value';
}

async function addBehaviorRule() {
    const templateId = window.currentTemplateId;
    if (!templateId) {
        showError('No template selected');
        return;
    }

    const behaviorType = document.getElementById('new-behavior-type').value;
    const value = document.getElementById('new-behavior-value').value.trim();
    const action = document.getElementById('new-behavior-action').value;
    const description = document.getElementById('new-behavior-description').value.trim();

    if (!value) {
        showError('Please enter a value for the behavior rule');
        return;
    }

    // Build parameters based on type
    let parameters = {};
    switch (behaviorType) {
        case 'allowed_ports':
            // Support: single port (443), range (5060-5090), or comma-separated (80,443,8080)
            if (value.includes('-')) {
                // Port range
                parameters = { port_range: value };
            } else if (value.includes(',')) {
                // Multiple ports
                parameters = { ports: value.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p)) };
            } else {
                // Single port
                parameters = { ports: [parseInt(value)] };
            }
            break;
        case 'allowed_protocols':
            parameters = { protocols: value.toUpperCase().split(',').map(p => p.trim()) };
            break;
        case 'bandwidth_limit':
            parameters = { limit: parseFloat(value) };
            break;
        case 'connection_behavior':
            parameters = { max_connections: parseInt(value) || value };
            break;
        case 'expected_destinations':
            parameters = { destinations: value.split(',').map(d => d.trim()) };
            break;
        case 'time_restrictions':
            parameters = { schedule: value };
            break;
        case 'dns_behavior':
            parameters = { pattern: value };
            break;
        case 'traffic_pattern':
            parameters = { pattern: value };
            break;
        default:
            parameters = { value: value };
    }

    try {
        const response = await fetch(`/api/device-templates/${templateId}/behaviors`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                behavior_type: behaviorType,
                parameters: parameters,
                action: action,
                description: description || null
            })
        });

        const result = await response.json();

        if (result.success) {
            showSuccess('Behavior rule added');
            hideAddBehaviorForm();
            // Reload template details to refresh behaviors table
            showTemplateDetails(templateId);
        } else {
            showError('Failed to add behavior: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error adding behavior:', error);
        showError('Network error while adding behavior');
    }
}

async function deleteBehaviorRule(behaviorId) {
    if (!confirm('Are you sure you want to delete this behavior rule?')) {
        return;
    }

    try {
        const response = await fetch(`/api/device-templates/behaviors/${behaviorId}`, {
            method: 'DELETE'
        });

        const result = await response.json();

        if (result.success) {
            showSuccess('Behavior rule deleted');
            // Reload template details to refresh behaviors table
            if (window.currentTemplateId) {
                showTemplateDetails(window.currentTemplateId);
            }
        } else {
            showError('Failed to delete behavior: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error deleting behavior:', error);
        showError('Network error while deleting behavior');
    }
}

// ==================== Utility Functions ====================

function formatRelativeTime(date) {
    const now = new Date();
    const diffMs = now - date;
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffSecs / 60);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffSecs < 60) return 'just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
}

function showError(message) {
    // Use existing alert system if available, otherwise use console
    if (typeof showNotification === 'function') {
        showNotification(message, 'danger');
    } else {
        console.error(message);
        alert(message);
    }
}

function showSuccess(message) {
    if (typeof showNotification === 'function') {
        showNotification(message, 'success');
    } else {
        console.log(message);
    }
}

// Simple notification function if not defined elsewhere
if (typeof showNotification === 'undefined') {
    window.showNotification = function(message, type = 'info') {
        // Create toast notification
        const toastContainer = document.getElementById('toast-container') || createToastContainer();

        const toast = document.createElement('div');
        toast.className = `toast align-items-center text-white bg-${type} border-0`;
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;

        toastContainer.appendChild(toast);
        const bsToast = new bootstrap.Toast(toast, { delay: 3000 });
        bsToast.show();

        toast.addEventListener('hidden.bs.toast', () => toast.remove());
    };

    function createToastContainer() {
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        container.style.zIndex = '9999';
        document.body.appendChild(container);
        return container;
    }
}
