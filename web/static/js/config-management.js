// ==================== Configuration Management ====================

let configDefaults = {};
let configDescriptions = {};
let configCategories = {};
let currentConfigScope = 'global';
let currentConfigSensor = null;

// Initialize config management
function initConfigManagement() {
    console.log('[CONFIG] Initializing configuration management');

    // Load defaults and descriptions
    loadConfigDefaults();

    // Setup event listeners
    setupConfigEventListeners();

    // Load initial config
    loadConfigParameters();
}

function setupConfigEventListeners() {
    // Scope selector
    document.getElementById('config-scope-select').addEventListener('change', function() {
        const scope = this.value;
        currentConfigScope = scope;

        if (scope === 'sensor') {
            document.getElementById('config-sensor-container').style.display = 'block';
        } else {
            document.getElementById('config-sensor-container').style.display = 'none';
            currentConfigSensor = null;
        }

        loadConfigParameters();
    });

    // Sensor selector
    document.getElementById('config-sensor-select').addEventListener('change', function() {
        currentConfigSensor = this.value || null;
        loadConfigParameters();
    });

    // Show defaults toggle
    document.getElementById('config-show-defaults').addEventListener('change', function() {
        // Toggle example value visibility
        document.querySelectorAll('.param-example').forEach(el => {
            el.style.display = this.checked ? 'block' : 'none';
        });
    });

    // Reset config button
    document.getElementById('reset-config-btn').addEventListener('click', function() {
        showResetConfigModal();
    });

    // Reset confirmation checkbox
    document.getElementById('reset-confirm-checkbox').addEventListener('change', function() {
        document.getElementById('confirm-reset-btn').disabled = !this.checked;
    });

    // Confirm reset button
    document.getElementById('confirm-reset-btn').addEventListener('click', function() {
        resetConfigToDefaults();
    });

    // Tab change event - lazy load content
    document.querySelectorAll('#configTabs button[data-bs-toggle="tab"]').forEach(tab => {
        tab.addEventListener('shown.bs.tab', function(e) {
            const targetId = e.target.getAttribute('data-bs-target');
            console.log('[CONFIG] Tab changed to:', targetId);
        });
    });
}

function loadConfigDefaults() {
    fetch('/api/config/defaults')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                configDefaults = data.defaults;
                configDescriptions = data.descriptions || {};
                configCategories = data.categories || {};
                console.log('[CONFIG] Loaded defaults:', Object.keys(configDefaults).length, 'categories');
            }
        })
        .catch(error => {
            console.error('[CONFIG] Error loading defaults:', error);
        });
}

function loadConfigParameters() {
    const sensor_id = currentConfigScope === 'sensor' ? currentConfigSensor : null;

    if (currentConfigScope === 'sensor' && !sensor_id) {
        console.log('[CONFIG] Sensor scope selected but no sensor chosen');
        return;
    }

    console.log('[CONFIG] Loading parameters for:', currentConfigScope, sensor_id || 'global');

    // Show loading in all tabs
    document.querySelectorAll('.config-category-content').forEach(el => {
        el.innerHTML = '<div class="text-center text-muted p-4"><div class="spinner-border spinner-border-sm"></div><p class="mt-2">Loading...</p></div>';
    });

    fetch(`/api/config?sensor_id=${sensor_id || ''}`)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const config = data.config;
                renderConfigByCategory(config);
            } else {
                showConfigError(data.error);
            }
        })
        .catch(error => {
            console.error('[CONFIG] Error loading parameters:', error);
            showConfigError(error.message);
        });
}

function renderConfigByCategory(config) {
    // Render Detection Rules
    renderCategoryParams('detection-rules', config.detection || {}, 'detection');

    // Render Thresholds
    renderCategoryParams('thresholds', config.thresholds || {}, 'thresholds');

    // Render Alert Management
    renderCategoryParams('alerts-config', config.alerts || {}, 'alerts');

    // Render Performance
    renderCategoryParams('performance', config.performance || {}, 'performance');

    // Render All Parameters
    renderAllParameters(config);

    // Update parameter count
    const totalParams = countParameters(config);
    document.getElementById('config-params-count').textContent = totalParams;
}

function renderCategoryParams(categoryId, params, prefix) {
    const content = document.getElementById(`${categoryId}-content`);

    if (Object.keys(params).length === 0) {
        content.innerHTML = '<div class="alert alert-info"><i class="bi bi-info-circle"></i> No parameters in this category</div>';
        return;
    }

    let html = '<div class="row g-3">';

    for (const [key, value] of Object.entries(params)) {
        const fullPath = `${prefix}.${key}`;

        if (typeof value === 'object' && !Array.isArray(value)) {
            // Nested object - render as subsection
            html += `<div class="col-12"><h6 class="text-info mt-3">${formatParamName(key)}</h6></div>`;
            for (const [subKey, subValue] of Object.entries(value)) {
                const subPath = `${fullPath}.${subKey}`;
                html += renderParameterCard(subPath, subKey, subValue);
            }
        } else {
            html += renderParameterCard(fullPath, key, value);
        }
    }

    html += '</div>';
    content.innerHTML = html;

    // Attach event listeners to save buttons
    attachParameterEventListeners(content);
}

function renderParameterCard(path, name, value) {
    const description = configDescriptions[path] || 'No description available';
    const defaultValue = getDefaultValue(path);
    const paramType = detectParamType(value);
    const inputHtml = renderParameterInput(path, value, paramType);

    return `
        <div class="col-md-6">
            <div class="card bg-dark border-secondary">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <div>
                            <h6 class="card-title mb-1">${formatParamName(name)}</h6>
                            <small class="text-muted">${description}</small>
                        </div>
                        <span class="badge bg-secondary">${paramType}</span>
                    </div>
                    ${inputHtml}
                    <div class="param-example text-muted small mt-2" style="display: ${document.getElementById('config-show-defaults')?.checked ? 'block' : 'none'}">
                        <i class="bi bi-lightbulb"></i> Default: <code>${formatValue(defaultValue)}</code>
                    </div>
                    <div class="mt-3">
                        <button class="btn btn-sm btn-success save-param-btn" data-param-path="${path}">
                            <i class="bi bi-check-circle"></i> Save
                        </button>
                        <button class="btn btn-sm btn-outline-secondary reset-param-btn" data-param-path="${path}">
                            <i class="bi bi-arrow-counterclockwise"></i> Reset
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function renderParameterInput(path, value, type) {
    const inputId = `param-${path.replace(/\./g, '-')}`;

    switch (type) {
        case 'bool':
            return `
                <div class="form-check form-switch mt-2">
                    <input class="form-check-input param-input" type="checkbox" id="${inputId}"
                           ${value ? 'checked' : ''} data-param-path="${path}">
                    <label class="form-check-label" for="${inputId}">
                        ${value ? 'Enabled' : 'Disabled'}
                    </label>
                </div>
            `;

        case 'int':
        case 'float':
            return `
                <input type="number" class="form-control bg-dark text-light border-secondary param-input mt-2"
                       id="${inputId}" value="${value}" step="${type === 'float' ? '0.1' : '1'}"
                       data-param-path="${path}">
            `;

        case 'list':
            return `
                <textarea class="form-control bg-dark text-light border-secondary param-input mt-2"
                          id="${inputId}" rows="3" data-param-path="${path}">${Array.isArray(value) ? value.join('\n') : value}</textarea>
                <small class="text-muted">One item per line</small>
            `;

        case 'str':
        default:
            return `
                <input type="text" class="form-control bg-dark text-light border-secondary param-input mt-2"
                       id="${inputId}" value="${value}" data-param-path="${path}">
            `;
    }
}

function renderAllParameters(config) {
    const content = document.getElementById('all-params-content');
    const flatParams = flattenConfig(config);

    if (Object.keys(flatParams).length === 0) {
        content.innerHTML = '<div class="alert alert-info"><i class="bi bi-info-circle"></i> No parameters configured</div>';
        return;
    }

    let html = '<div class="table-responsive"><table class="table table-dark table-striped table-hover"><thead><tr>';
    html += '<th>Parameter</th><th>Value</th><th>Type</th><th>Actions</th></tr></thead><tbody>';

    for (const [path, value] of Object.entries(flatParams)) {
        const type = detectParamType(value);
        html += `
            <tr>
                <td><code>${path}</code></td>
                <td><strong>${formatValue(value)}</strong></td>
                <td><span class="badge bg-secondary">${type}</span></td>
                <td>
                    <button class="btn btn-sm btn-outline-primary edit-param-btn" data-param-path="${path}">
                        <i class="bi bi-pencil"></i>
                    </button>
                </td>
            </tr>
        `;
    }

    html += '</tbody></table></div>';
    content.innerHTML = html;

    // Attach event listeners
    attachParameterEventListeners(content);
}

function attachParameterEventListeners(container) {
    // Save buttons
    container.querySelectorAll('.save-param-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const path = this.getAttribute('data-param-path');
            saveParameter(path);
        });
    });

    // Reset buttons
    container.querySelectorAll('.reset-param-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const path = this.getAttribute('data-param-path');
            resetParameter(path);
        });
    });

    // Checkbox labels update
    container.querySelectorAll('.form-check-input.param-input').forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            const label = this.nextElementSibling;
            if (label) {
                label.textContent = this.checked ? 'Enabled' : 'Disabled';
            }
        });
    });
}

function saveParameter(path) {
    const inputId = `param-${path.replace(/\./g, '-')}`;
    const input = document.getElementById(inputId);

    if (!input) {
        console.error('[CONFIG] Input not found for:', path);
        return;
    }

    let value;
    if (input.type === 'checkbox') {
        value = input.checked;
    } else if (input.type === 'number') {
        value = input.step === '1' ? parseInt(input.value) : parseFloat(input.value);
    } else if (input.tagName === 'TEXTAREA') {
        // List type - split by lines
        value = input.value.split('\n').filter(line => line.trim());
    } else {
        value = input.value;
    }

    console.log('[CONFIG] Saving parameter:', path, '=', value);

    const payload = {
        parameter_path: path,
        value: value,
        sensor_id: currentConfigScope === 'sensor' ? currentConfigSensor : null,
        scope: currentConfigScope,
        updated_by: 'dashboard'
    };

    fetch('/api/config/parameter', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Success', `Parameter ${path} updated successfully`, 'success');
        } else {
            showToast('Error', data.error || 'Failed to update parameter', 'danger');
        }
    })
    .catch(error => {
        console.error('[CONFIG] Error saving parameter:', error);
        showToast('Error', error.message, 'danger');
    });
}

function resetParameter(path) {
    const defaultValue = getDefaultValue(path);
    if (defaultValue === undefined) {
        showToast('Info', 'No default value available for this parameter', 'info');
        return;
    }

    const inputId = `param-${path.replace(/\./g, '-')}`;
    const input = document.getElementById(inputId);

    if (input) {
        if (input.type === 'checkbox') {
            input.checked = defaultValue;
            input.dispatchEvent(new Event('change'));
        } else if (input.tagName === 'TEXTAREA' && Array.isArray(defaultValue)) {
            input.value = defaultValue.join('\n');
        } else {
            input.value = defaultValue;
        }
    }

    // Save the reset value
    saveParameter(path);
}

function showResetConfigModal() {
    const scopeDisplay = currentConfigScope === 'global' ?
        'Global (All Sensors)' :
        `Sensor: ${currentConfigSensor || '(not selected)'}`;

    document.getElementById('reset-scope-display').textContent = scopeDisplay;
    document.getElementById('reset-confirm-checkbox').checked = false;
    document.getElementById('confirm-reset-btn').disabled = true;

    const modal = new bootstrap.Modal(document.getElementById('resetConfigModal'));
    modal.show();
}

function resetConfigToDefaults() {
    const sensor_id = currentConfigScope === 'sensor' ? currentConfigSensor : null;

    console.log('[CONFIG] Resetting config to defaults for:', currentConfigScope, sensor_id || 'global');

    fetch('/api/config/reset', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            sensor_id: sensor_id,
            confirm: true
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Success', `Reset ${data.parameters_reset} parameters to defaults`, 'success');

            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('resetConfigModal'));
            modal.hide();

            // Reload config
            setTimeout(() => loadConfigParameters(), 500);
        } else {
            showToast('Error', data.error || 'Failed to reset config', 'danger');
        }
    })
    .catch(error => {
        console.error('[CONFIG] Error resetting config:', error);
        showToast('Error', error.message, 'danger');
    });
}

// ==================== Helper Functions ====================

function detectParamType(value) {
    if (typeof value === 'boolean') return 'bool';
    if (typeof value === 'number') return Number.isInteger(value) ? 'int' : 'float';
    if (Array.isArray(value)) return 'list';
    return 'str';
}

function formatParamName(name) {
    return name
        .split('_')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
}

function formatValue(value) {
    if (value === null || value === undefined) return '<em>not set</em>';
    if (typeof value === 'boolean') return value ? '✓ Yes' : '✗ No';
    if (Array.isArray(value)) return value.join(', ');
    return value.toString();
}

function getDefaultValue(path) {
    const parts = path.split('.');
    let value = configDefaults;

    for (const part of parts) {
        if (value && typeof value === 'object' && part in value) {
            value = value[part];
        } else {
            return undefined;
        }
    }

    return value;
}

function flattenConfig(obj, prefix = '') {
    let result = {};

    for (const [key, value] of Object.entries(obj)) {
        const path = prefix ? `${prefix}.${key}` : key;

        if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
            Object.assign(result, flattenConfig(value, path));
        } else {
            result[path] = value;
        }
    }

    return result;
}

function countParameters(obj) {
    let count = 0;
    for (const value of Object.values(obj)) {
        if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
            count += countParameters(value);
        } else {
            count++;
        }
    }
    return count;
}

function showConfigError(error) {
    document.querySelectorAll('.config-category-content').forEach(el => {
        el.innerHTML = `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle"></i> Error: ${error}</div>`;
    });
}

function showToast(title, message, type = 'info') {
    // Simple toast notification (you can enhance this with Bootstrap Toast)
    const alertClass = `alert-${type}`;
    const toastHtml = `
        <div class="alert ${alertClass} alert-dismissible fade show position-fixed top-0 end-0 m-3" role="alert" style="z-index: 9999;">
            <strong>${title}:</strong> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;

    const div = document.createElement('div');
    div.innerHTML = toastHtml;
    document.body.appendChild(div.firstElementChild);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        const alerts = document.querySelectorAll('.alert.position-fixed');
        alerts.forEach(alert => {
            if (alert.parentNode) {
                alert.remove();
            }
        });
    }, 5000);
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        setTimeout(initConfigManagement, 2000);
    });
} else {
    setTimeout(initConfigManagement, 2000);
}

// Populate sensor selects for config
function populateConfigSensorSelects() {
    fetch('/api/sensors')
        .then(response => response.json())
        .then(data => {
            if (data.success && data.sensors) {
                const select = document.getElementById('config-sensor-select');
                select.innerHTML = '<option value="">-- Select Sensor --</option>';

                data.sensors.forEach(sensor => {
                    const option = document.createElement('option');
                    option.value = sensor.sensor_id;
                    option.textContent = `${sensor.sensor_id} (${sensor.location || 'Unknown'})`;
                    select.appendChild(option);
                });
            }
        });
}

// Auto-populate sensor selects
setInterval(populateConfigSensorSelects, 30000);
setTimeout(populateConfigSensorSelects, 2000);
