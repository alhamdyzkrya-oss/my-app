// GNS3 Network Monitor - Main JavaScript
// Professional Dashboard Functionality

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    initializeTooltips();
    
    // Initialize sidebar
    initializeSidebar();
    
    // Initialize alerts auto-dismiss
    initializeAlerts();
    
    // Initialize data refresh
    initializeDataRefresh();
});

// Initialize Bootstrap tooltips
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Initialize sidebar functionality
function initializeSidebar() {
    // Set active menu item based on current page
    const currentPath = window.location.pathname;
    const navItems = document.querySelectorAll('.nav-item');
    
    navItems.forEach(item => {
        if (item.getAttribute('href') === currentPath) {
            item.classList.add('active');
        }
    });
    
    // Handle sidebar collapse on mobile
    const sidebar = document.getElementById('sidebar');
    if (window.innerWidth < 768) {
        sidebar.classList.remove('active');
    }
}

// Initialize alerts auto-dismiss
function initializeAlerts() {
    // Auto-dismiss success alerts after 5 seconds
    const successAlerts = document.querySelectorAll('.alert-success');
    successAlerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
}

// Initialize data refresh for dashboard
function initializeDataRefresh() {
    // Refresh dashboard stats every 30 seconds
    if (window.location.pathname === '/' || window.location.pathname.includes('dashboard')) {
        setInterval(refreshDashboardData, 30000);
    }
}

// Refresh dashboard data
function refreshDashboardData() {
    fetch('/api/dashboard/stats')
        .then(response => response.json())
        .then(data => {
            updateDashboardStats(data);
        })
        .catch(error => {
            console.error('Error refreshing dashboard data:', error);
        });
}

// Update dashboard stats
function updateDashboardStats(data) {
    // Update stat cards
    if (data.total_devices) {
        const totalDevicesEl = document.getElementById('total-devices');
        if (totalDevicesEl) {
            totalDevicesEl.textContent = data.total_devices;
            totalDevicesEl.classList.add('fade-in');
        }
    }
    
    if (data.devices_up) {
        const devicesUpEl = document.getElementById('devices-up');
        if (devicesUpEl) {
            devicesUpEl.textContent = data.devices_up;
            devicesUpEl.classList.add('fade-in');
        }
    }
    
    if (data.devices_down) {
        const devicesDownEl = document.getElementById('devices-down');
        if (devicesDownEl) {
            devicesDownEl.textContent = data.devices_down;
            devicesDownEl.classList.add('fade-in');
        }
    }
    
    if (data.active_alerts) {
        const activeAlertsEl = document.getElementById('active-alerts');
        if (activeAlertsEl) {
            activeAlertsEl.textContent = data.active_alerts;
            activeAlertsEl.classList.add('fade-in');
        }
    }
}

// Device management functions
function scanDevice(deviceId) {
    const scanBtn = document.getElementById(`scan-${deviceId}`);
    if (scanBtn) {
        scanBtn.disabled = true;
        scanBtn.innerHTML = '<i class="bi bi-arrow-repeat"></i> Scanning...';
        
        fetch(`/scan/${deviceId}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('success', 'Scan completed successfully');
                    updateDeviceStatus(deviceId, data.status);
                } else {
                    showAlert('danger', 'Scan failed: ' + data.message);
                }
            })
            .catch(error => {
                showAlert('danger', 'Scan failed: ' + error.message);
            })
            .finally(() => {
                scanBtn.disabled = false;
                scanBtn.innerHTML = '<i class="bi bi-search"></i> Scan';
            });
    }
}

function deleteDevice(deviceId, deviceName) {
    if (confirm(`Are you sure you want to delete device "${deviceName}"?`)) {
        fetch(`/delete/${deviceId}`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showAlert('success', 'Device deleted successfully');
                removeDeviceFromTable(deviceId);
            } else {
                showAlert('danger', 'Delete failed: ' + data.message);
            }
        })
        .catch(error => {
            showAlert('danger', 'Delete failed: ' + error.message);
        });
    }
}

function updateDeviceStatus(deviceId, status) {
    const statusEl = document.getElementById(`status-${deviceId}`);
    if (statusEl) {
        statusEl.className = `badge badge-${status}`;
        statusEl.textContent = status.toUpperCase();
    }
}

function removeDeviceFromTable(deviceId) {
    const row = document.getElementById(`device-${deviceId}`);
    if (row) {
        row.remove();
        
        // Update device count
        const deviceCount = document.querySelectorAll('.device-row').length;
        const countEl = document.getElementById('device-count');
        if (countEl) {
            countEl.textContent = deviceCount;
        }
    }
}

// Alert management
function showAlert(type, message) {
    const alertContainer = document.getElementById('alert-container') || document.querySelector('.page-content');
    
    const alertEl = document.createElement('div');
    alertEl.className = `alert alert-${type} alert-dismissible fade show`;
    alertEl.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    if (alertContainer) {
        alertContainer.insertBefore(alertEl, alertContainer.firstChild);
        
        // Auto-dismiss after 5 seconds for success alerts
        if (type === 'success') {
            setTimeout(() => {
                const bsAlert = new bootstrap.Alert(alertEl);
                bsAlert.close();
            }, 5000);
        }
    }
}

// Form validation
function validateForm(formId) {
    const form = document.getElementById(formId);
    if (!form) return true;
    
    const inputs = form.querySelectorAll('input[required], select[required], textarea[required]');
    let isValid = true;
    
    inputs.forEach(input => {
        if (!input.value.trim()) {
            input.classList.add('is-invalid');
            isValid = false;
        } else {
            input.classList.remove('is-invalid');
        }
    });
    
    return isValid;
}

// IP address validation
function validateIP(ip) {
    const regex = /^([0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!regex.test(ip)) return false;
    
    const parts = ip.split('.');
    return parts.every(part => parseInt(part) >= 0 && parseInt(part) <= 255);
}

// Format date/time
function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Format bytes to human readable
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Export functions to global scope
window.scanDevice = scanDevice;
window.deleteDevice = deleteDevice;
window.showAlert = showAlert;
window.validateForm = validateForm;
window.validateIP = validateIP;
window.formatDateTime = formatDateTime;
window.formatBytes = formatBytes;
