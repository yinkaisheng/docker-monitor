/**
 * Docker Monitor Application using Alpine.js
 * Main component and API interaction logic
 */

function dockerMonitor() {
    return {
        // State
        containers: [],
        gpuUsage: {},
        containerStats: {},
        isLoading: false,
        statusText: '',
        refreshInterval: 0,
        autoRefreshTimer: null,
        pageWidth: 100,
        logLines: 50,
        logFontSize: 14,
        restartLogFontSize: 14,
        theme: 'light',

        // Sorting
        sortColumn: null,
        sortDirection: 'asc',

        // Filtering
        filterText: '',

        // Modals
        showLogModal: false,
        logModalTitle: '',
        currentLogEventSource: null,
        currentLogContainerId: null,
        currentLogContainerName: null,
        logReconnectAttempts: 0,
        maxLogReconnectAttempts: 5,
        isRestarting: false,
        logConnectionStatus: 'connecting', // 'connecting', 'connected', 'receiving'

        showPasswordModal: false,
        passwordModalTitle: '',
        usernameInput: 'admin',
        passwordInput: '',
        passwordError: '',
        pendingRestartContainerId: null,
        pendingRestartContainerName: null,

        showRestartLogModal: false,
        restartLogModalTitle: '',
        restartStatus: '',
        restartError: false,
        showRestartActions: false,
        currentRestartReader: null,

        /**
         * Initialize component
         */
        init() {
            this.loadSettings();
            this.setupColumnResize();
            this.refreshContainers();
            this.setupEscapeKeyHandler();
        },

        /**
         * Setup ESC key handler to close modals
         */
        setupEscapeKeyHandler() {
            document.addEventListener('keydown', (event) => {
                if (event.key === 'Escape') {
                    // Close modals in priority order (most specific first)
                    if (this.showRestartLogModal) {
                        this.closeRestartLogModal();
                    } else if (this.showLogModal) {
                        this.closeLogModal();
                    } else if (this.showPasswordModal) {
                        this.closePasswordModal();
                    }
                }
            });
        },

        /**
         * Load settings from localStorage
         */
        loadSettings() {
            // Load refresh interval
            const savedInterval = localStorage.getItem('refreshInterval');
            if (savedInterval !== null) {
                this.refreshInterval = parseInt(savedInterval, 10);
            }

            // Load page width
            const savedWidth = localStorage.getItem('pageWidth');
            if (savedWidth !== null) {
                this.pageWidth = parseInt(savedWidth, 10);
            }

            // Load log lines
            const savedLogLines = localStorage.getItem('logLines');
            if (savedLogLines !== null) {
                this.logLines = parseInt(savedLogLines, 10);
            }

            // Load log font size
            const savedLogFontSize = localStorage.getItem('logFontSize');
            if (savedLogFontSize !== null) {
                this.logFontSize = parseInt(savedLogFontSize, 10);
            }

            // Load restart log font size
            const savedRestartLogFontSize = localStorage.getItem('restartLogFontSize');
            if (savedRestartLogFontSize !== null) {
                this.restartLogFontSize = parseInt(savedRestartLogFontSize, 10);
            }

            // Load theme
            const savedTheme = localStorage.getItem('theme');
            if (savedTheme !== null) {
                this.theme = savedTheme;
            }

            // Apply settings
            this.updatePageWidth();
            this.updateTheme();
            this.updateRestartLogFontSize();

            // Setup auto refresh if interval > 0
            if (this.refreshInterval > 0) {
                this.setupAutoRefresh();
            }
        },

        /**
         * Setup auto refresh timer
         */
        setupAutoRefresh() {
            if (this.autoRefreshTimer) {
                clearInterval(this.autoRefreshTimer);
            }

            if (this.refreshInterval > 0) {
                this.autoRefreshTimer = setInterval(() => {
                    this.refreshContainers(true); // Silent refresh
                }, this.refreshInterval * 1000);
            }
        },

        /**
         * Update auto refresh interval
         */
        updateAutoRefresh() {
            localStorage.setItem('refreshInterval', this.refreshInterval.toString());
            this.setupAutoRefresh();
        },

        /**
         * Update page width
         */
        updatePageWidth() {
            const container = document.querySelector('.container');
            if (container) {
                container.style.width = `${this.pageWidth}%`;
            }
            localStorage.setItem('pageWidth', this.pageWidth.toString());
        },

        /**
         * Update log lines setting
         */
        updateLogLines() {
            localStorage.setItem('logLines', this.logLines.toString());
        },

        /**
         * Update log font size
         */
        updateLogFontSize() {
            localStorage.setItem('logFontSize', this.logFontSize.toString());
        },

        /**
         * Update restart log font size
         */
        updateRestartLogFontSize() {
            localStorage.setItem('restartLogFontSize', this.restartLogFontSize.toString());
            const restartLogContainer = this.$refs.restartLogContainer;
            if (restartLogContainer) {
                restartLogContainer.style.fontSize = `${this.restartLogFontSize}px`;
            }
        },

        /**
         * Update theme
         */
        updateTheme() {
            document.documentElement.setAttribute('data-theme', this.theme);
            localStorage.setItem('theme', this.theme);
        },

        /**
         * Refresh container list
         * @param {boolean} silent - If true, don't show loading indicator
         */
        async refreshContainers(silent = false) {
            const startTime = performance.now();

            if (!silent) {
                this.isLoading = true;
                this.statusText = 'Refreshing...';
            }

            try {
                // Fetch container list
                const containersStartTime = performance.now();
                const containersResponse = await fetch('/api/containers');
                const containersResult = await containersResponse.json();
                const containersTime = performance.now() - containersStartTime;

                if (containersResult.code === 0) {
                    // Process containers
                    this.containers = this.processContainers(containersResult.data);

                    if (!silent) {
                        this.statusText = `Last updated: ${new Date().toLocaleTimeString()} (Containers: ${containersTime.toFixed(0)}ms, GPU loading...)`;
                    }

                    // Fetch GPU usage and container stats asynchronously
                    const gpuStartTime = performance.now();
                    const statsStartTime = performance.now();

                    // Fetch GPU usage
                    fetch('/api/gpu/usage')
                        .then(response => response.json())
                        .then(gpuResult => {
                            const gpuTime = performance.now() - gpuStartTime;

                            if (gpuResult.code === 0) {
                                this.gpuUsage = gpuResult.data || {};
                                console.log(`[GPU] Loaded GPU usage data for ${Object.keys(this.gpuUsage).length} containers`);

                                // Force Alpine to detect the change by creating a new array
                                this.containers = this.updateContainersWithGpu();
                            } else {
                                if (!silent) {
                                    console.warn('GPU info failed:', gpuResult.message);
                                }
                            }
                        })
                        .catch(error => {
                            console.error('Failed to fetch GPU usage:', error);
                        });

                    // Fetch container stats
                    fetch('/api/containers/stats')
                        .then(response => response.json())
                        .then(statsResult => {
                            const statsTime = performance.now() - statsStartTime;

                            if (statsResult.code === 0) {
                                this.containerStats = statsResult.data || {};
                                console.log(`[Stats] Loaded container stats for ${Object.keys(this.containerStats).length} containers`);

                                // Force Alpine to detect the change by creating a new array
                                this.containers = this.updateContainersWithStats();

                                const totalTime = performance.now() - startTime;
                                const gpuTime = performance.now() - gpuStartTime;
                                this.statusText = `Last updated: ${new Date().toLocaleTimeString()} (Total: ${totalTime.toFixed(0)}ms, GPU: ${gpuTime.toFixed(0)}ms, Stats: ${statsTime.toFixed(0)}ms)`;
                            } else {
                                if (!silent) {
                                    console.warn('Container stats failed:', statsResult.message);
                                    this.statusText = `Last updated: ${new Date().toLocaleTimeString()} (Stats info failed)`;
                                }
                            }
                        })
                        .catch(error => {
                            console.error('Failed to fetch container stats:', error);
                            if (!silent) {
                                this.statusText = `Last updated: ${new Date().toLocaleTimeString()} (Stats info error)`;
                            }
                        });
                } else {
                    this.statusText = `Error: ${containersResult.message}`;
                }
            } catch (error) {
                console.error('Failed to refresh containers:', error);
                this.statusText = `Error: ${error.message}`;
            } finally {
                if (!silent) {
                    this.isLoading = false;
                }
            }
        },

        /**
         * Process raw container data
         * @param {Array} rawContainers - Raw container data from API
         * @returns {Array} Processed containers
         */
        processContainers(rawContainers) {
            return rawContainers.map(container => {
                const shortId = container.Id.substring(0, 12);
                const created = new Date(container.Created);
                const createdFormatted = this.formatDate(created);

                // Extract GPU devices
                const gpuDevices = this.extractGpuDevices(container);

                // Extract entrypoint
                const entrypoint = container.Entrypoint || [];
                const entrypointDisplay = Array.isArray(entrypoint)
                    ? entrypoint.join(' ')
                    : entrypoint;

                // Format PortBindings display
                const portBindingsDisplay = this.formatPortBindings(container.NetworkMode, container.PortBindings);

                return {
                    ...container,
                    shortId,
                    createdFormatted,
                    gpuDevices,
                    entrypointDisplay,
                    portBindingsDisplay,
                    memUsageDisplay: '-',  // Will be updated by updateContainersWithStats
                    cpuDisplay: '-',  // Will be updated by updateContainersWithStats
                    stats: null,
                    gpuInfo: null,
                    gpuMemoryDisplay: '-',
                    gpuTooltip: ''
                };
            });
        },

        /**
         * Find container stats by matching ID (full ID or short ID)
         * @param {string} containerId - Full container ID
         * @param {string} shortId - Short container ID (first 12 chars)
         * @returns {Object|null} Container stats object or null
         */
        findContainerStats(containerId, shortId) {
            // Try full ID first
            let containerStats = this.containerStats[containerId] || null;

            // If not found and ID is longer than 12 chars, try short ID
            if (!containerStats && containerId.length > 12) {
                containerStats = this.containerStats[shortId] || null;
            }

            // If still not found, try to match by prefix or suffix
            if (!containerStats) {
                for (const key in this.containerStats) {
                    if (containerId.startsWith(key) || key.startsWith(shortId)) {
                        containerStats = this.containerStats[key];
                        console.log(`[Stats Match] Container ${shortId} matched stats via key: ${key}`);
                        break;
                    }
                }
            }

            return containerStats;
        },

        /**
         * Update containers with stats information
         * @returns {Array} Updated containers array
         */
        updateContainersWithStats() {
            return this.containers.map(container => {
                const shortId = container.shortId || container.Id.substring(0, 12);
                const stats = this.findContainerStats(container.Id, shortId);

                // Preserve existing GPU info if available
                const containerGpuInfo = container.gpuInfo || this.findGpuInfo(container.Id, shortId);
                let gpuMemoryDisplay = container.gpuMemoryDisplay || '-';
                let gpuTooltip = container.gpuTooltip || '';

                // Update GPU display if GPU info is available
                if (containerGpuInfo && containerGpuInfo.total_memory_mib > 0) {
                    const memoryMB = containerGpuInfo.total_memory_mib || 0;
                    const memoryGB = (memoryMB / 1024).toFixed(3);
                    gpuMemoryDisplay = `${memoryGB} GB`;
                    if (containerGpuInfo.gpu_processes && containerGpuInfo.gpu_processes.length > 0) {
                        const uniqueGpuIds = [...new Set(containerGpuInfo.gpu_processes.map(proc => proc.gpu_id))];
                        if (uniqueGpuIds.length > 1) {
                            const gpuDetails = containerGpuInfo.gpu_processes.map(proc => {
                                const memoryMib = proc.memory_mib || 0;
                                const memoryGb = memoryMib > 0 ? (memoryMib / 1024).toFixed(3) : '0.000';
                                return `${proc.gpu_id}: ${memoryGb}GB`;
                            }).join('<br>');
                            gpuMemoryDisplay = `${memoryGB} GB<br>${gpuDetails}`;
                        }
                        gpuTooltip = JSON.stringify(containerGpuInfo.gpu_processes, null, 2);
                    }
                }

                if (stats) {
                    // Format memory usage display: "10.11 / 64GB"
                    const memUsageGB = (stats.mem_usage_bytes / (1024 ** 3)).toFixed(2);
                    const memLimitGB = (stats.mem_limit_bytes / (1024 ** 3)).toFixed(2);
                    const memUsageDisplay = `${memUsageGB} / ${memLimitGB}GB`;

                    // Format CPU percentage: "15.80%"
                    const cpuDisplay = `${stats.cpu_percent.toFixed(2)}%`;

                    return {
                        ...container,
                        memUsageDisplay,
                        cpuDisplay,
                        stats,
                        gpuInfo: containerGpuInfo,
                        gpuMemoryDisplay,
                        gpuTooltip
                    };
                } else {
                    return {
                        ...container,
                        memUsageDisplay: '-',
                        cpuDisplay: '-',
                        stats: null,
                        gpuInfo: containerGpuInfo,
                        gpuMemoryDisplay,
                        gpuTooltip
                    };
                }
            });
        },

        /**
         * Extract GPU devices from container
         * @param {Object} container - Container object
         * @returns {string} GPU devices string
         */
        extractGpuDevices(container) {
            if (!container.GpuDevices || container.GpuDevices.length === 0) {
                return '-';
            }

            return container.GpuDevices.join(', ');
        },

        /**
         * Format PortBindings display
         * @param {string} networkMode - Network mode (e.g., 'host', 'bridge', 'law_net')
         * @param {Object} portBindings - Port bindings object
         * @returns {string} Formatted port bindings string
         */
        formatPortBindings(networkMode, portBindings) {
            if (!networkMode) {
                return '-';
            }

            // If network mode is 'host', PortBindings is empty
            if (networkMode === 'host') {
                return `host`;
            }

            // For other network modes, show NetworkMode and port mappings
            const lines = [networkMode];

            if (portBindings && Object.keys(portBindings).length > 0) {
                // Sort port bindings for consistent display
                const sortedPorts = Object.keys(portBindings).sort();
                sortedPorts.forEach(portKey => {
                    const bindings = portBindings[portKey];
                    if (bindings && bindings.length > 0) {
                        // Extract protocol (tcp/udp) from port key (e.g., "9997/tcp")
                        const parts = portKey.split('/');
                        const containerPort = parts[0];
                        const protocol = parts.length > 1 ? parts[1] : 'tcp';

                        bindings.forEach(binding => {
                            const hostPort = binding.HostPort || '';
                            if (hostPort) {
                                lines.push(` ${protocol} ${hostPort}:${containerPort}`);
                            }
                        });
                    }
                });
            }

            return lines.join('\n');
        },

        /**
         * Format Memory display
         * @param {number} memoryBytes - Memory limit in bytes (0 means unlimited)
         * @param {number} memorySwapBytes - Memory+Swap limit in bytes (0 means unlimited)
         * @returns {string} Formatted memory string
         */
        formatMemory(memoryBytes, memorySwapBytes) {
            if (!memoryBytes || memoryBytes === 0) {
                return 'Unlimited';
            }

            // Convert bytes to MB and GB
            const memoryMB = memoryBytes / (1024 * 1024);
            const memoryGB = memoryMB / 1024;

            // Format: "MB (GB)" or just "MB" if less than 1GB
            if (memoryGB >= 1) {
                return `${Math.round(memoryMB)} MB (${memoryGB.toFixed(2)} GB)`;
            } else {
                return `${Math.round(memoryMB)} MB`;
            }
        },

        /**
         * Find GPU info for a container by matching ID (full ID or short ID)
         * @param {string} containerId - Full container ID
         * @param {string} shortId - Short container ID (first 12 chars)
         * @returns {Object|null} GPU info object or null
         */
        findGpuInfo(containerId, shortId) {
            // Try full ID first
            let containerGpuInfo = this.gpuUsage[containerId] || null;

            // If not found and ID is longer than 12 chars, try short ID
            if (!containerGpuInfo && containerId.length > 12) {
                containerGpuInfo = this.gpuUsage[shortId] || null;
            }

            // If still not found, try to match by prefix or suffix
            if (!containerGpuInfo) {
                for (const key in this.gpuUsage) {
                    if (containerId.startsWith(key) || key.startsWith(shortId)) {
                        containerGpuInfo = this.gpuUsage[key];
                        console.log(`[GPU Match] Container ${shortId} matched GPU info via key: ${key}`);
                        break;
                    }
                }
            }

            return containerGpuInfo;
        },

        /**
         * Update containers with GPU information
         * @returns {Array} Updated containers array
         */
        updateContainersWithGpu() {
            return this.containers.map(container => {
                const shortId = container.shortId || container.Id.substring(0, 12);
                const containerGpuInfo = this.findGpuInfo(container.Id, shortId);

                if (containerGpuInfo && containerGpuInfo.total_memory_mib > 0) {
                    const memoryMB = containerGpuInfo.total_memory_mib || 0;
                    const memoryGB = (memoryMB / 1024).toFixed(3);

                    let gpuMemoryDisplay = `${memoryGB} GB`;
                    let gpuTooltip = '';

                    // Build GPU details
                    // Only show GPU details if there are multiple GPUs
                    if (containerGpuInfo.gpu_processes && containerGpuInfo.gpu_processes.length > 0) {
                        // Get unique GPU IDs
                        const uniqueGpuIds = [...new Set(containerGpuInfo.gpu_processes.map(proc => proc.gpu_id))];

                        // Only show details if there are multiple GPUs
                        if (uniqueGpuIds.length > 1) {
                            const gpuDetails = containerGpuInfo.gpu_processes.map(proc => {
                                const memoryMib = proc.memory_mib || 0;
                                const memoryGb = memoryMib > 0 ? (memoryMib / 1024).toFixed(3) : '0.000';
                                return `${proc.gpu_id}: ${memoryGb}GB`;
                            }).join('<br>');

                            gpuMemoryDisplay = `${memoryGB} GB<br>${gpuDetails}`;
                        }

                        gpuTooltip = JSON.stringify(containerGpuInfo.gpu_processes, null, 2);
                    }

                    return {
                        ...container,
                        gpuInfo: containerGpuInfo,
                        gpuMemoryDisplay,
                        gpuTooltip
                    };
                }

                // Return container with default GPU values if no GPU info
                return {
                    ...container,
                    gpuInfo: null,
                    gpuMemoryDisplay: '-',
                    gpuTooltip: ''
                };
            });
        },

        /**
         * Apply filter to containers
         */
        applyFilter() {
            // Filter is applied in sortedContainers getter
            // This method is called on input to trigger reactivity
        },

        /**
         * Clear filter
         */
        clearFilter() {
            this.filterText = '';
            // Focus back to input after clearing
            this.$nextTick(() => {
                const filterInput = document.getElementById('filterInput');
                if (filterInput) {
                    filterInput.focus();
                }
            });
        },

        /**
         * Check if container matches filter text
         * @param {Object} container - Container object
         * @param {string} filterText - Filter text
         * @returns {boolean} True if container matches filter
         */
        matchesFilter(container, filterText) {
            if (!filterText || !filterText.trim()) {
                return true;
            }

            const searchText = filterText.toLowerCase().trim();

            // Search in multiple fields
            const searchFields = [
                container.Id.substring(0, 12) || '',
                container.shortId || '',
                container.Name || '',
                container.Image || '',
                container.ComposeFile || '',
                container.gpuDevices || '',
                container.memUsageDisplay || '',
                container.cpuDisplay || '',
                container.portBindingsDisplay || '',
                container.entrypointDisplay || '',
                container.gpuMemoryDisplay || ''
            ];

            return searchFields.some(field =>
                field.toLowerCase().includes(searchText)
            );
        },

        /**
         * Get sorted and filtered containers
         * @returns {Array} Sorted and filtered containers
         */
        get sortedContainers() {
            // First apply filter
            let filtered = this.containers;
            if (this.filterText && this.filterText.trim()) {
                filtered = this.containers.filter(container =>
                    this.matchesFilter(container, this.filterText)
                );
            }

            // Then apply sorting
            if (!this.sortColumn) {
                return filtered;
            }

            const sorted = [...filtered].sort((a, b) => {
                let aValue, bValue;

                switch (this.sortColumn) {
                    case 'id':
                        aValue = a.Id || '';
                        bValue = b.Id || '';
                        break;
                    case 'name':
                        aValue = (a.Name || '').toLowerCase();
                        bValue = (b.Name || '').toLowerCase();
                        break;
                    case 'image':
                        aValue = (a.Image || '-').toLowerCase();
                        bValue = (b.Image || '-').toLowerCase();
                        break;
                    case 'created':
                        aValue = new Date(a.Created).getTime();
                        bValue = new Date(b.Created).getTime();
                        break;
                    case 'compose':
                        aValue = (a.ComposeFile || '-').toLowerCase();
                        bValue = (b.ComposeFile || '-').toLowerCase();
                        break;
                    case 'gpu':
                        aValue = a.gpuDevices || '-';
                        bValue = b.gpuDevices || '-';
                        break;
                    case 'memory':
                        aValue = a.gpuInfo ? (a.gpuInfo.total_memory_mib || 0) : 0;
                        bValue = b.gpuInfo ? (b.gpuInfo.total_memory_mib || 0) : 0;
                        break;
                    case 'memusage':
                        // Sort by memory usage bytes
                        aValue = a.stats ? (a.stats.mem_usage_bytes || 0) : -1;
                        bValue = b.stats ? (b.stats.mem_usage_bytes || 0) : -1;
                        break;
                    case 'cpu':
                        // Sort by CPU percentage
                        aValue = a.stats ? (a.stats.cpu_percent || 0) : -1;
                        bValue = b.stats ? (b.stats.cpu_percent || 0) : -1;
                        break;
                    case 'portbindings':
                        aValue = (a.portBindingsDisplay || '-').toLowerCase();
                        bValue = (b.portBindingsDisplay || '-').toLowerCase();
                        break;
                    case 'entrypoint':
                        aValue = (a.entrypointDisplay || '').toLowerCase();
                        bValue = (b.entrypointDisplay || '').toLowerCase();
                        break;
                    default:
                        return 0;
                }

                // Handle empty values
                if (aValue === '-' || aValue === '') aValue = '\uffff';
                if (bValue === '-' || bValue === '') bValue = '\uffff';

                if (aValue < bValue) return this.sortDirection === 'asc' ? -1 : 1;
                if (aValue > bValue) return this.sortDirection === 'asc' ? 1 : -1;
                return 0;
            });

            return sorted;
        },

        /**
         * Sort containers by column
         * @param {string} column - Column name
         */
        sortBy(column) {
            if (this.sortColumn === column) {
                if (this.sortDirection === 'asc') {
                    this.sortDirection = 'desc';
                } else if (this.sortDirection === 'desc') {
                    this.sortColumn = null;
                    this.sortDirection = 'asc';
                }
            } else {
                this.sortColumn = column;
                this.sortDirection = 'asc';
            }
        },

        /**
         * View container logs
         * @param {string} containerId - Container ID
         * @param {string} containerName - Container name
         */
        viewLogs(containerId, containerName) {
            this.logModalTitle = containerName || containerId.substring(0, 12);
            this.currentLogContainerId = containerId;
            this.currentLogContainerName = containerName || containerId;
            this.showLogModal = true;
            this.logConnectionStatus = 'connecting';

            // Clear previous logs
            const logContainer = this.$refs.logContainer;
            if (logContainer) {
                logContainer.innerHTML = '<span class="log-status">Connecting...</span>';
            }

            // Close previous connection
            if (this.currentLogEventSource) {
                this.currentLogEventSource.close();
            }

            // Create new SSE connection with lines parameter
            const encodedIdentifier = encodeURIComponent(this.currentLogContainerName);
            const linesParam = this.logLines > 0 ? `?lines=${this.logLines}` : '?lines=0';
            this.currentLogEventSource = new EventSource(`/api/containers/${encodedIdentifier}/logs${linesParam}`);

            // Handle connection opened
            this.currentLogEventSource.onopen = () => {
                this.logConnectionStatus = 'connected';
                if (logContainer && logContainer.innerHTML.includes('Connecting...')) {
                    logContainer.innerHTML = '<span class="log-status">Connected, waiting for logs...</span>';
                }
            };

            this.currentLogEventSource.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);

                    // Clear status message when first log arrives
                    if (this.logConnectionStatus !== 'receiving') {
                        this.logConnectionStatus = 'receiving';
                        if (logContainer && logContainer.innerHTML.includes('log-status')) {
                            logContainer.innerHTML = '';
                        }
                    }

                    if (data.type === 'log') {
                        this.appendLog(logContainer, data.data, false);
                    } else if (data.type === 'error') {
                        this.appendLog(logContainer, `[Error] ${data.data}\n`, true);
                    } else if (data.type === 'end') {
                        this.appendLog(logContainer, `[Log stream ended, exit code: ${data.exit_code}]\n`, false);
                        this.currentLogEventSource.close();
                        this.currentLogEventSource = null;
                        this.logConnectionStatus = 'connecting';
                    }
                } catch (error) {
                    console.error('Failed to parse log data:', error);
                }
            };

            this.currentLogEventSource.onerror = (event) => {
                if (this.currentLogEventSource.readyState === EventSource.CLOSED) {
                    // Connection closed
                    if (this.logConnectionStatus === 'connecting') {
                        // Connection failed before opening
                        if (logContainer) {
                            logContainer.innerHTML = '<span class="log-status log-error">Connection failed. Please check if the container is running.</span>';
                        }
                    } else {
                        // Connection was open but closed
                        this.appendLog(logContainer, '\n[Connection error, log stream disconnected]\n', true);
                    }
                    this.currentLogEventSource.close();
                    this.currentLogEventSource = null;
                    this.logConnectionStatus = 'connecting';
                }
            };
        },

        /**
         * Append log to log container
         * @param {HTMLElement} container - Log container element
         * @param {string} text - Log text
         * @param {boolean} isError - Is error log
         */
        appendLog(container, text, isError) {
            if (!container) return;

            const span = document.createElement('span');
            span.className = isError ? 'log-error' : 'log-normal';
            span.textContent = text;
            container.appendChild(span);

            // Auto scroll to bottom
            container.scrollTop = container.scrollHeight;
        },

        /**
         * Close log modal
         */
        closeLogModal() {
            this.showLogModal = false;
            this.logConnectionStatus = 'connecting';
            if (this.currentLogEventSource) {
                this.currentLogEventSource.close();
                this.currentLogEventSource = null;
            }
        },

        /**
         * Format date to YYYY-MM-DD HH:mm:ss format
         * @param {Date} date - Date object
         * @returns {string} Formatted date string
         */
        formatDate(date) {
            const year = date.getFullYear();
            const month = String(date.getMonth() + 1).padStart(2, '0');
            const day = String(date.getDate()).padStart(2, '0');
            const hours = String(date.getHours()).padStart(2, '0');
            const minutes = String(date.getMinutes()).padStart(2, '0');
            const seconds = String(date.getSeconds()).padStart(2, '0');
            return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
        },

        /**
         * Format JSON for display
         * @param {Object} obj - Object to format
         * @returns {string} Formatted JSON string
         */
        formatJSON(obj) {
            return JSON.stringify(obj, null, 2);
        },

        /**
         * Copy text to clipboard with fallback for older browsers
         * @param {string} text - Text to copy
         * @returns {Promise<boolean>} True if successful
         */
        async copyToClipboard(text) {
            // Try modern Clipboard API first (requires HTTPS or localhost)
            if (navigator.clipboard && navigator.clipboard.writeText) {
                try {
                    await navigator.clipboard.writeText(text);
                    return true;
                } catch (err) {
                    console.warn('Clipboard API failed, trying fallback:', err);
                }
            }

            // Fallback: use document.execCommand (works in HTTP)
            try {
                const textArea = document.createElement('textarea');
                textArea.value = text;
                textArea.style.position = 'fixed';
                textArea.style.left = '-999999px';
                textArea.style.top = '-999999px';
                document.body.appendChild(textArea);
                textArea.focus();
                textArea.select();

                const successful = document.execCommand('copy');
                document.body.removeChild(textArea);

                if (successful) {
                    return true;
                } else {
                    throw new Error('execCommand copy failed');
                }
            } catch (err) {
                console.error('Fallback copy method failed:', err);
                return false;
            }
        },

        /**
         * Copy container information to clipboard
         * @param {Object} container - Container object
         * @param {Event} event - Click event
         */
        async copyContainerInfo(container, event) {
            try {
                // Format container information as text
                const lines = [
                    `Container ID: ${container.Id}`,
                    `Short ID: ${container.shortId || container.Id.substring(0, 12)}`,
                    `Name: ${container.Name || '-'}`,
                    `Image: ${container.Image || '-'}`,
                    `Created: ${container.createdFormatted || container.Created || '-'}`,
                    `Compose File: ${container.ComposeFile || '-'}`,
                    `GPU Devices: ${container.gpuDevices || '-'}`,
                    `GPU Memory: ${container.gpuMemoryDisplay || '-'}`,
                    `Memory Limit: ${container.memoryDisplay || '-'}`,
                    `Port Bindings:`,
                    container.portBindingsDisplay || '-',
                    `Entrypoint: ${container.entrypointDisplay || '-'}`
                ];

                const text = lines.join('\n');

                // Copy to clipboard using method with fallback
                const success = await this.copyToClipboard(text);

                if (success) {
                    // Show feedback
                    console.log('Container information copied to clipboard');

                    // Show visual feedback
                    if (event && event.target) {
                        const button = event.target;
                        const originalText = button.textContent;
                        button.textContent = 'Copied!';
                        button.style.backgroundColor = '#28a745';
                        setTimeout(() => {
                            button.textContent = originalText;
                            button.style.backgroundColor = '';
                        }, 1000);
                    }
                } else {
                    throw new Error('All copy methods failed');
                }
            } catch (error) {
                console.error('Failed to copy container information:', error);
                alert('Failed to copy container information. Please try again or copy manually.');
            }
        },

        /**
         * Restart container
         * @param {string} containerId - Container ID
         * @param {string} containerName - Container name
         */
        restartContainer(containerId, containerName) {
            this.pendingRestartContainerId = containerId;
            this.pendingRestartContainerName = containerName;
            this.passwordModalTitle = containerName || containerId.substring(0, 12);
            this.usernameInput = 'admin';
            this.passwordInput = '';
            this.passwordError = '';
            this.showPasswordModal = true;
        },

        /**
         * Confirm password and start restart
         */
        async confirmPassword() {
            if (!this.usernameInput || !this.usernameInput.trim()) {
                this.passwordError = 'Please enter username';
                return;
            }

            if (!this.passwordInput) {
                this.passwordError = 'Please enter password';
                return;
            }

            this.passwordError = '';
            this.showPasswordModal = false;

            // Show restart log modal
            this.restartLogModalTitle = this.pendingRestartContainerName || this.pendingRestartContainerId.substring(0, 12);
            this.showRestartLogModal = true;
            this.restartStatus = 'Restarting container...';
            this.restartError = false;
            this.showRestartActions = false;
            this.isRestarting = true;

            const restartLogContainer = this.$refs.restartLogContainer;
            if (restartLogContainer) {
                restartLogContainer.innerHTML = '';
            }

            // Execute restart with SSE
            await this.executeRestart(this.pendingRestartContainerId, this.usernameInput.trim(), this.passwordInput, restartLogContainer);
        },

        /**
         * Execute restart using SSE stream
         * @param {string} containerId - Container ID
         * @param {string} username - Username
         * @param {string} password - Password
         * @param {HTMLElement} logContainer - Log container element
         */
        async executeRestart(containerId, username, password, logContainer) {
            try {
                const response = await fetch(`/api/containers/${containerId}/restart/stream`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });

                if (!response.ok) {
                    throw new Error(`HTTP error: ${response.status}`);
                }

                // Read SSE stream
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let buffer = '';

                this.currentRestartReader = reader;

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;

                    buffer += decoder.decode(value, { stream: true });
                    const lines = buffer.split('\n');
                    buffer = lines.pop() || '';

                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            try {
                                const data = JSON.parse(line.substring(6));
                                this.handleRestartEvent(data, logContainer);
                            } catch (error) {
                                console.error('Failed to parse restart event:', error);
                            }
                        }
                    }
                }
            } catch (error) {
                console.error('Restart failed:', error);
                this.appendLog(logContainer, `[Error] ${error.message}`, true);
                this.restartStatus = `Restart failed: ${error.message}`;
                this.restartError = true;
                this.showRestartActions = true;
                this.isRestarting = false;
            } finally {
                this.currentRestartReader = null;
            }
        },

        /**
         * Handle restart SSE event
         * @param {Object} data - Event data
         * @param {HTMLElement} logContainer - Log container element
         */
        handleRestartEvent(data, logContainer) {
            if (data.type === 'step') {
                this.appendLog(logContainer, `[Step] ${data.message}\n`, false);

                if (data.step === 'password_verified') {
                    this.restartStatus = 'Password verified, starting restart...';
                } else if (data.step === 'down_start') {
                    this.restartStatus = 'Executing docker compose down...';
                } else if (data.step === 'down_completed') {
                    this.restartStatus = 'docker compose down completed, starting up...';
                } else if (data.step === 'up_start') {
                    this.restartStatus = 'Executing docker compose up -d...';
                } else if (data.step === 'up_completed') {
                    this.restartStatus = 'docker compose up completed, refreshing list...';
                }
            } else if (data.type === 'output') {
                this.appendLog(logContainer, data.data, data.stream === 'stderr');
            } else if (data.type === 'success') {
                this.appendLog(logContainer, '[Success] Restart completed successfully!\n', false);
                this.restartStatus = 'Restart successful!';
                this.restartError = false;
                this.showRestartActions = true;
                this.isRestarting = false;

                // Refresh container list
                setTimeout(() => {
                    this.refreshContainers();
                }, 1000);
            } else if (data.type === 'error') {
                this.appendLog(logContainer, `[Error] ${data.data}\n`, true);
                this.restartStatus = `Restart failed: ${data.data}`;
                this.restartError = true;
                this.showRestartActions = true;
                this.isRestarting = false;
            }
        },

        /**
         * Retry restart
         */
        retryRestart() {
            this.closeRestartLogModal();
            this.restartContainer(this.pendingRestartContainerId, this.pendingRestartContainerName);
        },

        /**
         * Close password modal
         */
        closePasswordModal() {
            this.showPasswordModal = false;
            this.passwordInput = '';
            this.passwordError = '';
        },

        /**
         * Close restart log modal
         */
        closeRestartLogModal() {
            this.showRestartLogModal = false;
            this.restartStatus = '';
            this.restartError = false;
            this.showRestartActions = false;
            this.isRestarting = false;

            // Close reader if active
            if (this.currentRestartReader) {
                this.currentRestartReader.cancel();
                this.currentRestartReader = null;
            }
        },

        /**
         * Setup column resize functionality
         */
        setupColumnResize() {
            // This will be called after Alpine initializes
            this.$nextTick(() => {
                const table = document.querySelector('.containers-table');
                if (!table) return;

                // Setup column resizing
                const resizers = table.querySelectorAll('.resizer');
                resizers.forEach(resizer => {
                    const th = resizer.parentElement;
                    let isResizing = false;
                    let startX = 0;
                    let startWidth = 0;

                    resizer.addEventListener('mousedown', (e) => {
                        isResizing = true;
                        startX = e.pageX;
                        startWidth = th.offsetWidth;
                        document.addEventListener('mousemove', handleMouseMove);
                        document.addEventListener('mouseup', handleMouseUp);
                        e.preventDefault();
                    });

                    const handleMouseMove = (e) => {
                        if (!isResizing) return;
                        const diff = e.pageX - startX;
                        const newWidth = Math.max(30, startWidth + diff);
                        th.style.width = `${newWidth}px`;

                        // Save to localStorage
                        const column = th.getAttribute('data-column');
                        if (column) {
                            const widths = JSON.parse(localStorage.getItem('columnWidths') || '{}');
                            widths[column] = newWidth;
                            localStorage.setItem('columnWidths', JSON.stringify(widths));
                        }
                    };

                    const handleMouseUp = () => {
                        isResizing = false;
                        document.removeEventListener('mousemove', handleMouseMove);
                        document.removeEventListener('mouseup', handleMouseUp);
                    };
                });

                // Load saved column widths
                const savedWidths = JSON.parse(localStorage.getItem('columnWidths') || '{}');
                Object.keys(savedWidths).forEach(column => {
                    const th = table.querySelector(`th[data-column="${column}"]`);
                    if (th) {
                        th.style.width = `${savedWidths[column]}px`;
                    }
                });

                // Setup GPU tooltip
                this.setupGpuTooltip();
            });
        },

        /**
         * Setup GPU tooltip functionality
         */
        setupGpuTooltip() {
            // Get or create global tooltip element
            let tooltip = document.getElementById('global-gpu-tooltip');
            if (!tooltip) {
                tooltip = document.createElement('div');
                tooltip.id = 'global-gpu-tooltip';
                tooltip.className = 'gpu-tooltip';
                document.body.appendChild(tooltip);
            }

            // Use event delegation for dynamic content
            const table = document.querySelector('.containers-table');
            if (!table) return;

            table.addEventListener('mouseover', (e) => {
                const cell = e.target.closest('.gpu-memory-cell.has-tooltip');
                if (!cell) {
                    tooltip.style.display = 'none';
                    return;
                }

                const tooltipContent = cell.getAttribute('data-tooltip');
                if (!tooltipContent) {
                    tooltip.style.display = 'none';
                    return;
                }

                // Set tooltip content
                tooltip.textContent = tooltipContent;
                tooltip.style.display = 'block';

                // Position tooltip
                const cellRect = cell.getBoundingClientRect();
                const cellCenterX = cellRect.left + cellRect.width / 2;
                const cellTop = cellRect.top;
                const cellBottom = cellRect.bottom;

                // Calculate position
                tooltip.style.visibility = 'hidden';
                tooltip.style.opacity = '0';
                tooltip.style.left = cellCenterX + 'px';
                tooltip.style.top = '0px';
                tooltip.style.transform = 'translateX(-50%)';

                requestAnimationFrame(() => {
                    const tooltipRect = tooltip.getBoundingClientRect();
                    const tooltipHeight = tooltipRect.height;
                    const tooltipWidth = tooltipRect.width;

                    let top, left;

                    // Check if there's space above
                    if (cellTop - tooltipHeight - 20 > 20) {
                        top = cellTop - tooltipHeight - 10;
                    } else {
                        top = cellBottom + 10;
                    }

                    left = cellCenterX;

                    // Check boundaries
                    if (left + tooltipWidth / 2 > window.innerWidth - 20) {
                        left = window.innerWidth - tooltipWidth / 2 - 20;
                    }
                    if (left - tooltipWidth / 2 < 20) {
                        left = tooltipWidth / 2 + 20;
                    }

                    tooltip.style.top = top + 'px';
                    tooltip.style.left = left + 'px';
                    tooltip.style.visibility = 'visible';
                    tooltip.style.opacity = '1';
                });
            });

            table.addEventListener('mouseout', (e) => {
                const cell = e.target.closest('.gpu-memory-cell.has-tooltip');
                if (cell) {
                    // Check if mouse is moving to tooltip
                    const relatedTarget = e.relatedTarget;
                    if (!relatedTarget || !relatedTarget.closest('.gpu-tooltip')) {
                        tooltip.style.display = 'none';
                    }
                }
            });

            // Hide tooltip when mouse leaves tooltip
            tooltip.addEventListener('mouseleave', () => {
                tooltip.style.display = 'none';
            });
        }
    };
}
