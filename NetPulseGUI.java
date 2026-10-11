import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

/**
 * NetPulse: Multi-Threaded Network Port & Security Audit Tool
 * 
 * Main Graphical User Interface and Application Entry Point.
 * Built with standard Java Swing and concurrent multithreading.
 */
public class NetPulseGUI extends JFrame {

    // Theme & UI Colors
    private static final Color BG_DARK = new Color(24, 27, 33);
    private static final Color BG_CARD = new Color(33, 37, 45);
    private static final Color BG_INPUT = new Color(42, 47, 57);
    private static final Color TEXT_PRIMARY = new Color(240, 243, 246);
    private static final Color TEXT_MUTED = new Color(145, 155, 168);
    private static final Color ACCENT_BLUE = new Color(59, 130, 246);
    private static final Color COLOR_SAFE = new Color(34, 197, 94);
    private static final Color COLOR_CAUTION = new Color(245, 158, 11);
    private static final Color COLOR_HIGH = new Color(239, 68, 68);
    private static final Color COLOR_INFO = new Color(59, 130, 246);

    // Input Controls
    private JTextField hostField;
    private JRadioButton rangeModeRadio;
    private JRadioButton specificModeRadio;
    private JSpinner startPortSpinner;
    private JSpinner endPortSpinner;
    private JTextField customPortsField;
    private JSlider timeoutSlider;
    private JLabel timeoutValueLabel;
    private JComboBox<String> threadPoolCombo;

    // Action Buttons
    private JButton scanButton;
    private JButton stopButton;
    private JButton exportButton;
    private JButton clearButton;

    // Preset Buttons
    private JButton webPresetBtn;
    private JButton wellKnownBtn;
    private JButton dbPresetBtn;
    private JButton criticalBtn;

    // Status & Progress Feedback
    private JProgressBar progressBar;
    private JLabel statusLabel;
    private JLabel statsSummaryLabel;

    // Results Table & Filter
    private JTextField searchFilterField;
    private DefaultTableModel tableModel;
    private JTable resultsTable;
    private TableRowSorter<DefaultTableModel> tableSorter;

    // Scan State
    private ScannerWorker activeWorker;
    private final List<ScanResult> recordedResults = new ArrayList<>();
    private long scanStartTime = 0;

    public NetPulseGUI() {
        setTitle("AetherScan — Multi-Threaded Network Port & Security Audit Tool");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1080, 720);
        setMinimumSize(new Dimension(860, 580));
        setLocationRelativeTo(null);

        initComponents();
    }

    private void initComponents() {
        // Root Panel
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBackground(BG_DARK);
        mainPanel.setBorder(new EmptyBorder(12, 14, 12, 14));

        // Top Area: Header Banner + Config Panels
        JPanel topContainer = new JPanel();
        topContainer.setLayout(new BoxLayout(topContainer, BoxLayout.Y_AXIS));
        topContainer.setBackground(BG_DARK);

        topContainer.add(createHeaderBanner());
        topContainer.add(Box.createVerticalStrut(10));
        topContainer.add(createConfigPanel());
        topContainer.add(Box.createVerticalStrut(8));
        topContainer.add(createPresetBar());

        mainPanel.add(topContainer, BorderLayout.NORTH);

        // Center Area: Table Results + Filter Bar
        mainPanel.add(createResultsCenterPanel(), BorderLayout.CENTER);

        // Bottom Area: Progress Bar, Status Label, Action Controls
        mainPanel.add(createBottomPanel(), BorderLayout.SOUTH);

        setContentPane(mainPanel);
    }

    /**
     * Header banner introducing tool name and mission
     */
    private JPanel createHeaderBanner() {
        JPanel banner = new JPanel(new BorderLayout());
        banner.setBackground(BG_CARD);
        banner.setBorder(new CompoundBorder(
                new LineBorder(new Color(50, 56, 68), 1, true),
                new EmptyBorder(10, 14, 10, 14)
        ));

        JLabel titleLabel = new JLabel("AetherScan: Multi-Threaded Network Port & Security Audit Tool");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
        titleLabel.setForeground(TEXT_PRIMARY);

        JLabel subLabel = new JLabel("Asynchronous Multi-Threaded TCP Port Scanner & Vulnerability Risk Analyzer");
        subLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        subLabel.setForeground(new Color(203, 213, 225)); // High-contrast crisp subtitle

        JPanel leftTitles = new JPanel(new GridLayout(2, 1, 2, 4));
        leftTitles.setOpaque(false);
        leftTitles.add(titleLabel);
        leftTitles.add(subLabel);

        statsSummaryLabel = new JLabel("Status: Idle");
        statsSummaryLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        statsSummaryLabel.setForeground(new Color(96, 165, 250)); // Bright readable blue

        banner.add(leftTitles, BorderLayout.WEST);
        banner.add(statsSummaryLabel, BorderLayout.EAST);
        return banner;
    }

    /**
     * Input control configuration panel (Host, Ports, Timeout, Concurrency)
     */
    private JPanel createConfigPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(BG_CARD);
        panel.setBorder(new CompoundBorder(
                new LineBorder(new Color(50, 56, 68), 1, true),
                new EmptyBorder(12, 14, 12, 14)
        ));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 6, 5, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Row 0: Target Host and Port Mode
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        panel.add(createLabel("Target Host:"), gbc);

        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        hostField = new JTextField("127.0.0.1", 15);
        styleTextField(hostField);
        panel.add(hostField, gbc);

        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0;
        panel.add(createLabel("Port Selection:"), gbc);

        gbc.gridx = 3; gbc.gridy = 0; gbc.gridwidth = 3; gbc.weightx = 0.8;
        JPanel radioPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        radioPanel.setOpaque(false);
        rangeModeRadio = new JRadioButton("Port Range", true);
        rangeModeRadio.setForeground(TEXT_PRIMARY);
        rangeModeRadio.setFont(new Font("Segoe UI", Font.BOLD, 14));
        rangeModeRadio.setOpaque(false);
        rangeModeRadio.setFocusPainted(false);

        specificModeRadio = new JRadioButton("Specific Ports / Preset", false);
        specificModeRadio.setForeground(TEXT_PRIMARY);
        specificModeRadio.setFont(new Font("Segoe UI", Font.BOLD, 14));
        specificModeRadio.setOpaque(false);
        specificModeRadio.setFocusPainted(false);

        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(rangeModeRadio);
        modeGroup.add(specificModeRadio);

        rangeModeRadio.addActionListener(e -> setPortMode(true));
        specificModeRadio.addActionListener(e -> setPortMode(false));

        radioPanel.add(rangeModeRadio);
        radioPanel.add(specificModeRadio);
        panel.add(radioPanel, gbc);

        gbc.gridwidth = 1; // reset

        // Row 1: Start Port & End Port vs Custom Port List
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        panel.add(createLabel("Start Port:"), gbc);

        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 0.3;
        startPortSpinner = new JSpinner(new SpinnerNumberModel(1, 1, 65535, 1));
        styleSpinner(startPortSpinner);
        panel.add(startPortSpinner, gbc);

        gbc.gridx = 2; gbc.gridy = 1; gbc.weightx = 0;
        panel.add(createLabel("End Port:"), gbc);

        gbc.gridx = 3; gbc.gridy = 1; gbc.weightx = 0.3;
        endPortSpinner = new JSpinner(new SpinnerNumberModel(1024, 1, 65535, 1));
        styleSpinner(endPortSpinner);
        panel.add(endPortSpinner, gbc);

        gbc.gridx = 4; gbc.gridy = 1; gbc.weightx = 0;
        panel.add(createLabel("Specific Ports:"), gbc);

        gbc.gridx = 5; gbc.gridy = 1; gbc.weightx = 1.0;
        customPortsField = new JTextField("80, 443, 8080", 15);
        customPortsField.setEnabled(false);
        styleTextField(customPortsField);
        panel.add(customPortsField, gbc);

        // Row 2: Timeout Slider & Concurrency
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        panel.add(createLabel("Timeout (ms):"), gbc);

        gbc.gridx = 1; gbc.gridy = 2; gbc.weightx = 1.0;
        JPanel timeoutPanel = new JPanel(new BorderLayout(6, 0));
        timeoutPanel.setOpaque(false);
        timeoutSlider = new JSlider(50, 2000, 200);
        timeoutSlider.setBackground(BG_CARD);
        timeoutSlider.setForeground(TEXT_PRIMARY);
        timeoutValueLabel = new JLabel("200 ms");
        timeoutValueLabel.setForeground(TEXT_PRIMARY);
        timeoutValueLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        timeoutValueLabel.setPreferredSize(new Dimension(65, 22));
        timeoutSlider.addChangeListener(e -> timeoutValueLabel.setText(timeoutSlider.getValue() + " ms"));
        timeoutPanel.add(timeoutSlider, BorderLayout.CENTER);
        timeoutPanel.add(timeoutValueLabel, BorderLayout.EAST);
        panel.add(timeoutPanel, gbc);

        gbc.gridx = 2; gbc.gridy = 2; gbc.weightx = 0;
        panel.add(createLabel("Thread Pool:"), gbc);

        gbc.gridx = 3; gbc.gridy = 2; gbc.gridwidth = 3; gbc.weightx = 0.6;
        String[] threads = {"25 Threads", "50 Threads (Recommended)", "100 Threads (High Speed)", "150 Threads"};
        threadPoolCombo = new JComboBox<>(threads);
        threadPoolCombo.setSelectedIndex(1); // default 50
        styleComboBox(threadPoolCombo);
        panel.add(threadPoolCombo, gbc);

        return panel;
    }

    private void setPortMode(boolean isRange) {
        startPortSpinner.setEnabled(isRange);
        endPortSpinner.setEnabled(isRange);
        customPortsField.setEnabled(!isRange);
        if (!isRange) {
            customPortsField.requestFocus();
        }
    }

    /**
     * Preset buttons for convenient one-click target port sets
     */
    private JPanel createPresetBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        bar.setOpaque(false);

        JLabel presetLabel = new JLabel("Quick Scan Presets:");
        presetLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        presetLabel.setForeground(TEXT_PRIMARY);
        bar.add(presetLabel);

        webPresetBtn = createPillButton("Web Ports (80, 443, 8080)", new Color(56, 189, 248)); // #38BDF8 Cyan/Blue
        webPresetBtn.addActionListener(e -> applyPreset("WEB"));
        bar.add(webPresetBtn);

        wellKnownBtn = createPillButton("Standard Well-Known (1–1024)", new Color(168, 85, 247)); // #A855F7 Purple
        wellKnownBtn.addActionListener(e -> applyPreset("WELL_KNOWN"));
        bar.add(wellKnownBtn);

        dbPresetBtn = createPillButton("Database Ports (3306, 5432, 27017)", new Color(245, 158, 11)); // #F59E0B Amber
        dbPresetBtn.addActionListener(e -> applyPreset("DATABASE"));
        bar.add(dbPresetBtn);

        criticalBtn = createPillButton("Critical Infrastructure (21, 22, 23...)", new Color(239, 68, 68)); // #EF4444 Red
        criticalBtn.addActionListener(e -> applyPreset("CRITICAL"));
        bar.add(criticalBtn);

        return bar;
    }

    /**
     * Center results table with color rendering and filter field
     */
    private JPanel createResultsCenterPanel() {
        JPanel centerPanel = new JPanel(new BorderLayout(0, 8));
        centerPanel.setOpaque(false);

        // Search Filter Toolbar
        JPanel filterBar = new JPanel(new BorderLayout(8, 0));
        filterBar.setOpaque(false);

        JLabel filterLabel = new JLabel("Live Filter Results:");
        filterLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        filterLabel.setForeground(TEXT_PRIMARY);

        searchFilterField = new JTextField(20);
        styleTextField(searchFilterField);
        searchFilterField.setToolTipText("Filter results by port, service name, risk level (Safe, Caution, High), or advisory");
        searchFilterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyTableFilter(); }
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyTableFilter(); }
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyTableFilter(); }
        });

        filterBar.add(filterLabel, BorderLayout.WEST);
        filterBar.add(searchFilterField, BorderLayout.CENTER);
        centerPanel.add(filterBar, BorderLayout.NORTH);

        // Table Model definition
        String[] columnNames = {"Port", "Service Name", "Status", "Latency (ms)", "Risk Level", "Security Advisory"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // read-only results table
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0 || columnIndex == 3) {
                    return Integer.class;
                }
                return String.class;
            }
        };

        resultsTable = new JTable(tableModel);
        resultsTable.setBackground(BG_CARD);
        resultsTable.setForeground(TEXT_PRIMARY);
        resultsTable.setSelectionBackground(new Color(45, 55, 72));
        resultsTable.setSelectionForeground(Color.WHITE);
        resultsTable.setRowHeight(28); // 28px comfortable row height
        resultsTable.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        resultsTable.setGridColor(new Color(48, 54, 65));
        resultsTable.setShowVerticalLines(true);
        resultsTable.setShowHorizontalLines(true);

        // Custom Header Renderer ensuring bold white visible text on dark background
        resultsTable.getTableHeader().setDefaultRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                                                           boolean isSelected, boolean hasFocus,
                                                           int row, int column) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                l.setBackground(new Color(42, 47, 61));
                l.setForeground(Color.WHITE);
                l.setFont(new Font("Segoe UI", Font.BOLD, 13)); // 13pt Bold Header
                l.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createMatteBorder(0, 0, 2, 1, new Color(55, 65, 85)),
                        BorderFactory.createEmptyBorder(8, 10, 8, 10)
                ));
                l.setOpaque(true);
                return l;
            }
        });
        resultsTable.getTableHeader().setReorderingAllowed(false);
        resultsTable.getTableHeader().setPreferredSize(new Dimension(0, 36));

        // Sorting & filtering
        tableSorter = new TableRowSorter<>(tableModel);
        resultsTable.setRowSorter(tableSorter);

        // Set column widths
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(75);
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(130);
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(75);
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(95);
        resultsTable.getColumnModel().getColumn(4).setPreferredWidth(140);
        resultsTable.getColumnModel().getColumn(5).setPreferredWidth(450);

        // Custom Cell Renderer for Color-Coded Risk Levels
        resultsTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                                                           boolean isSelected, boolean hasFocus,
                                                           int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                
                if (!isSelected) {
                    // Alternate row background subtle styling
                    c.setBackground(row % 2 == 0 ? BG_CARD : new Color(28, 32, 40));
                    c.setForeground(TEXT_PRIMARY);
                }

                int modelRow = table.convertRowIndexToModel(row);
                String riskText = (String) tableModel.getValueAt(modelRow, 4);

                // Port column highlight (light sky blue for clear reading)
                if (column == 0) {
                    setFont(getFont().deriveFont(Font.BOLD));
                    c.setForeground(new Color(147, 197, 253));
                } else if (column == 4) {
                    setFont(getFont().deriveFont(Font.BOLD));
                    if (ScanResult.RiskLevel.SAFE.getDisplayName().equalsIgnoreCase(riskText)) {
                        c.setForeground(COLOR_SAFE);
                    } else if (ScanResult.RiskLevel.CAUTION.getDisplayName().equalsIgnoreCase(riskText)) {
                        c.setForeground(COLOR_CAUTION);
                    } else if (ScanResult.RiskLevel.HIGH.getDisplayName().equalsIgnoreCase(riskText)) {
                        c.setForeground(COLOR_HIGH);
                    } else {
                        c.setForeground(COLOR_INFO);
                    }
                } else if (column == 2) { // Status column
                    setFont(getFont().deriveFont(Font.BOLD));
                    c.setForeground(COLOR_SAFE); // OPEN is always green
                } else if (!isSelected) {
                    c.setForeground(TEXT_PRIMARY);
                }

                setBorder(new EmptyBorder(0, 10, 0, 10));
                return c;
            }
        });

        JScrollPane scrollPane = new JScrollPane(resultsTable);
        scrollPane.getViewport().setBackground(BG_CARD);
        scrollPane.setBorder(new LineBorder(new Color(50, 56, 68), 1));

        centerPanel.add(scrollPane, BorderLayout.CENTER);
        return centerPanel;
    }

    private void applyTableFilter() {
        if (searchFilterField == null || tableSorter == null) return;
        String text = searchFilterField.getText().trim();
        if (text.isEmpty()) {
            tableSorter.setRowFilter(null);
        } else {
            tableSorter.setRowFilter(RowFilter.regexFilter("(?i)" + text));
        }
    }

    /**
     * Bottom control & status bar
     */
    private JPanel createBottomPanel() {
        JPanel bottomPanel = new JPanel(new BorderLayout(8, 8));
        bottomPanel.setOpaque(false);

        // Progress indicators
        JPanel progressPanel = new JPanel(new BorderLayout(6, 4));
        progressPanel.setOpaque(false);

        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setForeground(new Color(22, 163, 74));
        progressBar.setBackground(BG_INPUT);
        progressBar.setFont(new Font("Segoe UI", Font.BOLD, 12));
        progressBar.setPreferredSize(new Dimension(100, 26));

        statusLabel = new JLabel("Ready to scan.");
        statusLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13)); // 13pt Plain status bar
        statusLabel.setForeground(TEXT_PRIMARY);

        progressPanel.add(statusLabel, BorderLayout.NORTH);
        progressPanel.add(progressBar, BorderLayout.SOUTH);

        // Action Buttons Row
        JPanel actionsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 4));
        actionsPanel.setOpaque(false);

        // Clear Results: Slate Dark Blue #334155, border #475569
        clearButton = createActionButton("Clear Results", new Color(51, 65, 85), new Color(71, 85, 105));
        clearButton.addActionListener(e -> clearResults());

        // Export Report: Slate Dark Blue #334155, border #475569
        exportButton = createActionButton("Export Report", new Color(51, 65, 85), new Color(71, 85, 105));
        exportButton.addActionListener(e -> exportReport());

        // Stop / Cancel: Solid Crimson Red #DC2626
        stopButton = createActionButton("Stop / Cancel", new Color(220, 38, 38), new Color(185, 28, 28));
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> cancelActiveScan());

        // Start Scan: Solid Emerald Green #16A34A
        scanButton = createActionButton("Start Scan", new Color(22, 163, 74), new Color(21, 128, 61));
        scanButton.addActionListener(e -> startScan());

        actionsPanel.add(clearButton);
        actionsPanel.add(exportButton);
        actionsPanel.add(stopButton);
        actionsPanel.add(scanButton);

        bottomPanel.add(progressPanel, BorderLayout.CENTER);
        bottomPanel.add(actionsPanel, BorderLayout.EAST);
        return bottomPanel;
    }

    /**
     * Applies preset port selections
     */
    private void applyPreset(String presetType) {
        if ("WELL_KNOWN".equals(presetType)) {
            rangeModeRadio.setSelected(true);
            setPortMode(true);
            startPortSpinner.setValue(1);
            endPortSpinner.setValue(1024);
            statusLabel.setText("Preset Loaded: Standard Well-Known Ports (1–1024). Click 'Start Scan' to begin.");
        } else if ("WEB".equals(presetType)) {
            specificModeRadio.setSelected(true);
            setPortMode(false);
            customPortsField.setText("80, 443, 8000, 8080, 8443, 8888");
            statusLabel.setText("Preset Loaded: Common Web Ports (80, 443, 8000, 8080, 8443, 8888).");
        } else if ("DATABASE".equals(presetType)) {
            specificModeRadio.setSelected(true);
            setPortMode(false);
            customPortsField.setText("1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017");
            statusLabel.setText("Preset Loaded: Database Ports (MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch).");
        } else if ("CRITICAL".equals(presetType)) {
            specificModeRadio.setSelected(true);
            setPortMode(false);
            customPortsField.setText("21, 22, 23, 25, 53, 110, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 8080");
            statusLabel.setText("Preset Loaded: Critical Infrastructure, cleartext shells & remote administration.");
        }
    }

    /**
     * Validates inputs and starts multi-threaded scanning
     */
    private void startScan() {
        String host = hostField.getText().trim();
        if (host.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a valid target host or IP address (e.g. 127.0.0.1 or scanme.nmap.org).",
                    "Input Error", JOptionPane.WARNING_MESSAGE);
            hostField.requestFocus();
            return;
        }

        List<Integer> portList = new ArrayList<>();
        if (rangeModeRadio.isSelected()) {
            int startPort = (Integer) startPortSpinner.getValue();
            int endPort = (Integer) endPortSpinner.getValue();

            if (startPort > endPort) {
                JOptionPane.showMessageDialog(this, "Start Port cannot be greater than End Port.",
                        "Port Range Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (startPort < 1 || endPort > 65535) {
                JOptionPane.showMessageDialog(this, "Port range must be within 1 and 65535.",
                        "Invalid Port Range", JOptionPane.ERROR_MESSAGE);
                return;
            }

            for (int p = startPort; p <= endPort; p++) {
                portList.add(p);
            }
        } else {
            // Specific Ports mode
            String rawPorts = customPortsField.getText().trim();
            if (rawPorts.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please enter port numbers separated by commas (e.g. 80, 443, 8080).",
                        "Port List Empty", JOptionPane.WARNING_MESSAGE);
                customPortsField.requestFocus();
                return;
            }

            String[] tokens = rawPorts.split("[,\\s]+");
            Set<Integer> uniquePorts = new LinkedHashSet<>();
            for (String tok : tokens) {
                if (tok.trim().isEmpty()) continue;
                try {
                    int p = Integer.parseInt(tok.trim());
                    if (p < 1 || p > 65535) {
                        JOptionPane.showMessageDialog(this, "Invalid port number: " + p + ". Must be between 1 and 65535.",
                                "Port Number Out of Bounds", JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                    uniquePorts.add(p);
                } catch (NumberFormatException ex) {
                    JOptionPane.showMessageDialog(this, "Invalid port entry: '" + tok + "'. Must be numeric.",
                            "Port Parse Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
            }
            portList.addAll(uniquePorts);
        }

        if (portList.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No ports selected for audit scan.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        int timeout = timeoutSlider.getValue();
        int threadPool = getSelectedThreadPoolSize();

        // Prepare UI state for scanning
        setScanningState(true);
        scanStartTime = System.currentTimeMillis();

        activeWorker = new ScannerWorker(host, portList, timeout, threadPool, new ScannerWorker.ScanProgressListener() {
            @Override
            public void onScanStarted(int totalPorts) {
                SwingUtilities.invokeLater(() -> {
                    progressBar.setValue(0);
                    progressBar.setString("0% (0 / " + totalPorts + ")");
                    statusLabel.setText(String.format("Connecting to %s with %d threads...", host, threadPool));
                    statsSummaryLabel.setText(String.format("Scanning: %s | Total: %d ports", host, totalPorts));
                });
            }

            @Override
            public void onPortScanned(int scannedCount, int totalPorts, int openCount, int currentPort) {
                SwingUtilities.invokeLater(() -> {
                    int percent = (int) (((double) scannedCount / totalPorts) * 100);
                    progressBar.setValue(percent);
                    progressBar.setString(String.format("%d%% (%d / %d ports) — Open: %d", percent, scannedCount, totalPorts, openCount));
                    statusLabel.setText(String.format("Inspecting port %d... | Open Ports Found: %d", currentPort, openCount));
                });
            }

            @Override
            public void onScanCompleted(int totalPorts, int openCount, boolean wasCancelled) {
                SwingUtilities.invokeLater(() -> {
                    long elapsed = (System.currentTimeMillis() - scanStartTime) / 1000;
                    setScanningState(false);
                    if (wasCancelled) {
                        progressBar.setString("Scan Cancelled by User");
                        statusLabel.setText(String.format("Scan aborted. Scanned ports up to interruption. Open found: %d", openCount));
                    } else {
                        progressBar.setValue(100);
                        progressBar.setString(String.format("Finished (100%%) — %d Open Ports", openCount));
                        statusLabel.setText(String.format("Scan complete in %d seconds! %d open ports detected on %s.", elapsed, openCount, host));
                    }
                    statsSummaryLabel.setText(String.format("Host: %s | Open: %d | Time: %ds", host, openCount, elapsed));
                });
            }

            @Override
            public void onScanError(String errorMessage) {
                SwingUtilities.invokeLater(() -> {
                    setScanningState(false);
                    statusLabel.setText("Error: " + errorMessage);
                    JOptionPane.showMessageDialog(NetPulseGUI.this, errorMessage, "Scan Error", JOptionPane.ERROR_MESSAGE);
                });
            }
        }) {
            @Override
            protected void process(List<ScanResult> chunks) {
                for (ScanResult res : chunks) {
                    recordedResults.add(res);
                    tableModel.addRow(new Object[]{
                            res.getPort(),
                            res.getServiceName(),
                            res.getStatus(),
                            res.getLatencyMs(),
                            res.getRiskLevel().getDisplayName(),
                            res.getSecurityNotes()
                    });
                }
            }
        };

        activeWorker.execute();
    }

    private void cancelActiveScan() {
        if (activeWorker != null && !activeWorker.isDone()) {
            stopButton.setEnabled(false);
            statusLabel.setText("Aborting scan threads, please wait...");
            activeWorker.cancelScan();
        }
    }

    private void clearResults() {
        tableModel.setRowCount(0);
        recordedResults.clear();
        progressBar.setValue(0);
        progressBar.setString("0%");
        statusLabel.setText("Results cleared. Ready to scan.");
        statsSummaryLabel.setText("Status: Idle");
        if (searchFilterField != null) {
            searchFilterField.setText("");
        }
    }

    private int getSelectedThreadPoolSize() {
        int idx = threadPoolCombo.getSelectedIndex();
        switch (idx) {
            case 0: return 25;
            case 1: return 50;
            case 2: return 100;
            case 3: return 150;
            default: return 50;
        }
    }

    private void setScanningState(boolean scanning) {
        scanButton.setEnabled(!scanning);
        stopButton.setEnabled(scanning);
        clearButton.setEnabled(!scanning);
        exportButton.setEnabled(!scanning);
        webPresetBtn.setEnabled(!scanning);
        wellKnownBtn.setEnabled(!scanning);
        dbPresetBtn.setEnabled(!scanning);
        criticalBtn.setEnabled(!scanning);
        hostField.setEnabled(!scanning);
        rangeModeRadio.setEnabled(!scanning);
        specificModeRadio.setEnabled(!scanning);
        startPortSpinner.setEnabled(!scanning && rangeModeRadio.isSelected());
        endPortSpinner.setEnabled(!scanning && rangeModeRadio.isSelected());
        customPortsField.setEnabled(!scanning && specificModeRadio.isSelected());
        timeoutSlider.setEnabled(!scanning);
        threadPoolCombo.setEnabled(!scanning);
    }

    /**
     * Exports table results to a timestamped CSV or TXT file with audit summary
     */
    private void exportReport() {
        if (tableModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(this, "No scan results available to export.",
                    "Export Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        String timeStamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        fileChooser.setSelectedFile(new File("NetPulse_Report_" + timeStamp + ".csv"));

        int choice = fileChooser.showSaveDialog(this);
        if (choice == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (PrintWriter writer = new PrintWriter(new FileWriter(file))) {
                boolean isCsv = file.getName().toLowerCase().endsWith(".csv");

                if (isCsv) {
                    writer.println("Port,Service Name,Status,Latency (ms),Risk Level,Security Advisory");
                    for (int i = 0; i < tableModel.getRowCount(); i++) {
                        writer.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"%n",
                                tableModel.getValueAt(i, 0),
                                tableModel.getValueAt(i, 1),
                                tableModel.getValueAt(i, 2),
                                tableModel.getValueAt(i, 3),
                                tableModel.getValueAt(i, 4),
                                tableModel.getValueAt(i, 5));
                    }
                } else {
                    // Formatted Text Audit Report
                    writer.println("================================================================================");
                    writer.println("           NetPulse Network Reconnaissance & Security Audit Report             ");
                    writer.println("================================================================================");
                    writer.println("Generated on : " + new Date());
                    writer.println("Target Host  : " + hostField.getText().trim());
                    writer.println("Total Open   : " + tableModel.getRowCount());
                    writer.println("--------------------------------------------------------------------------------");
                    writer.printf("%-7s | %-15s | %-8s | %-12s | %-18s | %s%n",
                            "PORT", "SERVICE", "STATUS", "LATENCY", "RISK LEVEL", "SECURITY ADVISORY");
                    writer.println("--------------------------------------------------------------------------------");
                    for (int i = 0; i < tableModel.getRowCount(); i++) {
                        writer.printf("%-7s | %-15s | %-8s | %-12s | %-18s | %s%n",
                                tableModel.getValueAt(i, 0),
                                tableModel.getValueAt(i, 1),
                                tableModel.getValueAt(i, 2),
                                tableModel.getValueAt(i, 3) + " ms",
                                tableModel.getValueAt(i, 4),
                                tableModel.getValueAt(i, 5));
                    }
                    writer.println("================================================================================");
                }

                JOptionPane.showMessageDialog(this, "Audit report successfully saved to:\n" + file.getAbsolutePath(),
                        "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Failed to write report file: " + ex.getMessage(),
                        "File Write Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // UI Helper Methods for modern dark aesthetics
    private JLabel createLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font("Segoe UI", Font.BOLD, 14));
        label.setForeground(TEXT_PRIMARY);
        return label;
    }

    private void styleTextField(JTextField field) {
        field.setBackground(BG_INPUT);
        field.setForeground(TEXT_PRIMARY);
        field.setCaretColor(TEXT_PRIMARY);
        field.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        field.setBorder(new CompoundBorder(
                new LineBorder(new Color(60, 67, 80), 1),
                new EmptyBorder(6, 10, 6, 10)
        ));
    }

    private void styleSpinner(JSpinner spinner) {
        spinner.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        JComponent editor = spinner.getEditor();
        if (editor instanceof JSpinner.DefaultEditor) {
            JTextField tf = ((JSpinner.DefaultEditor) editor).getTextField();
            tf.setBackground(BG_INPUT);
            tf.setForeground(TEXT_PRIMARY);
            tf.setCaretColor(TEXT_PRIMARY);
            tf.setFont(new Font("Segoe UI", Font.PLAIN, 14));
            tf.setBorder(new EmptyBorder(4, 6, 4, 6));
        }
        spinner.setBorder(new LineBorder(new Color(60, 67, 80), 1));
    }

    private void styleComboBox(JComboBox<?> box) {
        box.setUI(new javax.swing.plaf.basic.BasicComboBoxUI() {
            @Override
            protected JButton createArrowButton() {
                JButton button = new javax.swing.plaf.basic.BasicArrowButton(
                    javax.swing.plaf.basic.BasicArrowButton.SOUTH,
                    new Color(30, 34, 45),     // Background of arrow area
                    new Color(75, 85, 105),    // Shadow
                    Color.WHITE,               // Arrow color
                    new Color(75, 85, 105)     // Highlight
                );
                button.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 8));
                button.setContentAreaFilled(false);
                return button;
            }

            @Override
            public void paintCurrentValueBackground(Graphics g, Rectangle bounds, boolean hasFocus) {
                // Paints the background of the selected item box in dark slate
                g.setColor(new Color(30, 34, 45));
                g.fillRect(bounds.x, bounds.y, bounds.width, bounds.height);
            }
        });

        box.setBackground(new Color(30, 34, 45)); // #1E222D Dark Slate
        box.setForeground(Color.WHITE);
        box.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        box.setBorder(BorderFactory.createLineBorder(new Color(75, 85, 105), 1));
        box.setOpaque(true);

        box.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value,
                    int index, boolean isSelected, boolean cellHasFocus) {
                JLabel label = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);

                if (isSelected) {
                    label.setBackground(new Color(37, 99, 235)); // Accent Blue highlight on hover
                    label.setForeground(Color.WHITE);
                } else {
                    label.setBackground(new Color(30, 34, 45));  // Dark background (#1E222D)
                    label.setForeground(Color.WHITE);             // High-contrast white text
                }

                label.setOpaque(true);
                label.setFont(new Font("Segoe UI", Font.PLAIN, 13));
                label.setBorder(BorderFactory.createEmptyBorder(6, 10, 6, 10));
                return label;
            }
        });
    }

    private JButton createActionButton(String text, final Color bg, final Color borderColor) {
        JButton btn = new JButton(text) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                if (getModel().isPressed()) {
                    g2.setColor(bg.darker());
                } else if (getModel().isRollover()) {
                    g2.setColor(bg.brighter());
                } else {
                    g2.setColor(bg);
                }
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                g2.dispose();
                super.paintComponent(g);
            }
        };
        btn.setFont(new Font("Segoe UI", Font.BOLD, 14));
        btn.setForeground(Color.WHITE);
        btn.setOpaque(false);
        btn.setContentAreaFilled(false);
        btn.setFocusPainted(false);
        btn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(borderColor != null ? borderColor : bg.darker(), 1, true),
                BorderFactory.createEmptyBorder(8, 18, 8, 18)
        ));
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        return btn;
    }

    private JButton createPillButton(String text, final Color accentBorder) {
        final Color normalBg = new Color(30, 34, 45); // #1E222D dark sleek chip background
        JButton btn = new JButton(text) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                if (getModel().isPressed()) {
                    g2.setColor(accentBorder.darker());
                } else if (getModel().isRollover()) {
                    g2.setColor(accentBorder);
                } else {
                    g2.setColor(normalBg);
                }
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                g2.dispose();
                super.paintComponent(g);
            }
        };
        btn.setFont(new Font("Segoe UI", Font.BOLD, 13));
        btn.setForeground(Color.WHITE); // Pure White #FFFFFF
        btn.setOpaque(false);
        btn.setContentAreaFilled(false);
        btn.setFocusPainted(false);
        btn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(accentBorder, 2, true), // 1.5px/2px category outline
                BorderFactory.createEmptyBorder(6, 12, 6, 12)
        ));
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        return btn;
    }

    /**
     * Application Entry Point
     */
    public static void main(String[] args) {
        // Apply System Look and Feel
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {}

        SwingUtilities.invokeLater(() -> {
            NetPulseGUI gui = new NetPulseGUI();
            gui.setVisible(true);
        });
    }
}
