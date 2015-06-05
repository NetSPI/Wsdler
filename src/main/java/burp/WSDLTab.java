package burp;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class WSDLTab extends AbstractTableModel implements IMessageEditorController {

    private final List<WSDLEntry> entries = new ArrayList<WSDLEntry>();
    public WSDLTable wsdlTable;
    public EachRowEditor rowEditor = new EachRowEditor(wsdlTable);
    private IMessageEditor requestViewer;
    private IHttpRequestResponse currentlyDisplayedItem;
    JSplitPane splitPane;
    JTabbedPane tabbedPane;

    public WSDLTab(final IBurpExtenderCallbacks callbacks, JTabbedPane tabbedPane, String request) {
        this.tabbedPane = tabbedPane;
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        wsdlTable = new WSDLTable(WSDLTab.this);
        wsdlTable.setAutoCreateRowSorter(true);

                rowEditor = new EachRowEditor(wsdlTable);
        JScrollPane scrollPane = new JScrollPane(wsdlTable);

        splitPane.setLeftComponent(scrollPane);

        JTabbedPane tabs = new JTabbedPane();
        requestViewer = callbacks.createMessageEditor(WSDLTab.this, false);
        tabs.addTab("Request", requestViewer.getComponent());
        splitPane.setTopComponent(scrollPane);
        splitPane.setBottomComponent(tabs);
        tabbedPane.add(request, splitPane);
        tabbedPane.setTabComponentAt(WSDLParserTab.tabCount - WSDLParserTab.removedTabCount, new ButtonTabComponent(tabbedPane));

    }

    public void addEntry(WSDLEntry entry) {
        synchronized (entries) {
            int row = entries.size();
            entries.add(entry);
            fireTableRowsInserted(row, row);
            UIManager.put("tabbedPane.selected",
                    new javax.swing.plaf.ColorUIResource(Color.RED));
        }
    }

    public int getRowCount() {
        return entries.size();
    }

    public int getColumnCount() {
        return 3;
    }

    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "Operation";
            case 1:
                return "Binding";
            case 2:
                return "Endpoint";
            default:
                return "";
        }
    }

    public Class getColumnClass(int columnIndex) {
        return getValueAt(0, columnIndex).getClass();
    }

    public Object getValueAt(int rowIndex, int columnIndex) {

        WSDLEntry wsdlEntry = entries.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return wsdlEntry.operationName;
            case 1:
                return wsdlEntry.bindingName;
            case 2:
                return wsdlEntry.endpoints.get(0);
            default:
                return "";
        }
    }

    public boolean isCellEditable(int row, int col) {
        return col >= 2;
    }

    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    private class WSDLTable extends JTable {

        public WSDLTable(TableModel tableModel) {
            super(tableModel);
        }

        public void changeSelection(int row, int col, boolean toggle, boolean extend) {

            WSDLEntry wsdlEntry = entries.get(super.convertRowIndexToModel(row));
            requestViewer.setMessage(wsdlEntry.request, true);
            currentlyDisplayedItem = wsdlEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }

        private boolean painted;

        public void paint(Graphics g) {
            super.paint(g);

            if (!painted) {
                painted = true;
                splitPane.setResizeWeight(.30);
                splitPane.setDividerLocation(0.30);
            }
        }
    }

 }
