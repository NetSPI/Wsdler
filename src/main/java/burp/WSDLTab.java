package burp;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class WSDLTab extends AbstractTableModel implements ITab, IMessageEditorController {

  private final List<WSDLEntry> entries = new ArrayList<WSDLEntry>();
  public WSDLTable wsdlTable;
  public EachRowEditor rowEditor = new EachRowEditor(wsdlTable);
  private JSplitPane splitPane;
  private IMessageEditor requestViewer;
  private IHttpRequestResponse currentlyDisplayedItem;

  public WSDLTab(final IBurpExtenderCallbacks callbacks) {
    callbacks.setExtensionName("WSDL Parser");

    splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

    wsdlTable = new WSDLTable(WSDLTab.this);
    rowEditor = new EachRowEditor(wsdlTable);
    JScrollPane scrollPane = new JScrollPane(wsdlTable);
    splitPane.setLeftComponent(scrollPane);

    JTabbedPane tabs = new JTabbedPane();
    requestViewer = callbacks.createMessageEditor(WSDLTab.this, false);
    tabs.addTab("Request", requestViewer.getComponent());
    splitPane.setRightComponent(tabs);

    callbacks.customizeUiComponent(splitPane);
    callbacks.customizeUiComponent(wsdlTable);
    callbacks.customizeUiComponent(scrollPane);
    callbacks.customizeUiComponent(tabs);

    callbacks.addSuiteTab(WSDLTab.this);

  }

  public void addEntry(WSDLEntry entry) {
    synchronized (entries) {
      int row = entries.size();
      entries.add(entry);
      fireTableRowsInserted(row, row);
      //create combobox if there are more than one service URLs.
      //not really needed anymore.
    /*  if (entry.endpoints.size() > 1) {
        JComboBox<String> combo = createComboBox(entry);
        rowEditor.setEditorAt(row, new DefaultCellEditor(combo));
        wsdlTable.getColumnModel().getColumn(2).setCellEditor(rowEditor);
      }*/
    }
  }

  public JComboBox createComboBox(WSDLEntry entry) {
    JComboBox<String> comboBox = new JComboBox<String>();
    for (String endpoint : entry.endpoints) {
      comboBox.addItem(endpoint);
    }
    return comboBox;
  }

  @Override
  public int getRowCount() {
    return entries.size();
  }

  @Override
  public int getColumnCount() {
    return 3;
  }

  @Override
  public String getColumnName(int columnIndex) {
    switch (columnIndex) {
      case 0:
        return "Binding";
      case 1:
        return "Operation";
      case 2:
        return "Endpoint";
      default:
        return "";
    }
  }

  @Override
  public Class getColumnClass(int columnIndex) {
    return getValueAt(0, columnIndex).getClass();
  }

  @Override
  public Object getValueAt(int rowIndex, int columnIndex) {
    WSDLEntry wsdlEntry = entries.get(rowIndex);

    switch (columnIndex) {
      case 0:
        return wsdlEntry.bindingName;
      case 1:
        return wsdlEntry.operationName;
      case 2:
        return wsdlEntry.endpoints.get(0);
      default:
        return "";
    }
  }

  public boolean isCellEditable(int row, int col) {
    if (col < 2) {
      return false;
    } else {
      return true;
    }
  }

  @Override
  public byte[] getRequest() {
    return currentlyDisplayedItem.getRequest();
  }

  @Override
  public byte[] getResponse() {
    return currentlyDisplayedItem.getResponse();
  }

  @Override
  public IHttpService getHttpService() {
    return currentlyDisplayedItem.getHttpService();
  }

  @Override
  public String getTabCaption() {
    return "WSDLer";
  }

  @Override
  public Component getUiComponent() {
    return splitPane;
  }

  private class WSDLTable extends JTable {

    public WSDLTable(TableModel tableModel) {
      super(tableModel);

    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {

      WSDLEntry wsdlEntry = entries.get(row);
      requestViewer.setMessage(wsdlEntry.request, true);
      currentlyDisplayedItem = wsdlEntry.requestResponse;
      super.changeSelection(row, col, toggle, extend);
    }
  }
}
