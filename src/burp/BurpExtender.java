package burp;

import java.awt.Component;
import java.awt.Dimension;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.prefs.Preferences;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JToggleButton;
import javax.swing.SpringLayout;
import javax.swing.SwingUtilities;
import javax.swing.JFileChooser;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;



public class BurpExtender implements IBurpExtender, IScannerCheck, ActionListener,ITab,IProxyListener,IScannerInsertionPointProvider//IIntruderPayloadGeneratorFactory,IIntruderPayloadProcessor
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    //our scanExtender
    private ScanExtender scanExtend;

    //UI Stuffs
    private JPanel mPane;
    private JToggleButton isEnabled = new JToggleButton("Enable");
    private JToggleButton debugLog  = new JToggleButton("Verbose Output");
    private JButton loadDefs;
    private JButton unloadDefs;
    private JButton reloadDefs;
    private JTable table;
    private CustomTableModel model;
    
    //table view size
    private int VPORT_WIDTH = 800;
    private int VPORT_HEIGHT = 300;
    
    //table col size
    private int ENABLED_WIDTH = 60;
    private int NAME_WIDTH = 200;
    private int DESCRIPTION_WIDTH = 450;
    private int TYPE_WIDTH = 90;
    
    //table cols
    private int ENABLED_COL = 0;
    private int NAME_COL = 1;
    private int DESCRIPTION_COL = 2;
    private int TYPE_COL = 3;
    private int HASHCODE_COL = 4;
    
    //actions
    private String LOAD_DEFS = "0";
    private String UNLOAD_DEFS = "1";
    private String RELOAD_DEFS = "2";
    
    // test / grep strings
    private static final byte[] INJ_TEST = "turds".getBytes();
    private static final byte[] INJ_ERROR = "Unexpected pipe".getBytes();
    
    private boolean isPro;
    
    //private values
    String pwd = new File(".").getAbsolutePath();
    
    //get values from registry
    Preferences prefs = Preferences.userNodeForPackage(burp.BurpExtender.class);
    final String PREF_NAME = "brewskiLastDefinitionsPath";
    String lastDefinitionsPath = prefs.get(PREF_NAME, pwd); 
    
    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(),true);
        
        // set our extension name
        callbacks.setExtensionName("BReWSki - JavaScript Extension");
        
        // create our UI
        SwingUtilities.invokeLater(new Runnable() 
        {
            @Override
            public void run()
            {
                // main pane
                mPane = new JPanel();
                
                
                loadDefs = new JButton("Load Definition");
                unloadDefs = new JButton("Unload All Definitions");
                reloadDefs = new JButton("Reload All Definitions");
                
                loadDefs.addActionListener(BurpExtender.this);
                loadDefs.setActionCommand(LOAD_DEFS);
                
                unloadDefs.addActionListener(BurpExtender.this);
                unloadDefs.setActionCommand(UNLOAD_DEFS);
                
                reloadDefs.addActionListener(BurpExtender.this);
                reloadDefs.setActionCommand(RELOAD_DEFS);
                
                JLabel lblTable = new JLabel("Active Plugins");
                
                //create table;
                model = new CustomTableModel();
                table = new JTable(model);
                table.setPreferredScrollableViewportSize(new Dimension(VPORT_WIDTH, VPORT_HEIGHT));
                table.setFillsViewportHeight(true);
                table.getSelectionModel().addListSelectionListener(new RowListener());
                table.getColumnModel().getSelectionModel().addListSelectionListener(new ColumnListener());  
                model.addTableModelListener(new CustomTableModelListener());
                table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
                TableRowSorter<TableModel> sorter = new TableRowSorter<TableModel>(table.getModel());
                table.setRowSorter(sorter);
                //table.getTableHeader().setReorderingAllowed(true);
                model.addColumn("Enabled");
                model.addColumn("Name");
                model.addColumn("Description");
                model.addColumn("Type");
                model.addColumn("hashCode");
                table.getColumn("Enabled").setPreferredWidth(ENABLED_WIDTH);
                table.getColumn("Name").setPreferredWidth(NAME_WIDTH);
                table.getColumn("Description").setPreferredWidth(DESCRIPTION_WIDTH);
                table.getColumn("Type").setPreferredWidth(TYPE_WIDTH);
                
                //hide hashcode column
                table.removeColumn(table.getColumnModel().getColumn(4));
                
                /*JTable is a bitch, so commenting out right click events
                final JPopupMenu popupMenu = new JPopupMenu();
                JMenuItem deleteItem = new JMenuItem("Delete");
                deleteItem.addActionListener(new ActionListener() 
                {

                    @Override
                    public void actionPerformed(ActionEvent e) 
                    {
                        //packrat code for showing a message box
                        //JOptionPane.showMessageDialog(table, "Right-click performed on table and choose DELETE");
                        
                        
                    }
                });
                popupMenu.add(deleteItem);
                table.setComponentPopupMenu(popupMenu);
                */
               
                JScrollPane defsTable = new JScrollPane(table);
                
                try{
                    SpringLayout layout = new SpringLayout();
                    mPane.setLayout(layout);

                    int ypos = 100;
                    int xlabel = 20;

                    //load button
                    layout.putConstraint(SpringLayout.WEST, loadDefs, 15, SpringLayout.WEST, mPane);
                    layout.putConstraint(SpringLayout.NORTH, loadDefs, xlabel, SpringLayout.NORTH, mPane);

                    //unload button
                    layout.putConstraint(SpringLayout.WEST,unloadDefs,15,SpringLayout.EAST,loadDefs);
                    layout.putConstraint(SpringLayout.NORTH, unloadDefs, xlabel, SpringLayout.NORTH, mPane);
                    
                    //reload button
                    layout.putConstraint(SpringLayout.WEST,reloadDefs,15,SpringLayout.EAST,unloadDefs);
                    layout.putConstraint(SpringLayout.NORTH, reloadDefs, xlabel, SpringLayout.NORTH, mPane);                   

                    //Selection Table
                    //layout.putConstraint(SpringLayout.WEST,loadDefs,200,SpringLayout.WEST,defsTable);
                    //.putConstraint(SpringLayout.SOUTH, loadDefs, 300, SpringLayout.NORTH, defsTable);

                    //table label
                    layout.putConstraint(SpringLayout.NORTH, lblTable, 15, SpringLayout.SOUTH, loadDefs);
                    layout.putConstraint(SpringLayout.WEST, lblTable, 20, SpringLayout.WEST, mPane);

                    //plugin table
                    layout.putConstraint(SpringLayout.NORTH, defsTable, 5, SpringLayout.SOUTH, lblTable);
                    layout.putConstraint(SpringLayout.WEST, defsTable, 15, SpringLayout.WEST, mPane);

                    //output text area
                    //layout.putConstraint(SpringLayout.WEST,outText,15,SpringLayout.WEST,mPane);
                    //layout.putConstraint(SpringLayout.NORTH, outText, 10, SpringLayout.SOUTH, loadDefs);

                    //mPane.add(jText);
                    mPane.add(loadDefs);
                    mPane.add(unloadDefs);
                    mPane.add(reloadDefs);
                    mPane.add(defsTable);
                    mPane.add(lblTable);
                    //mPane.add(outText);

                    // customize our UI components
                    callbacks.customizeUiComponent(mPane);

                    // register ourselves as a custom scanner check
                    callbacks.registerScannerCheck(BurpExtender.this);

                    //test register a scan insertion point
                    callbacks.registerScannerInsertionPointProvider(BurpExtender.this);
                                        
                    // add the custom tab to Burp's UI
                    callbacks.addSuiteTab(BurpExtender.this);

                    callbacks.registerProxyListener(BurpExtender.this);
                    
                    // register ourselves as an Intruder payload generator
                    //callbacks.registerIntruderPayloadGeneratorFactory(BurpExtender.this);

                    // register ourselves as an Intruder payload processor
                    //callbacks.registerIntruderPayloadProcessor(BurpExtender.this);

                    scanExtend = new ScanExtender(stdout,stderr);


               }catch (Exception e){
                    stdout.println("something bad happened when building UI");
                }
                
                //load defs by default
                scanExtend.loadScanFiles(lastDefinitionsPath);
                loadTable(); // Put valutes into UI
            }
        });
   
        isPro = isPro();
    }
    
    private boolean isPro()
    {
        //String currentJar = new java.io.File(IBurpExtender.class.getProtectionDomain().getCodeSource().getLocation().getPath()).getName();       
        if(callbacks.getBurpVersion()[0].equals("Burp Suite Professional"))
            return true;
        else
        {
            stdout.println("Free version detected. Passive vulnerabilites will be logged to the console. No active checks are conducted. Note that line numbers include the response headers in the count.");
            //stdout.println(callbacks.getBurpVersion()[0]);
            return false;
        }
    }
    
    //something wonky is going on here, i thought maybe it was threading thing
    //so i added in the invoke later, but its still messed up, breaks afer unloadTable()...
    private void loadTable(){
        try{
            SwingUtilities.invokeLater (new Runnable() 
            {
                @Override
                public void run()
                {        
                    List<ScanItem> scanItems = scanExtend.getScanItems();
                    //CustomTableModel model = (CustomTableModel)table.getModel();
                    
                    //clear out the table to avoid dupes showing
                    unloadTable();
                    
                    for(ScanItem item: scanItems)
                    {
                        model.addRow(new Object[] {true, item.getIssueName(), item.getIssueDescription(), item.getIssueType(),item.hashCode()});
                        
                    }
                }
 
            });
        }catch(Exception ex){
            stderr.println(ex.toString());
        }
    }
    

    private void unloadTable(){
        // remove all rows from the table
        model.setRowCount(0);
    }
    
    private class CustomTableModelListener implements TableModelListener {
    @Override 
        public void tableChanged(TableModelEvent e) {
            //check if we are updating the table (deleting all the items)
            //this was tossing an error in some instances
            if(e.getType() == e.UPDATE)
            {
                int modifiedRow = table.getSelectedRow();
                if(modifiedRow != -1)
                {

                    int hashCode = (int)table.getModel().getValueAt(modifiedRow, HASHCODE_COL);
                    boolean modifiedValue = (boolean)model.getValueAt(modifiedRow, ENABLED_COL);
                    scanExtend.setScanItem(hashCode, modifiedValue);
               }
            }
         }
    }
      
    private class RowListener implements ListSelectionListener {
        public void valueChanged(ListSelectionEvent event) {
            if (event.getValueIsAdjusting()) {
                return;
            }
        }
    }
    
    private class ColumnListener implements ListSelectionListener {
        public void valueChanged(ListSelectionEvent event) {
            if (event.getValueIsAdjusting()) {
                return;
            }
        }
    }
   
    
    // helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    private List<int[]> getMatches(byte[] response, byte[] match)
    {
        List<int[]> matches = new ArrayList<int[]>();

        
        
        int start = 0;
        while (start < response.length)
        {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }
        
        return matches;
    }

    
  
    
    //
    // implement IIntruderPayloadGeneratorFactory
    //
    /*THIS SECTION IS NOT CURRENTLY NEEDED -- not sure if we'll use it
    @Override
    public String getGeneratorName()
    {
        return "BReWSki Generated";
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack)
    {
        try {
            // return a new IIntruderPayloadGenerator to generate payloads for this attack
            return new IntruderPayloadGenerator();
        } catch (IOException ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    //
    // implement IIntruderPayloadProcessor
    //
    
    @Override
    public String getProcessorName()
    {
        return "Serialized input wrapper";
    }

    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue)
    {
        // decode the base value
        String dataParameter = helpers.bytesToString(helpers.base64Decode(helpers.urlDecode(baseValue)));
        
        // parse the location of the input string in the decoded data
        int start = dataParameter.indexOf("input=") + 6;
        if (start == -1)
            return currentPayload;
        String prefix = dataParameter.substring(0, start);
        int end = dataParameter.indexOf("&", start);
        if (end == -1)
            end = dataParameter.length();
        String suffix = dataParameter.substring(end, dataParameter.length());
        
        // rebuild the serialized data with the new payload
        dataParameter = prefix + helpers.bytesToString(currentPayload) + suffix;
        return helpers.stringToBytes(helpers.urlEncode(helpers.base64Encode(dataParameter)));
    }*/
    
    //
    // class to generate payloads from a simple list
    //
    
    /*class IntruderPayloadGenerator implements IIntruderPayloadGenerator
    {
        int payloadIndex;
        
        List<String> lines;
        private byte[][] payloads;

        IntruderPayloadGenerator() throws IOException {
            this.payloads = new byte[10][100];
            payloads[0] = "a".getBytes();
            payloads[1] = "b".getBytes();
            
            //not reading -- need to just read from RhinoJS
            /*this.lines = Files.readAllLines(Paths.get("C:\\Apps\\Burp\\wordlists\\raft-10000-directoriesandfiles.txt"),  Charset.defaultCharset());
            
            int index = 0;
            for(String line : this.lines)
            {
                payloads[index] = line.getBytes();
                System.out.println();
            }*/
            
        /*}
        
        //for (String line : lines) {
        //    System.out.println(line);
        //}
        
        byte[] a = "a".getBytes();
        byte[] b = "b".getBytes();
        
        
        
        @Override
        public boolean hasMorePayloads()
        {
            return payloadIndex < payloads.length;
        }

        @Override
        public byte[] getNextPayload(byte[] baseValue)
        {
            byte[] payload = payloads[payloadIndex];
            payloadIndex++;
            return payload;
        }

        @Override
        public void reset()
        {
            payloadIndex = 0;
        }*/
    //}
    
    //
    // implement IScannerCheck
    //
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        // look for matches of our passive check grep string
        //List<int[]> matches = getMatches(baseRequestResponse.getResponse(), GREP_STRING);

        //turn the request into a string to pass into our javascript test
        String resString = helpers.bytesToString(baseRequestResponse.getResponse());
        String resURL = helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
        List<ScanIssue> results;
        results = scanExtend.doPassiveScan(resString,resURL);
        
        if (!results.isEmpty())
        {   
            List<IScanIssue> issues = new ArrayList<>();
            //iterate over our results
            for(ScanIssue result: results){
                // report the issue
                issues.add(new CustomScanIssue(
                        //if passive checks are ever performed here by active scans, it may need to use get the request/response from the result object (esult.requestRespons), like the active scan object returns currently
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, result.requestMarkers, result.responseMarkers) }, 
                        result.issueName,
                        result.issueDetail,
                        result.issueBackground,
                        result.issueRemediation,
                        result.issueSeverity,
                        result.issueConfidence));
                
                if(!isPro)
                {
                    //Log issue to console
                    this.stdout.println("=====================ISSUE FOUND=====================");
                    this.stdout.println("Issue Name: " + result.issueName);
                    this.stdout.println("Issue Severity: " + result.issueSeverity);
                    this.stdout.println("Issue Detail: " + result.issueDetail);
                    this.stdout.println("Issue Background: " + result.issueBackground);
                    
                    this.stdout.println("Location: " + helpers.analyzeRequest(baseRequestResponse).getUrl());
                    
                    //log affected portion of response
                    this.stdout.println("Response:");
                    for(int[] markers: result.responseMarkers)
                    {
                        //get line number
                        Pattern p = Pattern.compile("\n");
                        Matcher m = p.matcher(resString.substring(0, markers[0]));
                        int count = 0;
                        int lastIndex = markers[0];
                        while (m.find())
                        { 
                            count++;
                        }

                        String flaggedString = resString.substring(markers[0], markers[1]);

                        //trim if over 300 chars
                        if(flaggedString.length() > 300)
                            flaggedString = flaggedString.substring(0, 300) + "...";

                        this.stdout.println("  Line " + count + ": "+ flaggedString);
                    }
                    
                    //repeat for request
                    this.stdout.println("Request:");
                    for(int[] markers: result.requestMarkers)
                    {
                        String reqString = helpers.bytesToString(baseRequestResponse.getResponse());
                        //get line number
                        Pattern p = Pattern.compile("\n");
                        Matcher m = p.matcher(reqString.substring(0, markers[0]));
                        int count = 0;
                        int lastIndex = markers[0];
                        while (m.find())
                        { 
                            count++;
                        }

                        String flaggedString = reqString.substring(markers[0], markers[1]);

                        //trim if over 300 chars
                        if(flaggedString.length() > 300)
                            flaggedString = flaggedString.substring(0, 300) + "...";

                        this.stdout.println("  Line " + count + ": "+ flaggedString);
                    }
                    this.stdout.println("=====================================================");

                }
            }
            return issues;
        }
        else return null;
    }
    

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message)
    {
        //Thinking this is the place to know to do once-per-host scans.
        
        //Do Passive Scan
        if(!messageIsRequest && !isPro)
        {
            //stdout.println(message.getMessageInfo())
            doPassiveScan(message.getMessageInfo());
        }
    }
    
    


    //called once for each insertion point - interface defined in iScannerCheck
    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        List<ScanIssue> results = scanExtend.doActiveScan(baseRequestResponse, insertionPoint, callbacks);
        
        if (!results.isEmpty())
        {   
            List<IScanIssue> issues = new ArrayList<>();
            //iterate over our results
            for(ScanIssue result: results){
                // report the issue
                issues.add(new CustomScanIssue( 
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                        new IHttpRequestResponse[] {baseRequestResponse, callbacks.applyMarkers(result.requestResponse, result.requestMarkers, result.responseMarkers)}, 
                        result.issueName,
                        result.issueDetail,
                        result.issueBackground,
                        result.issueRemediation,
                        result.issueSeverity,
                        result.issueConfidence));
            }
            return issues;
        }
        else return null;
    }
    

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        // This method is called when multiple issues are reported for the same URL 
        // path by the same extension-provided check. The value we return from this 
        // method determines how/whether Burp consolidates the multiple issues
        // to prevent duplication
        //
        // Since the issue name is sufficient to identify our issues as different,
        // if both issues have the same name, only report the existing issue
        // otherwise report both issues
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }
    
    
    //
    // implement ITab
    //

    @Override
    public String getTabCaption()
    {
        return "BReWSki";
    }

    @Override
    public Component getUiComponent()
    {
        return mPane;
    }
    
    
    @Override
    public void actionPerformed(ActionEvent evt)
    {
        //do stuff
        
        
        if(evt.getActionCommand().equals(LOAD_DEFS))
        {  
            JFileChooser chooser = new JFileChooser(lastDefinitionsPath);
            /*this override of chooser allows the file chooser but reject file selections
            {
                
              public void approveSelection() 
              {
                if (getSelectedFile().isFile()) 
                {
                    return;
                } 
                else
                    super.approveSelection();
                }  
            };*/
            
            FileNameExtensionFilter filter = new FileNameExtensionFilter("Scan Definition Directory or File", "def");
            chooser.setFileFilter(filter);
            chooser.setFileSelectionMode(chooser.FILES_AND_DIRECTORIES); 
            //chooser.setMultiSelectionEnabled(true); //this would allow individual file multi-selection
            chooser.setSelectedFile(new File(lastDefinitionsPath));
            //chooser.setFileSelectionMode(chooser.DIRECTORIES_ONLY);  //this hides the files but it allows the "load definition" reload to be easier...
            int returnVal = chooser.showOpenDialog(null);
            if(returnVal == JFileChooser.APPROVE_OPTION) {
                stdout.println("Loading Scan Definition Files: " + chooser.getSelectedFile().getAbsolutePath());
                lastDefinitionsPath = chooser.getSelectedFile().getAbsolutePath();
                scanExtend.loadScanFiles(chooser.getSelectedFile().getAbsolutePath());
                loadTable(); // Put valutes into UI
                
                //update registry
                prefs.put(PREF_NAME, lastDefinitionsPath);
            }
           
        }
        else if(evt.getActionCommand().equals(UNLOAD_DEFS))
        {
            scanExtend.unloadScanDefinitions();
            stdout.println("Unloaded all scan definitions.");
            unloadTable(); 
        }
        else if(evt.getActionCommand().equals(RELOAD_DEFS))
        {
            //will need to reload all items that are currently loaded, unload
            //the table, then reload the table with the new scan items in the
            //instance that the name, description has been updated.
            scanExtend.reloadScanDefinitions();
            stdout.println("reloaded all scan definitions.");
            unloadTable();
            loadTable();
        }
        
    }
    
    
     /**
     * When a request is actively scanned, the Scanner will invoke this method,
     * and the provider should provide a list of custom insertion points that
     * will be used in the scan. <b>Note:</b> these insertion points are used in
     * addition to those that are derived from Burp Scanner's configuration, and
     * those provided by any other Burp extensions.
     *
     * @param baseRequestResponse The base request that will be actively
     * scanned.
     * @return A list of
     * <code>IScannerInsertionPoint</code> objects that should be used in the
     * scanning, or
     * <code>null</code> if no custom insertion points are applicable for this
     * request.
     */
    @Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse)
    {
        List<IScannerInsertionPoint> insertionPoints = scanExtend.getInsertionPoints(baseRequestResponse, callbacks);
        
        if (!insertionPoints.isEmpty())
        {   
            stdout.println("returning insertion points");
            return insertionPoints;
        }
        else 
        {
            stdout.println("returning null (insertion points)");
            return null;
        }
    }

    
}//end burp extender class

//
// class implementing IScanIssue to hold our custom scan issue details
//
//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String background;
    private String remediation;
    private String severity;
    private String confidence;

    public CustomScanIssue(
            IHttpService httpService,
            URL url, 
            IHttpRequestResponse[] httpMessages, 
            String name,
            String detail,
            String background,
            String remediation,
            String severity,
            String confidence)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.background = background;
        this.remediation = remediation;
        this.severity = severity;
        this.confidence = confidence;
    }
    
    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return confidence;
    }

    @Override
    public String getIssueBackground()
    {
        return background;
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        return detail;
    }

    @Override
    public String getRemediationDetail()
    {
        return remediation;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }
    
    

    
    
    
    
}

class CustomTableModel extends DefaultTableModel
{

    @Override
    public Class<?> getColumnClass(int column)
    {
        try{
        if(getValueAt(0,column).getClass() == Boolean.class )
            return Boolean.class;
        if(getValueAt(0,column).getClass() == Integer.class)
            return Integer.class;
        return String.class;
        }catch(Exception ex)
        {
            return String.class;
        }
    }                  
    
    @Override
    public boolean isCellEditable(int row, int column) {
       //all non-checkboxes uneditable
       if(column > 0)
            return false;
       else
           return true;
    }
}
