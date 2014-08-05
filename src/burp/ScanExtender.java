/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package burp;

import java.io.PrintWriter;
import java.io.File;
import java.io.FilenameFilter;
import java.io.FileNotFoundException;
import java.util.Scanner;
import java.util.List;
import java.util.ArrayList;
import java.util.Collection;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.script.Bindings;

/**
 *
 * @author cbellows
 */
public class ScanExtender {
    
    private PrintWriter stdout;
    private PrintWriter stderr;
    private List<ScanItem> scanItems = new ArrayList<>();
    
    public ScanExtender(PrintWriter stdout, PrintWriter stderr){
                this.stderr = stderr;
                this.stdout = stdout;
        
    }
    
    
    //get all scan loaded items
    public List<ScanItem> getScanItems(){ 
        return scanItems;
    }
    
    public void setScanItem(int hashCode, boolean value){ 
       // scanItems.get(index).setEnabled(value) ;
       // stdout.println("looking for: "+ hashCode);
        for(int i=0;i<scanItems.size();i++)
        {
            if(scanItems.get(i).hashCode()==hashCode)
            {
               // stdout.println("Found it!");
                scanItems.get(i).setEnabled(value);
            }
        }
        
    }
    
    //load a scan file from a given path
    public boolean loadScanFile(String fpath){
        
        ScanItem sI = new ScanItem(); 
        String script = "";
        try{
        script = readFile(fpath);
        sI.setScanScript(script);
        sI.scanFilePath = fpath;
        int lastSlash = sI.scanFilePath.lastIndexOf("/");
        if(sI.scanFilePath.lastIndexOf("\\") > lastSlash)
        {
            lastSlash = sI.scanFilePath.lastIndexOf("\\");
        }
        
        sI.scanFileName = sI.scanFilePath.substring(lastSlash+1);
        
        }catch(Exception ex){
            stderr.println("Something bad happened when trying to load a scan file:");
            stderr.println(ex.toString());
            return false;
        }
        
        //we have to execute the script to get the value for the table
        ScriptEngineManager factory = new ScriptEngineManager();
        ScriptEngine engine = factory.getEngineByName("JavaScript");
        try {
            //add a response var to our script to avoid error on initial eval
            //may be a performance hit since the script is fully eval'd but I would rather
            //toss an error here and not load it in vs waste time trying to scan with it
            engine.put("response","");
            engine.eval(script);
        } catch (ScriptException ex) {
            stderr.println(ex.toString());
            //Logger.getLogger(ScanExtender.class.getName()).log(Level.SEVERE, null, ex);
        }                    

        //need to handle exceptions here incase these items are not defined
        sI.setIssueName((String)engine.get("name"));
        if(sI.getIssueName() == null)
        {
            stderr.println("Error Loading Definition: 'name' variable (var name) does not exist");
            return false;
        }
        
        sI.setIssueDescription((String)engine.get("description"));
        if(sI.getIssueDetail() == null)
        {
            stderr.println("Error Loading Definition: 'description' variable (var description) does not exist");
            return false;
        }
        
        sI.setIssueType((String)engine.get("type"));
        if(sI.getIssueType() == null)
        {
            stderr.println("Error Loading Definition: 'type' variable (var type) does not exist");
            return false;
        }
        if(sI.getIssueType().toLowerCase().equals("active"))
        {
            sI.setInjectionVal((String)engine.get("injection_value"));
                    if(sI.getInjectionVal()== null)
                    {
                        stderr.println("Error Loading Definition: 'injection_value' variable (var injection_value) does not exist");
                        return false;
                    }
        }  
        scanItems.add(sI);
        stdout.println("Loaded: "+sI.scanFileName);
        return true;
     }
    
    public void unloadScanDefinitions(){
        scanItems = new ArrayList<>();
    }
    
    public void reloadScanDefinitions(){
        //temp items list to hold our currently loaded items
        List<ScanItem> tItems = scanItems;
        
        //unload the currently loaded items
        unloadScanDefinitions();
        for(ScanItem sI: tItems)
        {
            loadScanFile(sI.scanFilePath);
        }
        
    }

    
    //load scan files from a given directory, returns how many were loaded
    public int loadScanFiles(String path){
        
       // List<ScanItem> sItems = new ArrayList<>();
        File dPath = new File(path);
        
        //setup a file name filter to only load ".def" files
        FilenameFilter fFilter;
        fFilter = new FilenameFilter(){
            @Override
            public boolean accept(File dir, String name){
                return name.toLowerCase().endsWith(".def");
            }
        };
        
        int lCount = 0;
        //check that we are looking at a directory
        if(dPath.isDirectory()){
            
            File[] files = dPath.listFiles(fFilter);
            for (File file : files) {
                boolean temp = false;
                temp = loadScanFile(file.getAbsolutePath());
                if(temp){
                    lCount++;
                }
            }
            
        }
        //otherwise we are looking at a file
        else
        {
            boolean temp = false;
            temp = loadScanFile(dPath.getAbsolutePath());
            if(temp)
                lCount++;
        }
        
        return lCount;
    }
    
    public List<ScanIssue> doPassiveScan(String response, String URL){
        
        List<ScanIssue> issues = new ArrayList<>();
        
        for(ScanItem item: scanItems){
            //only use scanItems that are enabled
          if(item.getEnabled() && item.getIssueType().toLowerCase().equals("passive"))
            {
                //stdout.println(input);
                ScanIssue t = execScan(item, "", response, URL);
                if(t != null){
                   //debug: stdout.println(item.scanFileName + " found an issue");
                   issues.add(t);
                }
            }
        }
        
        return issues;
        
    }
      
    public List<ScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, IBurpExtenderCallbacks callbacks){
        
        List<ScanIssue> issues = new ArrayList<>();
        
        for(ScanItem item : scanItems)
        {
            if(item.getEnabled() && item.getIssueType().toLowerCase().equals("active"))
            {
                // make a request containing our injection test in the insertion point
                //leaving debug outputs here until buildRequest is fixed
                //stdout.println("2: " + item.getInjectionVal());
                //stdout.println("3: " + callbacks.getHelpers().bytesToString(callbacks.getHelpers().stringToBytes(item.getInjectionVal())));
                
                //stdout.println("4: " + new String(callbacks.getHelpers().stringToBytes(item.getInjectionVal())));//values are not encoded here
                
                byte[] checkRequest = insertionPoint.buildRequest(callbacks.getHelpers().stringToBytes(item.getInjectionVal()));

                //stdout.println("5: " + new String(checkRequest)); //values are encoded here.
                
                stdout.println("Doing Custom Scan");
                stdout.println(new String(checkRequest));
                IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                //execPassiveScan(item,new String(checkRequestResponse.getResponse()));
                ScanIssue t = execScan(item, new String(checkRequestResponse.getRequest()), new String(checkRequestResponse.getResponse()), callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl().toString());
                if(t != null){
                    //capture the request response object so we can use it in reporting
                   t.requestResponse = checkRequestResponse;
                   stdout.println("Found an issue! " + item.scanFileName);
                   issues.add(t);
                }
            }
        }
        return issues;
        
    }
    
    //read a file given a File object
    private String readFile(String fpath){
        try{
            // Reads until it hits EOF "\\Z"
            String fileContents = new Scanner(new File(fpath)).useDelimiter("\\Z").next();
            return fileContents;
        }catch(FileNotFoundException ex){
            stderr.println("File Not Found: " + fpath);
            return null;
        }
        
    }
    
                     
    
    //executes a javascript statement and expects to find a boolean value in the
    // "result" variable.
    private ScanIssue execScan(ScanItem inputScan, String request, String response, String URL){
        ScriptEngineManager factory = new ScriptEngineManager();
        ScriptEngine engine = factory.getEngineByName("JavaScript");
       // StringWriter sw = new StringWriter();
        
        boolean ret = false;
        ScanIssue sIssue = new ScanIssue();
        
        try{
          //  engine.getContext().setWriter(sw);
            engine.put("request",request);
            engine.put("response",response);
            engine.put("url", URL);
            //stdout.println(inputString);
            engine.eval(inputScan.getScanScript());
            
            //retreive all of the scan issue variables
            try{
                ret = (boolean)engine.get("result");
            }catch(Exception ex){
                stderr.println("Error getting script result var.");
                stderr.println("File: " + inputScan.scanFileName);
                stderr.println("Exception: " + ex.getMessage());
                return null;
            }
            
            //this is for logging of some output value when building scripts
            try{
                String scriptOut = (String)engine.get("output");
                String scriptError = (String)engine.get("error");
                if(scriptOut != null && !"".equals(scriptOut.trim()))
                {
                    //scriptOut = scriptOut.replaceAll("\n", "\n" + inputScan.scanFileName + ": ");
                    scriptOut = inputScan.scanFileName + " output:" + scriptOut.replaceAll("\n", "\n" + "  ");
                    stdout.println(scriptOut);
                }
                if(scriptError != null && !"".equals(scriptError.trim()))
                {
                    scriptError = inputScan.scanFileName + " error:" + scriptError.replaceAll("\n", "\n" + "  ");
                    stderr.println(inputScan.scanFileName + scriptError);
                }
            }catch(Exception ex){
                stdout.println("Exception: " + ex.getMessage());
            }
            
            
            //if ret is true, get the rest of the vars, skip otherwise
            if(ret){
                //stdout.println("found issue, getting values");

                    sIssue.issueName = (String)engine.get("name");
                    if(sIssue.issueName == null){
                        stderr.println("Error getting Issue Name (\"var name\"), not defined in definition script: "+ inputScan.scanFileName);
                        return null;
                    }                    
                    sIssue.issueDetail = (String)engine.get("detail");
                    if(sIssue.issueDetail == null){
                        stderr.println("Error getting Issue Detail (\"var detail\"), not defined in definition script: "+ inputScan.scanFileName);
                        return null;
                    }
                    sIssue.issueBackground = (String)engine.get("background");
                    /*if(sIssue.issueBackground == null){
                        stderr.println("Error getting Issue Background (\"var detail\"), not defined in definition script: "+ inputScan.scanFileName);
                        return null;
                    }*/
                    sIssue.issueRemediation = (String)engine.get("remediation");
                    /*if(sIssue.issueRemedation == null){
                        stderr.println("Error getting Issue Remedation (\"var detail\"), not defined in definition script: "+ inputScan.scanFileName);
                        return null;
                    }*/
                    sIssue.issueSeverity = (String)engine.get("severity");
                    if(sIssue.issueSeverity == null){
                        stderr.println("Error getting Issue Severity (\"var severity\"), not defined in definition script: "+ inputScan.scanFileName);
                        return null;
                    }
                    sIssue.issueConfidence = (String)engine.get("confidence");
                    if(sIssue.issueConfidence == null){
                        stderr.println("Error getting Issue Confidence (\"var confidence\"), not defined in definition script: "+ inputScan.scanFileName);
                        return null;
                    }
                    
                    Integer[] reqMarkers = (Integer[])convertJSIntArray(engine.get("requestMarkers"));
                    Integer[] resMarkers = (Integer[])convertJSIntArray(engine.get("responseMarkers"));
                    
                    //THIS IS OLD, REMOVE ONCE CONFIRMED WORKING
                    //some of this request markers code may be able to be simplified slightly
                    //because of Native array have to do some juggling
                    //Object[] reqMarkers = ((List<?>) engine.get("requestMarkers")).toArray();
                    //Object[] resMarkers = ((List<?>) engine.get("responseMarkers")).toArray();
                    
                    if(sIssue.requestMarkers == null){
                        stderr.println("Error getting Issue start (\"var requestMarkers\"), not defined in definition script: "+ inputScan.scanFileName);
                        //return null;
                    }
                    else
                    {
                        //convert integer array into array list
                        for(int i = 0; i < reqMarkers.length-1; i+=2)
                        {
                            //int[] tempMarkers = new int[]{((Double)reqMarkers[i]).intValue(),((Double)reqMarkers[i+1]).intValue()};
                            int[] tempMarkers = {reqMarkers[i],reqMarkers[i+1]};
                            sIssue.requestMarkers.add(tempMarkers);
                        }
                    }
                    if(sIssue.responseMarkers == null){
                        stderr.println("Error getting Issue end (\"var responseMarkers\"), not defined in definition script: "+ inputScan.scanFileName);
                        //return null;
                    }
                    else
                    {
                       for(int i = 0; i < resMarkers.length-1; i+=2)
                        {
                            //int[] tempMarkers = new int[]{((Double)resMarkers[i]).intValue(),((Double)resMarkers[i+1]).intValue()};
                            int[] tempMarkers = {resMarkers[i],resMarkers[i+1]};
                            sIssue.responseMarkers.add(tempMarkers);
                        } 
                    }
                    
            }
           //check was false 
           else
                return null;
              
        }catch(ScriptException se){
            //dump script execution error to error window
            stderr.println("Error executing a script.");
            stderr.println("File: " + inputScan.scanFileName);
            if(se.getMessage() != null && se.getMessage().trim() != "")
                stderr.println();
            return null;
        }
        
        return sIssue;
    }
    
    
    //this functions purpose is to call the following function for each scanitem and add them together into a single list
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks){
        
        List<IScannerInsertionPoint> insertionPoints = new ArrayList<>();
        
        //call execInsertionPoints
        for(ScanItem item : scanItems)
        {
            if(item.getEnabled() && item.getIssueType().toLowerCase().equals("insertionpoint"))
            {
                stdout.println("Processing Insertion Point");
                List<IScannerInsertionPoint> t = execInsertionPoint(item, baseRequestResponse, callbacks);//callbacks.getHelpers().bytesToString(baseRequestResponse.getRequest()), callbacks.getHelpers().bytesToString(baseRequestResponse.getResponse()));
                if(t != null){
                   stdout.println("Adding an insertion point! " + item.scanFileName);
                   insertionPoints.addAll(t);
                }
            }
        }
        
        return insertionPoints;
        
    }
    
    //executes a javascript statement and expects to find a boolean value in the
    // "result" variable.
    private List<IScannerInsertionPoint> execInsertionPoint(ScanItem inputScan, IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks){
        ScriptEngineManager factory = new ScriptEngineManager();
        ScriptEngine engine = factory.getEngineByName("JavaScript");
        
        boolean ret = false;
        List<IScannerInsertionPoint> insertionPoints = new ArrayList();
        
        try{
            engine.put("request", callbacks.getHelpers().bytesToString(baseRequestResponse.getRequest()));
            engine.put("response", callbacks.getHelpers().bytesToString(baseRequestResponse.getResponse()));
            engine.eval(inputScan.getScanScript());
            
            //retreive ret variable
            try{
                ret = (boolean)engine.get("result");
            }catch(Exception ex){
                stderr.println("Error getting script result var.");
                stderr.println("File: " + inputScan.scanFileName);
                stderr.println("Exception: " + ex.getMessage());
                return null;
            }
            
            //this is for logging of some output value when building scripts
            try{
                String scriptOut = (String)engine.get("output");
                String scriptError = (String)engine.get("error");
                if(scriptOut != null && !"".equals(scriptOut.trim()))
                {
                    scriptOut = inputScan.scanFileName + " output:" + scriptOut.replaceAll("\n", "\n" + "  ");
                    stdout.println(scriptOut);
                }
                if(scriptError != null && !"".equals(scriptError.trim()))
                {
                    scriptError = inputScan.scanFileName + " error:" + scriptError.replaceAll("\n", "\n" + "  ");
                    stderr.println(inputScan.scanFileName + scriptError);
                }
            }catch(Exception ex){
                stdout.println("Exception: " + ex.getMessage());
            }
            
            
            
            
            //if ret is true, get the rest of the vars, skip otherwise
            if(ret){
                    //for each marker set returned from JS, create new ScannerInsertionPoint and append to list

                    Integer[] insertionMarkers = (Integer[])convertJSIntArray(engine.get("insertionPoints"));
                    
                    if(insertionMarkers == null){
                        stderr.println("Error getting insertionMarkers (\"var insertionMarkers\"), not defined in definition script: "+ inputScan.scanFileName);
                        return null;
                    }
                    
                    String[] baseValue = (String[])convertJSStringArray(engine.get("baseValue"));
                    
                    if(baseValue == null){
                        stderr.println("Error getting BaseValue (\"var baseValue\"), not defined in definition script: "+ inputScan.scanFileName);
                        return null;
                    }
                    
                    if(insertionMarkers == null){
                        stderr.println("Error getting Issue start (\"var insertionPoints\"), not defined in definition script: "+ inputScan.scanFileName);
                    }
                    else
                    {
                        //convert integer array into array list
                        for(int i = 0; i < insertionMarkers.length-1; i+=2)//0,2,4
                        {
                            int[] tempMarkers = {insertionMarkers[i],insertionMarkers[i+1]};
                            insertionPoints.add(new ScannerInsertionPoint(baseRequestResponse.getRequest(), baseValue[i/2], tempMarkers[0], tempMarkers[1], callbacks));
                        }
                    }  
            }
           //check was false 
           else
                return null;
              
        }catch(ScriptException se){
            //dump script execution error to error window
            stderr.println("Error executing a script.");
            stderr.println("File: " + inputScan.scanFileName);
            if(se.getMessage() != null && se.getMessage().trim() != "")
                stderr.println();
            return null;
        }
        
        return insertionPoints;
    }

    //uses reflection to check if we are running in java8 to handle the fact nashorn
    //returns "ScriptObjectMirror" types
    private Object convertJSIntArray(final Object obj) {
        if (obj instanceof Bindings) {
            try {
                //check if we have the ScriptObjectMirror class indicating nashorn
                final Class<?> cls = Class.forName("jdk.nashorn.api.scripting.ScriptObjectMirror");
               // stdout.println("Nashorn detected");
                if (cls.isAssignableFrom(obj.getClass())) {
                    final Method isArray = cls.getMethod("isArray");
                    final Object result = isArray.invoke(obj);
                    if (result != null && result.equals(true)) {
                        final Method values = cls.getMethod("values");
                        final Object vals = values.invoke(obj);
                        if (vals instanceof Collection<?>) {
                            //convert the collection to an Integer array and return
                            final Collection<?> coll = (Collection<?>) vals;
                            return coll.toArray(new Integer[coll.size()]);
                        }
                    }
                }
            } catch (ClassNotFoundException | NoSuchMethodException | SecurityException
                    | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {}
        }
        if (obj instanceof List<?>) {
            //we are in the java7 runtime as the returning array is a List
            final List<?> list = (List<?>) obj;
            //convert the List to an Integer array and ret
            Integer[] ret = new Integer[list.size()];
            for(int i=0;i<ret.length;i++)
                ret[i] = ((Double)list.get(i)).intValue();
            return ret;
        }
        //shouldnt end up here so return empty array and log an error
        stderr.println("Error with Request or Response markers in definition.");
        stderr.println(obj.getClass().getName());
        return new Integer[0];
    }
    
    
    //uses reflection to check if we are running in java8 to handle the fact nashorn
    //returns "ScriptObjectMirror" types
    private Object convertJSStringArray(final Object obj) {
        if (obj instanceof Bindings) {
            try {
                //check if we have the ScriptObjectMirror class indicating nashorn
                final Class<?> cls = Class.forName("jdk.nashorn.api.scripting.ScriptObjectMirror");
               // stdout.println("Nashorn detected");
                if (cls.isAssignableFrom(obj.getClass())) {
                    final Method isArray = cls.getMethod("isArray");
                    final Object result = isArray.invoke(obj);
                    if (result != null && result.equals(true)) {
                        final Method values = cls.getMethod("values");
                        final Object vals = values.invoke(obj);
                        if (vals instanceof Collection<?>) {
                            //convert the collection to an String array and return
                            final Collection<?> coll = (Collection<?>) vals;
                            return coll.toArray(new String[coll.size()]);
                        }
                    }
                }
            } catch (ClassNotFoundException | NoSuchMethodException | SecurityException
                    | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {}
        }
        if (obj instanceof List<?>) {
            //we are in the java7 runtime as the returning array is a List
            final List<?> list = (List<?>) obj;
            //convert the List to an Integer array and ret
            String[] ret = new String[list.size()];
            for(int i=0;i<ret.length;i++)
                ret[i] = ((String)list.get(i)).toString();
            return ret;
        }
        //shouldnt end up here so return empty array and log an error
        stderr.println("Error with Request or Response markers in definition.");
        stderr.println(obj.getClass().getName());
        return new String[0];
    }
}
