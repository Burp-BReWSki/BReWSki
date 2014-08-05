/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package burp;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author cbellows
 */
public class ScanItem {

    public String scanFilePath = "";
    public String scanFileName = "";
    private String scanScript = "";
    private String issueName = "";
    private String issueDetail = "";
    private String issueDescription = "";
    private List<int[]> requestMarkers = new ArrayList<int[]>();
    private List<int[]> responseMarkers = new ArrayList<int[]>();
    private String issueType = "";
    private String injectionVal =  "";
    private boolean enabled = true;
    
    
    public void setScanScript(String scanScript){
        
        this.scanScript = scanScript;
    }
    
    public String getScanScript(){
        
        return this.scanScript;
    }
    
    public String getIssueName(){
        
        return this.issueName;
    }
    
    public void setIssueName(String issueName){
        
        this.issueName = issueName;
    }
    
    public String getIssueDetail(){
        
        return this.issueDetail;
    }
    
    public void setIssueDetail(String issueDetail){
        
        this.issueDetail = issueDetail;
    }
    
    public String getIssueDescription(){
        
        return this.issueDescription;
    }
    
    public void setIssueDescription(String issueDescription){
        
        this.issueDescription = issueDescription;
    }
    
    public List<int[]> getRequestMarkers(){
        
        return this.requestMarkers;
    }
    
    public void setRequestMarkers(List<int[]> requestMarkers){
        
        this.requestMarkers = requestMarkers;
    }
    
    public List<int[]> getResponseMarkers(){
        
        return this.responseMarkers;
    }
    
    public void setResponseMarkers(List<int[]> responseMarkers){
        
        this.responseMarkers = responseMarkers;
    }
    
    public String getIssueType(){
        
        return this.issueType;
    }
    
    public void setIssueType(String issueType){
        
        this.issueType = issueType;
    }
    
    public boolean getEnabled(){
        
        return this.enabled;
    }
        
    public void setEnabled(boolean enabled){
        
        this.enabled = enabled;
    }
    
    public String getInjectionVal(){
        return this.injectionVal;
    }
    
    public void setInjectionVal(String injectionVal)
    {
        this.injectionVal = injectionVal;
    }
}
