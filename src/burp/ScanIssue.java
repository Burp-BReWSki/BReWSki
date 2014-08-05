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
public class ScanIssue {
        public String issueName = "";
        public String issueDetail = "";
        public String issueBackground = "";
        public String issueRemediation = "";
        public String issueSeverity = "";
        public String issueConfidence = "";
        public String issueDescription = "";
        public List<int[]> requestMarkers = new ArrayList<int[]>();
        public List<int[]> responseMarkers = new ArrayList<int[]>();
        //need these to capture the active check modified req/res
        public IHttpRequestResponse requestResponse = null;
        
}
