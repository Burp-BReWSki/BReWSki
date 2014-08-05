/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package burp;

/**
 *
 * @author Alex
 */

//class implementing our IScannerInsertionPoint - Currently only supports normal insertion points, not insertion points within a custom data type
    class ScannerInsertionPoint implements IScannerInsertionPoint
    {
        private byte[] baseRequest;
        private String baseValue;
        private byte[] insertionPointPrefix;//the entire request before the payload
        private byte[] insertionPointSuffix;//the entire request after the payload
        private int insertionStart;
        private IBurpExtenderCallbacks callbacks;
        private final IExtensionHelpers helpers;
        
        //constructor 
        ScannerInsertionPoint(byte[] baseRequest, String baseValue, int insertStart, int insertStop, IBurpExtenderCallbacks callbacks)
        {
            this.callbacks = callbacks;
            this.helpers = this.callbacks.getHelpers();
            
            this.baseRequest = baseRequest;
            this.insertionStart = insertStart;
            this.baseValue = baseValue;
            this.insertionPointPrefix = helpers.stringToBytes(helpers.bytesToString(this.baseRequest).substring(0, insertStart));
            this.insertionPointSuffix = helpers.stringToBytes(helpers.bytesToString(this.baseRequest).substring(insertStop, this.baseRequest.length));
        }

        @Override
        public byte getInsertionPointType()
        {
            //this indicates that this is an extension provided insertion point
            return INS_EXTENSION_PROVIDED;
        }

        @Override
        public String getInsertionPointName() {
            return "BReWSki";
        }

        @Override
        public String getBaseValue() {
            return baseValue;
        }

        @Override //build request given a payload. In a static location for now.  this would need to execute JS each time if it wasn't this way.
        public byte[] buildRequest(byte[] payload) {
            return helpers.stringToBytes( helpers.bytesToString(insertionPointPrefix) + helpers.bytesToString(payload) + helpers.bytesToString(insertionPointSuffix) );
        }

        /**
        * This method is used to determine the offsets of the payload value within
        * the request, when it is placed into the insertion point. Scan checks may
        * invoke this method when reporting issues, so as to highlight the relevant
        * part of the request within the UI.
        *
        * @param payload The payload that should be placed into the insertion
        * point.
        * @return An int[2] array containing the start and end offsets of the
        * payload within the request, or null if this is not applicable (for
        * example, where the insertion point places a payload into a serialized
        * data structure, the raw payload may not literally appear anywhere within
        * the resulting request).
        */
        @Override
        public int[] getPayloadOffsets(byte[] payload) {
            return new int[] {this.insertionStart, (this.insertionStart + helpers.bytesToString(payload).length())};
        }

    }//end CustomScannerInsertionPoint class
