BReWSki
=========

BReWSki (Burp Rhino Web Scanner) is a Java extension for [Burp Suite](http://portswigger.net/burp/) that allows user to write custom scanner checks in JavaScript. BReWSki provides Burp Suite users with a Javascript interface to write custom passive, and active scan definitions for Burp quickly without having to understand the internals of the Burp API. This makes writing scanner extensions much quicker, and sharing a library of them much easier than loading many different jar files.

## Requirements
- Java JRE 7 (JRE 8 partially supported) - OVER 3 BILLION DEVICES RUN BREWSKI
- [BurpSuite](http://portswigger.net/burp/)

## Downloading and Installing
BReWSki will be available in Burp's BApp store, and it also can be downloaded from this repository. You only need the .jar and the definitions to use it, which are included in the zip file ([BReWSki-v0.1.zip](../../raw/master/dist/BReWSki-v0.1.zip)) in the [dist folder](/dist/).

## Usage
![BReWSki Example](/img/BReWSkiExample1.png "BReWSki Example")
![Scanner Example](/img/ScannerExample1.png "Scanner Example")

## How are the results?
Currently BReWSki checks provide tentative results that require more manual analysis. Some checks should never produce a false positive, and other checks will produce a high number of false positives.

## Security
Scanner definition files have the same permissions as jar files and could compromise your machine.

## Development
Please use this git repository for reporting issues, feature requests and pull requests. Alternatively, you may email alex(DOT)lauerman ~at~ gmail.

