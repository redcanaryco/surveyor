surveyor
================

## What's New
- Support for VMWare Cloud Enterprise EDR 
- Ability to specify an output location. 
- Python 3 support only. 


## About
Surveyor is a Python utility that queries Endpoint Detection and Response products and summarizes the results. It provides security and IT teams with a method for quickly baselining an environment to identify normal and abnormal activity. Surveyor uses both definition files and pre-built queries to run searches across an environment and provide insights into what applications or activities exist within an enterprise, who is using them, and how.

EDR user interfaces and REST APIs provide direct access to events and processes and are very useful for real-time threat detection, digital forensics, and incident response (to name a few use cases). Surveyor is intended to provide high-level information about an environment, meeting use cases more closely aligned with inventory maintenance and proactive threat hunting. 

Surveyor currently supports the following EDR platforms: 
- Carbon Black (Cb) Enterprise Response
- VMWare Cloud Enterprise EDR (formerly Carbon Black ThreatHunter) 

More information about surveyor can be found [on this blog post](https://redcanary.com/blog/carbon-black-response-how-tos-surveyor/)  

## Contributing
We encourage and welcome all contributions to Surveyor, which accepts two types of contributions: 
- Definition Files 
- New Features  
  
Please see our [contribution page](https://github.com/redcanaryco/cb-response-surveyor/blob/master/Contributing.md) to learn more about what is accepted for the different types of contributions and how to contribute.  

## Getting Started
- Clone the repository from Github  
    ```git clone https://github.com/redcanaryco/surveyor.git```
- Change to the surveyor directory  
     ```cd surveyor```  
- Run setup.py to install all the required dependencies  
  ```python setup.py``` 

### Updating Existing Local Git Repos 
- We strongly recommend updating any existing local clones to point to the new repository URL. You can do this by using git remote on the command line:
``` git remote set-url origin https://github.com/redcanaryco/surveyor```

## Requirements
In order to use Surveyor, you will need access to Carbon Black API tokens. Surveyor utilizes the Carbon Black API to run it’s queries against the endpoints in your environment.

You can find in-depth instructions on how to create and populate your Carbon Black API (cbapi) credentials in the cbapi repo found here: https://github.com/carbonblack/cbapi-python

Once you have the API token, you should be able to follow these step-by-step instructions:
* Grab your API token located in your user profile in your Carbon Black portal. 
* Your API token should be stored in one of the following default credential file locations:  
  - /etc/carbonblack/
  - ~/.carbonblack/
  - /current_working_directory/.carbonblack/ 
   
Depending on which Carbon Black product you are using, utilize the following naming conventions for your credential files
- credentials.psc for CB ThreatHunter
- credentials.response for CB Response
 
Unless otherwise specified with the ```--profile``` tag, the credentials and URL provided in the ```[default]``` configuration will be used.  
```./surveyor.py --profile otheruser --defdir definitions```

For ThreatHunter, we have found that the following API permissions work best and return the appropriate results from Surveyor. 
- Create, update, and delete custom watchlists and related reports and IOCs - Read
- Custom Detections - Feeds - Create,Read,Update,Delete
- Access and manage configuration settings to forward events - Read
- Access event and process data; create and cancel searches - Create,Read,Update,Delete
- Retrieve SHA-256 hash metadata of stored binaries - Read
- Unified Binary Store - File - Read 

## Using
### Definition Files
There are over a dozen predefined definition files that can be run out of the box against an environment. Definition files allow you to query an environment for a group of processes and/or hashes at a single time.  
To run Surveyor using a predefined definition file, you’ll want to use the following command:  
    ```./surveyor.py --deffile [DEFINITION FILE LOCATION]```  
    Example: ```./surveyor.py --deffile definitions/file-transfer.json```  
      
### Definition Directory
Using the ```--defdir``` option, you can run Surveyor against an entire directory of definitions at once.  
    ```./surveyor.py --defdir definitions```

### Output Location
The default output file is located in the directory Surveyor is run and titled - survey.csv. You can use the ```--output``` option to specify a different location and name for surveyor output.  

### Enterprise EDR (ThreatHunter)
By default surveyor will attempt to use Carbon Black Response to to run it's queries. If you would like to use it against a VMWare Cloud Enterprise EDR environment you must use the ```--threathunter``` option.  
```./surveyor.py --threathunter --defdir definitions```

### Query 
If there is no current definition file or you want to search for something specific, you can use the ```--query``` option to provide a query. The query should mimic the same syntax that would be used in the GUI query.  
   ```./surveyor.py --query 'process_name:explorer.exe AND username:joebob'```

### Profile
To differentiate between different Carbon Black profiles add the ```--profile``` tag to the command line.  
```./surveyor.py --profile``` 

