# Contributing  
We welcome all types of contributions to Surveyor. To get started with contributing, follow the instructions below to properly fork and submit a PR.  
* Fork the Surveyor repository in Github - https://github.com/redcanaryco/cb-response-surveyor/fork  
* ```git clone git@github.com/YOUR_GITHUB_ACCOUNT/cb-response-surveyor```
* ```cd cb-response-surveyor```
* ```git checkout -b BRANCH_NAME_DESCRIBING_YOUR_CHANGE```
  
Make your changes locally. When you're satisfied with your updates, run the following commands to submit a pull request:  
* ```git add -a```  
* ```git commit -m "MESSAGE_FOR_UPDATING"```  
* ```git push -u origin $(git branch |grep '*'|cut -f2 -d' ')```  
* Go to github.com/YOUR_GITHUB_ACCOUNT/cb-response-surveyor and follow the instructions to create a new Pull Request.

## Definition Files
Whenever possible update an existing definition file that fits the appropriate processes for what you would like to add. In the event that there is no overlap and it requires a new definition file, make sure that it’s as complete as possible. 
Whenever adding process groupings to a definition file, ensure that it is not already in an existing definition file. 
Whenever adding process groupings to an existing definition file or a new definition file, ensure that you have captured all the variations of the process (i.e. all the binaries associated with it). 

## New Features 
Ensure that the feature has been thoroughly tested and works across the supported EDR platforms. 
Limit use of external Python libraries.
Must be Python 3.X compatible. 
