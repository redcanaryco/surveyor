cb-response-surveyor
================

About
-----

A Python utility that queries Carbon Black (Cb) Enterprise Response and
summarizes results. This has many uses, but is used primarily to understand
where certain applications or activities exist within an enterprise, who is
using them and how.

Installation
------------

Clone the repository from Github and install:

    git clone https://github.com/redcanaryco/cb-response-surveyor.git
    
    python setup.py develop

Using
-----

Create and populate your cbapi credential file per the instructions found
here: https://github.com/carbonblack/cbapi-python.

Run using one of the test definitions:

    ./surveyor.py --deffile definitions/file-transfer.json

Then open and review the default output file (survey.csv.

You can also run using an entire directory of  definition files in one shot:

    ./surveyor.py --defdir definitions

