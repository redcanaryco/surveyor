cb-response-surveyor
================

About
-----

A Python utility that queries Carbon Black (Cb) Enterprise Response and
summarizes results. This has many uses, but is used primarily to understand
where certain applications or activities exist within an enterprise, who is
using them and how.

Contributing
------------

Join the community and share updates to survey definition files by forking this
repository and sending a Pull Request with any definition updates or new
definitions you've found useful. We'll do our best to adjudicate any differences 
in opinions (sorry, you can't classify your coupon printer as wanted software :smile:)

Fork the Surveyor repository in Github - https://github.com/redcanaryco/cb-response-surveyor/fork
git clone git@github.com/YOUR_GITHUB_ACCOUNT/cb-response-surveyor
cd cb-response-surveyor
git checkout -b BRANCH_NAME_DESCRIBING_YOUR_CHANGE

Make your changes locally. When you're satisfied with your updates run the following commands to submit a pull request:
git add -a
git commit -m "MESSAGE_FOR_UPDATING"
git push -u origin $(git branch |grep '*'|cut -f2 -d' ')

Go to github.com/YOUR_GITHUB_ACCOUNT/cb-response-surveyor and follow the instructions to create a new Pull Request.


Installation
------------

Clone the repository from Github and install:

    git clone https://github.com/redcanaryco/cb-response-surveyor.git

    cd cb-response-surveyor

    python setup.py develop

Using
-----

Create and populate your cbapi credential file per the instructions found
here: https://github.com/carbonblack/cbapi-python.

Run using one of the test definitions:

    ./surveyor.py --deffile definitions/file-transfer.json

Then open and review the default output file (survey.csv).

You can also run using an entire directory of definition files in one shot:

    ./surveyor.py --defdir definitions

If you're looking for instances of something specific and a Cb query suits you
best, you can do that too:

    ./surveyor.py --query 'process_name:explorer.exe username:joebob'

