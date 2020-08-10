Heads Up!
---------
On August 31, `cb-response-surveyor` will be renamed to `Surveyor` and updated with a new Main branch. Over the past few months we have been working hard on refactoring the codebase, adding support for a new EDR platform and new features. Since the addition of Carbon Black ThreatHunter we felt the old name no longer fits, so we decided to rebrand and pivot! We're not actually pivoting, just changing our name so we can add support for other EDR platforms as well.

As all good things must come to an end so does our support for Python2. While Surveyor may run perfectly fine with Python2, we will not be adding support,  accepting bugs, feature requests or issues for Python2.

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

