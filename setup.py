#!/usr/bin/env python

from setuptools import setup, find_packages
import os


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


def find_scripts():
    scripts = []
    exclude = ['setup.py']
    for file in os.scandir(''):
        if file.name.endswith('.py') and file.is_file() and (file.name not in exclude):
            scripts.append(file.name)
    return scripts


setup(
    name='cb-response-surveyor',
    author='Keith McCammon',
    author_email='keith@redcanary.com',
    url='https://github.com/redcanaryco/cb-response-surveyor',
    license='MIT',
    packages=find_packages(),
    scripts=find_scripts(),
    description='Extracts summarized process data from Cb Enterprise Response ',
    version='0.1',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: Freely Distributable',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        ],
    install_requires=[
        'cbapi=1.7.0', 'click'
        ]
    )
