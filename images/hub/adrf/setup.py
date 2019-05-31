#!/usr/bin/env python

from distutils.core import setup
from setuptools import find_packages

setup(name='adrf',
      version='1.0',
      description='Extension of Kube Spawner from ADRF',
      author='Rafael Ladislau',
      author_email='rafael.ladislau@nyu.edu',
      url='http://adrf.cloud/',
      packages=find_packages(),
      install_requires=['jupyterhub-kubespawner==0.9.0','tornado==6.0.2']
     )
