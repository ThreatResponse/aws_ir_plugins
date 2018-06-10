import re
import unittest

from distutils.command.build import build
from setuptools import setup

VERSION = re.search(
    r"^__version__ = ['\"]([^'\"]*)['\"]",
    open('aws_ir_plugins/_version.py', 'r').read(),
    re.MULTILINE
).group(1)

def test_suite():
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover('tests', pattern='test_*.py')
    return test_suite

setup(name="aws_ir_plugins",
      version=VERSION,
      author="Andrew Krug, Alex McCormack, Joel Ferrier, Jeff Parr",
      author_email="andrewkrug@gmail.com,developer@amccormack.net,joel@ferrier.io,jp@ephemeralsystems.com",
      packages=["aws_ir_plugins"],
      package_data={'aws_ir_plugins': ['templates/*.j2']},
      license="MIT",
      description="AWS Incident Response ToolKit Core Supported plugins",
      url='https://github.com/ThreatResponse/aws_ir_plugins',
      download_url="",
      use_2to3=True,
      test_suite=('setup.test_suite'),
      install_requires=['boto3>=1.3.0',
                        'requests',
                        'jinja2',
                        ],
      tests_require=['moto',
                     'mock',
                     'magicmock'],
      )
