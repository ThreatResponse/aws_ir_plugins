from distutils.command.build import build
from setuptools import setup
from setuptools.command.install import install as _install

class install(_install):
    def run(self):
        self.run_command('build')
        _install.run(self)

setup(name="aws_ir_plugins",
      version="0.0.1",
      author="Andrew Krug, Alex McCormack, Joel Ferrier",
      author_email="andrewkrug@gmail.com,developer@amccormack.net,joel@ferrier.io",
      packages=["aws_ir_plugins"],
      package_data={'aws_ir_plugins': ['templates/*.j2']},
      license="MIT",
      description="AWS Incident Response ToolKit Core Supported plugins",
      url='https://github.com/ThreatResponse/aws_ir_plugins',
      download_url="",
      use_2to3=True,
      install_requires=['boto3>=1.3.0',
                        'requests',
                        'jinja2'
                        ],
      tests_require=['moto',
                     'mock',
                     'magicmock'],
      )
