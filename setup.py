from setuptools import setup

setup(name='noway',
      version='0.1',
      description='Simple API wrapper around scaleway API',
      url='http://github.com/emergencybutter/noway',
      author='Arnaud Cornet',
      author_email='arnaud.cornet+noway@gmail.com',
      license='MIT',
      packages=['noway'],
      install_requires=[
          'retrying',
      ])
