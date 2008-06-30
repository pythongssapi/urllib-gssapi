from setuptools import setup
import version_detect

setup(
    name = "urllib2_kerberos",
    version = version_detect.version,
    py_modules = [ 'urllib2_kerberos' ],

#    install_requires = ['kerberos'],

    author = "Tim Olsen",
    author_email = "tolsen@limespot.com",
    description = "Kerberos over HTTP Negotiate/SPNEGO support for urllib2",
    license = "GPLv3",
    url = "http://limedav.com/hg/urllib2_kerberos/",
    keywords = "urllib2 kerberos http negotiate spnego",
    
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Natural Language :: English',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Systems Administration :: Authentication/Directory'
        ]
    
    )

