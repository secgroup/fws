 
from distutils.core import setup

setup(name = "fws",
    version = "1.0",
    description = "FireWall Sinthesizer: Language-independent Synthesis of Firewall Policies",
    packages = ['fwsynthesizer', 'fwsynthesizer.parsers', 'fwsynthesizer.frontends', 'fwsynthesizer.synthesis', 'fwsynthesizer.compile', 'fwsynthesizer.utils', 'fwsynthesizer.web'],
    package_data = {'fwsynthesizer' : ["diagrams/*"] },
    scripts = ["fws"],
) 
