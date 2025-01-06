from setuptools import setup, find_packages

setup(
    name='nmap_scanner',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'colorama',
    ],
    entry_points={
        'console_scripts': [
            'nmap-scanner = nmap_scanner.your_script:main_menu',
        ],
    },
    author='Your Name',
    author_email='your_email@example.com',
    description='A script to automate Nmap and SSLScan operations with a simple menu.',
    url='https://github.com/yourusername/nmap-scanner',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
