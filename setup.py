from setuptools import setup, find_packages

setup(
    name='nmap_scanner',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'colorama',  # Ensure colorama is installed for colored output
    ],
    entry_points={
        'console_scripts': [
            'nmap-scanner = nmap_scanner:main_menu',  # Replace with your actual entry point function and script name
        ],
    },
    author='Your Name',
    author_email='your_email@example.com',
    description='A script to automate Nmap and SSLScan operations with a simple menu.',
    long_description=open('README.md').read(),  # You can add a README.md file for documentation
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/nmap-scanner',  # Replace with your GitHub or project URL
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',  # Adjust the Python version requirement
)
