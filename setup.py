from setuptools import setup, find_packages

setup(
    name='psi-commit',
    version='1.0.0',
    packages=find_packages(),
    install_requires=[
        'click>=8.0',
        'jcs>=0.2.1',
    ],
    extras_require={
        'dev': [
            'pytest>=7.0',
            'hypothesis>=6.0',
            'argon2-cffi>=21.0',
        ]
    },
    entry_points={
        'console_scripts': [
            'psi-commit=psi_commit.cli:cli',
        ],
    },
    author='Rayan Oghabian',
    author_email='rayanoghabian@gmail.com',
    description='Cryptographic commitment scheme for verifiable decisions',
    long_description=open('README.md').read() if False else '',
    long_description_content_type='text/markdown',
    url='https://github.com/RayanOgh/psi-commit',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.8',
    ],
    python_requires='>=3.8',
)