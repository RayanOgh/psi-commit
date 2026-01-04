#!/usr/bin/env python3
"""
PSI-COMMIT CLI
Command-line interface for creating and verifying commitments.
"""

import click
import json
import sys
from pathlib import Path
from psi_commit.core import seal, verify, __version__

@click.group()
@click.version_option(version=__version__)
def cli():
    """PSI-COMMIT: Cryptographic commitment scheme for verifiable decisions."""
    pass

@cli.command()
@click.argument('message')
@click.option('--context', default='default', help='Domain context for commitment')
@click.option('--output', '-o', type=click.Path(), help='Save to file instead of stdout')
def commit(message, context, output):
    """Create a cryptographic commitment to MESSAGE."""
    commitment, key = seal(message, context=context)
    
    result = {
        "commitment": commitment,
        "key": key.hex(),
        "message_preview": message[:50] + "..." if len(message) > 50 else message
    }
    
    output_json = json.dumps(result, indent=2)
    
    if output:
        Path(output).write_text(output_json)
        click.echo(f"Commitment saved to {output}")
        click.echo(f"Key: {key.hex()}")
    else:
        click.echo(output_json)

@cli.command()
@click.argument('message')
@click.argument('key')
@click.argument('commitment-file', type=click.Path(exists=True))
def verify_cmd(message, key, commitment_file):
    """Verify MESSAGE matches COMMITMENT using KEY."""
    try:
        commitment_data = json.loads(Path(commitment_file).read_text())
        if "commitment" in commitment_data:
            commitment = commitment_data["commitment"]
        else:
            commitment = commitment_data
    except json.JSONDecodeError:
        click.echo("Error: Invalid JSON in commitment file", err=True)
        sys.exit(1)
    
    try:
        key_bytes = bytes.fromhex(key)
    except ValueError:
        click.echo("Error: Key must be hex-encoded", err=True)
        sys.exit(1)
    
    is_valid = verify(message, key_bytes, commitment)
    
    if is_valid:
        click.echo("VERIFIED: Commitment matches message and key")
    else:
        click.echo("FAILED: Commitment does not match", err=True)
        sys.exit(1)

@cli.command()
@click.argument('commitment-file', type=click.Path(exists=True))
def info(commitment_file):
    """Display information about a commitment."""
    data = json.loads(Path(commitment_file).read_text())
    if "commitment" in data:
        commitment = data["commitment"]
    else:
        commitment = data
    
    click.echo("Commitment Information:")
    click.echo(f"  Version: {commitment['v']}")
    click.echo(f"  Algorithm: {commitment['alg']}")
    click.echo(f"  Domain: {commitment['domain']}")

if __name__ == '__main__':
    cli()