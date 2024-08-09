# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Optional

import click
import nagiosplugin


@click.group()
@click.option(
    "--host",
    required=True,
    help="Hostname or IP address of the device to connect to",
)
@click.option(
    "--hostname",
    help="Use this hostname to check the SSL certificates",
)
@click.option(
    "--port",
    default=None,
    help="The port to use. Defaults to 8728 for non SSL connections and 8729 for SSL connections",
)
@click.option(
    "--username",
    required=True,
    help="The username of the monitoring user. Do NOT use a user with admin privileges",
)
@click.option(
    "--password",
    required=True,
    help="The password of the monitoring user",
)
@click.option(
    "--routeros-version",
    default="auto",
    help=(
        "Version of RouterOS running on the device. "
        "The value 'auto' is special and if set the check will try to detect the version automatically. "
        "The 'auto' option is recommended. "
        "Examples: '6', '6.48.8', '7', '7.8', 'auto' "
        "(Default: auto)"
    )
)
@click.option(
    "--ssl/--no-ssl",
    "use_ssl",
    default=True,
    help="Use a SSL encrypted connections to communicate with the device",
)
@click.option(
    "--ssl-cafile",
    help="Custom CA file to check SSL certificates",
)
@click.option(
    "--ssl-capath",
    help="Custom path to look for CA files to check SSL certificates",
)
@click.option(
    "--ssl-force-no-certificate",
    is_flag=True,
    default=False,
    help="Force an anonymous connection",
)
@click.option(
    "--ssl-verify/--no-ssl-verify",
    default=True,
    help="Verify the SSL certificate",
)
@click.option("--ssl-verify-hostname/--no-ssl-verify-hostname", default=True)
@click.option("-v", "--verbose", count=True)
@click.pass_context
def cli(ctx, host: str, hostname: Optional[str], port: int, username: str, password: str, routeros_version: str,
        use_ssl: bool, ssl_cafile: Optional[str], ssl_capath: Optional[str], ssl_force_no_certificate: bool,
        ssl_verify: bool, ssl_verify_hostname: bool, verbose: int):
    ctx.ensure_object(dict)
    ctx.obj["host"] = host
    ctx.obj["hostname"] = hostname
    ctx.obj["port"] = port
    ctx.obj["username"] = username
    ctx.obj["password"] = password
    ctx.obj["routeros_version"] = routeros_version
    ctx.obj["ssl"] = use_ssl
    ctx.obj["ssl_cafile"] = ssl_cafile
    ctx.obj["ssl_capath"] = ssl_capath
    ctx.obj["ssl_force_no_certificate"] = ssl_force_no_certificate
    ctx.obj["ssl_verify"] = ssl_verify
    ctx.obj["ssl_verify_hostname"] = ssl_verify_hostname
    ctx.obj["verbose"] = verbose

    runtime = nagiosplugin.Runtime()
    runtime.verbose = verbose
