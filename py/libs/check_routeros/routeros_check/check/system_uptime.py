# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

import click
import librouteros
import librouteros.query
import nagiosplugin

from ..cli import cli
from ..helper import logger
from ..resource import RouterOSCheckResource


class SystemUptimeResource(RouterOSCheckResource):
    name = "UPTIME"

    def __init__(self, cmd_options):
        super().__init__(cmd_options=cmd_options)

    def probe(self):
        api = self._connect_api()

        logger.info("Fetching data ...")
        call = api.path(
            "/system/resource"
        ).select(
            librouteros.query.Key("uptime"),
        )
        results = tuple(call)
        result = results[0]

        yield nagiosplugin.Metric(
            name="uptime",
            value=self.parse_routeros_time_duration(result["uptime"]),
            uom="s",
            min=0,
        )


@cli.command("system.uptime")
@click.pass_context
@nagiosplugin.guarded
def system_uptime(ctx):
    """Get Uptime of a device"""
    check = nagiosplugin.Check(
        SystemUptimeResource(
            cmd_options=ctx.obj,
        ),
        nagiosplugin.ScalarContext(
            name="uptime",
        )
    )

    check.main(verbose=ctx.obj["verbose"])
