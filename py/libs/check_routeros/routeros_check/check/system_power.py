# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

import click
import nagiosplugin

from ..cli import cli
from ..helper import logger, RouterOSVersion
from ..resource import RouterOSCheckResource


class SystemPowerResource(RouterOSCheckResource):
    name = "Power"

    def __init__(
        self,
        cmd_options,
        check: nagiosplugin.Check,
    ):
        super().__init__(cmd_options=cmd_options)

        self._check = check

        self._routeros_metric_values = [
            {"name": "power-consumption", "type": float},
        ]

    def probe(self):
        logger.info("Fetching data ...")
        call = self.api.path(
            "/system/health"
        )
        if self.routeros_version < RouterOSVersion("7"):
            call = call.select(
                *self.get_routeros_select_keys()
            )
            api_result_items = tuple(call)
            api_result_items = self._convert_v6_list_to_v7(api_result_items)
        else:
            api_result_items = tuple(call)

        result_metrics = self.get_routeros_metrics(api_result_items)
        if len(result_metrics) == 0:
            self._check.results.add(
                nagiosplugin.Result(
                    nagiosplugin.state.Unknown,
                    hint="Power consumption not found."
                )
            )
        return result_metrics


@cli.command("system.power")
@click.option(
    "--warning",
    help="Warning threshold for total power consumption",
)
@click.option(
    "--critical",
    help="Critical threshold for total power consumption",
)
@click.pass_context
@nagiosplugin.guarded
def system_power(ctx, warning, critical):
    """Check the total power consumption of a device. This might not be available on all devices"""
    check = nagiosplugin.Check()

    check.add(
        SystemPowerResource(
            cmd_options=ctx.obj,
            check=check,
        ),
        nagiosplugin.ScalarContext(
            "power-consumption",
            warning=warning,
            critical=critical,
            fmt_metric="Power consumption {value}W",
        ),
    )

    check.main(verbose=ctx.obj["verbose"])
