# SPDX-FileCopyrightText: PhiBo DinoTools (2023)
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime
from pprint import pformat
from typing import List

import click
import nagiosplugin

from ..cli import cli
from ..context import SimplePositiveFloatContext
from ..helper import logger
from ..resource import RouterOSCheckResource


class SystemClockResource(RouterOSCheckResource):
    name = "CLOCK"

    def __init__(
        self,
        cmd_options,
        check: nagiosplugin.Check,
    ):
        super().__init__(cmd_options=cmd_options)

        self._check = check

    def probe(self):
        api = self._connect_api()

        logger.info("Fetching clock data ...")
        call = api.path(
            "/system/clock"
        )

        results = tuple(call)

        result = results[0]
        logger.debug(f"Extracted values {pformat(result)}")

        device_datetime = self.parse_routeros_date_time(result["date"], result["time"])

        device_timediff = datetime.now() - device_datetime

        yield nagiosplugin.Metric(
            name="time-diff",
            value=device_timediff.total_seconds(),
            uom="s",
        )


class SystemClockSummary(nagiosplugin.Summary):
    def ok(self, results: List[nagiosplugin.Result]):
        for result in results:
            if result.metric and result.metric.name == "time-diff":
                return f"Time diff is {result.metric.value:.2f}s"

        return ""


@cli.command("system.clock")
@click.option(
    "--warning",
    help="Warning threshold for time diff in seconds",
    type=float,
)
@click.option(
    "--critical",
    help="Critical threshold for time diff in seconds",
    type=float,
)
@click.pass_context
@nagiosplugin.guarded
def system_clock(ctx, warning, critical):
    """This command reads the information from /system/clock to extract the required information."""
    check = nagiosplugin.Check()

    resource = SystemClockResource(
        cmd_options=ctx.obj,
        check=check,
    )
    check.add(
        resource,
        SimplePositiveFloatContext(
            name="time-diff",
            warning=warning,
            critical=critical,
            fmt_metric="Time diff is {valueunit}",
        ),
        SystemClockSummary(),
    )

    check.main(verbose=ctx.obj["verbose"])
