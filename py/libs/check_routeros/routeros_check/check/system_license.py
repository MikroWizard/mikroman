# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later
from datetime import datetime
from typing import List, Optional

import click
import nagiosplugin

from ..cli import cli
from ..helper import logger
from ..resource import RouterOSCheckResource


class SystemLicenseResource(RouterOSCheckResource):
    name = "License"

    def __init__(self, cmd_options):
        super().__init__(cmd_options=cmd_options)

        def days_left(value):
            time_delta = self.parse_routeros_datetime(value) - datetime.now()
            return int(time_delta.total_seconds()) / 60 / 60 / 24

        logger.info("Fetching information ...")
        call = self.api.path(
            "/system/resource"
        )
        result = tuple(call)[0]

        self.has_renewal = result["board-name"].lower() == "chr"

        self.deadline_datetime: Optional[datetime] = None
        self.next_renewal_datetime: Optional[datetime] = None

        self._routeros_metric_values = []

        if self.has_renewal:
            self._routeros_metric_values += [
                {"name": "level", "type": None},
                {"name": "deadline-at", "dst": "deadline-in", "type": days_left, "missing_ok": True},
                {"name": "next-renewal-at", "dst": "next-renewal-in", "type": days_left, "missing_ok": True},
            ]
        else:
            self._routeros_metric_values += [
                {"name": "nlevel", "dst": "level", "type": None},
            ]

    def probe(self):
        logger.info("Fetching data ...")
        call = self.api.path(
            "/system/license"
        )
        result = tuple(call)[0]

        if self.has_renewal:
            if "deadline-at" in result:
                self.deadline_datetime = self.parse_routeros_datetime(result["deadline-at"])
            if "next-renewal-at" in result:
                self.next_renewal_datetime = self.parse_routeros_datetime(result["next-renewal-at"])

        return self.get_routeros_metric_item(result)


class SystemLicenseRenewSummary(nagiosplugin.Summary):
    def ok(self, results: List[nagiosplugin.Result]):
        hints = []
        resource: Optional[SystemLicenseResource] = None
        for result in results:
            if result.resource:
                resource = result.resource
            if result.hint:
                hints.append(result.hint)

        if resource and resource.has_renewal:
            if resource.next_renewal_datetime:
                time_delta = resource.next_renewal_datetime - datetime.now()
                hints.append(f"Next renewal in {time_delta.days} day(s) ({resource.next_renewal_datetime})")
            if resource.deadline_datetime:
                time_delta = resource.deadline_datetime - datetime.now()
                hints.append(f"Deadline in {time_delta.days} day(s) ({resource.deadline_datetime})")

        return ", ".join(hints)


class SystemLicenseLevelContext(nagiosplugin.Context):
    def __init__(self, *args, levels=None, **kwargs):
        self._levels = levels
        super(SystemLicenseLevelContext, self).__init__(*args, **kwargs)

    def evaluate(self, metric, resource):
        if self._levels is None or len(self._levels) == 0 or metric.value in self._levels:
            return nagiosplugin.Result(
                nagiosplugin.Ok,
                hint=f"License level is '{metric.value}'"
            )

        return nagiosplugin.Result(
            nagiosplugin.Warn,
            hint=f"License level '{metric.value}' not in list with allowed levels: {', '.join(self._levels)}"
        )


@cli.command("system.license")
@click.option("--deadline-warning", default="28:", help="Number of days until deadline is reached (Default: '28:')")
@click.option("--deadline-critical", default="14:", help="Number of days until deadline is reached (Default: '14:')")
@click.option(
    "--next-renewal-warning",
    default=None,
    help="Number of days until renewal is done (Default: None, Example: '-14:')"
)
@click.option("--next-renewal-critical", default=None, help="Number of days until renewal is done (Default: None)")
@click.option(
    "--level",
    "levels",
    default=None,
    multiple=True,
    help="Allowed license levels. Repeat to use multiple values."
)
@click.pass_context
@nagiosplugin.guarded
def system_license(ctx, deadline_warning, deadline_critical, next_renewal_warning, next_renewal_critical, levels):
    resource = SystemLicenseResource(
        cmd_options=ctx.obj,
    )
    check = nagiosplugin.Check(resource)

    if resource.has_renewal:
        check.add(
            nagiosplugin.ScalarContext(
                name="deadline-in",
                warning=deadline_warning,
                critical=deadline_critical,
            ),
            nagiosplugin.ScalarContext(
                name="next-renewal-in",
                warning=next_renewal_warning,
                critical=next_renewal_critical,
            ),
            SystemLicenseRenewSummary(),
        )

    check.add(
        SystemLicenseLevelContext(
            name="level",
            levels=levels,
        )
    )

    check.main(verbose=ctx.obj["verbose"])
