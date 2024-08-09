# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import List

import click
import librouteros
import librouteros.query
import nagiosplugin

from ..cli import cli
from ..context import ScalarPercentContext
from ..helper import logger
from ..resource import RouterOSCheckResource


class SystemMemoryResource(RouterOSCheckResource):
    name = "MEMORY"

    def __init__(self, cmd_options):
        super().__init__(cmd_options=cmd_options)

        self.memory_total = None

    def probe(self):
        api = self._connect_api()

        logger.info("Fetching data ...")
        call = api.path(
            "/system/resource"
        ).select(
            librouteros.query.Key("free-memory"),
            librouteros.query.Key("total-memory")
        )
        results = tuple(call)
        result = results[0]

        memory_free = result["free-memory"]
        self.memory_total = result["total-memory"]

        yield nagiosplugin.Metric(
            name="free",
            value=memory_free,
            uom="B",
            min=0,
            max=self.memory_total,
        )

        yield nagiosplugin.Metric(
            name="used",
            value=self.memory_total - memory_free,
            uom="B",
            min=0,
            max=self.memory_total,
        )


class SystemMemorySummary(nagiosplugin.summary.Summary):
    def __init__(self, result_names: List[str]):
        super().__init__()
        self._result_names = result_names

    def ok(self, results):
        msgs = []
        for result_name in self._result_names:
            msgs.append(str(results[result_name]))
        return " ".join(msgs)


@cli.command("system.memory")
@click.option(
    "--used/--free",
    is_flag=True,
    default=True,
    help="Set if used or free memory should be checked. (Default: used)",
)
@click.option(
    "--warning",
    required=True,
    help="Warning threshold in % or MB. Example (20% oder 20 = 20MB)",
)
@click.option(
    "--critical",
    required=True,
    help="Critical threshold in % or MB. Example (20% oder 20 = 20MB)",
)
@click.pass_context
@nagiosplugin.guarded
def system_memory(ctx, used, warning, critical):
    check = nagiosplugin.Check(
        SystemMemoryResource(
            cmd_options=ctx.obj,
        )
    )

    if used:
        check.add(nagiosplugin.ScalarContext(
            name="free",
        ))
        check.add(ScalarPercentContext(
            name="used",
            total_name="memory_total",
            warning=warning,
            critical=critical
        ))
    else:
        check.add(ScalarPercentContext(
            name="free",
            total_name="memory_total",
            warning=f"{warning}:",
            critical=f"{critical}:"
        ))
        check.add(nagiosplugin.ScalarContext(
            name="used",
        ))

    check.add(SystemMemorySummary(
        result_names=["used"] if used else ["free"]
    ))

    check.main(verbose=ctx.obj["verbose"])
