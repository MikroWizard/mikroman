# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

from pprint import pformat
import re
from typing import Dict, List

import click
import librouteros
import librouteros.query
import nagiosplugin

from ..cli import cli
from ..helper import logger
from ..resource import RouterOSCheckResource


class SystemCpuResource(RouterOSCheckResource):
    name = "CPU"

    def __init__(
        self,
        cmd_options,
        check: nagiosplugin.Check,
        warning_values: List[str],
        critical_values: List[str],
        use_regex: bool
    ):
        super().__init__(cmd_options=cmd_options)

        self._check = check

        self.values: Dict[str, float] = {}
        self.use_regex: bool = use_regex

        self.warning_values: Dict[str, str] = {}
        self.critical_values: Dict[str, str] = {}
        self.warning_regex_values: Dict[re.Pattern, str] = {}
        self.critical_regex_values: Dict[re.Pattern, str] = {}

        if self.use_regex:
            self.warning_regex_values = self.prepare_regex_thresholds(warning_values)
            self.critical_regex_values = self.prepare_regex_thresholds(critical_values)
        else:
            self.warning_values = self.prepare_thresholds(warning_values)
            self.critical_values = self.prepare_thresholds(critical_values)

    def probe(self):
        key_cpu_load = librouteros.query.Key("cpu-load")
        api = self._connect_api()

        logger.info("Fetching global data ...")
        call = api.path(
            "/system/resource"
        ).select(
            key_cpu_load
        )
        results = tuple(call)
        result = results[0]
        logger.debug(f"Extracted values {pformat(result)}")

        yield nagiosplugin.Metric(
            name="cpu-load",
            value=result["cpu-load"],
            uom="%",
            min=0,
            max=100,
        )

        logger.info("Fetching cpu data ...")
        call = api.path(
            "/system/resource/cpu"
        )
        results = tuple(call)
        logger.debug(f"Extracted values {pformat(results)}")

        for cpu in results:
            name = cpu["cpu"]
            for value_name_suffix in ("load", "irq", "disk"):
                value_name = f"{name}-{value_name_suffix}"
                if self.use_regex:
                    for regex, threshold in self.warning_regex_values.items():
                        if regex.match(value_name):
                            self.warning_values[value_name] = threshold
                            break

                    for regex, threshold in self.critical_regex_values.items():
                        if regex.match(value_name):
                            self.critical_values[value_name] = threshold
                            break

                self.values[value_name] = float(cpu[value_name_suffix])

        for name, value in self.values.items():
            self._check.add(nagiosplugin.ScalarContext(
                name=name,
                warning=self.warning_values.get(name),
                critical=self.critical_values.get(name),
            ))
            yield nagiosplugin.Metric(
                name=name,
                value=value,
                uom="%",
                min=0,
                max=100,
            )


class SystemCpuSummary(nagiosplugin.Summary):
    def ok(self, results: List[nagiosplugin.Result]):
        for result in results:
            if result.metric and result.metric.name == "cpu-load":
                return f"System load is {result.metric.value}%"

        return ""


@cli.command("system.cpu")
@click.option(
    "--load-warning",
    help="Warning threshold for global cpu load",
)
@click.option(
    "--load-critical",
    help="Critical threshold for global cpu load",
)
@click.option(
    "warning_values",
    "--value-warning",
    multiple=True,
    help=(
            "Set a warning threshold for a value. "
            "Example: If cpu1-load should be in the range of 10% to 20% you can set "
            "--value-warning cpu-load:10:200 "
            "Can be specified multiple times"
    )
)
@click.option(
    "critical_values",
    "--value-critical",
    multiple=True,
    help=(
        "Set a critical threshold for a value. "
        "Example: If cpu1-load should be in the range of 10% to 20% you can set "
        "--value-critical cpu-load:10:200 "
        "Can be specified multiple times"
    )
)
@click.option(
    "--regex",
    "use_regex",
    default=False,
    is_flag=True,
    help=(
        "Treat values from --value-warning and --value-critical as regex to find all matching values."
        "Example: Warn if cpu load of at least one CPU is above 80%: --value-warning 'cpu\\d+-load:80'"
    )
)
@click.pass_context
@nagiosplugin.guarded
def system_cpu(ctx, load_warning, load_critical, warning_values, critical_values, use_regex):
    """This command reads the information from /system/resource and /system/resource/cpu to extract the required
    information.
    """
    check = nagiosplugin.Check()

    resource = SystemCpuResource(
        cmd_options=ctx.obj,
        check=check,
        warning_values=warning_values,
        critical_values=critical_values,
        use_regex=use_regex,
    )
    check.add(
        resource,
        nagiosplugin.ScalarContext(
            name="cpu-load",
            warning=load_warning,
            critical=load_critical,
        ),
        SystemCpuSummary(),
    )

    check.main(verbose=ctx.obj["verbose"])
