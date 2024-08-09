# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

import re
from typing import Dict, List, Set

import click
import nagiosplugin

from ..cli import cli
from ..helper import logger, RouterOSVersion
from ..resource import RouterOSCheckResource


class SystemTemperatureResource(RouterOSCheckResource):
    name = "Temperature"

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

        self.names: Set[str] = set()
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

        self._fetch_data()

    def _fetch_data(self):
        logger.info("Fetching data ...")
        call = self.api.path(
            "/system/health"
        )
        api_result_items = tuple(call)
        if self.routeros_version < RouterOSVersion("7"):
            api_result_items = self._convert_v6_list_to_v7(api_result_items)

        regex_name = re.compile(r".*temperature.*")
        for item in api_result_items:
            m = regex_name.match(item["name"])
            if not m:
                continue

            if self.use_regex:
                for regex, threshold in self.warning_regex_values.items():
                    if regex.match(item["name"]):
                        self.warning_values[item["name"]] = threshold
                        break

                for regex, threshold in self.critical_regex_values.items():
                    if regex.match(item["name"]):
                        self.critical_values[item["name"]] = threshold
                        break

            self.names.add(item["name"])
            self.values[item["name"]] = float(item["value"])

    def probe(self):
        for name, value in self.values.items():
            self._check.add(nagiosplugin.ScalarContext(
                name=name,
                warning=self.warning_values.get(name),
                critical=self.critical_values.get(name),
            ))
            yield nagiosplugin.Metric(
                name=name,
                value=value,
            )


@cli.command("system.temperature")
@click.option(
    "warning_values",
    "--value-warning",
    multiple=True,
    help=(
        "Set a warning threshold for a value. "
        "Example: If cpu-temperature should be in the range of 40 and 60°C you can set "
        "--value-warning cpu-temperature:40:60 "
        "If cpu-temperature should not be higher than 50.5°C you can set "
        "--value-warning cpu-temperature:50.5 "
        "Can be specified multiple times"
    )
)
@click.option(
    "critical_values",
    "--value-critical",
    multiple=True,
    help=(
        "Set a critical threshold for a value. "
        "Example: If cpu-temperature should be in the range of 40 and 60°C you can set "
        "--value-critical cpu-temperature:40:60 "
        "If cpu-temperature should not be higher than 50.5°C you can set "
        "--value-critical cpu-temperature:50.5 "
        "Can be specified multiple times"
    )
)
@click.option(
    "--regex",
    "use_regex",
    default=False,
    is_flag=True,
    help="Treat values from --value-warning and --value-critical as regex to find all matching values"
)
@click.option(
    "--no-temperature-ok",
    is_flag=True,
    default=False,
    help="The check will be unknown if no temperature is available. Provide this option to ignore this."
)
@click.option(
    "expected_names",
    "--expect-temperature",
    multiple=True,
    default=[],
    help="Name of the temperature to expect. Can be specified multiple times. Example: board-temperature1"
)
@click.pass_context
@nagiosplugin.guarded
def system_temperature(ctx, warning_values, critical_values, use_regex, no_temperature_ok, expected_names):
    """This command reads the information from /system/health and extracts all values containing the
    word temperature in its name. Like 'board-temperature', 'board-temperature1', 'cpu-temperature', ...

    Be aware that not all devices return the same values.
    """
    check = nagiosplugin.Check()

    temperature_resource = SystemTemperatureResource(
        cmd_options=ctx.obj,
        check=check,
        warning_values=warning_values,
        critical_values=critical_values,
        use_regex=use_regex,
    )
    check.add(temperature_resource)

    check.results.add(
        nagiosplugin.Result(
            nagiosplugin.state.Ok,
            hint=f"Looks like all temperatures are OK:  {', '.join(sorted(temperature_resource.names))}"
        )
    )
    if len(temperature_resource.names) == 0 and not no_temperature_ok:
        check.results.add(
            nagiosplugin.Result(
                nagiosplugin.state.Unknown,
                hint="No temperatures found"
            )
        )

    if len(expected_names) > 0:
        missing_names = []
        for name in expected_names:
            if name not in temperature_resource.names:
                missing_names.append(name)

        if len(missing_names) > 0:
            check.results.add(
                nagiosplugin.Result(
                    nagiosplugin.state.Warn,
                    hint=f"Expected temperature(s) not found: {', '.join(missing_names)}"
                )
            )

    check.main(verbose=ctx.obj["verbose"])
