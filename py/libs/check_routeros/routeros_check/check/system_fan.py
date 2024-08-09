# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

import re
from typing import Dict, List, Set

import click
import nagiosplugin

from ..cli import cli
from ..helper import logger, RouterOSVersion
from ..resource import RouterOSCheckResource


class SystemFanResource(RouterOSCheckResource):
    name = "FAN"

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

        self.fan_names: Set[str] = set()
        self.fan_values: Dict[str, int] = {}
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
        api_results = tuple(call)
        if self.routeros_version < RouterOSVersion("7"):
            api_result_items = []
            for name, value in api_results[0].items():
                api_result_items.append({
                    "name": name,
                    "value": value,
                })
        else:
            api_result_items = api_results

        regex_name = re.compile(r"(?P<name>fan\d+)-(?P<type>(speed))")
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

            if m.group("type") in ("speed",):
                self.fan_values[item["name"]] = int(item["value"])

            self.fan_names.add(m.group("name"))

    def probe(self):
        for name, value in self.fan_values.items():
            self._check.add(nagiosplugin.ScalarContext(
                name=name,
                warning=self.warning_values.get(name),
                critical=self.critical_values.get(name),
            ))
            yield nagiosplugin.Metric(
                name=name,
                value=value,
            )


@cli.command("system.fan")
@click.option(
    "warning_values",
    "--value-warning",
    multiple=True,
    help=(
        "Set a warning threshold for a value. "
        "Example: If fan1-speed should be in the range of 4000 to 5000 you can set "
        "--value-warning fan1-speed:4000:5000 "
        "Can be specified multiple times"
    )
)
@click.option(
    "critical_values",
    "--value-critical",
    multiple=True,
    help=(
        "Set a critical threshold for a value. "
        "Example: If fan1-speed should be in the range of 4000 to 5000 you can set "
        "--value-critical fan1-speed:4000:5000 "
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
    "--no-fan-ok",
    is_flag=True,
    default=False,
    help="The check will be unknown if no fan is available. Provide this option to ignore this."
)
@click.option(
    "expected_names",
    "--expect-fan",
    multiple=True,
    default=[],
    help="Name of the fan to expect. Can be specified multiple times."
)
@click.pass_context
@nagiosplugin.guarded
def system_fan(ctx, warning_values, critical_values, use_regex, no_fan_ok, expected_names):
    check = nagiosplugin.Check()

    fan_resource = SystemFanResource(
        cmd_options=ctx.obj,
        check=check,
        warning_values=warning_values,
        critical_values=critical_values,
        use_regex=use_regex,
    )
    check.add(fan_resource)

    check.results.add(
        nagiosplugin.Result(
            nagiosplugin.state.Ok,
            hint=f"Looks like all fans work as expected: {', '.join(sorted(fan_resource.fan_names))}"
        )
    )
    if len(fan_resource.fan_names) == 0 and not no_fan_ok:
        check.results.add(
            nagiosplugin.Result(
                nagiosplugin.state.Unknown,
                hint="No FANs found"
            )
        )

    if len(expected_names) > 0:
        missing_names = []
        for name in expected_names:
            if name not in fan_resource.fan_names:
                missing_names.append(name)

        if len(missing_names) > 0:
            check.results.add(
                nagiosplugin.Result(
                    nagiosplugin.state.Warn,
                    hint=f"Expected FAN(s) not found: {', '.join(missing_names)}"
                )
            )

    check.main(verbose=ctx.obj["verbose"])
