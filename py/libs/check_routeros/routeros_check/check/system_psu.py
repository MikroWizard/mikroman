# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

import re
from typing import Dict, List, Set

import click
import nagiosplugin

from ..cli import cli
from ..context import BooleanContext
from ..helper import logger, RouterOSVersion
from ..resource import RouterOSCheckResource


class SystemPsuResource(RouterOSCheckResource):
    name = "PSU"

    def __init__(
        self, cmd_options, check: nagiosplugin.Check, warning_values: List[str], critical_values: List[str],
        no_psu_ok: bool,
    ):
        super().__init__(cmd_options=cmd_options)

        self._check = check

        self.psu_names: Set[str] = set()
        self.psu_states: Dict[str, str] = {}
        self.psu_values: Dict[str, float] = {}
        self.warning_values = self._prepare_thresholds(warning_values)
        self.critical_values = self._prepare_thresholds(critical_values)
        self.no_psu_ok = no_psu_ok

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

        regex_name = re.compile(r"(?P<name>psu\d+)-(?P<type>(state|current|voltage))")
        for api_result_item in api_result_items:
            m = regex_name.match(api_result_item["name"])
            if not m:
                continue

            self.psu_names.add(m.group("name"))

            if m.group("type") in ("current", "voltage"):
                self.psu_values[api_result_item["name"]] = float(api_result_item["value"])

            if m.group("type") == "state":
                self.psu_states[m.group("name")] = api_result_item["value"]

        if not self.no_psu_ok and len(self.psu_values) == 0 and len(self.psu_states) == 0:
            self._check.results.add(
                nagiosplugin.Result(
                    nagiosplugin.state.Unknown,
                    hint="No PSU values and stats found"
                )
            )

    @staticmethod
    def _prepare_thresholds(thresholds: List[str]):
        results = {}
        for threshold in thresholds:
            name, _, value = threshold.partition(":")
            if value is None or value == "":
                logger.warning(f"Unable to parse threshold for {name}")
            results[name] = value
        return results

    def probe(self):
        for name, value in self.psu_values.items():
            self._check.add(nagiosplugin.ScalarContext(
                name=name,
                warning=self.warning_values.get(name),
                critical=self.critical_values.get(name),
            ))
            yield nagiosplugin.Metric(
                name=name,
                value=value,
            )
        for name, value in self.psu_states.items():
            value_name = f"{name}-state-ok"
            self._check.add(
                BooleanContext(value_name)
            )
            if value != "ok":
                self._check.results.add(
                    nagiosplugin.Result(
                        nagiosplugin.state.Warn,
                        hint=f"PSU: {name} state {value}"
                    )
                )
            yield nagiosplugin.Metric(
                name=value_name,
                value=(value == "ok")
            )


@cli.command("system.psu")
@click.option(
    "warning_values",
    "--value-warning",
    multiple=True,
    help=(
        "Set a warning threshold for a value. "
        "Example: If psu1-voltage should be in the range of 12-12.1V you can set --value-warning psu1-voltage:12:12.1 "
        "Can be specified multiple times"
    )
)
@click.option(
    "critical_values",
    "--value-critical",
    multiple=True,
    help=(
        "Set a critical threshold for a value. "
        "Example: If psu1-voltage should be in the range of 12-12.1V you can set --value-critical psu1-voltage:12:12.1 "
        "Can be specified multiple times"
    )
)
@click.option(
    "--no-psu-ok",
    is_flag=True,
    default=False,
    help="The check will be unknown if not at least one psu stat or value is available. Set this to ignore this."
)
@click.option(
    "expected_psu_names",
    "--expect-psu",
    multiple=True,
    default=[],
    help="Name of the PSU to expect at least one value or state. Can be specified multiple times."
)
@click.pass_context
@nagiosplugin.guarded
def system_psu(ctx, warning_values, critical_values, no_psu_ok, expected_psu_names):
    """Check the power supply units (PSU)"""
    check = nagiosplugin.Check()

    psu_resource = SystemPsuResource(
        cmd_options=ctx.obj,
        check=check,
        warning_values=warning_values,
        critical_values=critical_values,
        no_psu_ok=no_psu_ok,
    )
    check.add(psu_resource)

    check.results.add(
        nagiosplugin.Result(
            nagiosplugin.state.Ok,
            hint=f"Looks like all PSU work like expected: {', '.join(psu_resource.psu_names)}"
        )
    )
    if len(expected_psu_names) > 0:
        missing_psu_names = []
        for psu_name in expected_psu_names:
            if psu_name not in psu_resource.psu_names:
                missing_psu_names.append(psu_name)

        if len(missing_psu_names) > 0:
            check.results.add(
                nagiosplugin.Result(
                    nagiosplugin.state.Warn,
                    hint=f"Expected PSU(s) not found: {', '.join(missing_psu_names)}"
                )
            )

    check.main(verbose=ctx.obj["verbose"])
