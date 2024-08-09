# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

import re
from typing import Any, Dict, List, Optional, Union

import click
import nagiosplugin

from ..cli import cli
from ..context import BooleanContext
from ..helper import logger
from ..resource import RouterOSCheckResource


class InterfaceGREResource(RouterOSCheckResource):
    name = "GRE"

    def __init__(
            self,
            cmd_options: Dict[str, Any],
            names: List[str],
            regex: bool,
            single_interface: bool,
            ignore_disabled: bool,
    ):
        super().__init__(cmd_options=cmd_options)

        self._interface_data: Optional[Dict[str, Any]] = None
        self.names: List[Union[Any]] = names
        self.regex = regex
        if self.regex:
            regex_names = []
            for name in names:
                regex_names.append(re.compile(name))
            self.names = regex_names
        self.single_interface = single_interface
        self.ignore_disabled = ignore_disabled

        self._routeros_metric_values = [
            {"name": "disabled", "type": bool},
            {"name": "running", "type": bool},
            {"name": "actual-mtu", "type": int, "min": 0},
        ]

    def fetch_data(self) -> Dict[str, Dict]:
        if self._interface_data:
            return self._interface_data

        api = self._connect_api()

        logger.info("Fetching data ...")
        call = api.path(
            "/interface/gre"
        )
        call_results = tuple(call)

        self._interface_data = {}
        for result in call_results:
            if self.ignore_disabled and result["disabled"]:
                continue
            if len(self.names) == 0:
                self._interface_data[result["name"]] = result
            elif self.regex:
                for name in self.names:
                    if name.match(result["name"]):
                        self._interface_data[result["name"]] = result
            elif result["name"] in self.names:
                self._interface_data[result["name"]] = result
        return self._interface_data

    @property
    def interface_names(self):
        return tuple(self.fetch_data().keys())

    def probe(self):
        routeros_metrics = []
        data = self.fetch_data()

        if self.single_interface:
            if len(self.interface_names) == 1:
                return self.get_routeros_metric_item(data[self.interface_names[0]])
        else:
            for name in self.interface_names:
                routeros_metrics += self.get_routeros_metric_item(data[name], name_prefix=f"{name} ")

        return routeros_metrics


class InterfaceGREDisabledContext(BooleanContext):
    def __init__(self, name, interface_name):
        super().__init__(name=name)
        self._interface_name = interface_name

    def evaluate(self, metric, resource: InterfaceGREResource):
        if metric.value is True:
            return self.result_cls(
                nagiosplugin.state.Warn,
                hint="GRE interface '{self._interface_name}' is disabled",
                metric=metric
            )
        return self.result_cls(nagiosplugin.state.Ok)


class InterfaceGRERunningContext(BooleanContext):
    def __init__(self, name, interface_name):
        super().__init__(name=name)

        self._interface_name = interface_name

    def evaluate(self, metric, resource: InterfaceGREResource):
        if metric.value is False:
            return self.result_cls(
                state=nagiosplugin.state.Warn,
                hint=f"GRE interface '{self._interface_name}' not running",
                metric=metric
            )
        return self.result_cls(nagiosplugin.state.Ok)


@cli.command("interface.gre")
@click.option(
    "--name",
    "names",
    default=[],
    multiple=True,
    help="The name of the GRE interface to monitor. This can be specified multiple times",
)
@click.option(
    "--regex",
    "regex",
    default=False,
    is_flag=True,
    help="Treat the specified names as regular expressions and try to find all matching interfaces. (Default: not set)",
)
@click.option(
    "--single",
    "single",
    default=False,
    is_flag=True,
    help="If set the check expects the interface to exist",
)
@click.option(
    "--ignore-disabled/--no-ignore-disabled",
    default=True,
    is_flag=True,
    help="Ignore disabled interfaces",
)
@click.pass_context
def interface_gre(ctx, names, regex, single, ignore_disabled):
    """Check the state of a GRE interface."""
    resource = InterfaceGREResource(
        cmd_options=ctx.obj,
        names=names,
        regex=regex,
        single_interface=single,
        ignore_disabled=ignore_disabled,
    )
    check = nagiosplugin.Check(
        resource,
    )

    if single:
        if len(resource.interface_names) == 1:
            name = resource.interface_names[0]
            check.add(
                InterfaceGREDisabledContext("disabled", interface_name=name),
                InterfaceGRERunningContext("running", interface_name=name),
                nagiosplugin.ScalarContext("actual-mtu"),
            )
        else:
            check.results.add(
                nagiosplugin.Result(
                    nagiosplugin.state.Unknown,
                    f"Only one matching interface is allowed. Found {len(resource.interface_names)}"
                )
            )
    else:
        for name in resource.interface_names:
            check.add(
                InterfaceGREDisabledContext(f"{name} disabled", interface_name=name),
                InterfaceGRERunningContext(f"{name} running", interface_name=name),
                nagiosplugin.ScalarContext(f"{name} actual-mtu"),
            )

    check.main(verbose=ctx.obj["verbose"])
