# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

import re
from typing import Any, Dict, List, Optional, Union

import click
import nagiosplugin

from ..cli import cli
from ..context import BooleanContext, ScalarPercentContext
from ..helper import escape_filename, logger
from ..resource import RouterOSCheckResource


class InterfaceResource(RouterOSCheckResource):
    name = "Interface"

    def __init__(
            self,
            cmd_options: Dict[str, Any],
            check: nagiosplugin.Check,
            names: List[str],
            regex: bool,
            single_interface: bool,
            ignore_disabled: bool,
            cookie_filename: str,
            warning_values: List[str],
            critical_values: List[str],
            override_values: List[str],
    ):
        super().__init__(cmd_options=cmd_options)

        self._check = check
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
        self.cookie_filename = cookie_filename

        self._parsed_warning_values: Dict[str, str] = self.prepare_thresholds(warning_values)
        self._parsed_critical_values: Dict[str, str] = self.prepare_thresholds(critical_values)
        self._parsed_override_values: Dict[str, str] = self.prepare_override_values(override_values)

        self._routeros_metric_values = [
            # Later values depend on the speed
            {
                "name": "speed",
                "missing_ok": True,
                "dst_value_name": "speed-byte",
                "type": self.parse_routeros_speed,
                "factor": 1 / 8,
                "no_metric": True,
            },
            {
                "name": "speed",
                "missing_ok": True,
                "type": self.parse_routeros_speed,
                "min": 0,
            },
            {
                "name": "disabled",
                "type": bool,
                "context_class": None,
            },
            {
                "name": "running",
                "type": bool,
                "context_class": None,
            },
            {
                "name": "actual-mtu",
                "type": int,
                "min": 0,
            },
            {
                "name": "fp-rx-byte",
                "type": int,
                "min": 0,
                "uom": "B",
                "rate": True,
                "rate_percent_total_name": "speed-byte",
            },
            {
                "name": "fp-rx-packet",
                "type": int,
                "min": 0,
                "uom": "c",
                "rate": True,
            },
            {
                "name": "fp-tx-byte",
                "type": int,
                "min": 0,
                "uom": "B",
                "rate": True,
                "rate_percent_total_name": "speed-byte",
            },
            {
                "name": "fp-tx-packet",
                "type": int,
                "min": 0,
                "uom": "c",
                "rate": True,
            },
            {
                "name": "l2mtu",
                "type": int,
                "min": 0,
                # CHR devices don't report l2mtu
                "missing_ok": True,
            },
            {
                "name": "link-downs",
                "type": int,
                "min": 0,
                "uom": "c",
            },
            # {"name": "mtu", "type": int, "min": 0},
            {
                "name": "rx-byte",
                "type": int,
                "min": 0,
                "uom": "B",
                "rate": True,
                "rate_percent_total_name": "speed-byte",
            },
            {
                "name": "rx-drop",
                "type": int,
                "min": 0,
                "uom": "c",
                "rate": True,
            },
            {
                "name": "rx-error",
                "type": int,
                "min": 0,
                "uom": "c",
                "rate": True,
            },
            {
                "name": "rx-packet",
                "type": int,
                "min": 0,
                "uom": "c",
                "rate": True,
                "rate_percent_total_name": "speed-byte",
            },
            {
                "name": "tx-byte",
                "type": int,
                "min": 0,
                "uom": "B",
                "rate": True,
            },
            {
                "name": "tx-drop",
                "type": int,
                "min": 0,
                "uom": "c",
                "rate": True,
            },
            {
                "name": "tx-error",
                "type": int,
                "min": 0,
                "uom": "c",
                "rate": True,
            },
            {
                "name": "tx-packet",
                "type": int,
                "min": 0,
                "uom": "c",
                "rate": True,
            },
            {
                "name": "tx-queue-drop",
                "type": int,
                "min": 0,
                "uom": "c",
                "rate": True
            },
        ]

    def _add_contexts(self, name, values, metric_prefix=""):
        self._check.add(
            InterfaceDisabledContext(f"{metric_prefix.format(name=name)}disabled", interface_name=name),
            InterfaceRunningContext(f"{metric_prefix.format(name=name)}running", interface_name=name),
        )
        custom_metric_names = ["disabled", "running"]

        for metric_value in self._routeros_metric_values:
            metric_value_name = metric_value.get("dst", metric_value["name"])
            if metric_value_name in custom_metric_names:
                continue

            if metric_value.get("no_metric"):
                continue

            context_class = metric_value.get("context_class", nagiosplugin.ScalarContext)
            self._check.add(
                context_class(
                    f"{metric_prefix.format(name=name)}{metric_value_name}",
                    warning=self._parsed_warning_values.get(metric_value["name"]),
                    critical=self._parsed_critical_values.get(metric_value["name"]),
                )
            )

            if metric_value.get("rate"):
                rate_percent_total_name = metric_value.get("rate_percent_total_name")
                rate_total_value = None
                if rate_percent_total_name:
                    rate_total_value = values.get(rate_percent_total_name)

                if rate_total_value is not None:
                    rate_context_class_percent = metric_value.get("context_class", ScalarPercentContext)
                    self._check.add(
                        rate_context_class_percent(
                            name=f"{metric_prefix.format(name=name)}{metric_value_name}_rate",
                            total_value=rate_total_value,
                            warning=self._parsed_warning_values.get(f"{metric_value['name']}_rate"),
                            critical=self._parsed_critical_values.get(f"{metric_value['name']}_rate"),
                        )
                    )
                else:
                    rate_context_class = metric_value.get("context_class", nagiosplugin.ScalarContext)
                    self._check.add(
                        rate_context_class(
                            name=f"{metric_prefix.format(name=name)}{metric_value_name}_rate",
                            warning=self._parsed_warning_values.get(metric_value["name"]),
                            critical=self._parsed_critical_values.get(metric_value["name"]),
                        )
                    )

    def fetch_data(self) -> Dict[str, Dict]:
        if self._interface_data:
            return self._interface_data

        api = self._connect_api()

        logger.info("Fetching data ...")
        interface_ethernet_data = {}
        call = api.path(
            "/interface/ethernet"
        )
        call_results = tuple(call)
        for result in call_results:
            interface_ethernet_data[result["name"]] = {
                "speed": result["speed"],
            }

        call = api.path(
            "/interface"
        )
        call_results = tuple(call)

        self._interface_data = {}
        for result in call_results:
            if self.ignore_disabled and result["disabled"]:
                continue

            if result["name"] in interface_ethernet_data:
                result.update(interface_ethernet_data[result["name"]])

            result.update(self._parsed_override_values)

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
                cookie_filename = self.cookie_filename.format(
                    name=escape_filename(self.interface_names[0])
                )
                with nagiosplugin.Cookie(cookie_filename) as cookie:
                    routeros_metrics += self.get_routeros_metric_item(data[self.interface_names[0]], cookie=cookie)
                self._add_contexts(name=self.interface_names[0], values=data[self.interface_names[0]])
        else:
            for name in self.interface_names:
                cookie_filename = self.cookie_filename.format(
                    name=escape_filename(name)
                )
                with nagiosplugin.Cookie(cookie_filename) as cookie:
                    routeros_metrics += self.get_routeros_metric_item(data[name], name_prefix=f"{name} ", cookie=cookie)
                self._add_contexts(name=name, values=data[name], metric_prefix="{name} ")

        return routeros_metrics


class InterfaceDisabledContext(BooleanContext):
    def __init__(self, name, interface_name):
        super().__init__(name=name)
        self._interface_name = interface_name

    def evaluate(self, metric, resource: InterfaceResource):
        if metric.value is True:
            return self.result_cls(
                nagiosplugin.state.Warn,
                hint="Interface '{self._interface_name}' is disabled",
                metric=metric
            )
        return self.result_cls(nagiosplugin.state.Ok)


class InterfaceRunningContext(BooleanContext):
    def __init__(self, name, interface_name):
        super().__init__(name=name)

        self._interface_name = interface_name

    def evaluate(self, metric, resource: InterfaceResource):
        if metric.value is False:
            return self.result_cls(
                state=nagiosplugin.state.Warn,
                hint=f"Interface '{self._interface_name}' not running",
                metric=metric
            )
        return self.result_cls(nagiosplugin.state.Ok)


@cli.command("interface")
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
@click.option(
    "--cookie-filename",
    "cookie_filename",
    default="/tmp/check_routeros_interface_{name}.data",
    help=(
        "The filename to use to store the information to calculate the rate. '{name}' will be replaced with an "
        "internal uniq id. It Will create one file per interface."
        "(Default: /tmp/check_routeros_interface_{name}.data)"
    ),
)
@click.option(
    "override_values",
    "--value-override",
    multiple=True,
    help=(
        "Override a value read from the RouterOS device. "
        "Format of the value must be compatible with RouterOS values. "
        "Example: Override/Set the speed value for bridges or tunnels: "
        "--value-override speed:10Gbps"
    )
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
@click.pass_context
def interface(
    ctx, names, regex, single, ignore_disabled, cookie_filename, warning_values, critical_values, override_values
):
    """Check the state and the stats of interfaces"""
    check = nagiosplugin.Check()
    resource = InterfaceResource(
        cmd_options=ctx.obj,
        check=check,
        names=names,
        regex=regex,
        single_interface=single,
        ignore_disabled=ignore_disabled,
        cookie_filename=cookie_filename,
        warning_values=warning_values,
        critical_values=critical_values,
        override_values=override_values,
    )

    check.add(resource)
    check.results.add(
        nagiosplugin.Result(
            nagiosplugin.state.Ok,
            "All interfaces UP"
        )
    )

    if single and len(resource.interface_names) != 1:
        check.results.add(
            nagiosplugin.Result(
                nagiosplugin.state.Unknown,
                f"Only one matching interface is allowed. Found {len(resource.interface_names)}"
            )
        )

    check.main(verbose=ctx.obj["verbose"])
