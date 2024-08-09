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


class RoutingBGPPeerResource(RouterOSCheckResource):
    name = "BGP Peer"

    def __init__(
            self,
            cmd_options: Dict[str, Any],
            names: List[str],
            regex: bool,
            single_peer: bool,
    ):
        super().__init__(cmd_options=cmd_options)

        self._peer_data: Optional[Dict[str, Any]] = None
        self.names: List[Union[Any]] = names
        self.regex = regex
        if self.regex:
            regex_names = []
            for name in names:
                regex_names.append(re.compile(name))
            self.names = regex_names
        self.single_peer = single_peer
        self.state: Optional[str] = None

        self._routeros_metric_values = [
            {"name": "disabled", "type": bool},
            {"name": "prefix-count", "dst": "prefix_count", "type": int},
            {"name": "state", "type": str},
            {"name": "updates-received", "dst": "updates_received", "type": int},
            {"name": "updates-sent", "dst": "updates_sent", "type": int},
            {"name": "uptime", "type": self.parse_routeros_time_duration, "min": 0, "uom": "s"},
        ]

    def fetch_data(self) -> Dict[str, Dict]:
        if self._peer_data:
            return self._peer_data

        api = self._connect_api()

        logger.info("Fetching data ...")
        call = api.path(
            "/routing/bgp/peer"
        )
        call_results = tuple(call)

        self._peer_data = {}
        for result in call_results:
            if self.regex:
                for name in self.names:
                    if name.match(result["name"]):
                        self._peer_data[result["name"]] = result
            elif result["name"] in self.names:
                self._peer_data[result["name"]] = result
        return self._peer_data

    @property
    def peer_names(self):
        return tuple(self.fetch_data().keys())

    def probe(self):
        routeros_metrics = []
        data = self.fetch_data()

        if self.single_peer:
            if len(self.peer_names) == 1:
                return self.get_routeros_metric_item(data[self.peer_names[0]])
        else:
            for name in self.peer_names:
                routeros_metrics += self.get_routeros_metric_item(data[name], name_prefix=f"{name} ")

        return routeros_metrics


class RoutingBGPPeerState(BooleanContext):
    def __init__(self, *args, **kwargs):
        super(RoutingBGPPeerState, self).__init__(*args, **kwargs)
        self.fmt_metric = "{name} is {valueunit}"

    def evaluate(self, metric, resource: RoutingBGPPeerResource):
        if metric.value is None:
            return nagiosplugin.Result(
                state=nagiosplugin.state.Critical,
                # hint=f"Neighbor for instance '{resource.instance}' and router-id '{resource.router_id}' not found"
            )

        value = metric.value
        if value in ("established",):
            return self.result_cls(
                state=nagiosplugin.state.Ok,
                hint="Connection with peer established",
            )

        elif value in ("idle", "connect", "active", "opensent", "openconfirm"):
            return self.result_cls(
                state=nagiosplugin.state.Critical,
                hint=f"Connection to peer not established (State: {value})"
            )
        else:
            return self.result_cls(
                state=nagiosplugin.state.Unknown,
                hint=f"Unable to find peer state (State: {value})"
            )


class RoutingBGPPeerSummary(nagiosplugin.Summary):
    def ok(self, results: List[nagiosplugin.Result]):
        for result in results:
            if isinstance(result.resource, RoutingBGPPeerResource):
                data = result.resource.fetch_data()
                texts = []
                for name in result.resource.peer_names:
                    texts.append(f"Connection to {name} is {data[name]['state']}")
                return ", ".join(texts)

        return ""


@cli.command("routing.bgp.peers")
@click.option(
    "--name",
    "names",
    default=[],
    multiple=True,
    help="The name of the BGP peer to check. This can be specified multiple times",
)
@click.option(
    "--regex",
    "regex",
    default=False,
    is_flag=True,
    help="Treat the specified names as regular expressions and try to find all matching peers. (Default: not set)",
)
@click.option(
    "--single",
    "single",
    default=False,
    is_flag=True,
    help="If set the check expects the peer to exist",
)
@click.pass_context
def routing_bgp_peer(ctx, names, regex, single):
    resource = RoutingBGPPeerResource(
        cmd_options=ctx.obj,
        names=names,
        regex=regex,
        single_peer=single,
    )
    check = nagiosplugin.Check(
        resource,
        RoutingBGPPeerSummary(),
    )

    if single:
        if len(resource.peer_names) == 1:
            check.add(
                BooleanContext("disabled"),
                RoutingBGPPeerState("state"),
                nagiosplugin.ScalarContext("prefix_count"),
                nagiosplugin.ScalarContext("uptime"),
                nagiosplugin.ScalarContext("updates_received"),
                nagiosplugin.ScalarContext("updates_sent"),
            )
        else:
            check.results.add(
                nagiosplugin.Result(
                    nagiosplugin.state.Unknown,
                    f"Only one matching peer is allowed. Found {len(resource.peer_names)}"
                )
            )
    else:
        for name in resource.peer_names:
            check.add(
                BooleanContext(f"{name} disabled"),
                RoutingBGPPeerState(f"{name} state"),
                nagiosplugin.ScalarContext(f"{name} prefix_count"),
                nagiosplugin.ScalarContext(f"{name} uptime"),
                nagiosplugin.ScalarContext(f"{name} updates_received"),
                nagiosplugin.ScalarContext(f"{name} updates_sent"),
            )

    check.main(verbose=ctx.obj["verbose"])
