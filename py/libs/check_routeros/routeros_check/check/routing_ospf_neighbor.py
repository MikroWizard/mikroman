# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Any, Dict, Optional

import click
import librouteros
import librouteros.query
import nagiosplugin

from ..cli import cli
from ..context import BooleanContext
from ..helper import logger, RouterOSVersion
from ..resource import RouterOSCheckResource


class RoutingOSPFNeighborResource(RouterOSCheckResource):
    name = "OSPF NEIGHBOR"

    def __init__(
            self,
            cmd_options: Dict[str, Any],
            instance: str,
            router_id: str,
            area: Optional[str] = None
    ):
        super().__init__(cmd_options=cmd_options)

        self.area = area
        self.instance = instance
        self.router_id = router_id

        self.state: Optional[str] = None

        self._routeros_metric_values = [
            {"name": "adjacency", "type": self.parse_routeros_time_duration, "min": 0, "uom": "s"},
            {"name": "state", "type": None},
            {"name": "state-changes", "dst": "state_changes", "type": int},
        ]
        if self.routeros_version < RouterOSVersion("7"):
            self._routeros_metric_values += [
                {"name": "priority", "type": int},
                {"name": "ls-retransmits", "dst": "ls_retransmits", "type": int},
                {"name": "ls-requests", "dst": "ls_requests", "type": int},
                {"name": "db-summaries", "dst": "db_summaries", "type": int},
            ]

    def probe(self):
        # ToDo: Only available in v7.x
        key_area = librouteros.query.Key("area")
        key_instance = librouteros.query.Key("instance")
        key_router_id = librouteros.query.Key("router-id")

        logger.info("Fetching data ...")

        select_keys = [
            key_instance,
            key_router_id,
        ] + self.get_routeros_select_keys()

        if self.routeros_version >= RouterOSVersion("7"):
            select_keys.append(key_area)

        where = [
            key_instance == self.instance,
            key_router_id == self.router_id,
        ]

        if self.area is not None:
            if self.routeros_version >= RouterOSVersion("7"):
                where.append(key_area == self.area)
            else:
                logger.warning("The area selector is only available on RouterOS 7.x")

        call = self.api.path(
            "/routing/ospf/neighbor"
        ).select(
            *select_keys
        ).where(
            *where
        )
        results = tuple(call)
        if len(results) == 0:
            return nagiosplugin.Metric(
                name="state",
                value=None
            )

        result = results[0]

        return self.get_routeros_metric_item(result)


class RoutingOSPFNeighborState(BooleanContext):
    def evaluate(self, metric, resource: RoutingOSPFNeighborResource):
        if metric.value is None:
            if resource.area is None:
                hint = f"Neighbor for instance '{resource.instance}' and router-id '{resource.router_id}' not found"
            else:
                hint = (
                    f"Neighbor for area '{resource.area}', instance '{resource.instance}' and "
                    f"router-id '{resource.router_id}' not found"
                )
            return nagiosplugin.Result(
                state=nagiosplugin.state.Critical,
                hint=hint
            )
        elif metric.value in ("Down",):
            return self.result_cls(
                state=nagiosplugin.state.Critical,
                hint="Link to neighbor down"
            )
        elif metric.value in ("Full",):
            return self.result_cls(
                state=nagiosplugin.state.Ok,
                hint="Communicating with neighbor"
            )
        else:
            return self.result_cls(
                state=nagiosplugin.state.Warn,
                hint=f"Link to neighbor not fully up, state: {metric.value}"
            )


@cli.command("routing.ospf.neighbors")
@click.option(
    "--area",
    help="The area the neighbor router belongs to (only supported on RouterOS v7.x",
)
@click.option(
    "--instance",
    required=True,
    help="The name of the OSPF instance",
)
@click.option(
    "--router-id",
    required=True,
    help="The ID of the neighbor router",
)
@click.pass_context
def routing_ospf_neighbors(ctx, area, instance, router_id):
    """Check the state of an OSPF neighbor"""
    resource = RoutingOSPFNeighborResource(
        cmd_options=ctx.obj,
        area=area,
        instance=instance,
        router_id=router_id,
    )
    check = nagiosplugin.Check(
        resource,
        nagiosplugin.ScalarContext("priority"),
        nagiosplugin.ScalarContext("adjacency"),
        nagiosplugin.ScalarContext("state_changes"),
        nagiosplugin.ScalarContext("ls_retransmits"),
        nagiosplugin.ScalarContext("ls_requests"),
        nagiosplugin.ScalarContext("db_summaries"),
        RoutingOSPFNeighborState("state")
    )

    check.main(verbose=ctx.obj["verbose"])
