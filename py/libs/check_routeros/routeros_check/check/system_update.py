# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import List, Optional

import click
import nagiosplugin

from ..cli import cli
from ..helper import logger, RouterOSVersion
from ..resource import RouterOSCheckResource


class SystemUpdateResource(RouterOSCheckResource):
    name = "Update"

    def __init__(
        self,
        cmd_options,
        check: nagiosplugin.Check,
        check_for_update: bool = False,
        latest_version: Optional[str] = None,
    ):
        super().__init__(cmd_options=cmd_options)

        self._check = check
        self._check_for_update = check_for_update
        self._installed_version = None
        self._latest_version = None
        if latest_version:
            self._latest_version = RouterOSVersion(latest_version)

    def probe(self):
        logger.info("Fetching data ...")
        if self._check_for_update:
            logger.debug("Run command to check for updates ...")
            call = self.api(
                "/system/package/update/check-for-updates"
            )
            logger.debug("Waiting that update command finished")
            # Wait until command has finished
            tuple(call)

        call = self.api.path(
            "/system/package/update"
        )
        result = tuple(call)[0]

        self._routeros_metric_values = [
            {"name": "channel", "type": None},
        ]

        installed_version = result.get("installed-version")
        if installed_version:
            self._installed_version = RouterOSVersion(installed_version)
            self._check.results.add(
                nagiosplugin.Result(
                    nagiosplugin.Ok,
                    hint=f"Installed version: {self._installed_version}"
                )
            )
        else:
            self._check.results.add(
                nagiosplugin.Result(
                    nagiosplugin.Warn,
                    hint="Unable to get installed version"
                )
            )

        latest_version = result.get("latest-version")
        if self._latest_version is None and latest_version:
            self._latest_version = RouterOSVersion(latest_version)

        if self._installed_version and self._latest_version:
            if self._installed_version < self._latest_version:
                self._check.results.add(
                    nagiosplugin.Result(
                        nagiosplugin.Critical,
                        hint=(
                            f"Update version '{self._latest_version}' available. "
                            f"Version installed '{self._installed_version}'"
                        )
                    )
                )

        status = result.get("status")
        if isinstance(status, str) and "error" in status.lower():
            self._check.results.add(
                nagiosplugin.Result(
                    nagiosplugin.Critical,
                    hint=f"Looks like there was an error: '{status}'"
                )
            )

        return self.get_routeros_metric_item(result)


class SystemUpdateChannelContext(nagiosplugin.Context):
    def __init__(self, *args, channels: Optional[List[str]] = None, **kwargs):
        super(SystemUpdateChannelContext, self).__init__(*args, **kwargs)
        self._channels = channels

    def evaluate(self, metric, resource):
        if self._channels is None or len(self._channels) == 0 or metric.value in self._channels:
            return nagiosplugin.Result(
                nagiosplugin.Ok,
                hint=f"Update channel is '{metric.value}'"
            )

        return nagiosplugin.Result(
            nagiosplugin.Warn,
            hint=f"Update channel '{metric.value}' not in list with allowed channels: {', '.join(self._channels)}"
        )


class SystemUpdateSummary(nagiosplugin.Summary):
    def ok(self, results: List[nagiosplugin.Result]):
        messages = []
        for result in results:
            messages.append(result.hint)

        if len(messages) > 0:
            return ", ".join(messages)

        return "Looks good"


@cli.command("system.update")
@click.option(
    "--channel",
    "channels",
    default=None,
    multiple=True,
    help="Allowed update channel. Repeat to use multiple values."
)
@click.option(
    "--latest-version",
    "latest_version",
    default=None,
    help=(
        "Set a version that should at least be installed. "
        "Use this if the update server is not available or if you want check with your own update policy."
    )
)
@click.option(
    "--check-for-update",
    "check_for_update",
    is_flag=True,
    default=False,
    help=(
        "Actively check for updates. "
        "This will run the command /system/package/update/check-for-updates . "
        "If you don't whant to use this feature you have to schedule a task to look for updates."
    )
)
@click.pass_context
@nagiosplugin.guarded
def system_update(ctx, channels, latest_version, check_for_update):
    check = nagiosplugin.Check()

    check.add(
        SystemUpdateResource(
            cmd_options=ctx.obj,
            check=check,
            check_for_update=check_for_update,
            latest_version=latest_version,
        ),
        SystemUpdateChannelContext(
            name="channel",
            channels=channels,
        ),
        SystemUpdateSummary(),
    )

    check.main(verbose=ctx.obj["verbose"])
