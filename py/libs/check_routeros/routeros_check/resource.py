# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later
from datetime import date, datetime, time
from decimal import Decimal
import re
import ssl
from typing import Any, Dict, List, Optional, Union

import librouteros
import librouteros.query
import nagiosplugin

from .helper import logger, RouterOSVersion
from .exeption import MissingValue


class RouterOSCheckResource(nagiosplugin.Resource):
    month_mapping: Dict[str, int] = {
        "jan": 1,
        "feb": 2,
        "mar": 3,
        "apr": 4,
        "may": 5,
        "jun": 6,
        "jul": 7,
        "aug": 8,
        "sep": 9,
        "oct": 10,
        "nov": 11,
        "dec": 12,
    }

    regex_datetime = re.compile(
        r"(?P<month>[a-z]{3})/(?P<day>\d+)/(?P<year>\d{4})\s+(?P<hour>\d+):(?P<minute>\d+):(?P<second>\d+)",
        flags=re.IGNORECASE
    )

    regex_date = re.compile(
        r"(?P<month>[a-z]{3})/(?P<day>\d+)/(?P<year>\d{4})",
        flags=re.IGNORECASE
    )

    regex_date_iso = re.compile(
        r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})",
        flags=re.IGNORECASE
    )

    regex_time = re.compile(
        r"(?P<hour>\d+):(?P<minute>\d+):(?P<second>\d+)",
        flags=re.IGNORECASE
    )

    def __init__(self, cmd_options: Dict[str, Any]):
        self._cmd_options = cmd_options
        self._routeros_metric_values: List[Dict[str, Any]] = []
        self._routeros_version: Optional[RouterOSVersion] = None
        self._api: Optional[librouteros.api.Api] = None
        self.current_time = datetime.now()

    @property
    def api(self):
        if self._api is None:
            self._api = self.connect_api()

        return self._api

    @property
    def routeros_version(self):
        if self._routeros_version is None:
            if self._cmd_options["routeros_version"].strip().lower() == "auto":
                self._routeros_version = self._get_routeros_version()
            else:
                self._routeros_version = RouterOSVersion(self._cmd_options["routeros_version"].strip())

        return self._routeros_version

    @staticmethod
    def _calc_rate(
            cookie: nagiosplugin.Cookie,
            name: str,
            cur_value: int,
            elapsed_seconds: Optional[float],
            factor: int
    ) -> float:
        old_value: Optional[int] = cookie.get(name)
        cookie[name] = cur_value
        if old_value is None:
            raise MissingValue(f"Unable to find old value for '{name}'")
        if elapsed_seconds is None:
            raise MissingValue("Unable to get elapsed seconds")
        return (cur_value - old_value) / elapsed_seconds * factor

    def _connect_api(self) -> librouteros.api.Api:
        def wrap_socket(socket):
            server_hostname: Optional[str] = self._cmd_options["hostname"]
            if server_hostname is None:
                server_hostname = self._cmd_options["host"]
            return ssl_ctx.wrap_socket(socket, server_hostname=server_hostname)

        # logger.info("Connecting to device ...")
        port = self._cmd_options["port"]
        extra_kwargs = {}
        if self._cmd_options["ssl"]:
            if port is None:
                port = 8729

            context_kwargs = {}
            if self._cmd_options["ssl_cafile"]:
                context_kwargs["cafile"] = self._cmd_options["ssl_cafile"]
            if self._cmd_options["ssl_capath"]:
                context_kwargs["capath"] = self._cmd_options["ssl_capath"]

            ssl_ctx = ssl.create_default_context(**context_kwargs)

            if self._cmd_options["ssl_force_no_certificate"]:
                ssl_ctx.check_hostname = False
                ssl_ctx.set_ciphers("ADH:@SECLEVEL=0")
            elif not self._cmd_options["ssl_verify"]:
                # We have do disable hostname check if we disable certificate verification
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            elif not self._cmd_options["ssl_verify_hostname"]:
                ssl_ctx.check_hostname = False

            extra_kwargs["ssl_wrapper"] = wrap_socket
        else:
            if port is None:
                port = 8728

        api = librouteros.connect(
            host=self._cmd_options["host"],
            username=self._cmd_options["username"],
            password=self._cmd_options["password"],
            port=port,
            timeout=self._cmd_options.get("timeout",5) ,
            **extra_kwargs
        )
        return api

    @staticmethod
    def _convert_v6_list_to_v7(api_results) -> List[Dict[str, Any]]:
        result_items = []
        for name, value in api_results[0].items():
            result_items.append({
                "name": name,
                "value": value,
            })
        return result_items

    def _get_routeros_version(self) -> RouterOSVersion:
        call = self.api.path(
            "/system/resource"
        )
        results = tuple(call)
        result: Dict[str, str] = results[0]
        # version: 7.8 (stable)
        version_string = result["version"].partition(" ")[0]
        return RouterOSVersion(version_string)

    def connect_api(self) -> librouteros.api.Api:
        if self._api is None:
            self._api = self._connect_api()

        return self._api

    @classmethod
    def parse_routeros_date(cls, date_string: str) -> date:
        # Try iso date
        # Looks like they have switched date format in 7.11
        m = cls.regex_date_iso.match(date_string)
        if m:
            return date(
                year=int(m.group("year")),
                month=int(m.group("month")),
                day=int(m.group("day"))
            )

        # Try US date
        m = cls.regex_date.match(date_string)
        if m:
            return date(
                year=int(m.group("year")),
                month=cls.month_mapping[m.group("month").lower()],
                day=int(m.group("day"))
            )

        raise ValueError("Unable to parse datetime string")

    @classmethod
    def parse_routeros_date_time(cls, date_string: str, time_string: str) -> datetime:
        parsed_date = cls.parse_routeros_date(date_string=date_string)
        parsed_time = cls.parse_routeros_time(time_string=time_string)

        return datetime.combine(parsed_date, parsed_time)

    @classmethod
    def parse_routeros_datetime(cls, datetime_string: str) -> datetime:
        m = cls.regex_datetime.match(datetime_string)
        if not m:
            raise ValueError("Unable to parse datetime string")

        return datetime(
            year=int(m.group("year")),
            month=cls.month_mapping[m.group("month").lower()],
            day=int(m.group("day")),
            hour=int(m.group("hour")),
            minute=int(m.group("minute")),
            second=int(m.group("second"))
        )

    @staticmethod
    def parse_routeros_speed(value_string: str) -> int:
        factors = {
            "": 1,
            "K": 1000,
            "M": 1000 * 1000,
            "G": 1000 * 1000 * 1000,
        }

        m = re.compile(r"(?P<value>\d+)(?P<factor>[A-Z]*)bps").match(value_string)
        if not m:
            raise ValueError(f"Unable to parse speed string: '{value_string}'")

        factor = factors.get(m.group("factor"))

        if factor is None:
            raise ValueError(f"Unable to parse element '{m.group()}' of speed string: '{value_string}'")

        return int(m.group("value")) * factor

    @classmethod
    def parse_routeros_time(cls, time_string: str) -> time:
        m = cls.regex_time.match(time_string)
        if not m:
            raise ValueError("Unable to parse datetime string")

        return time(
            hour=int(m.group("hour")),
            minute=int(m.group("minute")),
            second=int(m.group("second"))
        )

    @staticmethod
    def parse_routeros_time_duration(time_string: str) -> float:
        factors: Dict[str, Union[int, Decimal]] = {
            "us": Decimal(1e-6),
            "ms": Decimal(0.001),
            "s": 1,
            "m": 60,
            "h": 60 * 60,
            "d": 24 * 60 * 60,
            "w": 7 * 24 * 60 * 60,
        }

        value_is_negativ = time_string.startswith("-")

        seconds = Decimal(0)
        for m in re.compile(r"(?P<value>\d+)(?P<type>[a-z]+)").finditer(time_string):
            factor = factors.get(m.group("type"))
            if factor is None:
                raise ValueError(f"Unable to parse element '{m.group()}' of time string: '{time_string}'")
            seconds += int(m.group("value")) * factor

        seconds_float = float(round(seconds, 6))

        if value_is_negativ:
            return -seconds_float
        return seconds_float

    @staticmethod
    def prepare_override_values(override_values: List[str]) -> Dict[str, str]:
        results: Dict[str, str] = {}
        for override_value in override_values:
            name, _, value = override_value.partition(":")
            if value is None or value == "":
                logger.warning(f"Unable to parse override value for {name}")
            results[name] = value
        return results

    @staticmethod
    def prepare_thresholds(thresholds: List[str]) -> Dict[str, str]:
        results: Dict[str, str] = {}
        for threshold in thresholds:
            name, _, value = threshold.partition(":")
            if value is None or value == "":
                logger.warning(f"Unable to parse threshold for {name}")
            results[name] = value
        return results

    @staticmethod
    def prepare_regex_thresholds(thresholds: List[str]) -> Dict[re.Pattern, str]:
        results: Dict[re.Pattern, str] = {}
        for threshold in thresholds:
            name, _, value = threshold.partition(":")
            if value is None or value == "":
                logger.warning(f"Unable to parse threshold for {name}")
            results[re.compile(name)] = value
        return results

    def get_routeros_select_keys(self) -> List[librouteros.query.Key]:
        keys = []
        for metric_value in self._routeros_metric_values:
            keys.append(librouteros.query.Key(metric_value["name"]))
        return keys

    def get_routeros_metric_item(
        self, api_result: Dict[str, Any], name_prefix="", cookie=None
    ) -> List[nagiosplugin.Metric]:
        metrics = []

        elapsed_seconds = None
        if cookie:
            last_time_tuple = cookie.get("last_time")
            if isinstance(last_time_tuple, (list, tuple)):
                last_time = datetime(*last_time_tuple[0:6])
                delta_time = self.current_time - last_time
                elapsed_seconds = delta_time.total_seconds()

        #
        for metric_value in self._routeros_metric_values:
            metric_value_name = metric_value["name"]
            if metric_value.get("missing_ok", False) and metric_value_name not in api_result:
                continue

            value = api_result[metric_value_name]
            metric_value_type = metric_value.get("type")
            if callable(metric_value_type):
                try:
                    value = metric_value_type(value)
                except ValueError as e:
                    logger.warning(f"Error parsing value with name {metric_value_name}", exc_info=True)
                    raise e

            value = value * metric_value.get("factor", 1)

            extra_kwargs = {}
            for n in ("min", "max", "uom"):
                if n in metric_value:
                    extra_kwargs[n] = metric_value[n]

            dst_value_name = metric_value.get("dst_value_name")
            if isinstance(dst_value_name, str):
                api_result[dst_value_name] = value

            if not metric_value.get("no_metric"):
                metrics.append(
                    nagiosplugin.Metric(
                        name=name_prefix + metric_value.get("dst", metric_value_name),
                        value=value,
                        **extra_kwargs,
                    )
                )

            if metric_value.get("rate"):
                try:
                    rate_value = self._calc_rate(
                        cookie=cookie,
                        name=metric_value_name,
                        cur_value=value,
                        elapsed_seconds=elapsed_seconds,
                        factor=metric_value.get("rate_factor", 1)
                    )
                    metrics.append(
                        nagiosplugin.Metric(
                            name=f"{name_prefix}{metric_value.get('dst', metric_value_name)}_rate",
                            value=rate_value,
                            uom=metric_value.get("rate_uom"),
                            min=metric_value.get("rate_min"),
                            max=metric_value.get("rate_max"),
                        )
                    )
                except MissingValue as e:
                    logger.debug(f"{e}", exc_info=e)

        if cookie:
            cookie["last_time"] = self.current_time.timetuple()

        return metrics

    def get_routeros_metrics(
        self, api_results: Union[List[Dict[str, Any]], Dict[str, Any]], name_prefix="", cookie=None
    ) -> List[nagiosplugin.Metric]:
        def get_api_result_by_name(api_results, name):
            for item in api_results:
                if name == item["name"]:
                    return item
            return None

        def new_api_result_item(api_results, item, ignore_if_exist=True):
            tmp_item = get_api_result_by_name(api_results, item["name"])
            if tmp_item is not None:
                api_results.append(item)
                return api_results

            if ignore_if_exist:
                return api_results

            raise ValueError("Duplicated entry")

        metrics = []

        elapsed_seconds = None
        if cookie:
            last_time_tuple = cookie.get("last_time")
            if isinstance(last_time_tuple, (list, tuple)):
                last_time = datetime(*last_time_tuple[0:6])
                delta_time = self.current_time - last_time
                elapsed_seconds = delta_time.total_seconds()

        if isinstance(api_results, dict):
            from pprint import pprint
            pprint(api_results)
            api_results = self._convert_v6_list_to_v7(api_results=api_results)

        #
        for metric_value in self._routeros_metric_values:
            metric_value_name = metric_value["name"]
            api_result = get_api_result_by_name(api_results, metric_value_name)

            if metric_value.get("missing_ok", False) and api_result is None:
                continue

            value = api_result["value"]
            metric_value_type = metric_value.get("type")
            if callable(metric_value_type):
                try:
                    value = metric_value_type(value)
                except ValueError as e:
                    logger.warning(f"Error parsing value with name {metric_value_name}", exc_info=True)
                    raise e

            value = value * metric_value.get("factor", 1)

            extra_kwargs = {}
            for n in ("min", "max", "uom"):
                if n in metric_value:
                    extra_kwargs[n] = metric_value[n]

            dst_value_name = metric_value.get("dst_value_name")
            if isinstance(dst_value_name, str):
                api_results = new_api_result_item(
                    api_results,
                    {
                        "name": dst_value_name,
                        "value": value,
                    },
                    ignore_if_exist=True
                )

            if not metric_value.get("no_metric"):
                metrics.append(
                    nagiosplugin.Metric(
                        name=name_prefix + metric_value.get("dst", metric_value_name),
                        value=value,
                        **extra_kwargs,
                    )
                )

            if metric_value.get("rate"):
                try:
                    rate_value = self._calc_rate(
                        cookie=cookie,
                        name=metric_value_name,
                        cur_value=value,
                        elapsed_seconds=elapsed_seconds,
                        factor=metric_value.get("rate_factor", 1)
                    )
                    metrics.append(
                        nagiosplugin.Metric(
                            name=f"{name_prefix}{metric_value.get('dst', metric_value_name)}_rate",
                            value=rate_value,
                            uom=metric_value.get("rate_uom"),
                            min=metric_value.get("rate_min"),
                            max=metric_value.get("rate_max"),
                        )
                    )
                except MissingValue as e:
                    logger.debug(f"{e}", exc_info=e)

        if cookie:
            cookie["last_time"] = self.current_time.timetuple()

        return metrics
