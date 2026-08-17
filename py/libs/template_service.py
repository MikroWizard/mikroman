#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
import logging
from libs.db.db_pam import DeviceTemplates
from libs.db.db_device import Devices
from playhouse.shortcuts import model_to_dict

log = logging.getLogger("template_service")

class TemplateService:
    @staticmethod
    def _model_to_dict(template):
        if not template:
            return None
        return model_to_dict(template)

    @staticmethod
    def get_template_for_device(device_id) -> dict:
        """Looks up device's template_id, returns template JSON, falls back to generic/generic template if not set"""
        try:
            device = Devices.get_by_id(device_id)
            template = None
            if getattr(device, 'template_id', None):
                template = DeviceTemplates.get_or_none(DeviceTemplates.id == device.template_id)
            
            if not template:
                brand = getattr(device, 'device_type', 'mikrotik') or 'mikrotik'
                template = DeviceTemplates.select().where(
                    DeviceTemplates.brand == brand,
                    DeviceTemplates.is_system == True,
                    DeviceTemplates.is_active == True,
                ).first()

            if not template:
                # Fallback to generic if none assigned
                template = DeviceTemplates.get_or_none(
                    DeviceTemplates.brand == 'generic', 
                    DeviceTemplates.os_type == 'generic',
                    DeviceTemplates.is_system == True
                )
                
            return TemplateService._model_to_dict(template)
        except Devices.DoesNotExist:
            log.warning(f"Device {device_id} not found when looking up template.")
            return None
        except Exception as e:
            log.error(f"Error fetching template for device {device_id}: {e}")
            return None

    @staticmethod
    def get_template_by_id(template_id) -> dict:
        """Direct lookup by template ID"""
        template = DeviceTemplates.get_or_none(DeviceTemplates.id == template_id)
        return TemplateService._model_to_dict(template)

    @staticmethod
    def get_template_for_brand(brand, os_type=None) -> dict:
        """Get system template for a brand"""
        q = DeviceTemplates.select().where(
            DeviceTemplates.brand == brand,
            DeviceTemplates.is_system == True,
            DeviceTemplates.is_active == True
        )
        if os_type:
            q = q.where(DeviceTemplates.os_type == os_type)
        template = q.first()
        return TemplateService._model_to_dict(template)

    @staticmethod
    def resolve_command(template: dict, command_key: str) -> str:
        """Resolve logical command key to actual CLI command string from template's commands JSON"""
        if not template:
            return ""
        commands = template.get('commands') or {}
        return commands.get(command_key, "")

    @staticmethod
    def list_templates(include_inactive=False, brand=None) -> list:
        """List templates, optionally filtered by brand"""
        q = DeviceTemplates.select()
        if brand:
            q = q.where(DeviceTemplates.brand == brand)
        if not include_inactive:
            q = q.where(DeviceTemplates.is_active == True)
        
        return [TemplateService._model_to_dict(t) for t in q]

    @staticmethod
    def create_template(data: dict) -> int:
        """Create custom template (public API)"""
        now = datetime.datetime.utcnow()
        template = DeviceTemplates.create(
            brand=data.get('brand', 'generic'),
            os_type=data.get('os_type', 'generic'),
            display_name=data.get('display_name', 'Custom Template'),
            connection=data.get('connection'),
            prompt=data.get('prompt'),
            privilege_escalation=data.get('privilege_escalation'),
            commands=data.get('commands'),
            pagination=data.get('pagination'),
            error_patterns=data.get('error_patterns'),
            post_login_commands=data.get('post_login_commands'),
            pre_logout_commands=data.get('pre_logout_commands'),
            diff_exclusions=data.get('diff_exclusions'),
            pre_connect=data.get('pre_connect'),
            post_disconnect=data.get('post_disconnect'),
            config_mode=data.get('config_mode'),
            is_system=False,  # Enforce user templates cannot be system
            is_active=data.get('is_active', True),
            created=now
        )
        return template.id

    @staticmethod
    def update_template(template_id: int, data: dict) -> bool:
        """Update template — allow both system and user templates, but protect identity fields for system templates"""
        template = DeviceTemplates.get_or_none(DeviceTemplates.id == template_id)
        if not template:
            return False

        is_sys = getattr(template, 'is_system', False)

        # For user-created templates only, allow changing brand, os_type, display_name
        if not is_sys:
            if 'brand' in data: template.brand = data['brand']
            if 'os_type' in data: template.os_type = data['os_type']
            if 'display_name' in data: template.display_name = data['display_name']

        # Commands, connection, prompt, etc. can be updated for both system and custom templates
        if 'connection' in data: template.connection = data['connection']
        if 'prompt' in data: template.prompt = data['prompt']
        if 'privilege_escalation' in data: template.privilege_escalation = data['privilege_escalation']
        if 'commands' in data: template.commands = data['commands']
        if 'pagination' in data: template.pagination = data['pagination']
        if 'error_patterns' in data: template.error_patterns = data['error_patterns']
        if 'post_login_commands' in data: template.post_login_commands = data['post_login_commands']
        if 'pre_logout_commands' in data: template.pre_logout_commands = data['pre_logout_commands']
        if 'diff_exclusions' in data: template.diff_exclusions = data['diff_exclusions']
        if 'pre_connect' in data: template.pre_connect = data['pre_connect']
        if 'post_disconnect' in data: template.post_disconnect = data['post_disconnect']
        if 'config_mode' in data: template.config_mode = data['config_mode']
        if 'is_active' in data: template.is_active = data['is_active']
        
        template.save()
        return True

    @staticmethod
    def delete_template(template_id: int) -> bool:
        """Delete template — only non-system templates"""
        template = DeviceTemplates.get_or_none(DeviceTemplates.id == template_id)
        if not template:
            return False

        if getattr(template, 'is_system', False):
            log.warning(f"Attempted to delete system template {template_id}")
            return False

        template.delete_instance()
        return True

    @staticmethod
    def get_diff_exclusions(template):
        """Return diff_exclusions dict from template (dict or model), empty dict if absent."""
        if template is None:
            return {}
        if isinstance(template, dict):
            return template.get("diff_exclusions") or {}
        return template.diff_exclusions or {}

    @staticmethod
    def get_pre_connect_hooks(template):
        """Return pre_connect hooks list from template, empty list if absent."""
        if template is None:
            return []
        if isinstance(template, dict):
            return template.get("pre_connect") or []
        return template.pre_connect or []

    @staticmethod
    def get_post_disconnect_hooks(template):
        """Return post_disconnect hooks list from template, empty list if absent."""
        if template is None:
            return []
        if isinstance(template, dict):
            return template.get("post_disconnect") or []
        return template.post_disconnect or []

    @staticmethod
    def get_config_mode(template):
        """Return config_mode dict from template, None if absent."""
        if template is None:
            return None
        if isinstance(template, dict):
            return template.get("config_mode")
        return template.config_mode
