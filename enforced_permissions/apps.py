import logging
from django.apps import apps, AppConfig
from django.conf import settings
from django.db.models import Model
from django.db.models import signals
from django.contrib.auth.models import Group, Permission
from django.contrib.auth import get_permission_codename
from django.contrib.contenttypes.models import ContentType
from django.db.utils import OperationalError, ProgrammingError

logger = logging.getLogger(__name__)


class EnforcedPermissionsAppConfig(AppConfig):

    name = 'enforced_permissions'
    verbose_name = 'Enforced Permissions'

    def ready(self):
        super(EnforcedPermissionsAppConfig, self).ready()
        try:
            do_enforced_permissions()
        except Exception as e:
            # Fails if the database tables haven't yet been created
            if not ("doesn't exist" in str(e) or 'no such table:' in str(e)):
                raise
            else:
                logger.warn("Skipping enforced permissions as db table doesn't exist")


def do_enforced_permissions():
    
    errors = []
    mismatch = []

    groups = settings.ENFORCED_PERMISSIONS['groups']
    exclude = settings.ENFORCED_PERMISSIONS['exclude']
    perms = settings.ENFORCED_PERMISSIONS['permissions']
    group_objects = {}

    try:
        groups_count = Group.objects.all().count()
    except (OperationalError, ProgrammingError):
        print "The database/table isn't created yet. "
        return
    if not groups_count:
        raise Exception('No groups exist')
    
    group_errors = []
    for group, group_name in groups.items():
        try:
            group_objects.update({
                group: Group.objects.get(name=group_name)
            })
        except Group.DoesNotExist:
            group_errors += group
        if len(group_errors):
            raise Exception('Groups do not exist: {}'.format(','.join(group_errors)))
    
    def is_excluded(l):
        # TODO Allow wildcards
        return l in exclude

    for model in apps.get_models():
        meta = model._meta

        if not issubclass(model, Model):
            continue

        label = '{}.{}'.format(meta.app_label, meta.model_name)
        label_wildcard = '{}.*'.format(meta.app_label)
        if is_excluded(label) or is_excluded(label_wildcard):
            continue
        
        if label in perms:
            model_perms = perms[label]
        elif label_wildcard in perms:
            model_perms = perms[label_wildcard]
        else:
            errors.append("No permissions defined for {} in settings.ENFORCED_PERMISSIONS".format(label))
            continue

        for group in groups:
            group_obj = group_objects.get(group)
            if model_perms is False:
                model_group_perms = False
            elif group in model_perms:
                model_group_perms = model_perms[group]
            elif '*' in model_perms:
                model_group_perms = model_perms['*']
            else:
                errors.append("No permissions defined for group {} and model {} "
                              "in settings.ENFORCED_PERMISSIONS".format(group, label))
                continue
            
            # Should probably accommodate duck typing somehow but this is simpler
            if isinstance(model_group_perms, dict):
                add, change, delete = model_group_perms.values()
            elif isinstance(model_group_perms, list):
                add, change, delete = model_group_perms
            elif isinstance(model_group_perms, bool):
                add, change, delete = [model_group_perms] * 3
            else:
                errors.append(TypeError('Invalid model permissions for {}'.format(label)))
                continue

            for action, should_has_perm in [('add', add), ('change', change), ('delete', delete), ]:
                codename = get_permission_codename(action, model._meta)
                content_type = ContentType.objects.get_for_model(model)
                has_perm = group_obj.permissions.filter(codename=codename, content_type=content_type).exists()
                if has_perm != should_has_perm:
                    try:
                        perm = Permission.objects.get(codename=codename, content_type=content_type)
                    except Permission.DoesNotExist:
                        app_config = model._meta.app_config
                        signals.post_migrate.send(
                            sender=app_config,
                            app_config=app_config,
                        )
                        perm = Permission.objects.get(
                            codename=codename,
                            content_type=content_type,
                        )
                    if should_has_perm:
                        print 'Adding: permission {} for {}'.format(label, group)
                        group_obj.permissions.add(perm)
                    else:
                        print 'Removing: group {} should not have permission {} for {}.'.format(
                            group,
                            codename,
                            label,
                        )
                        group_obj.permissions.remove(perm)

    if errors:
        raise Exception(errors)  # TODO - prettier display
