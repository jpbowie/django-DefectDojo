import datetime
from dojo.importers import utils as importer_utils
from dojo.models import Test, Finding, \
    Test_Type, \
    Endpoint, BurpRawRequestResponse, \
    Endpoint_Status, \
    Test_Import

from dojo.utils import get_current_user, max_safe

from django.core.exceptions import MultipleObjectsReturned
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
import dojo.notifications.helper as notifications_helper
import base64
import logging

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


class DojoDefaultImporter(object):

    def create_test(self, scan_type, engagement, lead, environment, tags=None,
                    scan_date=None, version=None, branch_tag=None, build_id=None, commit_hash=None, now=timezone.now()):

        test_type, created = Test_Type.objects.get_or_create(
            name=scan_type)

        if created:
            logger.info('Created new Test_Type with name %s because a report is being imported', test_type.name)

        test = Test(
            engagement=engagement,
            lead=lead,
            test_type=test_type,
            target_start=scan_date if scan_date else now.date(),
            target_end=scan_date if scan_date else now.date(),
            environment=environment,
            percent_complete=100,
            version=version,
            branch_tag=branch_tag,
            build_id=build_id,
            commit_hash=commit_hash,
            tags=tags)
        try:
            # TODO What is going on here?
            test.full_clean()
        except ValidationError:
            pass

        test.save()
        return test

    def process_parsed_findings(self, test, parsed_findings, scan_type, user, active, verified, minimum_severity=None,
                                endpoints_to_add=None, push_to_jira=None, now=timezone.now()):
        logger.debug('endpoints_to_add: %s', endpoints_to_add)
        new_findings = []
        items = parsed_findings
        logger.debug('starting import of %i items.', len(items) if items else 0)
        i = 0
        for item in items:
            sev = item.severity
            if sev == 'Information' or sev == 'Informational':
                sev = 'Info'

            item.severity = sev
            item.numerical_severity = Finding.get_numerical_severity(sev)

            if minimum_severity and (Finding.SEVERITIES[sev] >
                    Finding.SEVERITIES[minimum_severity]):
                continue

            item.test = test
            item.reporter = user if user else get_current_user
            item.last_reviewed = now
            item.last_reviewed_by = user if user else get_current_user

            # Only set active/verified flags if they were NOT set by default value(True)
            if item.active:
                item.active = active
            if item.verified:
                item.verified = verified

            item.created = now
            item.updated = now
            item.save(dedupe_option=False)

            if (hasattr(item, 'unsaved_req_resp') and
                    len(item.unsaved_req_resp) > 0):
                for req_resp in item.unsaved_req_resp:
                    burp_rr = BurpRawRequestResponse(
                        finding=item,
                        burpRequestBase64=base64.b64encode(req_resp["req"].encode("utf-8")),
                        burpResponseBase64=base64.b64encode(req_resp["resp"].encode("utf-8")))
                    burp_rr.clean()
                    burp_rr.save()

            if (item.unsaved_request is not None and
                    item.unsaved_response is not None):
                burp_rr = BurpRawRequestResponse(
                    finding=item,
                    burpRequestBase64=base64.b64encode(item.unsaved_request.encode()),
                    burpResponseBase64=base64.b64encode(item.unsaved_response.encode()))
                burp_rr.clean()
                burp_rr.save()

            for endpoint in item.unsaved_endpoints:
                try:
                    ep, created = Endpoint.objects.get_or_create(
                        protocol=endpoint.protocol,
                        host=endpoint.host,
                        path=endpoint.path,
                        query=endpoint.query,
                        fragment=endpoint.fragment,
                        product=test.engagement.product)
                except (MultipleObjectsReturned):
                    pass

                try:
                    eps, created = Endpoint_Status.objects.get_or_create(
                        finding=item,
                        endpoint=ep)
                except (MultipleObjectsReturned):
                    pass

                ep.endpoint_status.add(eps)
                item.endpoint_status.add(eps)
                item.endpoints.add(ep)

            if endpoints_to_add:
                for endpoint in endpoints_to_add:
                    logger.debug('adding endpoint %s', endpoint)
                    # TODO Not sure what happens here, we get an endpoint model and try to create it again?
                    try:
                        ep, created = Endpoint.objects.get_or_create(
                            protocol=endpoint.protocol,
                            host=endpoint.host,
                            path=endpoint.path,
                            query=endpoint.query,
                            fragment=endpoint.fragment,
                            product=test.engagement.product)
                    except (MultipleObjectsReturned):
                        pass
                    try:
                        eps, created = Endpoint_Status.objects.get_or_create(
                            finding=item,
                            endpoint=ep)
                    except (MultipleObjectsReturned):
                        pass

                    ep.endpoint_status.add(eps)
                    item.endpoints.add(ep)
                    item.endpoint_status.add(eps)

            if item.unsaved_tags:
                item.tags = item.unsaved_tags

            new_findings.append(item)
            item.save(push_to_jira=push_to_jira)

        return new_findings

    def close_old_findings(self, test, scan_date_time, user, push_to_jira=None):
        old_findings = []
        # Close old active findings that are not reported by this scan.
        new_hash_codes = test.finding_set.values('hash_code')

        # TODO I don't think these criteria are 100% correct, why are findings with the same hash_code excluded?
        # Would it make more sense to exclude duplicates? But the deduplication process can be unfinished because it's
        # run in a celery async task...
        if test.engagement.deduplication_on_engagement:
            old_findings = Finding.objects.exclude(test=test) \
                                            .exclude(hash_code__in=new_hash_codes) \
                                            .filter(test__engagement=test.engagement,
                                                test__test_type=test.test_type,
                                                active=True)
        else:
            # TODO BUG? this will violate the deduplication_on_engagement setting for other engagements
            old_findings = Finding.objects.exclude(test=test) \
                                            .exclude(hash_code__in=new_hash_codes) \
                                            .filter(test__engagement__product=test.engagement.product,
                                                test__test_type=test.test_type,
                                                active=True)

        for old_finding in old_findings:
            old_finding.active = False
            old_finding.is_Mitigated = True
            old_finding.mitigated = scan_date_time
            old_finding.notes.create(author=user,
                                        entry="This finding has been automatically closed"
                                        " as it is not present anymore in recent scans.")
            endpoint_status = old_finding.endpoint_status.all()
            for status in endpoint_status:
                status.mitigated_by = user
                status.mitigated_time = timezone.now()
                status.mitigated = True
                status.last_modified = timezone.now()
                status.save()

            old_finding.tags.add('stale')
            old_finding.save(dedupe_option=False, push_to_jira=push_to_jira)

        return old_findings

    def update_timestamps(self, test, scan_date, version, branch_tag, build_id, commit_hash, now, scan_date_time):
        test.engagement.updated = now
        if test.engagement.engagement_type == 'CI/CD':
            test.engagement.target_end = max_safe([scan_date, test.engagement.target_end])

        test.updated = now
        test.target_end = max_safe([scan_date_time, test.target_end])

        if version:
            test.version = version

        if branch_tag:
            test.branch_tag = branch_tag
            test.engagement.version = version

        if build_id:
            test.build_id = build_id

        if branch_tag:
            test.commit_hash = commit_hash

        test.save()
        test.engagement.save()

    def import_scan(self, scan, scan_type, engagement, lead, environment, active, verified, tags=None, minimum_severity=None,
                    user=None, endpoints_to_add=None, scan_date=None, version=None, branch_tag=None, build_id=None,
                    commit_hash=None, push_to_jira=None, close_old_findings=False):

        user = user or get_current_user()

        now = timezone.now()
        # retain weird existing logic to use current time for provided scan date
        scan_date_time = datetime.datetime.combine(scan_date, timezone.now().time())
        if settings.USE_TZ:
            scan_date_time = timezone.make_aware(scan_date_time, timezone.get_default_timezone())

        logger.debug('IMPORT_SCAN: Create Test')
        test = self.create_test(scan_type, engagement, lead, environment, scan_date=scan_date, tags=tags,
                            version=version, branch_tag=branch_tag, build_id=build_id, commit_hash=commit_hash, now=now)

        logger.debug('IMPORT_SCAN: Parse findings')
        parsed_findings = importer_utils.parse_findings(scan, test, active, verified, scan_type)

        logger.debug('IMPORT_SCAN: Processing findings')
        new_findings = self.process_parsed_findings(test, parsed_findings, scan_type, user, active,
                                                    verified, minimum_severity=minimum_severity,
                                                    endpoints_to_add=endpoints_to_add, push_to_jira=push_to_jira,
                                                    now=now)

        closed_findings = []
        if close_old_findings:
            logger.debug('IMPORT_SCAN: Closing findings no longer present in scan report')
            closed_findings = self.close_old_findings(test, scan_date_time, user=user, push_to_jira=push_to_jira)

        logger.debug('IMPORT_SCAN: Updating test/engagement timestamps')
        importer_utils.update_timestamps(test, scan_date, version, branch_tag, build_id, commit_hash, now, scan_date_time)

        if settings.TRACK_IMPORT_HISTORY:
            logger.debug('IMPORT_SCAN: Updating Import History')
            importer_utils.update_import_history(Test_Import.IMPORT_TYPE, active, verified, tags, minimum_severity,
                                                    endpoints_to_add, version, branch_tag, build_id, commit_hash,
                                                    push_to_jira, close_old_findings, test, new_findings, closed_findings)

        logger.debug('IMPORT_SCAN: Generating notifications')
        notifications_helper.notify_test_created(test)
        updated_count = len(new_findings) + len(closed_findings)
        if updated_count > 0:
            notifications_helper.notify_scan_added(test, updated_count, new_findings=new_findings, findings_mitigated=closed_findings)

        logger.debug('IMPORT_SCAN: Done')

        return test, len(new_findings), len(closed_findings)
