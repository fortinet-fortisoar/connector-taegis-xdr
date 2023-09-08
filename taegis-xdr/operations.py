""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """
import requests
import time
from connectors.core.connector import get_logger, ConnectorError
from connectors.core.utils import update_connnector_config
from taegis_xdr_api_auth import TaegisXDRAuth
import base64, json

logger = get_logger("taegis-xdr")

server_url_dict = {"US1": "https://api.ctpx.secureworks.com", "US2": "https://api.delta.taegis.secureworks.com",
                   "USWEST": "https://api.foxtrot.taegis.secureworks.com",
                   "EU": "https://api.echo.taegis.secureworks.com"}


class TaegisXDR:
    def __init__(self, config):
        self.server_url = server_url_dict.get(config.get('environment'))
        if not self.server_url.startswith('http') or not self.server_url.startswith('https'):
            self.server_url = 'https://' + self.server_url
        self.verify_ssl = config.get("verify_ssl", True)
        self.client_secret = config['client_secret']
        self.client_id = config['client_id']
        self.environment = config['environment']
        self.auth = TaegisXDRAuth(config)
        self.connector_info = config.pop('connector_info', '')
        self.access_token = self.auth.validate_token(config, self.connector_info)

    def make_request(self, endpoint='', params=None, data=None, method='GET', headers=None, url=None, json_data=None):
        try:
            if url is None:
                url = self.server_url + endpoint
            method_headers = {'Authorization': self.access_token, 'Content-Type': 'application/json'}
            headers.update(method_headers)
            response = requests.request(method=method, url=url,
                                        headers=headers, data=data, json=json_data, params=params,
                                        verify=self.verify_ssl)

            if response.ok:
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response.text
            else:
                logger.error("Error: {0}".format(response.json()))
                raise ConnectorError('{0}'.format(response.text))
        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format('ssl_error'))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format('time_out'))
        except Exception as e:
            logger.error('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))


def get_alerts(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {"query": f"""
    query alertsServiceSearch($in: SearchRequestInput = {{cql_query: "{params.get('cql_query')}", limit: {params.get('limit')}, offset: {params.get('offset')}}})
    {{
        alertsServiceSearch(in: $in)
        {{
            reason search_id status alerts {{ previous_offset total_results first_offset group_by {{ key value }} last_offset next_offset total_parts list {{ resolution_reason third_party_details {{ generic {{ generic {{ record {{ key value }} }} name }} }} id parent_tenant_id metadata {{ confidence began_at {{ seconds nanos }} full_title title severity_updated_at {{ seconds nanos }} first_seen_at {{ seconds nanos }} created_at {{ seconds nanos }} inserted_at {{ seconds nanos }} first_investigated_at {{ seconds nanos }} description updated_at {{ seconds nanos }} engine {{ version name }} origin first_resolved_at {{ seconds nanos }} creator {{ rule {{ version rule_id }} detector {{ detector_id detector_name version }} }} ended_at {{ seconds nanos }} severity }} severity_history {{ id changed_at {{ seconds nanos }} severity }} enrichment_details {{ travel_features {{ prior_location {{ radius country_code_iso asn geohash ip_address longitude latitude }} current_location {{ radius country_code_iso asn geohash ip_address longitude latitude }} accurate_geo travel_speed_impossible long_distance_travel travel_km_min travel_hours foreign_travel travel_km_h_min username }} account_compromise_detector_detail {{ user_name }} whois {{ registrarName registrant_country administrativeContact_street1 registrant_street1 standardRegUpdatedDate registrant_faxExt administrativeContact_postalCode registrant_street2 administrativeContact_state administrativeContact_telephoneExt administrativeContact_street3 reg_created_date_usec registrant_state registrant_city administrativeContact_faxExt whoisServer contactEmail nameServers standardRegExpiresDate createdDate administrativeContact_email standardRegCreatedDate Audit_auditUpdatedDate registrant_postalCode reg_updated_date_usec expiresDate administrativeContact_telephone updatedDate administrativeContact_name registrant_telephoneExt administrativeContact_organization registrant_name domainName registrant_telephone administrativeContact_country registrant_organization registrant_street3 reg_expires_date_usec administrativeContact_street2 registrant_fax registrant_email status administrativeContact_fax registrant_street4 administrativeContact_street4 administrativeContact_city }} mitre_attack_info {{ technique_id version technique url system_requirements contributors data_sources description defence_bypassed tactics type platform }} trust_features {{ current_event_time_sec location {{ radius country_code_iso asn geohash ip_address longitude latitude }} user_unknown_asn prior_event_time_sec network_unknown_asn user_unknown_ip current_event_id network_unknown_ip prior_event_id username }} improbable_logon_detail {{ user_logon_baselines {{ feature_value days_in_baseline feature_frequency_in_org approximate_count_in_user feature_frequency_in_user }} logon_anomaly {{ min_allowed_org_percentage feature_value feature_frequency_in_org min_allowed_user_percentage approximate_count_in_user feature_frequency_in_user }} user feature_name source_address }} auth_scan_detail {{ failed_logon_attempts {{ has_logon_success target_user_name num_attempts }} total_attempts successful_logon_attempts {{ has_logon_success target_user_name num_attempts }} }} kerberoasting {{ suspicious_num_requests user_baseline total_spns user_avg_requests percentage_accessed hostname spns_accessed user_max_requests user source_address }} geo_ip {{ radius country_code_iso asn geohash ip_address longitude latitude }} watchlist_matches {{ details {{ reason attacks list_name }} entity }} login_failure {{ host target_address failed_auth_event user successful_auth_event source_address }} rare_program_rare_ip {{ host connections {{ source_ip destination_ip }} programs }} password_spray_detail {{ num_auth_failures num_auth_successes all_affected_users {{ target_user_name target_domain_name user_had_auth_success }} source_address }} hands_on_keyboard_details {{ host_id num_admin_events total_num_events matched_num_events common_parent_image_path matched_process {{ process_resource_id score event_time_sec image {{ image_path matched_features }} num_matched_features commandline {{ matched_features commandline }} severity }} username }} generic {{ generic {{ record {{ key value }} }} name }} dns_exfil {{ num_queries }} tactic_graph_detail {{ graph_id events {{ key values }} }} brute_force_detail {{ most_recent_auths_failures {{ resource_record_identifier action win_event_id domain event_timestamp target_username }} num_auth_successes last_successful_auth {{ resource_record_identifier action win_event_id domain event_timestamp target_username }} num_auth_failures }} ddos_source_ip {{ host_id sensor_id top_destination_ips {{ count ip_address }} analytic_observable_min_count event_observable_count historical_ip_counts {{ date {{ seconds nanos }} count }} event_observable_count_std_dev baseline_observable_count_std_dev baseline_observable_count_mean analytic_time_threshold analytic_observable_std_dev_threshold hour_partition baseline_num_days baseline_observable_count_median }} business_email_compromise {{ source_address_geo_summary {{ city {{ confidence name locale_names {{ record {{ key value }} }} geoname_id }} location {{ radius metro_code timezone longitude us_metro_code gmt_offset latitude }} asn {{ autonomous_system_org autonomous_system_no }} country {{ confidence code iso_code geoname_id }} continent {{ code geoname_id }} }} user_name source_address }} }} priority {{ version model_version model_name applied_time {{ seconds nanos }} value prioritizer evidence }} sensor_types events_metadata {{ began_at {{ seconds nanos }} first_event_id last_event_id updated_at {{ seconds nanos }} total_events ended_at {{ seconds nanos }} }} reference_details {{ reference {{ description url type }} }} group_key entities {{ relationships {{ to_entity relationship from_entity type }} entities }} event_ids {{ id }} tags suppressed resolution_history {{ user_id timestamp {{ seconds nanos }} id num_alerts_affected reason status }} tenant_id key_entities {{ entity label }} observation_ids {{ id }} visibility suppression_rules {{ id version }} alerting_rules {{ id version }} collection_ids {{ id }} status attack_technique_ids investigation_ids {{ id GenesisAlertsFlag }} }} part }}
        }}
    }}
    """}
    return tx.make_request(method="POST", data=data_query)


def get_assets(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": f"""query allAssets($offset: Int = {params.get('offset')}, $limit: Int = {params.get('limit')}, $order_by: AssetsOrderByInput = {params.get('order_by')}, $order_direction: AssetsOrderDirectionInput = {params.get('order_direction')}, $filter_asset_state: AssetStateFilter = {params.get('filter_asset_state')}, $only_most_recent: Boolean = {params.get('only_most_recent')})
{{
    allAssets(offset: $offset, limit: $limit, order_by: $order_by, order_direction: $order_direction, filter_asset_state: $filter_asset_state, only_most_recent: $only_most_recent)
    {{
        totalResults offset limit assets {{ id hostId rn tenantId sensorTenant sensorId ingestTime createdAt updatedAt deletedAt lastSeenAt biosSerial firstDiskSerial systemVolumeSerial sensorVersion endpointType endpointPlatform hostnames {{ id created_at updated_at host_id hostname createdAt updatedAt hostId }} ethernetAddresses {{ id created_at updated_at host_id mac createdAt updatedAt hostId }} ipAddresses {{ id created_at updated_at ip host_id createdAt updatedAt hostId }} users {{ id created_at updated_at host_id username createdAt updatedAt hostId }} architecture osFamily osVersion osDistributor osRelease systemType osCodename kernelRelease kernelVersion tags {{ id hostId tenantId createdAt updatedAt tag key }} connectionStatus model cloudProviderName cloudInstanceId endpointGroup {{ id }} status }}
    }}
}}
"""}
    return tx.make_request(method="POST", data=data_query)


def get_endpoint(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": f"""query assetEndpointInfoV2($id: ID! = {params.get('id')})
{{
    assetEndpointInfoV2(id: $id)
    {{
        totalResults offset limit assets {{ id hostId rn tenantId sensorTenant sensorId ingestTime createdAt updatedAt deletedAt lastSeenAt biosSerial firstDiskSerial systemVolumeSerial sensorVersion endpointType endpointPlatform hostnames {{ id created_at updated_at host_id hostname createdAt updatedAt hostId }} ethernetAddresses {{ id created_at updated_at host_id mac createdAt updatedAt hostId }} ipAddresses {{ id created_at updated_at ip host_id createdAt updatedAt hostId }} users {{ id created_at updated_at host_id username createdAt updatedAt hostId }} architecture osFamily osVersion osDistributor osRelease systemType osCodename kernelRelease kernelVersion tags {{ id hostId tenantId createdAt updatedAt tag key }} connectionStatus model cloudProviderName cloudInstanceId endpointGroup {{ id }} status }}
    }}
}}
"""}
    return tx.make_request(method="POST", data=data_query)


def get_investigations(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": f"""query investigationsSearch($page: Int = {params.get('page')}, $perPage: Int = {params.get('per_page')}, $query: String = "{params.get('query')}", $filterText: String, $orderByField: OrderFieldInput = {params.get('order_by_field')}, $orderDirection: OrderDirectionInput = {params.get('order_by_direction')})
    {{
        investigationsSearch(page: $page, perPage: $perPage, query: $query, filterText: $filterText, orderByField: $orderByField, orderDirection: $orderDirection)
        {{
            totalCount investigations {{ search_queries {{ id }} first_notified_at notified_at transition_state {{ handed_off acknowledge_time resolved_at_least_once handoff_time initial_handoff_time resolution_time initial_resolution_time acknowledged initial_acknowledge_time acknowledged_at_least_once resolved handed_off_at_least_once }} tenant_id description contributors genesis_events {{ id }} events_count alerts2 {{ id }} assignee {{ id email family_name name tenants {{ id name }} status email_normalized user_id given_name email_verified roles }} service_desk_type updated_at investigationType assets_count genesis_events_count alerts_count assignee_id tags created_by_scwx created_at created_by_partner activity_logs {{ id target comment tenant_id investigation_id description user_id created_at type updated_at }} auth_credentials type events {{ id }} assignee_user {{ id }} rn deleted_at alerts {{ id }} processing_status {{ events alerts assets }} first_notified_at_scwx archived_at service_desk_id status genesis_alerts_count files_count created_by_user {{ id }} priority assets {{ id }} contributed_users {{ id }} id created_by genesis_alerts {{ id }} access_vectors {{ id name investigation_id mitre_info {{ data_sources tactics technique description platform technique_id system_requirements defence_bypassed contributors url version type }} created_at updated_at }} comments_count {{ parent_id unread parent_type total }} latest_activity genesis_alerts2 {{ id }} shortId key_findings }}
        }}
    }}

    """}
    return tx.make_request(method="POST", data=data_query)


def get_investigations_alerts(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": f"""query investigationsAlerts($page: Int = {params.get('page')}, $perPage: Int = {params.get('per_page')}, $investigation_id: ID! = {params.get('investigation_id')})
{{
    investigationsSearch(page: $page, perPage: $perPage, query: $query, investigation_id: $investigation_id)
    {{
        totalCount investigations {{ search_queries {{ id }} first_notified_at notified_at transition_state {{ handed_off acknowledge_time resolved_at_least_once handoff_time initial_handoff_time resolution_time initial_resolution_time acknowledged initial_acknowledge_time acknowledged_at_least_once resolved handed_off_at_least_once }} tenant_id description contributors genesis_events {{ id }} events_count alerts2 {{ id }} assignee {{ id email family_name name tenants {{ id name }} status email_normalized user_id given_name email_verified roles }} service_desk_type updated_at investigationType assets_count genesis_events_count alerts_count assignee_id tags created_by_scwx created_at created_by_partner activity_logs {{ id target comment tenant_id investigation_id description user_id created_at type updated_at }} auth_credentials type events {{ id }} assignee_user {{ id }} rn deleted_at alerts {{ id }} processing_status {{ events alerts assets }} first_notified_at_scwx archived_at service_desk_id status genesis_alerts_count files_count created_by_user {{ id }} priority assets {{ id }} contributed_users {{ id }} id created_by genesis_alerts {{ id }} access_vectors {{ id name investigation_id mitre_info {{ data_sources tactics technique description platform technique_id system_requirements defence_bypassed contributors url version type }} created_at updated_at }} comments_count {{ parent_id unread parent_type total }} latest_activity genesis_alerts2 {{ id }} shortId key_findings }}
    }}
}}

"""}
    return tx.make_request(method="POST", data=data_query)


def get_playbook_execution(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": f"""query playbookExecution($playbookExecutionId: ID! = {params.get('playbookExecutionId')})
{{
    investigationsSearch($playbookExecutionId: $playbookExecutionId)
    {{
        id createdAt createdBy updatedAt updatedBy name tags icon sequence tenant head versions instances categories title description requires
    }}
}}

"""}
    return tx.make_request(method="POST", data=data_query)


def get_user_by_id(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {"query": f"""query tdruser($id: ID! = {params.get('user_id')}, $excludeDeactivatedRoleAssignments: Boolean, $includeMaskedRelatedUsers: Boolean)
    {{
        tdruser(id: $id, excludeDeactivatedRoleAssignments: $excludeDeactivatedRoleAssignments, includeMaskedRelatedUsers: $includeMaskedRelatedUsers)
        {{
            id id_uuid user_id user_id_v1 created_at updated_at created_by updated_by last_login invited_date registered_date deactivated_date status status_localized email email_normalized family_name given_name phone_number phone_extension secondary_phone_number secondary_phone_extension roles tenants {{ id }} tenants_v2 {{ id role }} accessible_tenants {{ id name name_normalized enabled allow_response_actions actions_approver expires_at environments {{ name enabled }} labels {{ id tenant_id name value }} services {{ id name description }} is_partner parent }} role_assignments {{ id tenant_id role_id deactivated role_name role_display_name expires_at created_at updated_at allowed_environments }} environments eula {{ date version }} timezone tenant_status tenant_status_localized entitlement_channel allowed_entitlement_channels masked community_role is_scwx is_partner preferred_language pre_verified
        }}
    }}

    """}
    return tx.make_request(method="POST", data=data_query, headers={"x-tenant-context": params.get('tenant_id')})


def isolate_assets(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": f"""mutation isolateAsset($id: ID! = {params.get('id')}, $reason: String! = "{params.get('reason')}")
    {{
        isolateAsset(id: $id, reason: $reason)
        {{
            totalResults offset limit assets {{ id hostId rn tenantId sensorTenant sensorId ingestTime createdAt updatedAt deletedAt lastSeenAt biosSerial firstDiskSerial systemVolumeSerial sensorVersion endpointType endpointPlatform hostnames {{ id created_at updated_at host_id hostname createdAt updatedAt hostId }} ethernetAddresses {{ id created_at updated_at host_id mac createdAt updatedAt hostId }} ipAddresses {{ id created_at updated_at ip host_id createdAt updatedAt hostId }} users {{ id created_at updated_at host_id username createdAt updatedAt hostId }} architecture osFamily osVersion osDistributor osRelease systemType osCodename kernelRelease kernelVersion tags {{ id hostId tenantId createdAt updatedAt tag key }} connectionStatus model cloudProviderName cloudInstanceId endpointGroup {{ id }} status }}
        }}
    }}
    """}
    return tx.make_request(method="POST", data=data_query)


def update_alert_status(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {"query": f"""
        mutation alertsServiceUpdateResolutionInfo($in: UpdateResolutionRequestInput = {{ alert_ids: [{params.get('alert_ids')}], resolution_status: {params.get('resolution_status')}, reason: {params.get('reason')} }})
        {{
            alertsServiceUpdateResolutionInfo(in: $in)
            {{
                reason search_id status alerts {{ previous_offset total_results first_offset group_by {{ key value }} last_offset next_offset total_parts list {{ resolution_reason third_party_details {{ generic {{ generic {{ record {{ key value }} }} name }} }} id parent_tenant_id metadata {{ confidence began_at {{ seconds nanos }} full_title title severity_updated_at {{ seconds nanos }} first_seen_at {{ seconds nanos }} created_at {{ seconds nanos }} inserted_at {{ seconds nanos }} first_investigated_at {{ seconds nanos }} description updated_at {{ seconds nanos }} engine {{ version name }} origin first_resolved_at {{ seconds nanos }} creator {{ rule {{ version rule_id }} detector {{ detector_id detector_name version }} }} ended_at {{ seconds nanos }} severity }} severity_history {{ id changed_at {{ seconds nanos }} severity }} enrichment_details {{ travel_features {{ prior_location {{ radius country_code_iso asn geohash ip_address longitude latitude }} current_location {{ radius country_code_iso asn geohash ip_address longitude latitude }} accurate_geo travel_speed_impossible long_distance_travel travel_km_min travel_hours foreign_travel travel_km_h_min username }} account_compromise_detector_detail {{ user_name }} whois {{ registrarName registrant_country administrativeContact_street1 registrant_street1 standardRegUpdatedDate registrant_faxExt administrativeContact_postalCode registrant_street2 administrativeContact_state administrativeContact_telephoneExt administrativeContact_street3 reg_created_date_usec registrant_state registrant_city administrativeContact_faxExt whoisServer contactEmail nameServers standardRegExpiresDate createdDate administrativeContact_email standardRegCreatedDate Audit_auditUpdatedDate registrant_postalCode reg_updated_date_usec expiresDate administrativeContact_telephone updatedDate administrativeContact_name registrant_telephoneExt administrativeContact_organization registrant_name domainName registrant_telephone administrativeContact_country registrant_organization registrant_street3 reg_expires_date_usec administrativeContact_street2 registrant_fax registrant_email status administrativeContact_fax registrant_street4 administrativeContact_street4 administrativeContact_city }} mitre_attack_info {{ technique_id version technique url system_requirements contributors data_sources description defence_bypassed tactics type platform }} trust_features {{ current_event_time_sec location {{ radius country_code_iso asn geohash ip_address longitude latitude }} user_unknown_asn prior_event_time_sec network_unknown_asn user_unknown_ip current_event_id network_unknown_ip prior_event_id username }} improbable_logon_detail {{ user_logon_baselines {{ feature_value days_in_baseline feature_frequency_in_org approximate_count_in_user feature_frequency_in_user }} logon_anomaly {{ min_allowed_org_percentage feature_value feature_frequency_in_org min_allowed_user_percentage approximate_count_in_user feature_frequency_in_user }} user feature_name source_address }} auth_scan_detail {{ failed_logon_attempts {{ has_logon_success target_user_name num_attempts }} total_attempts successful_logon_attempts {{ has_logon_success target_user_name num_attempts }} }} kerberoasting {{ suspicious_num_requests user_baseline total_spns user_avg_requests percentage_accessed hostname spns_accessed user_max_requests user source_address }} geo_ip {{ radius country_code_iso asn geohash ip_address longitude latitude }} watchlist_matches {{ details {{ reason attacks list_name }} entity }} login_failure {{ host target_address failed_auth_event user successful_auth_event source_address }} rare_program_rare_ip {{ host connections {{ source_ip destination_ip }} programs }} password_spray_detail {{ num_auth_failures num_auth_successes all_affected_users {{ target_user_name target_domain_name user_had_auth_success }} source_address }} hands_on_keyboard_details {{ host_id num_admin_events total_num_events matched_num_events common_parent_image_path matched_process {{ process_resource_id score event_time_sec image {{ image_path matched_features }} num_matched_features commandline {{ matched_features commandline }} severity }} username }} generic {{ generic {{ record {{ key value }} }} name }} dns_exfil {{ num_queries }} tactic_graph_detail {{ graph_id events {{ key values }} }} brute_force_detail {{ most_recent_auths_failures {{ resource_record_identifier action win_event_id domain event_timestamp target_username }} num_auth_successes last_successful_auth {{ resource_record_identifier action win_event_id domain event_timestamp target_username }} num_auth_failures }} ddos_source_ip {{ host_id sensor_id top_destination_ips {{ count ip_address }} analytic_observable_min_count event_observable_count historical_ip_counts {{ date {{ seconds nanos }} count }} event_observable_count_std_dev baseline_observable_count_std_dev baseline_observable_count_mean analytic_time_threshold analytic_observable_std_dev_threshold hour_partition baseline_num_days baseline_observable_count_median }} business_email_compromise {{ source_address_geo_summary {{ city {{ confidence name locale_names {{ record {{ key value }} }} geoname_id }} location {{ radius metro_code timezone longitude us_metro_code gmt_offset latitude }} asn {{ autonomous_system_org autonomous_system_no }} country {{ confidence code iso_code geoname_id }} continent {{ code geoname_id }} }} user_name source_address }} }} priority {{ version model_version model_name applied_time {{ seconds nanos }} value prioritizer evidence }} sensor_types events_metadata {{ began_at {{ seconds nanos }} first_event_id last_event_id updated_at {{ seconds nanos }} total_events ended_at {{ seconds nanos }} }} reference_details {{ reference {{ description url type }} }} group_key entities {{ relationships {{ to_entity relationship from_entity type }} entities }} event_ids {{ id }} tags suppressed resolution_history {{ user_id timestamp {{ seconds nanos }} id num_alerts_affected reason status }} tenant_id key_entities {{ entity label }} observation_ids {{ id }} visibility suppression_rules {{ id version }} alerting_rules {{ id version }} collection_ids {{ id }} status attack_technique_ids investigation_ids {{ id GenesisAlertsFlag }} }} part }}
            }}
        }}
        """}
    return tx.make_request(method="POST", data=data_query)


def update_investigation(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": f"""mutation updateInvestigation($investigation_id: ID! = {params.get('investigation_id')}, $investigation: UpdateInvestigationInput = {{ description: {params.get('description')}, key_findings: {params.get('key_findings')}, priority: {params.get('priority')}, status: {params.get('status')}, asignee_id: {params.get('asignee_id')} }} }})
    {{
        updateInvestigation(investigation_id: $investigation_id, investigation: $investigation)
        {{
            totalCount investigations {{ search_queries {{ id }} first_notified_at notified_at transition_state {{ handed_off acknowledge_time resolved_at_least_once handoff_time initial_handoff_time resolution_time initial_resolution_time acknowledged initial_acknowledge_time acknowledged_at_least_once resolved handed_off_at_least_once }} tenant_id description contributors genesis_events {{ id }} events_count alerts2 {{ id }} assignee {{ id email family_name name tenants {{ id name }} status email_normalized user_id given_name email_verified roles }} service_desk_type updated_at investigationType assets_count genesis_events_count alerts_count assignee_id tags created_by_scwx created_at created_by_partner activity_logs {{ id target comment tenant_id investigation_id description user_id created_at type updated_at }} auth_credentials type events {{ id }} assignee_user {{ id }} rn deleted_at alerts {{ id }} processing_status {{ events alerts assets }} first_notified_at_scwx archived_at service_desk_id status genesis_alerts_count files_count created_by_user {{ id }} priority assets {{ id }} contributed_users {{ id }} id created_by genesis_alerts {{ id }} access_vectors {{ id name investigation_id mitre_info {{ data_sources tactics technique description platform technique_id system_requirements defence_bypassed contributors url version type }} created_at updated_at }} comments_count {{ parent_id unread parent_type total }} latest_activity genesis_alerts2 {{ id }} shortId key_findings }}
        }}
    }}

    """}
    return tx.make_request(method="POST", data=data_query)


def _build_payload(params):
    return {key: val for key, val in params.items() if val is not None and val != ''}


operations = {
    "get_alerts": get_alerts,
    "get_assets": get_assets,
    "get_endpoint": get_endpoint,
    "get_investigations": get_investigations,
    "get_investigations_alerts": get_investigations_alerts,
    "get_playbook_execution": get_playbook_execution,
    "get_user_by_id": get_user_by_id,
    "isolate_assets": isolate_assets,
    "update_alert_status": update_alert_status,
    "update_investigation": update_investigation
}
