import { format as dateFormat, isValid } from 'date-fns';

import intl from 'panel/common/intl';
import theme from 'panel/lib/theme';
import {
    FILTERED_STATUS,
    FILTERED_STATUS_TO_COLOR_MAP,
    QUERY_STATUS_COLORS,
    SCHEME_TO_PROTOCOL_MAP,
    DEFAULT_TIME_FORMAT,
    LONG_TIME_FORMAT,
    SPECIAL_FILTER_ID,
} from 'panel/helpers/constants';
import {
    formatElapsedMs,
    getFilterNames,
    type Filter,
} from 'panel/helpers/helpers';
import { ResponseEntry, WhoisInfo } from './types';

const parseLogDate = (time: string): Date | null => {
    const parsedTime = new Date(time);

    return isValid(parsedTime) ? parsedTime : null;
};

export type QueryStatusKey = 'all' | 'allowed' | 'processed' | 'blocked' | 'rewritten' | 'error';

export type QueryReasonKey =
    | 'all'
    | 'none'
    | 'allowlists'
    | 'blocked_by_filter'
    | 'custom_filtering_rules'
    | 'blocked_threats'
    | 'blocked_by_parental_control'
    | 'dns_rewrites'
    | 'error';

export const isSniReason = (reason?: string): boolean =>
    reason === FILTERED_STATUS.FILTERED_SNI || reason === FILTERED_STATUS.NOT_FILTERED_SNI;

export const getQueryStatusLabel = (statusKey: Exclude<QueryStatusKey, 'all'>): string => {
    switch (statusKey) {
        case 'allowed':
            return intl.getMessage('query_log_allowed');
        case 'processed':
            return intl.getMessage('query_log_processed');
        case 'blocked':
            return intl.getMessage('query_log_blocked');
        case 'rewritten':
            return intl.getMessage('query_log_rewritten');
        case 'error':
            return intl.getMessage('error');
        default:
            return '';
    }
};

export const getQueryReasonLabel = (reasonKey: Exclude<QueryReasonKey, 'all'>): string => {
    switch (reasonKey) {
        case 'none':
            return '-';
        case 'allowlists':
            return intl.getMessage('allowlists');
        case 'blocked_by_filter':
            return intl.getMessage('query_log_blocked_by_filter');
        case 'custom_filtering_rules':
            return intl.getMessage('query_log_custom_filtering_rules');
        case 'blocked_threats':
            return intl.getMessage('query_log_blocked_threats');
        case 'blocked_by_parental_control':
            return intl.getMessage('query_log_blocked_by_parental_control');
        case 'dns_rewrites':
            return intl.getMessage('dns_rewrites');
        case 'error':
            return intl.getMessage('error');
        default:
            return '';
    }
};

export const getStatusLabel = (
    reason: string,
    originalResponse: ResponseEntry[],
    isBlockedByResponse: boolean,
): string => {
    if (isBlockedByResponse) {
        return intl.getMessage('blocked_by_cname_or_ip');
    }

    switch (reason) {
        case FILTERED_STATUS.NOT_FILTERED_WHITE_LIST:
            return intl.getMessage('allowed');
        case FILTERED_STATUS.NOT_FILTERED_NOT_FOUND:
            return intl.getMessage('show_processed_responses');
        case FILTERED_STATUS.FILTERED_BLACK_LIST:
            return intl.getMessage('blocked');
        case FILTERED_STATUS.REWRITE:
        case FILTERED_STATUS.REWRITE_HOSTS:
        case FILTERED_STATUS.REWRITE_RULE:
            return intl.getMessage('rewritten');
        case FILTERED_STATUS.FILTERED_SAFE_BROWSING:
            return intl.getMessage('blocked_threats');
        case FILTERED_STATUS.FILTERED_PARENTAL:
            return intl.getMessage('blocked_adult_websites');
        case FILTERED_STATUS.FILTERED_SNI:
            return intl.getMessage('blocked_by_sni');
        case FILTERED_STATUS.NOT_FILTERED_SNI:
            return intl.getMessage('allowed_by_sni');
        case FILTERED_STATUS.NOT_FILTERED_ERROR:
            return intl.getMessage('error');
        case FILTERED_STATUS.FILTERED_INVALID:
            return intl.getMessage('invalid');
        default:
            if (originalResponse && originalResponse.length > 0) {
                return intl.getMessage('rewritten');
            }

            return intl.getMessage('show_processed_responses');
    }
};

const STATUS_COLOR_TO_CLASS: Record<string, string> = {
    [QUERY_STATUS_COLORS.RED]: theme.status.statusRed,
    [QUERY_STATUS_COLORS.GREEN]: theme.status.statusGreen,
    [QUERY_STATUS_COLORS.YELLOW]: theme.status.statusYellow,
    [QUERY_STATUS_COLORS.BLUE]: theme.status.statusBlue,
};

const PROTOCOL_LABEL_GETTERS = {
    dns_over_https: () => intl.getMessage('dns_over_https'),
    dns_over_quic: () => intl.getMessage('dns_over_quic'),
    dns_over_tls: () => intl.getMessage('dns_over_tls'),
    plain_dns: () => intl.getMessage('plain_dns'),
} as const;

export const getStatusClassName = (reason?: string): string =>
    STATUS_COLOR_TO_CLASS[
        FILTERED_STATUS_TO_COLOR_MAP[reason as keyof typeof FILTERED_STATUS_TO_COLOR_MAP]
    ] || '';

export const isBlockedReason = (reason?: string): boolean =>
    !!reason && reason.startsWith('Filtered');

export const getProtocolName = (clientProto: string, reason?: string): string => {
    if (isSniReason(reason)) {
        return '';
    }

    const key = SCHEME_TO_PROTOCOL_MAP[clientProto as keyof typeof SCHEME_TO_PROTOCOL_MAP];
    if (key) {
        return PROTOCOL_LABEL_GETTERS[key as keyof typeof PROTOCOL_LABEL_GETTERS]();
    }

    return PROTOCOL_LABEL_GETTERS.plain_dns();
};

export const formatLogTime = (time: string): string => {
    const parsedTime = parseLogDate(time);

    return parsedTime ? dateFormat(parsedTime, DEFAULT_TIME_FORMAT) : time;
};

export const formatLogDate = (time: string): string => {
    const parsedTime = parseLogDate(time);

    return parsedTime
        ? parsedTime.toLocaleDateString(intl.getUILanguage(), {
              day: 'numeric',
              month: 'short',
              year: 'numeric',
          })
        : time;
};

export const formatLogTimeDetailed = (time: string): string => {
    const parsedTime = parseLogDate(time);

    return parsedTime ? dateFormat(parsedTime, LONG_TIME_FORMAT) : time;
};

export const getClientLocation = (whois?: WhoisInfo | null): string =>
    [whois?.city, whois?.country].filter(Boolean).join(', ');

type ResponseDetailsParams = {
    elapsedMs?: string;
    filters: Filter[];
    reason?: string;
    rules: { filter_list_id?: number; text?: string }[];
    whitelistFilters: Filter[];
};

export const getQueryStatusKey = (
    reason?: string,
    originalResponse: { value?: string; type?: string; ttl?: number }[] = [],
): Exclude<QueryStatusKey, 'all'> => {
    switch (reason) {
        case FILTERED_STATUS.NOT_FILTERED_WHITE_LIST:
            return 'allowed';
        case FILTERED_STATUS.REWRITE:
        case FILTERED_STATUS.REWRITE_HOSTS:
        case FILTERED_STATUS.REWRITE_RULE:
            return 'rewritten';
        case FILTERED_STATUS.NOT_FILTERED_NOT_FOUND:
            return 'processed';
        case FILTERED_STATUS.FILTERED_SNI:
            return 'blocked';
        case FILTERED_STATUS.NOT_FILTERED_SNI:
            return 'processed';
        case FILTERED_STATUS.NOT_FILTERED_ERROR:
        case FILTERED_STATUS.FILTERED_INVALID:
            return 'error';
        default:
            if (originalResponse.length > 0) {
                return 'rewritten';
            }

            if (reason && reason.startsWith('Filtered')) {
                return 'blocked';
            }

            return 'processed';
    }
};

export const getQueryReasonKey = (
    reason?: string,
    rules: { filter_list_id?: number; text?: string }[] = [],
): Exclude<QueryReasonKey, 'all'> => {
    switch (reason) {
        case FILTERED_STATUS.NOT_FILTERED_WHITE_LIST:
            return 'allowlists';
        case FILTERED_STATUS.NOT_FILTERED_NOT_FOUND:
            return 'none';
        case FILTERED_STATUS.REWRITE:
        case FILTERED_STATUS.REWRITE_HOSTS:
        case FILTERED_STATUS.REWRITE_RULE:
            return 'dns_rewrites';
        case FILTERED_STATUS.FILTERED_SAFE_BROWSING:
            return 'blocked_threats';
        case FILTERED_STATUS.FILTERED_PARENTAL:
            return 'blocked_by_parental_control';
        case FILTERED_STATUS.NOT_FILTERED_ERROR:
        case FILTERED_STATUS.FILTERED_INVALID:
            return 'error';
        case FILTERED_STATUS.FILTERED_BLACK_LIST:
            return rules.some(
                ({ filter_list_id }) => filter_list_id === SPECIAL_FILTER_ID.CUSTOM_FILTERING_RULES,
            )
                ? 'custom_filtering_rules'
                : 'blocked_by_filter';
        case FILTERED_STATUS.FILTERED_SNI:
            return 'blocked_by_filter';
        default:
            return 'none';
    }
};

export const getQueryStatusDetails = (elapsedMs: string): string =>
    formatElapsedMs(elapsedMs, intl.getMessage('milliseconds_abbreviation'));

export const getQueryReasonDetails = ({
    filters,
    reason,
    rules,
    whitelistFilters,
}: ResponseDetailsParams): string => {
    switch (getQueryReasonKey(reason, rules)) {
        case 'blocked_by_filter':
        case 'allowlists':
            return getFilterNames(rules, filters, whitelistFilters).filter(Boolean).join(', ');
        default:
            return '';
    }
};

export const filterLogsByStatus = <
    T extends { reason?: string; originalResponse?: { type?: string; value?: string }[] },
>(
    logs: T[],
    status: QueryStatusKey | string,
): T[] => {
    if (status === 'all') {
        return logs;
    }

    return logs.filter(
        (log) => getQueryStatusKey(log.reason ?? '', log.originalResponse ?? []) === status,
    );
};

export const getResponseDetails = ({
    elapsedMs,
    filters,
    reason,
    rules,
    whitelistFilters,
}: ResponseDetailsParams): string => {
    const formattedElapsedMs = formatElapsedMs(
        elapsedMs || '',
        intl.getMessage('milliseconds_abbreviation'),
    );

    switch (reason) {
        case FILTERED_STATUS.FILTERED_BLACK_LIST:
        case FILTERED_STATUS.FILTERED_SNI:
        case FILTERED_STATUS.NOT_FILTERED_WHITE_LIST: {
            const filterNames = getFilterNames(rules, filters, whitelistFilters)
                .filter(Boolean)
                .join(', ');

            return filterNames || formattedElapsedMs;
        }
        default:
            return formattedElapsedMs;
    }
};
